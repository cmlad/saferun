use std::env;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::approval::{
    lowercase_hex, session_digest, ApprovalClient, ApprovalDecision, ApprovalRequest,
    ApprovalScope, PROTOCOL_VERSION,
};
use crate::policy::{
    classify, configured_prefix_consumptions, deny_match as policy_deny_match, is_denied,
    shell_prefix_matches, Policy, PolicyDecision, RuleMatch,
};
use crate::shell::{
    analyze_shell_invocation, shell_prefix_candidates_for_shell_command, ShellCommandUnit,
    ShellInvocation,
};

pub const DENIED_EXIT_CODE: i32 = 126;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationKind {
    Deny,
    Ask,
    Allow,
}

impl AuthorizationKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Deny => "DENIED",
            Self::Ask => "ASK",
            Self::Allow => "ALLOW",
        }
    }

    pub fn rule_kind(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Ask => "ask",
            Self::Allow => "allow",
        }
    }
}

#[derive(Debug)]
pub enum AuthorizationOutcome<'a> {
    Denied {
        diagnostic: Option<String>,
    },
    DryRun {
        kind: AuthorizationKind,
        matched: RuleMatch<'a>,
    },
    Execute {
        kind: AuthorizationKind,
        matched: RuleMatch<'a>,
        approval: Option<ApprovalScope>,
    },
}

#[derive(Debug)]
pub struct ShellUnitAuthorization<'a> {
    pub unit: ShellCommandUnit,
    pub kind: AuthorizationKind,
    pub matched: RuleMatch<'a>,
    pub approval: Option<ApprovalScope>,
}

#[derive(Debug)]
pub enum ShellAuthorizationOutcome<'a> {
    Denied {
        diagnostic: Option<String>,
        units: Vec<ShellUnitAuthorization<'a>>,
    },
    DryRun {
        aggregate_kind: AuthorizationKind,
        units: Vec<ShellUnitAuthorization<'a>>,
    },
    Execute {
        aggregate_kind: AuthorizationKind,
        units: Vec<ShellUnitAuthorization<'a>>,
    },
}

#[derive(Debug)]
pub enum InvocationAuthorizationOutcome<'a> {
    Direct(AuthorizationOutcome<'a>),
    Shell(ShellAuthorizationOutcome<'a>),
}

impl AuthorizationOutcome<'_> {
    pub fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Denied { .. } => Some(DENIED_EXIT_CODE),
            Self::DryRun { .. } => Some(0),
            Self::Execute { .. } => None,
        }
    }
}

impl InvocationAuthorizationOutcome<'_> {
    pub fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Direct(outcome) => outcome.exit_code(),
            Self::Shell(ShellAuthorizationOutcome::Denied { .. }) => Some(DENIED_EXIT_CODE),
            Self::Shell(ShellAuthorizationOutcome::DryRun { .. }) => Some(0),
            Self::Shell(ShellAuthorizationOutcome::Execute { .. }) => None,
        }
    }
}

/// Classify and authorize one command, using the injected client only for live asks.
pub fn authorize_command<'a>(
    policy: &'a Policy,
    command: &[String],
    config_path: &Path,
    dry_run: bool,
    token: Option<&[u8; 32]>,
    client: &dyn ApprovalClient,
) -> AuthorizationOutcome<'a> {
    if let Some(nested) = nested_saferun_command(policy, command) {
        return AuthorizationOutcome::Denied {
            diagnostic: Some(nested_saferun_diagnostic(&nested)),
        };
    }

    match classify(policy, command) {
        PolicyDecision::Deny => AuthorizationOutcome::Denied { diagnostic: None },
        PolicyDecision::Allow(matched) if dry_run => AuthorizationOutcome::DryRun {
            kind: AuthorizationKind::Allow,
            matched,
        },
        PolicyDecision::Allow(matched) => AuthorizationOutcome::Execute {
            kind: AuthorizationKind::Allow,
            matched,
            approval: None,
        },
        PolicyDecision::Ask(matched) if dry_run => AuthorizationOutcome::DryRun {
            kind: AuthorizationKind::Ask,
            matched,
        },
        PolicyDecision::Ask(matched) => {
            match request_approval(policy, command, config_path, token, matched, client) {
                Ok(scope) => AuthorizationOutcome::Execute {
                    kind: AuthorizationKind::Ask,
                    matched,
                    approval: Some(scope),
                },
                Err(diagnostic) => AuthorizationOutcome::Denied { diagnostic },
            }
        }
    }
}

pub fn authorize_invocation<'a>(
    policy: &'a Policy,
    command: &[String],
    config_path: &Path,
    dry_run: bool,
    token: Option<&[u8; 32]>,
    client: &dyn ApprovalClient,
) -> InvocationAuthorizationOutcome<'a> {
    if let Some(nested) = nested_saferun_command(policy, command) {
        return InvocationAuthorizationOutcome::Direct(AuthorizationOutcome::Denied {
            diagnostic: Some(nested_saferun_diagnostic(&nested)),
        });
    }

    let Some(shell_invocation) = analyze_shell_invocation(policy, command) else {
        return InvocationAuthorizationOutcome::Direct(authorize_command(
            policy,
            command,
            config_path,
            dry_run,
            token,
            client,
        ));
    };

    InvocationAuthorizationOutcome::Shell(authorize_shell_invocation(
        policy,
        command,
        shell_invocation,
        config_path,
        dry_run,
        token,
        client,
    ))
}

fn authorize_shell_invocation<'a>(
    policy: &'a Policy,
    original_command: &[String],
    shell_invocation: ShellInvocation,
    config_path: &Path,
    dry_run: bool,
    token: Option<&[u8; 32]>,
    client: &dyn ApprovalClient,
) -> ShellAuthorizationOutcome<'a> {
    let mut classified = Vec::with_capacity(shell_invocation.units.len());
    for unit in shell_invocation.units {
        classified.push(classify_unit(policy, unit));
    }
    let aggregate_kind = aggregate_kind(&classified);

    if let Some(nested) = shell_invocation
        .static_commands
        .iter()
        .find_map(|argv| nested_saferun_command(policy, argv))
    {
        return ShellAuthorizationOutcome::Denied {
            diagnostic: Some(nested_saferun_diagnostic(&nested)),
            units: classified,
        };
    }

    if let Some(nested) = shell_invocation
        .static_commands
        .iter()
        .find_map(|argv| nested_shell_command(policy, argv))
    {
        return ShellAuthorizationOutcome::Denied {
            diagnostic: Some(format!(
                "saferun: nested shell invocation is not permitted: {}",
                crate::policy::shlex_join(&nested)
            )),
            units: classified,
        };
    }

    if aggregate_kind == AuthorizationKind::Deny
        || is_denied(policy, original_command)
        || shell_invocation
            .static_commands
            .iter()
            .any(|argv| denied(policy, argv))
    {
        return ShellAuthorizationOutcome::Denied {
            diagnostic: None,
            units: classified,
        };
    }

    if dry_run {
        return ShellAuthorizationOutcome::DryRun {
            aggregate_kind,
            units: classified,
        };
    }

    let mut authorized = Vec::with_capacity(classified.len());
    for mut unit in classified {
        if unit.kind == AuthorizationKind::Ask {
            let approval_command = unit.unit.approval_command();
            match request_approval(
                policy,
                &approval_command,
                config_path,
                token,
                unit.matched,
                client,
            ) {
                Ok(scope) => unit.approval = Some(scope),
                Err(diagnostic) => {
                    return ShellAuthorizationOutcome::Denied {
                        diagnostic,
                        units: Vec::new(),
                    };
                }
            }
        }
        authorized.push(unit);
    }

    ShellAuthorizationOutcome::Execute {
        aggregate_kind,
        units: authorized,
    }
}

fn aggregate_kind(units: &[ShellUnitAuthorization<'_>]) -> AuthorizationKind {
    if units
        .iter()
        .any(|unit| unit.kind == AuthorizationKind::Deny)
    {
        AuthorizationKind::Deny
    } else if units.iter().any(|unit| unit.kind == AuthorizationKind::Ask) {
        AuthorizationKind::Ask
    } else {
        AuthorizationKind::Allow
    }
}

fn classify_unit<'a>(policy: &'a Policy, unit: ShellCommandUnit) -> ShellUnitAuthorization<'a> {
    let (kind, matched) = match &unit {
        ShellCommandUnit::Parsed(argv) => {
            if let Some(matched) = shell_deny_match(policy, argv) {
                (AuthorizationKind::Deny, matched)
            } else {
                match classify(policy, argv) {
                    PolicyDecision::Deny => (
                        AuthorizationKind::Deny,
                        policy_deny_match(policy, argv).expect("denied command has a match"),
                    ),
                    PolicyDecision::Ask(matched) => (AuthorizationKind::Ask, matched),
                    PolicyDecision::Allow(matched) => (AuthorizationKind::Allow, matched),
                }
            }
        }
        ShellCommandUnit::Redirection { .. } => {
            let argv = unit.approval_command();
            match classify(policy, &argv) {
                PolicyDecision::Deny => (
                    AuthorizationKind::Deny,
                    policy_deny_match(policy, &argv).expect("denied command has a match"),
                ),
                PolicyDecision::Ask(matched) => (AuthorizationKind::Ask, matched),
                PolicyDecision::Allow(matched) => (AuthorizationKind::Allow, matched),
            }
        }
        ShellCommandUnit::Opaque(_) => (AuthorizationKind::Ask, policy.implicit_ask_match()),
    };

    ShellUnitAuthorization {
        unit,
        kind,
        matched,
        approval: None,
    }
}

fn denied(policy: &Policy, argv: &[String]) -> bool {
    shell_deny_match(policy, argv).is_some()
}

fn nested_saferun_command(policy: &Policy, argv: &[String]) -> Option<Vec<String>> {
    let mut candidates = Vec::new();
    push_nested_candidate(&mut candidates, argv);
    push_nested_assignment_stripped_candidate(&mut candidates, argv);

    let mut index = 0;
    while index < candidates.len() {
        let candidate = candidates[index];
        index += 1;

        if is_saferun_command(candidate) {
            return Some(candidate.to_vec());
        }

        for consumed in configured_prefix_consumptions(policy, candidate) {
            if consumed <= candidate.len() {
                push_nested_candidate(&mut candidates, &candidate[consumed..]);
                push_nested_assignment_stripped_candidate(&mut candidates, &candidate[consumed..]);
            }
            if consumed > 0 && consumed <= candidate.len() {
                let last_consumed = &candidate[consumed - 1..];
                push_nested_candidate(&mut candidates, last_consumed);
                push_nested_assignment_stripped_candidate(&mut candidates, last_consumed);
            }
        }
    }

    None
}

fn push_nested_candidate<'a>(candidates: &mut Vec<&'a [String]>, candidate: &'a [String]) {
    if candidates.iter().any(|existing| {
        existing.as_ptr() == candidate.as_ptr() && existing.len() == candidate.len()
    }) {
        return;
    }
    candidates.push(candidate);
}

fn push_nested_assignment_stripped_candidate<'a>(
    candidates: &mut Vec<&'a [String]>,
    candidate: &'a [String],
) {
    if let Some(effective) = crate::shell::strip_leading_assignments(candidate) {
        push_nested_candidate(candidates, effective);
    }
}

fn is_saferun_command(argv: &[String]) -> bool {
    argv.first()
        .and_then(|command| std::path::Path::new(command).file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("saferun"))
}

fn nested_saferun_diagnostic(command: &[String]) -> String {
    format!(
        "saferun: nested saferun invocation is not permitted: {}",
        crate::policy::shlex_join(command)
    )
}

fn shell_deny_match<'a>(policy: &'a Policy, argv: &[String]) -> Option<RuleMatch<'a>> {
    shell_prefix_candidates_for_shell_command(policy, argv)
        .into_iter()
        .find_map(|candidate| policy_deny_match(policy, candidate))
}

fn nested_shell_command(policy: &Policy, argv: &[String]) -> Option<Vec<String>> {
    for candidate in shell_prefix_candidates_for_shell_command(policy, argv) {
        if !shell_prefix_matches(policy, candidate).is_empty() {
            return Some(candidate.to_vec());
        }
    }
    None
}

fn request_approval(
    policy: &Policy,
    command: &[String],
    config_path: &Path,
    token: Option<&[u8; 32]>,
    matched: RuleMatch<'_>,
    client: &dyn ApprovalClient,
) -> Result<ApprovalScope, Option<String>> {
    let Some(token) = token else {
        return Err(Some(
            "saferun: ask command requires -t TOKEN_FILE".to_string(),
        ));
    };

    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(|error| {
            service_failure(format!("cannot canonicalize current directory: {error}"))
        })?;
    let canonical_config = fs::canonicalize(config_path)
        .map_err(|error| service_failure(format!("cannot canonicalize config path: {error}")))?;
    let prefix_parts_consumed = u32::try_from(matched.prefix_parts_consumed())
        .map_err(|_| service_failure("matched prefix count is too large".to_string()))?;
    let request = ApprovalRequest {
        version: PROTOCOL_VERSION,
        session_digest: session_digest(token),
        command: command.to_vec(),
        cwd: cwd.as_os_str().as_bytes().to_vec(),
        config_path: canonical_config.as_os_str().as_bytes().to_vec(),
        policy_digest: lowercase_hex(&policy.digest()),
        ask_rule_source: matched.rule_source().to_string(),
        implicit_ask: matched.is_implicit(),
        prefix_rule_source: matched.prefix_rule_source().map(str::to_string),
        prefix_parts_consumed,
    };

    match client.request(&request) {
        Ok(ApprovalDecision::Denied) => Err(None),
        Ok(ApprovalDecision::Approved { scope }) => Ok(scope),
        Err(error) => Err(service_failure(error.to_string())),
    }
}

fn service_failure(message: String) -> Option<String> {
    Some(format!("saferun: approval service error: {message}"))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io;
    use std::path::PathBuf;

    use super::*;
    use crate::approval::{ApprovalError, ApprovalScope};
    use crate::policy::load_policy;

    struct FakeClient {
        calls: Cell<usize>,
        last: std::cell::RefCell<Option<ApprovalRequest>>,
        result: Result<ApprovalDecision, &'static str>,
    }

    impl ApprovalClient for FakeClient {
        fn request(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalError> {
            self.calls.set(self.calls.get() + 1);
            self.last.replace(Some(request.clone()));
            self.result.clone().map_err(|message| {
                ApprovalError::Io(io::Error::new(io::ErrorKind::ConnectionRefused, message))
            })
        }
    }

    struct QueueClient {
        calls: Cell<usize>,
        requests: std::cell::RefCell<Vec<ApprovalRequest>>,
        results: std::cell::RefCell<VecDeque<Result<ApprovalDecision, &'static str>>>,
    }

    impl QueueClient {
        fn new(results: impl IntoIterator<Item = Result<ApprovalDecision, &'static str>>) -> Self {
            Self {
                calls: Cell::new(0),
                requests: std::cell::RefCell::new(Vec::new()),
                results: std::cell::RefCell::new(results.into_iter().collect()),
            }
        }
    }

    impl ApprovalClient for QueueClient {
        fn request(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalError> {
            self.calls.set(self.calls.get() + 1);
            self.requests.borrow_mut().push(request.clone());
            self.results
                .borrow_mut()
                .pop_front()
                .expect("queued approval result")
                .map_err(|message| {
                    ApprovalError::Io(io::Error::new(io::ErrorKind::ConnectionRefused, message))
                })
        }
    }

    fn ask_policy() -> (tempfile::TempDir, Policy) {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("saferun.yaml");
        std::fs::write(&path, "allow: [/bin/true]\nask: [/usr/bin/touch]\n").expect("write policy");
        let policy = load_policy(&path).expect("load policy");
        (directory, policy)
    }

    fn policy(text: &str) -> (tempfile::TempDir, PathBuf, Policy) {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("saferun.yaml");
        std::fs::write(&path, text).expect("write policy");
        let policy = load_policy(&path).expect("load policy");
        (directory, path, policy)
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    fn approved(scope: ApprovalScope) -> Result<ApprovalDecision, &'static str> {
        Ok(ApprovalDecision::Approved { scope })
    }

    #[test]
    fn ask_dry_run_needs_neither_token_nor_client() {
        let (directory, policy) = ask_policy();
        let client = FakeClient {
            calls: Cell::new(0),
            last: std::cell::RefCell::new(None),
            result: Err("must not be called"),
        };
        let command = vec!["/usr/bin/touch".to_string(), "file".to_string()];
        let outcome = authorize_command(
            &policy,
            &command,
            &directory.path().join("saferun.yaml"),
            true,
            None,
            &client,
        );
        assert!(matches!(
            outcome,
            AuthorizationOutcome::DryRun {
                kind: AuthorizationKind::Ask,
                ..
            }
        ));
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn missing_token_and_client_error_fail_closed() {
        let (directory, policy) = ask_policy();
        let config = directory.path().join("saferun.yaml");
        let command = vec!["/usr/bin/touch".to_string(), "file".to_string()];
        let client = FakeClient {
            calls: Cell::new(0),
            last: std::cell::RefCell::new(None),
            result: Err("refused"),
        };
        let missing = authorize_command(&policy, &command, &config, false, None, &client);
        assert_eq!(missing.exit_code(), Some(DENIED_EXIT_CODE));
        let AuthorizationOutcome::Denied { diagnostic } = &missing else {
            panic!("missing token must deny");
        };
        assert_eq!(
            diagnostic.as_deref(),
            Some("saferun: ask command requires -t TOKEN_FILE")
        );
        assert_eq!(client.calls.get(), 0);

        let failed = authorize_command(&policy, &command, &config, false, Some(&[7; 32]), &client);
        assert_eq!(failed.exit_code(), Some(DENIED_EXIT_CODE));
        assert!(matches!(failed, AuthorizationOutcome::Denied { .. }));
        assert_eq!(client.calls.get(), 1);
    }

    #[test]
    fn approval_returns_execution_outcome() {
        let (directory, policy) = ask_policy();
        let config = directory.path().join("saferun.yaml");
        let command = vec!["/usr/bin/touch".to_string(), "file".to_string()];
        let client = FakeClient {
            calls: Cell::new(0),
            last: std::cell::RefCell::new(None),
            result: Ok(ApprovalDecision::Approved {
                scope: ApprovalScope::Session,
            }),
        };
        let outcome = authorize_command(&policy, &command, &config, false, Some(&[7; 32]), &client);
        assert!(matches!(
            outcome,
            AuthorizationOutcome::Execute {
                kind: AuthorizationKind::Ask,
                approval: Some(ApprovalScope::Session),
                ..
            }
        ));
        assert_eq!(client.calls.get(), 1);
        assert_eq!(
            client
                .last
                .borrow()
                .as_ref()
                .map(|request| request.implicit_ask),
            Some(false)
        );
    }

    #[test]
    fn unmatched_commands_use_implicit_ask() {
        let (directory, policy) = ask_policy();
        let config = directory.path().join("saferun.yaml");
        let command = vec!["/completely/unmatched".to_string(), "argument".to_string()];
        let unused_client = FakeClient {
            calls: Cell::new(0),
            last: std::cell::RefCell::new(None),
            result: Err("must not be called"),
        };
        let dry_run = authorize_command(&policy, &command, &config, true, None, &unused_client);
        let AuthorizationOutcome::DryRun { matched, .. } = dry_run else {
            panic!("unmatched dry run must ask");
        };
        assert!(matched.is_implicit());
        assert_eq!(unused_client.calls.get(), 0);

        let client = FakeClient {
            calls: Cell::new(0),
            last: std::cell::RefCell::new(None),
            result: Ok(ApprovalDecision::Approved {
                scope: ApprovalScope::Once,
            }),
        };
        let approved =
            authorize_command(&policy, &command, &config, false, Some(&[9; 32]), &client);
        assert!(matches!(
            approved,
            AuthorizationOutcome::Execute {
                kind: AuthorizationKind::Ask,
                approval: Some(ApprovalScope::Once),
                ..
            }
        ));
        assert_eq!(
            client
                .last
                .borrow()
                .as_ref()
                .map(|request| request.implicit_ask),
            Some(true)
        );
    }

    #[test]
    fn direct_nested_saferun_invocation_is_denied_before_policy_or_prompt() {
        let (_directory, config, policy) = policy("allow:\n  - saferun **\nask:\n  - '**'\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["saferun", "--dry-run", "--", "git", "status"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[2; 32]), &client);

        let InvocationAuthorizationOutcome::Direct(AuthorizationOutcome::Denied {
            diagnostic: Some(message),
        }) = outcome
        else {
            panic!("expected direct nested saferun denial");
        };
        assert_eq!(
            message,
            "saferun: nested saferun invocation is not permitted: saferun --dry-run -- git status"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn direct_nested_saferun_after_generic_prefix_is_denied() {
        let (_directory, config, policy) =
            policy("prefixes: ['env *']\nallow:\n  - saferun **\nask:\n  - '**'\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["env", "A=1", "saferun", "--dry-run", "--", "git", "status"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[2; 32]), &client);

        let InvocationAuthorizationOutcome::Direct(AuthorizationOutcome::Denied {
            diagnostic: Some(message),
        }) = outcome
        else {
            panic!("expected prefixed nested saferun denial");
        };
        assert_eq!(
            message,
            "saferun: nested saferun invocation is not permitted: saferun --dry-run -- git status"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn direct_nested_saferun_consumed_by_generic_prefix_is_denied() {
        let (_directory, config, policy) =
            policy("prefixes: ['env *']\nallow:\n  - saferun **\n  - git status\nask:\n  - '**'\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["env", "saferun", "--dry-run", "--", "git", "status"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[2; 32]), &client);

        let InvocationAuthorizationOutcome::Direct(AuthorizationOutcome::Denied {
            diagnostic: Some(message),
        }) = outcome
        else {
            panic!("expected consumed nested saferun denial");
        };
        assert_eq!(
            message,
            "saferun: nested saferun invocation is not permitted: saferun --dry-run -- git status"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn direct_nested_saferun_consumed_before_shell_prefix_is_denied_before_shell_analysis() {
        let (_directory, config, policy) =
            policy("prefixes: ['env *']\nshell_prefixes: ['bash -c']\nallow:\n  - git status\nask:\n  - '**'\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["env", "saferun", "bash", "-c", "git status"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[2; 32]), &client);

        let InvocationAuthorizationOutcome::Direct(AuthorizationOutcome::Denied {
            diagnostic: Some(message),
        }) = outcome
        else {
            panic!("expected consumed nested saferun denial before shell analysis");
        };
        assert_eq!(
            message,
            "saferun: nested saferun invocation is not permitted: saferun bash -c 'git status'"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn direct_nested_saferun_detection_is_case_insensitive() {
        let (_directory, config, policy) = policy("allow:\n  - saferun **\nask:\n  - '**'\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["SaFeRuN", "--dry-run", "--", "git", "status"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[2; 32]), &client);

        let InvocationAuthorizationOutcome::Direct(AuthorizationOutcome::Denied {
            diagnostic: Some(message),
        }) = outcome
        else {
            panic!("expected case-insensitive nested saferun denial");
        };
        assert_eq!(
            message,
            "saferun: nested saferun invocation is not permitted: SaFeRuN --dry-run -- git status"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn direct_nested_saferun_detection_reserves_the_executable_basename() {
        let (_directory, config, policy) =
            policy("allow:\n  - /tmp/repo/bin/saferun **\nask:\n  - '**'\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["/tmp/repo/bin/saferun", "--version"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[2; 32]), &client);

        let InvocationAuthorizationOutcome::Direct(AuthorizationOutcome::Denied {
            diagnostic: Some(message),
        }) = outcome
        else {
            panic!("expected basename-reserved nested saferun denial");
        };
        assert_eq!(
            message,
            "saferun: nested saferun invocation is not permitted: /tmp/repo/bin/saferun --version"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn implicit_prefixed_ask_forwards_prefix_metadata() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("saferun.yaml");
        std::fs::write(&path, "allow: [/bin/true]\nprefixes: ['env *']\n").expect("write policy");
        let policy = load_policy(&path).expect("load policy");
        let client = FakeClient {
            calls: Cell::new(0),
            last: std::cell::RefCell::new(None),
            result: Ok(ApprovalDecision::Approved {
                scope: ApprovalScope::Once,
            }),
        };
        let command = vec![
            "env".to_string(),
            "X=1".to_string(),
            "/completely/unmatched".to_string(),
            "arg".to_string(),
        ];
        let outcome = authorize_command(&policy, &command, &path, false, Some(&[3; 32]), &client);
        assert!(matches!(
            outcome,
            AuthorizationOutcome::Execute {
                kind: AuthorizationKind::Ask,
                approval: Some(ApprovalScope::Once),
                ..
            }
        ));
        let last = client.last.borrow();
        let request = last.as_ref().expect("request was sent");
        assert!(request.implicit_ask);
        assert_eq!(request.prefix_rule_source.as_deref(), Some("env *"));
        assert_eq!(request.prefix_parts_consumed, 2);
    }

    #[test]
    fn shell_all_allowed_payload_does_not_prompt() {
        let (_directory, config, policy) = policy(
            "shell_prefixes: ['bash -c']\nallow:\n  - cargo test\n  - git status\nask:\n  - git push **\n",
        );
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&["bash", "-c", "cargo test && git status"]);
        let outcome = authorize_invocation(&policy, &command, &config, false, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell execution");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Allow);
        assert_eq!(units.len(), 2);
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_ignores_stderr_dev_null_without_prompting() {
        let (_directory, config, policy) = policy(
            "shell_prefixes: ['bash -c']\nallow:\n  - printf hi\n  - grep h\n  - cargo test\nask:\n  - '2> /dev/null'\n",
        );
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&[
            "bash",
            "-c",
            "printf hi 2>/dev/null | grep h 2> /dev/null && cargo test 2>'/dev/null'",
        ]);
        let outcome = authorize_invocation(&policy, &command, &config, false, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell execution");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Allow);
        assert_eq!(units.len(), 3);
        assert_eq!(
            units[0].unit,
            ShellCommandUnit::Parsed(argv(&["printf", "hi"]))
        );
        assert_eq!(
            units[1].unit,
            ShellCommandUnit::Parsed(argv(&["grep", "h"]))
        );
        assert_eq!(
            units[2].unit,
            ShellCommandUnit::Parsed(argv(&["cargo", "test"]))
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_ignores_separator_adjacent_stderr_dev_null_without_prompting() {
        let (_directory, config, policy) = policy(
            "shell_prefixes: ['bash -c']\nallow:\n  - printf hi\n  - printf bye\n  - grep bye\n  - cargo test\nask:\n  - '2> /dev/null'\n",
        );
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&[
            "bash",
            "-c",
            "printf hi;2>/dev/null printf bye|2>/dev/null grep bye&&2> /dev/null cargo test",
        ]);
        let outcome = authorize_invocation(&policy, &command, &config, false, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell execution");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Allow);
        assert_eq!(units.len(), 4);
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_quoted_expansions_with_ignored_stderr_dev_null_do_not_match_allow() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow:\n  - echo **\nask:\n  - git push **\n");
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&["bash", "-c", "echo \"$HOME\" 2>/dev/null"]);
        let outcome = authorize_invocation(&policy, &command, &config, true, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::DryRun {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell dry-run");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Ask);
        assert_eq!(units.len(), 1);
        assert!(matches!(units[0].unit, ShellCommandUnit::Opaque(_)));
        assert!(units[0].matched.is_implicit());
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_ignores_stderr_dev_null_only_payload_without_prompting() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow: [/bin/true]\nask: ['**']\n");
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&["bash", "-c", "2>/dev/null"]);
        let outcome = authorize_invocation(&policy, &command, &config, false, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell execution");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Allow);
        assert!(units.is_empty());
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_empty_payload_authorizes_without_prompting() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow: [/bin/true]\nask: ['**']\n");
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&["bash", "-c", ""]);
        let outcome = authorize_invocation(&policy, &command, &config, false, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell execution");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Allow);
        assert!(units.is_empty());
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_extra_arguments_force_one_exact_opaque_approval() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow:\n  - cargo test\nask:\n  - cargo test\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "cargo test", "bash"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[13; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell execution");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Ask);
        assert_eq!(units.len(), 1);
        assert_eq!(
            units[0].unit.approval_command(),
            &["bash -c 'cargo test' bash"]
        );
        assert_eq!(units[0].approval, Some(ApprovalScope::Once));
        assert!(units[0].matched.is_implicit());
        let requests = client.requests.borrow();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].command, vec!["bash -c 'cargo test' bash"]);
        assert!(requests[0].implicit_ask);
    }

    #[test]
    fn shell_mixed_allow_and_ask_prompts_for_asks_in_order() {
        let (_directory, config, policy) = policy(
            "shell_prefixes: ['bash -c']\nallow:\n  - cargo test\nask:\n  - git push **\n  - gh pr create **\n",
        );
        let client = QueueClient::new([
            approved(ApprovalScope::Once),
            approved(ApprovalScope::Session),
        ]);
        let command = argv(&[
            "bash",
            "-c",
            "cargo test; git push origin main; gh pr create --fill",
        ]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[4; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell execution");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Ask);
        assert_eq!(units.len(), 3);
        assert_eq!(client.calls.get(), 2);
        let requests = client.requests.borrow();
        assert_eq!(
            requests[0].command,
            argv(&["git", "push", "origin", "main"])
        );
        assert_eq!(requests[1].command, argv(&["gh", "pr", "create", "--fill"]));
    }

    #[test]
    fn shell_redirections_are_classified_as_independent_units() {
        let (_directory, config, policy) = policy(
            "shell_prefixes: ['bash -c']\nallow:\n  - printf hi\n  - git status\n  - '> out'\nask:\n  - '>> status.log'\n",
        );
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&["bash", "-c", "printf hi > out; git status >> status.log"]);
        let outcome = authorize_invocation(&policy, &command, &config, true, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::DryRun {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell dry-run");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Ask);
        assert_eq!(units.len(), 4);
        assert_eq!(units[0].kind, AuthorizationKind::Allow);
        assert_eq!(
            units[0].unit,
            ShellCommandUnit::Parsed(vec!["printf".into(), "hi".into()])
        );
        assert_eq!(units[1].kind, AuthorizationKind::Allow);
        assert_eq!(
            units[1].unit,
            ShellCommandUnit::Redirection {
                operator: ">".into(),
                target: "out".into(),
            }
        );
        assert_eq!(units[2].kind, AuthorizationKind::Allow);
        assert_eq!(
            units[2].unit,
            ShellCommandUnit::Parsed(vec!["git".into(), "status".into()])
        );
        assert_eq!(units[3].kind, AuthorizationKind::Ask);
        assert_eq!(
            units[3].unit,
            ShellCommandUnit::Redirection {
                operator: ">>".into(),
                target: "status.log".into(),
            }
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_ignores_stderr_dev_null_while_authorizing_stdout_redirection() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow:\n  - printf hi\nask:\n  - '> out'\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "printf hi 2>/dev/null > out"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[4; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell execution");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Ask);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].kind, AuthorizationKind::Allow);
        assert_eq!(
            units[0].unit,
            ShellCommandUnit::Parsed(argv(&["printf", "hi"]))
        );
        assert_eq!(units[1].kind, AuthorizationKind::Ask);
        assert_eq!(
            units[1].unit,
            ShellCommandUnit::Redirection {
                operator: ">".into(),
                target: "out".into(),
            }
        );
        assert_eq!(client.calls.get(), 1);
        assert_eq!(client.requests.borrow()[0].command, argv(&[">", "out"]));
    }

    #[test]
    fn shell_redirection_asks_are_prompted_in_source_order() {
        let (_directory, config, policy) = policy(
            "shell_prefixes: ['bash -c']\nallow: [/bin/true]\nask:\n  - git push **\n  - '> out'\n",
        );
        let client = QueueClient::new([
            approved(ApprovalScope::Once),
            approved(ApprovalScope::Session),
        ]);
        let command = argv(&["bash", "-c", "git push origin main > out"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[4; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell execution");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Ask);
        assert_eq!(units.len(), 2);
        assert_eq!(client.calls.get(), 2);
        let requests = client.requests.borrow();
        assert_eq!(
            requests[0].command,
            argv(&["git", "push", "origin", "main"])
        );
        assert_eq!(requests[1].command, argv(&[">", "out"]));
    }

    #[test]
    fn shell_denial_is_detected_before_prompting() {
        let (_directory, config, policy) = policy(
            "shell_prefixes: ['bash -c']\nallow: [cargo test]\nask: ['git push **']\ndeny: ['rm **']\n",
        );
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "git push origin main; rm target"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[5; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
            diagnostic: None,
            units,
        }) = outcome
        else {
            panic!("expected shell denial");
        };
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].kind, AuthorizationKind::Ask);
        assert_eq!(
            units[0].unit,
            ShellCommandUnit::Parsed(vec![
                "git".into(),
                "push".into(),
                "origin".into(),
                "main".into()
            ])
        );
        assert_eq!(units[1].kind, AuthorizationKind::Deny);
        assert_eq!(
            units[1].unit,
            ShellCommandUnit::Parsed(vec!["rm".into(), "target".into()])
        );
        assert_eq!(units[1].matched.rule_source(), "rm **");
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_denial_is_detected_with_ignored_stderr_dev_null() {
        let (_directory, config, policy) = policy(
            "shell_prefixes: ['bash -c']\nallow: [cargo test]\nask: ['git push **']\ndeny: ['rm **']\n",
        );
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "git push origin main; rm target 2>/dev/null"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[5; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
            diagnostic: None,
            units,
        }) = outcome
        else {
            panic!("expected shell denial");
        };
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].kind, AuthorizationKind::Ask);
        assert_eq!(units[1].kind, AuthorizationKind::Deny);
        assert_eq!(
            units[1].unit,
            ShellCommandUnit::Parsed(vec!["rm".into(), "target".into()])
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_denial_inside_outer_generic_prefix_is_detected_before_prompting() {
        let (_directory, config, policy) = policy(
            "prefixes: ['env *']\nshell_prefixes: ['bash -c']\nallow: [/bin/true]\nask: ['git push **']\ndeny: ['rm **']\n",
        );
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&[
            "env",
            "X=1",
            "bash",
            "-c",
            "git push origin main; rm target",
        ]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[10; 32]), &client);

        assert!(matches!(
            outcome,
            InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
                diagnostic: None,
                ..
            })
        ));
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_denial_inside_outer_generic_prefix_with_multiple_assignments_is_detected() {
        let (_directory, config, policy) = policy(
            "prefixes: ['env *']\nshell_prefixes: ['bash -c']\nallow: [/bin/true]\nask: ['git push **']\ndeny: ['rm **']\n",
        );
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["env", "A=1", "B=2", "bash", "-c", "rm target"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[11; 32]), &client);

        assert!(matches!(
            outcome,
            InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
                diagnostic: None,
                ..
            })
        ));
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_denial_inside_stacked_generic_wrappers_is_detected_before_prompting() {
        let (_directory, config, policy) = policy(
            "prefixes:\n  - command\n  - env *\nshell_prefixes: ['bash -c']\nallow: [/bin/true]\nask: ['**']\ndeny: ['rm **']\n",
        );
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "command env A=1 B=2 rm target; git status"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[12; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
            diagnostic: None,
            units,
        }) = outcome
        else {
            panic!("expected shell denial");
        };
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].kind, AuthorizationKind::Ask);
        assert_eq!(
            units[0].unit,
            ShellCommandUnit::Opaque("'command env A=1 B=2 rm target'".into())
        );
        assert_eq!(units[1].kind, AuthorizationKind::Ask);
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_parts_inside_outer_generic_prefix_are_classified_independently() {
        let (_directory, config, policy) = policy(
            "prefixes: ['env *']\nshell_prefixes: ['bash -c']\nallow:\n  - cargo test\nask:\n  - git push **\n",
        );
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&[
            "env",
            "X=1",
            "bash",
            "-c",
            "cargo test; git push origin main",
        ]);
        let outcome = authorize_invocation(&policy, &command, &config, true, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::DryRun {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell dry-run");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Ask);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].kind, AuthorizationKind::Allow);
        assert_eq!(
            units[0].unit,
            ShellCommandUnit::Parsed(vec!["cargo".into(), "test".into()])
        );
        assert_eq!(units[1].kind, AuthorizationKind::Ask);
        assert_eq!(
            units[1].unit,
            ShellCommandUnit::Parsed(vec![
                "git".into(),
                "push".into(),
                "origin".into(),
                "main".into()
            ])
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_parts_inside_stacked_generic_prefixes_are_classified_independently() {
        let (_directory, config, policy) = policy(
            "prefixes:\n  - command\n  - env *\nshell_prefixes: ['bash -c']\nallow:\n  - cargo test\nask:\n  - git push **\n",
        );
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&[
            "command",
            "env",
            "A=1",
            "B=2",
            "bash",
            "-c",
            "cargo test; git push origin main",
        ]);
        let outcome = authorize_invocation(&policy, &command, &config, true, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::DryRun {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell dry-run");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Ask);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].kind, AuthorizationKind::Allow);
        assert_eq!(
            units[0].unit,
            ShellCommandUnit::Parsed(vec!["cargo".into(), "test".into()])
        );
        assert_eq!(units[1].kind, AuthorizationKind::Ask);
        assert_eq!(
            units[1].unit,
            ShellCommandUnit::Parsed(vec![
                "git".into(),
                "push".into(),
                "origin".into(),
                "main".into()
            ])
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_command_position_brace_expansion_cannot_use_literal_allow_to_bypass_deny() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow:\n  - r{m,} target\ndeny:\n  - rm **\n");
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&["bash", "-c", "r{m,} target"]);
        let outcome = authorize_invocation(&policy, &command, &config, true, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::DryRun {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell dry-run");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Ask);
        assert_eq!(units.len(), 1);
        assert_eq!(
            units[0].unit,
            ShellCommandUnit::Opaque("'r{m,} target'".into())
        );
        assert!(units[0].matched.is_implicit());
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_command_position_tilde_expansion_cannot_use_literal_allow_to_bypass_deny() {
        let (_directory, config, policy) = policy(
            "shell_prefixes: ['bash -c']\nallow:\n  - ~/bin/danger target\ndeny:\n  - /expanded/home/bin/danger **\n",
        );
        let client = QueueClient::new([Err("must not be called")]);
        let command = argv(&["bash", "-c", "~/bin/danger target"]);
        let outcome = authorize_invocation(&policy, &command, &config, true, None, &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::DryRun {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell dry-run");
        };
        assert_eq!(aggregate_kind, AuthorizationKind::Ask);
        assert_eq!(units.len(), 1);
        assert_eq!(
            units[0].unit,
            ShellCommandUnit::Opaque("'~/bin/danger target'".into())
        );
        assert!(units[0].matched.is_implicit());
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn shell_rejection_stops_later_approvals() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow: [/bin/true]\nask: ['git push **']\n");
        let client =
            QueueClient::new([approved(ApprovalScope::Once), Ok(ApprovalDecision::Denied)]);
        let command = argv(&[
            "bash",
            "-c",
            "git push origin main; git push origin release; git push origin dev",
        ]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[6; 32]), &client);

        assert!(matches!(
            outcome,
            InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
                diagnostic: None,
                ..
            })
        ));
        assert_eq!(client.calls.get(), 2);
    }

    #[test]
    fn shell_redirection_unit_forces_exact_implicit_approval() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow:\n  - echo **\n");
        let client = QueueClient::new([approved(ApprovalScope::Session)]);
        let command = argv(&["bash", "-c", "echo hi > file"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[7; 32]), &client);

        assert!(matches!(
            outcome,
            InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
                aggregate_kind: AuthorizationKind::Ask,
                ..
            })
        ));
        assert_eq!(client.calls.get(), 1);
        let requests = client.requests.borrow();
        assert_eq!(requests[0].command, argv(&[">", "file"]));
        assert!(requests[0].implicit_ask);
        assert_eq!(
            requests[0].ask_rule_source,
            crate::policy::IMPLICIT_ASK_SOURCE
        );
    }

    #[test]
    fn nested_configured_shell_invocation_is_denied() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow:\n  - git status\nask:\n  - '**'\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "git status; bash -c 'git status'"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[8; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
            diagnostic: Some(message),
            ..
        }) = outcome
        else {
            panic!("expected nested shell denial");
        };
        assert_eq!(
            message,
            "saferun: nested shell invocation is not permitted: bash -c 'git status'"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn nested_saferun_invocation_in_shell_payload_is_denied() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow:\n  - saferun **\nask:\n  - '**'\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "git status; saferun --dry-run -- git status"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[8; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
            diagnostic: Some(message),
            ..
        }) = outcome
        else {
            panic!("expected nested saferun denial");
        };
        assert_eq!(
            message,
            "saferun: nested saferun invocation is not permitted: saferun --dry-run -- git status"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn nested_saferun_invocation_with_ignored_stderr_dev_null_is_denied() {
        let (_directory, config, policy) =
            policy("shell_prefixes: ['bash -c']\nallow:\n  - saferun **\nask:\n  - '**'\n");
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "saferun --dry-run -- git status 2>/dev/null"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[8; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
            diagnostic: Some(message),
            units,
        }) = outcome
        else {
            panic!("expected nested saferun denial");
        };
        assert_eq!(
            message,
            "saferun: nested saferun invocation is not permitted: saferun --dry-run -- git status"
        );
        assert_eq!(units.len(), 1);
        assert_eq!(
            units[0].unit,
            ShellCommandUnit::Parsed(argv(&["saferun", "--dry-run", "--", "git", "status"]))
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn nested_saferun_invocation_after_generic_prefix_in_shell_payload_is_denied() {
        let (_directory, config, policy) = policy(
            "prefixes: ['env *']\nshell_prefixes: ['bash -c']\nallow:\n  - saferun **\nask:\n  - '**'\n",
        );
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "env A=1 saferun --dry-run -- git status"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[8; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
            diagnostic: Some(message),
            ..
        }) = outcome
        else {
            panic!("expected prefixed nested saferun denial");
        };
        assert_eq!(
            message,
            "saferun: nested saferun invocation is not permitted: saferun --dry-run -- git status"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn nested_saferun_consumed_by_generic_prefix_in_shell_payload_is_denied() {
        let (_directory, config, policy) = policy(
            "prefixes: ['env *']\nshell_prefixes: ['bash -c']\nallow:\n  - saferun **\nask:\n  - '**'\n",
        );
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "env saferun --dry-run -- git status"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[8; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
            diagnostic: Some(message),
            ..
        }) = outcome
        else {
            panic!("expected consumed nested saferun denial");
        };
        assert_eq!(
            message,
            "saferun: nested saferun invocation is not permitted: saferun --dry-run -- git status"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn nested_configured_shell_invocation_after_generic_prefix_is_denied() {
        let (_directory, config, policy) = policy(
            "prefixes: ['env *']\nshell_prefixes: ['bash -c']\nallow:\n  - git status\nask:\n  - '**'\n",
        );
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "env X=1 bash -c 'git status'"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[9; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
            diagnostic: Some(message),
            ..
        }) = outcome
        else {
            panic!("expected nested shell denial");
        };
        assert_eq!(
            message,
            "saferun: nested shell invocation is not permitted: bash -c 'git status'"
        );
        assert_eq!(client.calls.get(), 0);
    }

    #[test]
    fn nested_configured_shell_invocation_after_stacked_generic_prefixes_is_denied() {
        let (_directory, config, policy) = policy(
            "prefixes:\n  - command\n  - env *\nshell_prefixes: ['bash -c']\nallow:\n  - git status\nask:\n  - '**'\n",
        );
        let client = QueueClient::new([approved(ApprovalScope::Once)]);
        let command = argv(&["bash", "-c", "command env A=1 B=2 bash -c 'git status'"]);
        let outcome =
            authorize_invocation(&policy, &command, &config, false, Some(&[9; 32]), &client);

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
            diagnostic: Some(message),
            ..
        }) = outcome
        else {
            panic!("expected nested shell denial");
        };
        assert_eq!(
            message,
            "saferun: nested shell invocation is not permitted: bash -c 'git status'"
        );
        assert_eq!(client.calls.get(), 0);
    }
}
