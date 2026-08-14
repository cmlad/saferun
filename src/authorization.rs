use std::env;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::approval::{
    lowercase_hex, session_digest, ApprovalClient, ApprovalDecision, ApprovalRequest,
    ApprovalScope, PROTOCOL_VERSION,
};
use crate::policy::{classify, Policy, PolicyDecision, RuleMatch};

pub const DENIED_EXIT_CODE: i32 = 126;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationKind {
    Ask,
    Allow,
}

impl AuthorizationKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ask => "ASK",
            Self::Allow => "ALLOW",
        }
    }

    pub fn rule_kind(self) -> &'static str {
        match self {
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

impl AuthorizationOutcome<'_> {
    pub fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Denied { .. } => Some(DENIED_EXIT_CODE),
            Self::DryRun { .. } => Some(0),
            Self::Execute { .. } => None,
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
            let Some(token) = token else {
                return AuthorizationOutcome::Denied {
                    diagnostic: Some(
                        "saferun: ask command requires SAFERUN_TOKEN_FILE".to_string(),
                    ),
                };
            };

            let cwd = match env::current_dir().and_then(fs::canonicalize) {
                Ok(path) => path,
                Err(error) => {
                    return service_failure(format!(
                        "cannot canonicalize current directory: {error}"
                    ));
                }
            };
            let canonical_config = match fs::canonicalize(config_path) {
                Ok(path) => path,
                Err(error) => {
                    return service_failure(format!("cannot canonicalize config path: {error}"));
                }
            };
            let prefix_parts_consumed = match u32::try_from(matched.prefix_parts_consumed()) {
                Ok(count) => count,
                Err(_) => return service_failure("matched prefix count is too large".to_string()),
            };
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
                Ok(ApprovalDecision::Denied) => AuthorizationOutcome::Denied { diagnostic: None },
                Ok(ApprovalDecision::Approved { scope }) => AuthorizationOutcome::Execute {
                    kind: AuthorizationKind::Ask,
                    matched,
                    approval: Some(scope),
                },
                Err(error) => service_failure(error.to_string()),
            }
        }
    }
}

fn service_failure(message: String) -> AuthorizationOutcome<'static> {
    AuthorizationOutcome::Denied {
        diagnostic: Some(format!("saferun: approval service error: {message}")),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io;

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

    fn ask_policy() -> (tempfile::TempDir, Policy) {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("saferun.yaml");
        std::fs::write(&path, "allow: [/bin/true]\nask: [/usr/bin/touch]\n").expect("write policy");
        let policy = load_policy(&path).expect("load policy");
        (directory, policy)
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
        assert!(matches!(missing, AuthorizationOutcome::Denied { .. }));
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
}
