//! Run a command only when allowed or interactively approved.
//!
//! It loads a YAML policy, classifies the requested command, and either execs
//! it or refuses with exit code 126.

use std::env;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use saferun::approval::{
    create_session_token_file, read_session_token_file, ApprovalScope, SocketApprovalClient,
    SESSION_TOKEN_FILE_ENV,
};
use saferun::authorization::{
    authorize_invocation, AuthorizationKind, AuthorizationOutcome, InvocationAuthorizationOutcome,
    ShellAuthorizationOutcome, ShellUnitAuthorization, DENIED_EXIT_CODE,
};
use saferun::policy::{describe_match, load_policy, shlex_join, ConfigError};

fn default_config_path() -> PathBuf {
    let home = env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join("config").join("saferun.yaml")
}

struct Args {
    config: PathBuf,
    dry_run: bool,
    explain: bool,
    command: Vec<String>,
}

/// Print usage to stderr and exit, mimicking argparse error handling.
fn arg_error(message: &str) -> ! {
    eprintln!(
        "usage: saferun [-h] [--config CONFIG] [--dry-run] [--explain] -- command ...\n\
         \x20      saferun session-token"
    );
    eprintln!("saferun: error: {message}");
    std::process::exit(2);
}

/// Parse CLI arguments. Everything from the first non-flag token (or after a
/// bare `--`) is treated as the command, like argparse's REMAINDER.
fn parse_args(raw: Vec<String>) -> Args {
    let mut config = default_config_path();
    let mut dry_run = false;
    let mut explain = false;
    let mut command: Vec<String> = Vec::new();

    let mut index = 0;
    while index < raw.len() {
        let arg = raw[index].as_str();
        match arg {
            "--dry-run" => dry_run = true,
            "--explain" => explain = true,
            "--config" | "-c" => {
                index += 1;
                let Some(value) = raw.get(index) else {
                    arg_error("argument --config/-c: expected one argument");
                };
                config = PathBuf::from(value);
            }
            "-h" | "--help" => {
                println!(
                    "usage: saferun [-h] [--config CONFIG] [--dry-run] [--explain] -- command ...\n\
                     \x20      saferun session-token"
                );
                println!("\nRun a command only when allowed");
                std::process::exit(0);
            }
            "--" => {
                command = raw[index + 1..].to_vec();
                break;
            }
            _ if arg.starts_with("--config=") => {
                config = PathBuf::from(&arg["--config=".len()..]);
            }
            _ => {
                command = raw[index..].to_vec();
                break;
            }
        }
        index += 1;
    }

    if command.first().map(String::as_str) == Some("--") {
        command.remove(0);
    }
    if command.is_empty() {
        arg_error("missing command to run");
    }

    Args {
        config,
        dry_run,
        explain,
        command,
    }
}

fn run() -> i32 {
    let raw: Vec<String> = env::args().skip(1).collect();
    if raw.first().map(String::as_str) == Some("session-token") {
        if raw.len() != 1 {
            arg_error("subcommand session-token takes no arguments");
        }
        return match create_session_token_file() {
            Ok(path) => {
                println!("{}", path.display());
                0
            }
            Err(error) => {
                eprintln!("saferun: cannot create session token: {error}");
                1
            }
        };
    }
    let args = parse_args(raw);
    let session_token_file = env::var_os(SESSION_TOKEN_FILE_ENV);
    env::remove_var(SESSION_TOKEN_FILE_ENV);
    let session_token = match session_token_file {
        Some(path) => match read_session_token_file(Path::new(&path)) {
            Ok(token) => Some(token),
            Err(error) => {
                eprintln!("saferun: invalid session token: {error}");
                return 2;
            }
        },
        None => None,
    };

    let policy = match load_policy(&args.config) {
        Ok(policy) => policy,
        Err(ConfigError(message)) => {
            eprintln!("saferun: invalid config: {message}");
            return 2;
        }
    };

    let command = args.command;
    let client = SocketApprovalClient::new();
    match authorize_invocation(
        &policy,
        &command,
        &args.config,
        args.dry_run,
        session_token.as_ref(),
        &client,
    ) {
        InvocationAuthorizationOutcome::Direct(outcome) => match outcome {
            AuthorizationOutcome::Denied { diagnostic } => {
                if let Some(message) = diagnostic {
                    eprintln!("{message}");
                }
                eprintln!("DENIED {}", shlex_join(&command));
                return DENIED_EXIT_CODE;
            }
            AuthorizationOutcome::DryRun { kind, matched } => {
                println!(
                    "{} {} ({})",
                    kind.label(),
                    shlex_join(&command),
                    describe_match(kind.rule_kind(), &matched)
                );
                return 0;
            }
            AuthorizationOutcome::Execute {
                kind,
                matched,
                approval,
            } => {
                if args.explain {
                    let matched = describe_match(kind.rule_kind(), &matched);
                    match approval {
                        Some(scope) => {
                            let scope = approval_scope_label(scope);
                            eprintln!(
                                "ALLOW {} ({matched}, approval='{scope}')",
                                shlex_join(&command)
                            );
                        }
                        None => eprintln!("ALLOW {} ({matched})", shlex_join(&command)),
                    }
                }
            }
        },
        InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied { diagnostic }) => {
            if let Some(message) = diagnostic {
                eprintln!("{message}");
            }
            eprintln!("DENIED {}", shlex_join(&command));
            return DENIED_EXIT_CODE;
        }
        InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::DryRun {
            aggregate_kind,
            units,
        }) => {
            print_shell_authorization(&command, aggregate_kind, &units, false, false);
            return 0;
        }
        InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) => {
            if args.explain {
                print_shell_authorization(&command, aggregate_kind, &units, true, true);
            }
        }
    }
    // execvp-equivalent: replaces the current process image on success.
    let error = Command::new(&command[0]).args(&command[1..]).exec();
    if error.kind() == std::io::ErrorKind::NotFound {
        eprintln!("saferun: command not found: {}", command[0]);
        127
    } else {
        eprintln!("saferun: failed to exec {}: {error}", command[0]);
        126
    }
}

fn print_shell_authorization(
    command: &[String],
    aggregate_kind: AuthorizationKind,
    units: &[ShellUnitAuthorization<'_>],
    stderr: bool,
    execution_approved: bool,
) {
    for line in shell_authorization_lines(command, aggregate_kind, units, execution_approved) {
        if stderr {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
}

fn shell_authorization_lines(
    command: &[String],
    aggregate_kind: AuthorizationKind,
    units: &[ShellUnitAuthorization<'_>],
    execution_approved: bool,
) -> Vec<String> {
    let mut lines = Vec::with_capacity(units.len() + 1);
    for (index, unit) in units.iter().enumerate() {
        let mut matched = describe_match(unit.kind.rule_kind(), &unit.matched);
        if execution_approved {
            if let Some(scope) = unit.approval {
                matched.push_str(&format!(", approval='{}'", approval_scope_label(scope)));
            }
        }
        let label = if execution_approved {
            AuthorizationKind::Allow.label()
        } else {
            unit.kind.label()
        };
        lines.push(format!(
            "PART {}/{} {} {} ({})",
            index + 1,
            units.len(),
            label,
            unit.unit.display_command(),
            matched
        ));
    }

    let aggregate_label = if execution_approved {
        AuthorizationKind::Allow.label()
    } else {
        aggregate_kind.label()
    };
    lines.push(format!(
        "{} {} (shell_parts={})",
        aggregate_label,
        shlex_join(command),
        units.len()
    ));
    lines
}

fn approval_scope_label(scope: ApprovalScope) -> &'static str {
    match scope {
        ApprovalScope::Once => "once",
        ApprovalScope::Session => "session",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use saferun::approval::{ApprovalClient, ApprovalDecision, ApprovalError, ApprovalRequest};

    struct ApprovingClient {
        calls: Cell<usize>,
    }

    impl ApprovalClient for ApprovingClient {
        fn request(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalError> {
            self.calls.set(self.calls.get() + 1);
            Ok(ApprovalDecision::Approved {
                scope: ApprovalScope::Session,
            })
        }
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn live_shell_explain_lines_include_approved_ask_scope() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = directory.path().join("saferun.yaml");
        std::fs::write(
            &config,
            "shell_prefixes: ['bash -c']\nallow:\n  - cargo test\nask:\n  - git push **\n",
        )
        .expect("write config");
        let policy = load_policy(&config).expect("load policy");
        let client = ApprovingClient {
            calls: Cell::new(0),
        };
        let command = argv(&["bash", "-c", "cargo test; git push origin main"]);
        let outcome = authorize_invocation(
            &policy,
            &command,
            &config,
            false,
            Some(&[1_u8; 32]),
            &client,
        );

        let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
            aggregate_kind,
            units,
        }) = outcome
        else {
            panic!("expected shell execution");
        };

        assert_eq!(client.calls.get(), 1);
        assert_eq!(
            shell_authorization_lines(&command, aggregate_kind, &units, true),
            vec![
                "PART 1/2 ALLOW cargo test (allow='cargo test')".to_string(),
                "PART 2/2 ALLOW git push origin main (ask='git push **', approval='session')"
                    .to_string(),
                "ALLOW bash -c 'cargo test; git push origin main' (shell_parts=2)".to_string(),
            ]
        );
    }
}

fn main() {
    std::process::exit(run());
}
