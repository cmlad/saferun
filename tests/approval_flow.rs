use std::collections::VecDeque;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;

use saferun::approval::{read_request_frame, ApprovalScope, SocketApprovalClient};
use saferun::authorization::{
    authorize_command, authorize_invocation, AuthorizationKind, AuthorizationOutcome,
    InvocationAuthorizationOutcome, ShellAuthorizationOutcome,
};
use saferun::broker::{
    handle_connection, PromptChoice, PromptError, Prompter, SessionCache, SessionSelection,
};
use saferun::policy::load_policy;

struct SharedPrompter {
    choices: Arc<Mutex<VecDeque<PromptChoice>>>,
    calls: Arc<Mutex<usize>>,
}

impl Prompter for SharedPrompter {
    fn prompt(
        &mut self,
        _request: &saferun::approval::ApprovalRequest,
    ) -> Result<PromptChoice, PromptError> {
        *self.calls.lock().expect("calls lock") += 1;
        Ok(self
            .choices
            .lock()
            .expect("choices lock")
            .pop_front()
            .expect("queued prompt choice"))
    }
}

fn bind_test_socket(path: &std::path::Path) -> UnixListener {
    std::fs::set_permissions(
        path.parent().expect("socket parent"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("secure socket directory mode");
    let listener = UnixListener::bind(path).expect("bind test socket");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("secure socket mode");
    listener
}

#[test]
fn approval_round_trips_once_session_and_cache_hit() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("saferun.yaml");
    std::fs::write(&config, "allow: [/bin/true]\nask: [/usr/bin/touch]\n").expect("write config");
    let policy = load_policy(&config).expect("load policy");
    let socket = directory.path().join("approval.sock");
    let listener = bind_test_socket(&socket);

    let choices = Arc::new(Mutex::new(VecDeque::from([
        PromptChoice::AllowOnce,
        PromptChoice::AllowSession(SessionSelection::MatchedAskRule),
    ])));
    let calls = Arc::new(Mutex::new(0_usize));
    let server_choices = Arc::clone(&choices);
    let server_calls = Arc::clone(&calls);
    let server = thread::spawn(move || {
        let cache = Mutex::new(SessionCache::with_capacity(8));
        let prompter = Mutex::new(SharedPrompter {
            choices: server_choices,
            calls: server_calls,
        });
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().expect("accept");
            handle_connection(&mut stream, &cache, &prompter).expect("dispatch");
        }
    });

    let client = SocketApprovalClient::with_path(&socket);
    let token = [9_u8; 32];
    let first_command = vec!["/usr/bin/touch".to_string(), "first".to_string()];
    let first = authorize_command(
        &policy,
        &first_command,
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(
            &first,
            AuthorizationOutcome::Execute {
                kind: AuthorizationKind::Ask,
                approval: Some(ApprovalScope::Once),
                ..
            }
        ),
        "{first:?}"
    );

    let second_command = vec!["/usr/bin/touch".to_string(), "second".to_string()];
    let second = authorize_command(
        &policy,
        &second_command,
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(matches!(
        second,
        AuthorizationOutcome::Execute {
            approval: Some(ApprovalScope::Session),
            ..
        }
    ));

    let cached_command = vec!["/usr/bin/touch".to_string(), "cached".to_string()];
    let cached = authorize_command(
        &policy,
        &cached_command,
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(matches!(
        cached,
        AuthorizationOutcome::Execute {
            approval: Some(ApprovalScope::Session),
            ..
        }
    ));

    server.join().expect("server thread");
    assert_eq!(*calls.lock().expect("calls lock"), 2);
    assert!(choices.lock().expect("choices lock").is_empty());
}

#[test]
fn all_commands_session_scope_approves_different_ask_targets() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "allow: [/bin/true]\nask:\n  - /usr/bin/touch\n  - cargo publish **\n",
    )
    .expect("write config");
    let policy = load_policy(&config).expect("load policy");
    let socket = directory.path().join("approval.sock");
    let listener = bind_test_socket(&socket);

    let choices = Arc::new(Mutex::new(VecDeque::from([
        PromptChoice::AllowSession(SessionSelection::AllCommands),
        PromptChoice::Deny,
    ])));
    let calls = Arc::new(Mutex::new(0_usize));
    let server_choices = Arc::clone(&choices);
    let server_calls = Arc::clone(&calls);
    let server = thread::spawn(move || {
        let cache = Mutex::new(SessionCache::with_capacity(8));
        let prompter = Mutex::new(SharedPrompter {
            choices: server_choices,
            calls: server_calls,
        });
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept");
            handle_connection(&mut stream, &cache, &prompter).expect("dispatch");
        }
    });

    let client = SocketApprovalClient::with_path(&socket);
    let token = [15_u8; 32];
    let first = authorize_command(
        &policy,
        &["/usr/bin/touch".to_string(), "first".to_string()],
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(
            &first,
            AuthorizationOutcome::Execute {
                kind: AuthorizationKind::Ask,
                approval: Some(ApprovalScope::Session),
                ..
            }
        ),
        "{first:?}"
    );

    let second = authorize_command(
        &policy,
        &[
            "cargo".to_string(),
            "publish".to_string(),
            "--dry-run".to_string(),
        ],
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(
            &second,
            AuthorizationOutcome::Execute {
                kind: AuthorizationKind::Ask,
                approval: Some(ApprovalScope::Session),
                ..
            }
        ),
        "{second:?}"
    );

    server.join().expect("server thread");
    assert_eq!(*calls.lock().expect("calls lock"), 1);
    assert_eq!(choices.lock().expect("choices lock").len(), 1);
}

#[test]
fn all_commands_session_scope_from_consumed_implicit_ask_caches_later_request() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "prefixes: ['env *']\nallow: [/bin/true]\nask: [/usr/bin/touch]\n",
    )
    .expect("write config");
    let policy = load_policy(&config).expect("load policy");
    let socket = directory.path().join("approval.sock");
    let listener = bind_test_socket(&socket);

    let choices = Arc::new(Mutex::new(VecDeque::from([
        PromptChoice::AllowSession(SessionSelection::AllCommands),
        PromptChoice::Deny,
    ])));
    let calls = Arc::new(Mutex::new(0_usize));
    let server_choices = Arc::clone(&choices);
    let server_calls = Arc::clone(&calls);
    let server = thread::spawn(move || {
        let cache = Mutex::new(SessionCache::with_capacity(8));
        let prompter = Mutex::new(SharedPrompter {
            choices: server_choices,
            calls: server_calls,
        });
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept");
            handle_connection(&mut stream, &cache, &prompter).expect("dispatch");
        }
    });

    let client = SocketApprovalClient::with_path(&socket);
    let token = [16_u8; 32];
    let consumed_implicit = authorize_command(
        &policy,
        &["env".to_string(), "X=1".to_string()],
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(
            &consumed_implicit,
            AuthorizationOutcome::Execute {
                kind: AuthorizationKind::Ask,
                approval: Some(ApprovalScope::Session),
                ..
            }
        ),
        "{consumed_implicit:?}"
    );

    let configured_ask = authorize_command(
        &policy,
        &["/usr/bin/touch".to_string(), "second".to_string()],
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(
            &configured_ask,
            AuthorizationOutcome::Execute {
                kind: AuthorizationKind::Ask,
                approval: Some(ApprovalScope::Session),
                ..
            }
        ),
        "{configured_ask:?}"
    );

    server.join().expect("server thread");
    assert_eq!(*calls.lock().expect("calls lock"), 1);
    assert_eq!(choices.lock().expect("choices lock").len(), 1);
}

#[test]
fn executable_scope_spans_prefix_forms() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("saferun.yaml");
    std::fs::write(&config, "allow: [/bin/true]\nprefixes:\n  - env *\n").expect("write config");
    let policy = load_policy(&config).expect("load policy");
    let socket = directory.path().join("approval.sock");
    let listener = bind_test_socket(&socket);

    let choices = Arc::new(Mutex::new(VecDeque::from([
        PromptChoice::AllowSession(SessionSelection::EffectiveCommandPrefix { parts: 1 }),
        PromptChoice::Deny,
    ])));
    let calls = Arc::new(Mutex::new(0_usize));
    let server_choices = Arc::clone(&choices);
    let server_calls = Arc::clone(&calls);
    let server = thread::spawn(move || {
        let cache = Mutex::new(SessionCache::with_capacity(8));
        let prompter = Mutex::new(SharedPrompter {
            choices: server_choices,
            calls: server_calls,
        });
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().expect("accept");
            handle_connection(&mut stream, &cache, &prompter).expect("dispatch");
        }
    });

    let client = SocketApprovalClient::with_path(&socket);
    let token = [10_u8; 32];
    let commands = [
        vec![
            "env".to_string(),
            "X=1".to_string(),
            "python3".to_string(),
            "-c".to_string(),
            "first".to_string(),
        ],
        vec![
            "python3".to_string(),
            "-c".to_string(),
            "second".to_string(),
        ],
        vec![
            "env".to_string(),
            "Y=2".to_string(),
            "python3".to_string(),
            "-c".to_string(),
            "third".to_string(),
        ],
    ];
    for command in &commands {
        let outcome = authorize_command(&policy, command, &config, false, Some(&token), &client);
        assert!(
            matches!(
                &outcome,
                AuthorizationOutcome::Execute {
                    kind: AuthorizationKind::Ask,
                    approval: Some(ApprovalScope::Session),
                    ..
                }
            ),
            "{command:?}: {outcome:?}"
        );
    }

    let other_executable = vec!["ruby".to_string(), "-e".to_string(), "puts 1".to_string()];
    let rejected = authorize_command(
        &policy,
        &other_executable,
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(&rejected, AuthorizationOutcome::Denied { diagnostic: None }),
        "{rejected:?}"
    );

    server.join().expect("server thread");
    assert_eq!(*calls.lock().expect("calls lock"), 2);
    assert!(choices.lock().expect("choices lock").is_empty());
}

#[test]
fn intermediate_scope_matches_only_that_prefix() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("saferun.yaml");
    std::fs::write(&config, "allow: [/bin/true]\nask: ['python3 **']\n").expect("write config");
    let policy = load_policy(&config).expect("load policy");
    let socket = directory.path().join("approval.sock");
    let listener = bind_test_socket(&socket);

    let choices = Arc::new(Mutex::new(VecDeque::from([
        PromptChoice::AllowSession(SessionSelection::EffectiveCommandPrefix { parts: 2 }),
        PromptChoice::Deny,
    ])));
    let calls = Arc::new(Mutex::new(0_usize));
    let server_choices = Arc::clone(&choices);
    let server_calls = Arc::clone(&calls);
    let server = thread::spawn(move || {
        let cache = Mutex::new(SessionCache::with_capacity(8));
        let prompter = Mutex::new(SharedPrompter {
            choices: server_choices,
            calls: server_calls,
        });
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().expect("accept");
            handle_connection(&mut stream, &cache, &prompter).expect("dispatch");
        }
    });

    let client = SocketApprovalClient::with_path(&socket);
    let token = [12_u8; 32];
    let approved = [
        vec!["python3".to_string(), "-c".to_string(), "first".to_string()],
        vec![
            "python3".to_string(),
            "-c".to_string(),
            "second".to_string(),
        ],
    ];
    for command in &approved {
        let outcome = authorize_command(&policy, command, &config, false, Some(&token), &client);
        assert!(
            matches!(
                &outcome,
                AuthorizationOutcome::Execute {
                    approval: Some(ApprovalScope::Session),
                    ..
                }
            ),
            "{command:?}: {outcome:?}"
        );
    }

    let narrowed = vec!["python3".to_string(), "--version".to_string()];
    let rejected = authorize_command(&policy, &narrowed, &config, false, Some(&token), &client);
    assert!(
        matches!(&rejected, AuthorizationOutcome::Denied { diagnostic: None }),
        "{rejected:?}"
    );

    server.join().expect("server thread");
    assert_eq!(*calls.lock().expect("calls lock"), 2);
    assert!(choices.lock().expect("choices lock").is_empty());
}

#[test]
fn denied_and_malformed_responses_fail_closed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("saferun.yaml");
    std::fs::write(&config, "allow: [/bin/true]\nask: [/usr/bin/touch]\n").expect("write config");
    let policy = load_policy(&config).expect("load policy");
    let command = vec!["/usr/bin/touch".to_string(), "file".to_string()];
    let token = [11_u8; 32];

    let denied_socket = directory.path().join("denied.sock");
    let denied_listener = bind_test_socket(&denied_socket);
    let denied_server = thread::spawn(move || {
        let (mut stream, _) = denied_listener.accept().expect("accept denied");
        let cache = Mutex::new(SessionCache::with_capacity(2));
        let prompter = Mutex::new(SharedPrompter {
            choices: Arc::new(Mutex::new(VecDeque::from([PromptChoice::Deny]))),
            calls: Arc::new(Mutex::new(0)),
        });
        handle_connection(&mut stream, &cache, &prompter).expect("dispatch denied");
    });
    let denied = authorize_command(
        &policy,
        &command,
        &config,
        false,
        Some(&token),
        &SocketApprovalClient::with_path(&denied_socket),
    );
    assert!(
        matches!(&denied, AuthorizationOutcome::Denied { diagnostic: None }),
        "{denied:?}"
    );
    assert_eq!(denied.exit_code(), Some(126));
    denied_server.join().expect("denied server");

    let malformed_socket = directory.path().join("malformed.sock");
    let malformed_listener = bind_test_socket(&malformed_socket);
    let malformed_server = thread::spawn(move || {
        let (mut stream, _) = malformed_listener.accept().expect("accept malformed");
        read_request_frame(&mut stream).expect("read real request");
        stream
            .write_all(&3_u32.to_be_bytes())
            .expect("write malformed length");
        stream.write_all(b"not").expect("write malformed body");
    });
    let malformed = authorize_command(
        &policy,
        &command,
        &config,
        false,
        Some(&token),
        &SocketApprovalClient::with_path(&malformed_socket),
    );
    assert!(matches!(
        &malformed,
        AuthorizationOutcome::Denied {
            diagnostic: Some(message)
        } if message.starts_with("saferun: approval service error:")
    ));
    assert_eq!(malformed.exit_code(), Some(126));
    malformed_server.join().expect("malformed server");
}

#[test]
fn shell_authorization_uses_session_cache_per_unit() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow: [/bin/true]\nask: ['git push **']\n",
    )
    .expect("write config");
    let policy = load_policy(&config).expect("load policy");
    let socket = directory.path().join("approval.sock");
    let listener = bind_test_socket(&socket);

    let choices = Arc::new(Mutex::new(VecDeque::from([
        PromptChoice::AllowSession(SessionSelection::MatchedAskRule),
        PromptChoice::Deny,
    ])));
    let calls = Arc::new(Mutex::new(0_usize));
    let server_choices = Arc::clone(&choices);
    let server_calls = Arc::clone(&calls);
    let server = thread::spawn(move || {
        let cache = Mutex::new(SessionCache::with_capacity(8));
        let prompter = Mutex::new(SharedPrompter {
            choices: server_choices,
            calls: server_calls,
        });
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().expect("accept");
            handle_connection(&mut stream, &cache, &prompter).expect("dispatch");
        }
    });

    let client = SocketApprovalClient::with_path(&socket);
    let token = [13_u8; 32];
    let first = authorize_invocation(
        &policy,
        &[
            "bash".to_string(),
            "-c".to_string(),
            "git push origin main; git push origin release".to_string(),
        ],
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(
            &first,
            InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
                aggregate_kind: AuthorizationKind::Ask,
                ..
            })
        ),
        "{first:?}"
    );

    let second = authorize_invocation(
        &policy,
        &[
            "bash".to_string(),
            "-c".to_string(),
            "git push origin dev".to_string(),
        ],
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(
            &second,
            InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
                aggregate_kind: AuthorizationKind::Ask,
                ..
            })
        ),
        "{second:?}"
    );

    server.join().expect("server thread");
    assert_eq!(*calls.lock().expect("calls lock"), 1);
    assert_eq!(choices.lock().expect("choices lock").len(), 1);
}

#[test]
fn redirection_session_scope_caches_exact_target_only() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow:\n  - printf hi\nask:\n  - '> **'\n",
    )
    .expect("write config");
    let policy = load_policy(&config).expect("load policy");
    let socket = directory.path().join("approval.sock");
    let listener = bind_test_socket(&socket);

    let choices = Arc::new(Mutex::new(VecDeque::from([
        PromptChoice::AllowSession(SessionSelection::EffectiveCommandPrefix { parts: 2 }),
        PromptChoice::Deny,
    ])));
    let calls = Arc::new(Mutex::new(0_usize));
    let server_choices = Arc::clone(&choices);
    let server_calls = Arc::clone(&calls);
    let server = thread::spawn(move || {
        let cache = Mutex::new(SessionCache::with_capacity(8));
        let prompter = Mutex::new(SharedPrompter {
            choices: server_choices,
            calls: server_calls,
        });
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().expect("accept");
            handle_connection(&mut stream, &cache, &prompter).expect("dispatch");
        }
    });

    let client = SocketApprovalClient::with_path(&socket);
    let token = [18_u8; 32];
    let first = authorize_invocation(
        &policy,
        &[
            "bash".to_string(),
            "-c".to_string(),
            "printf hi > out.log".to_string(),
        ],
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(
            &first,
            InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
                aggregate_kind: AuthorizationKind::Ask,
                units,
            }) if units.len() == 2
                && units[1].approval == Some(ApprovalScope::Session)
                && units[1].unit.approval_command() == [">".to_string(), "out.log".to_string()]
        ),
        "{first:?}"
    );

    let cached = authorize_invocation(
        &policy,
        &[
            "bash".to_string(),
            "-c".to_string(),
            "printf hi > out.log".to_string(),
        ],
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(
            &cached,
            InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
                aggregate_kind: AuthorizationKind::Ask,
                units,
            }) if units.len() == 2
                && units[1].approval == Some(ApprovalScope::Session)
                && units[1].unit.approval_command() == [">".to_string(), "out.log".to_string()]
        ),
        "{cached:?}"
    );

    let other_target = authorize_invocation(
        &policy,
        &[
            "bash".to_string(),
            "-c".to_string(),
            "printf hi > other.log".to_string(),
        ],
        &config,
        false,
        Some(&token),
        &client,
    );
    assert!(
        matches!(
            &other_target,
            InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Denied {
                diagnostic: None,
                ..
            })
        ),
        "{other_target:?}"
    );

    server.join().expect("server thread");
    assert_eq!(*calls.lock().expect("calls lock"), 2);
    assert!(choices.lock().expect("choices lock").is_empty());
}

#[test]
fn all_commands_session_scope_covers_later_ask_units_in_shell_invocation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow: [/bin/true]\nask:\n  - git push **\n  - gh pr create **\n",
    )
    .expect("write config");
    let policy = load_policy(&config).expect("load policy");
    let socket = directory.path().join("approval.sock");
    let listener = bind_test_socket(&socket);

    let choices = Arc::new(Mutex::new(VecDeque::from([
        PromptChoice::AllowSession(SessionSelection::AllCommands),
        PromptChoice::Deny,
    ])));
    let calls = Arc::new(Mutex::new(0_usize));
    let server_choices = Arc::clone(&choices);
    let server_calls = Arc::clone(&calls);
    let server = thread::spawn(move || {
        let cache = Mutex::new(SessionCache::with_capacity(8));
        let prompter = Mutex::new(SharedPrompter {
            choices: server_choices,
            calls: server_calls,
        });
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept");
            handle_connection(&mut stream, &cache, &prompter).expect("dispatch");
        }
    });

    let client = SocketApprovalClient::with_path(&socket);
    let token = [17_u8; 32];
    let outcome = authorize_invocation(
        &policy,
        &[
            "bash".to_string(),
            "-c".to_string(),
            "git push origin main; gh pr create --fill".to_string(),
        ],
        &config,
        false,
        Some(&token),
        &client,
    );

    let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
        aggregate_kind,
        units,
    }) = outcome
    else {
        panic!("expected shell execution");
    };
    assert_eq!(aggregate_kind, AuthorizationKind::Ask);
    assert_eq!(units.len(), 2);
    assert_eq!(units[0].kind, AuthorizationKind::Ask);
    assert_eq!(units[0].approval, Some(ApprovalScope::Session));
    assert_eq!(
        units[0].unit.approval_command(),
        &["git", "push", "origin", "main"]
    );
    assert_eq!(units[1].kind, AuthorizationKind::Ask);
    assert_eq!(units[1].approval, Some(ApprovalScope::Session));
    assert_eq!(
        units[1].unit.approval_command(),
        &["gh", "pr", "create", "--fill"]
    );

    server.join().expect("server thread");
    assert_eq!(*calls.lock().expect("calls lock"), 1);
    assert_eq!(choices.lock().expect("choices lock").len(), 1);
}

#[test]
fn stacked_wrapped_shell_authorization_prompts_live_asks_in_order() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "prefixes:\n  - command\n  - env *\nshell_prefixes: ['bash -c']\nallow: [/bin/true]\nask:\n  - git push **\n  - gh pr create **\n",
    )
    .expect("write config");
    let policy = load_policy(&config).expect("load policy");
    let socket = directory.path().join("approval.sock");
    let listener = bind_test_socket(&socket);

    let choices = Arc::new(Mutex::new(VecDeque::from([
        PromptChoice::AllowOnce,
        PromptChoice::AllowSession(SessionSelection::MatchedAskRule),
    ])));
    let calls = Arc::new(Mutex::new(0_usize));
    let server_choices = Arc::clone(&choices);
    let server_calls = Arc::clone(&calls);
    let server = thread::spawn(move || {
        let cache = Mutex::new(SessionCache::with_capacity(8));
        let prompter = Mutex::new(SharedPrompter {
            choices: server_choices,
            calls: server_calls,
        });
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept");
            handle_connection(&mut stream, &cache, &prompter).expect("dispatch");
        }
    });

    let client = SocketApprovalClient::with_path(&socket);
    let token = [14_u8; 32];
    let outcome = authorize_invocation(
        &policy,
        &[
            "command".to_string(),
            "env".to_string(),
            "A=1".to_string(),
            "B=2".to_string(),
            "bash".to_string(),
            "-c".to_string(),
            "git push origin main; gh pr create --fill".to_string(),
        ],
        &config,
        false,
        Some(&token),
        &client,
    );

    let InvocationAuthorizationOutcome::Shell(ShellAuthorizationOutcome::Execute {
        aggregate_kind,
        units,
    }) = outcome
    else {
        panic!("expected shell execution");
    };
    assert_eq!(aggregate_kind, AuthorizationKind::Ask);
    assert_eq!(units.len(), 2);
    assert_eq!(units[0].kind, AuthorizationKind::Ask);
    assert_eq!(units[0].approval, Some(ApprovalScope::Once));
    assert_eq!(
        units[0].unit.approval_command(),
        &["git", "push", "origin", "main"]
    );
    assert_eq!(units[1].kind, AuthorizationKind::Ask);
    assert_eq!(units[1].approval, Some(ApprovalScope::Session));
    assert_eq!(
        units[1].unit.approval_command(),
        &["gh", "pr", "create", "--fill"]
    );

    server.join().expect("server thread");
    assert_eq!(*calls.lock().expect("calls lock"), 2);
    assert!(choices.lock().expect("choices lock").is_empty());
}
