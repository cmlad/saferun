use std::collections::VecDeque;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;

use saferun::approval::{read_request_frame, ApprovalScope, SocketApprovalClient};
use saferun::authorization::{authorize_command, AuthorizationKind, AuthorizationOutcome};
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
