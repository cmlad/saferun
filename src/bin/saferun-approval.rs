use std::env;
use std::io;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;

use saferun::approval::BrokerEndpoint;
use saferun::broker::{handle_connection, SessionCache, SystemPrompter};
fn usage() {
    println!("usage: saferun-approval [-h]");
    println!("\nRun the interactive saferun approval broker in the foreground");
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [] => {}
        [argument] if argument == "-h" || argument == "--help" => {
            usage();
            return Ok(());
        }
        _ => {
            return Err("usage: saferun-approval [-h]".to_string());
        }
    }

    let endpoint = BrokerEndpoint::bind().map_err(|error| error.to_string())?;
    println!(
        "saferun-approval: listening on {}",
        endpoint.path().display()
    );

    let cache = Arc::new(Mutex::new(SessionCache::with_capacity(4_096)));
    let prompter = Arc::new(Mutex::new(SystemPrompter::new()));
    loop {
        match endpoint.listener().accept() {
            Ok((mut stream, _)) => {
                let cache = Arc::clone(&cache);
                let prompter = Arc::clone(&prompter);
                thread::spawn(move || {
                    if let Err(error) = handle_connection(&mut stream, &cache, &prompter) {
                        eprintln!("saferun-approval: {error}");
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => eprintln!("saferun-approval: accept failed: {error}"),
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("saferun-approval: {message}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use saferun::approval::{ApprovalRequest, PROTOCOL_VERSION};
    use saferun::broker::{PromptChoice, Prompter, SessionSelection, SystemPrompter};

    fn manual_request() -> ApprovalRequest {
        ApprovalRequest {
            version: PROTOCOL_VERSION,
            session_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            command: vec![
                "env".to_string(),
                "X=1".to_string(),
                "python3".to_string(),
                "-c".to_string(),
                "print('manual')".to_string(),
            ],
            cwd: b"/tmp/manual saferun prompt\xff".to_vec(),
            config_path: b"/tmp/manual saferun prompt/saferun.yaml".to_vec(),
            policy_digest: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                .to_string(),
            ask_rule_source: "python3 **".to_string(),
            implicit_ask: false,
            prefix_rule_source: Some("env *".to_string()),
            prefix_parts_consumed: 2,
        }
    }

    #[test]
    #[ignore = "requires a logged-in macOS desktop and manual button choices"]
    fn manual_system_prompt() {
        let mut prompter = SystemPrompter::new();
        let session = prompter
            .prompt(&manual_request())
            .expect("first system prompt");
        assert_eq!(
            session,
            PromptChoice::AllowSession(SessionSelection::EffectiveCommandPrefix { parts: 1 })
        );

        let denied = prompter
            .prompt(&manual_request())
            .expect("second system prompt");
        assert_eq!(denied, PromptChoice::Deny);
        println!("manual prompt results: session, denied");
    }
}
