use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[test]
fn session_token_subcommand_creates_private_token_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .arg("session-token")
        .output()
        .expect("create session token");

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 token path");
    assert_eq!(stdout.lines().count(), 1);
    let path = PathBuf::from(stdout.trim_end_matches('\n'));
    assert_eq!(
        path.parent(),
        Some(saferun::approval::production_runtime_dir().as_path())
    );

    let metadata = std::fs::symlink_metadata(&path).expect("token metadata");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.mode() & 0o777, 0o600);
    let token = std::fs::read(&path).expect("read generated token");
    assert_eq!(token.len(), 65);
    assert_eq!(token[64], b'\n');
    assert!(token[..64].iter().all(u8::is_ascii_hexdigit));
    std::fs::remove_file(path).expect("remove generated token");
}

#[test]
fn session_token_subcommand_rejects_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["session-token", "unexpected"])
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("subcommand session-token takes no arguments"));
}

#[test]
fn session_token_environment_rejects_files_outside_runtime() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    let token = temp.path().join("token");
    std::fs::write(&config, "allow:\n  - /bin/true\n").expect("write config");
    std::fs::write(
        &token,
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    )
    .expect("write token");
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))
        .expect("secure token mode");

    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .env(saferun::approval::SESSION_TOKEN_FILE_ENV, &token)
        .args(["--config"])
        .arg(&config)
        .args(["--", "/bin/true"])
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside"));
}

#[test]
fn token_environment_preserves_child_stdin() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(&config, "allow:\n  - /bin/cat\n").expect("write config");
    let token_output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .arg("session-token")
        .output()
        .expect("create session token");
    assert!(token_output.status.success(), "{token_output:?}");
    let token_path = PathBuf::from(
        String::from_utf8(token_output.stdout)
            .expect("UTF-8 path")
            .trim(),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .env(saferun::approval::SESSION_TOKEN_FILE_ENV, &token_path)
        .args(["--config"])
        .arg(&config)
        .args(["--", "/bin/cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn saferun");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(b"payload\n")
        .expect("write payload");
    let output = child.wait_with_output().expect("wait for cat");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"payload\n");
    assert!(output.stderr.is_empty(), "{output:?}");
    std::fs::remove_file(token_path).expect("remove token");
}

#[test]
fn token_environment_is_removed_before_exec() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(&config, "allow:\n  - /usr/bin/env\n").expect("write config");
    let token_output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .arg("session-token")
        .output()
        .expect("create session token");
    assert!(token_output.status.success(), "{token_output:?}");
    let token_path = PathBuf::from(
        String::from_utf8(token_output.stdout)
            .expect("UTF-8 path")
            .trim(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .env(saferun::approval::SESSION_TOKEN_FILE_ENV, &token_path)
        .args(["--config"])
        .arg(&config)
        .args(["--", "/usr/bin/env"])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.starts_with("SAFERUN_TOKEN_FILE=")));
    std::fs::remove_file(token_path).expect("remove token");
}

#[test]
fn unmatched_dry_run_defaults_to_ask() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(&config, "allow:\n  - /bin/true\n").expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args(["--dry-run", "--", "/bin/false"])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"ASK /bin/false (ask='<no matched rule>')\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn shell_dry_run_prints_parts_and_aggregate_decision() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow:\n  - cargo test\nask:\n  - git push **\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args([
            "--dry-run",
            "--",
            "bash",
            "-c",
            "cargo test; git push origin main",
        ])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"PART 1/2 ALLOW cargo test (allow='cargo test')\n\
          PART 2/2 ASK git push origin main (ask='git push **')\n\
          ASK bash -c 'cargo test; git push origin main' (shell_parts=2)\n"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn shell_dry_run_prints_parts_inside_outer_generic_prefix() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "prefixes: ['env *']\nshell_prefixes: ['bash -c']\nallow:\n  - cargo test\nask:\n  - git push **\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args([
            "--dry-run",
            "--",
            "env",
            "A=1",
            "B=2",
            "bash",
            "-c",
            "cargo test; git push origin main",
        ])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"PART 1/2 ALLOW cargo test (allow='cargo test')\n\
          PART 2/2 ASK git push origin main (ask='git push **')\n\
          ASK env A=1 B=2 bash -c 'cargo test; git push origin main' (shell_parts=2)\n"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn shell_dry_run_denial_prints_parts_and_aggregate_decision() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow:\n  - cargo test\nask:\n  - git push **\ndeny:\n  - rm **\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args([
            "--dry-run",
            "--",
            "bash",
            "-c",
            "cargo test; rm target; git push origin main",
        ])
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(126));
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "PART 1/3 ALLOW cargo test (allow='cargo test')\n\
         PART 2/3 DENIED rm target (deny='rm **')\n\
         PART 3/3 ASK git push origin main (ask='git push **')\n\
         DENIED bash -c 'cargo test; rm target; git push origin main' (shell_parts=3)\n"
    );
}

#[test]
fn nested_shell_dry_run_is_denied_with_diagnostic() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow:\n  - git status\nask:\n  - '**'\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args(["--dry-run", "--", "bash", "-c", "bash -c 'git status'"])
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(126));
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "saferun: nested shell invocation is not permitted: bash -c 'git status'\n\
         PART 1/1 ASK bash -c 'git status' (ask='**')\n\
         DENIED bash -c 'bash -c '\"'\"'git status'\"'\"'' (shell_parts=1)\n"
    );
}

#[test]
fn shell_invocation_executes_original_command_after_parts_are_allowed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['/bin/bash -c']\nallow:\n  - printf ok\n  - printf done\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args(["--", "/bin/bash", "-c", "printf ok; printf done"])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"okdone");
    assert!(output.stderr.is_empty(), "{output:?}");
}
