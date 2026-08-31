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
fn token_argument_rejects_files_outside_runtime() {
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
        .arg("-t")
        .arg(&token)
        .args(["--config"])
        .arg(&config)
        .args(["--", "/bin/true"])
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside"));
}

#[test]
fn token_argument_preserves_child_stdin() {
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
        .arg("-t")
        .arg(&token_path)
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
fn legacy_token_environment_does_not_supply_ask_token() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(&config, "allow:\n  - /bin/true\nask:\n  - /usr/bin/touch\n")
        .expect("write config");
    let target = temp.path().join("ask-target");
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
        .env("SAFERUN_TOKEN_FILE", &token_path)
        .args(["--config"])
        .arg(&config)
        .args(["--", "/usr/bin/touch"])
        .arg(&target)
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("saferun: ask command requires -t TOKEN_FILE"));
    assert!(!target.exists());
    std::fs::remove_file(token_path).expect("remove token");
}

#[test]
fn token_argument_requires_value() {
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .arg("-t")
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("saferun: error: argument -t: expected one argument"));
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
fn shell_dry_run_authorizes_tilde_as_literal_argument() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow:\n  - ls **\nask:\n  - git push **\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args(["--dry-run", "--", "bash", "-c", "ls ~/.codex/"])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"PART 1/1 ALLOW ls '~/.codex/' (allow='ls **')\n\
          ALLOW bash -c 'ls ~/.codex/' (shell_parts=1)\n"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn shell_dry_run_prints_redirection_parts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow:\n  - printf hi\n  - printf bye\nask:\n  - '> **'\n  - '>> **'\n",
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
            "printf hi > out; printf bye >> out",
        ])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"PART 1/4 ALLOW printf hi (allow='printf hi')\n\
          PART 2/4 ASK > out (ask='> **')\n\
          PART 3/4 ALLOW printf bye (allow='printf bye')\n\
          PART 4/4 ASK >> out (ask='>> **')\n\
          ASK bash -c 'printf hi > out; printf bye >> out' (shell_parts=4)\n"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn shell_dry_run_prints_dev_null_redirection_part() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow:\n  - printf hi\nask:\n  - '> /dev/null'\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args(["--dry-run", "--", "bash", "-c", "printf hi > /dev/null"])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"PART 1/2 ALLOW printf hi (allow='printf hi')\n\
          PART 2/2 ASK > /dev/null (ask='> /dev/null')\n\
          ASK bash -c 'printf hi > /dev/null' (shell_parts=2)\n"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn shell_dry_run_omits_stderr_dev_null_redirection_part() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow:\n  - printf hi\n  - grep h\nask:\n  - '2> /dev/null'\n",
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
            "printf hi 2>/dev/null | grep h 2> /dev/null",
        ])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"PART 1/2 ALLOW printf hi (allow='printf hi')\n\
          PART 2/2 ALLOW grep h (allow='grep h')\n\
          ALLOW bash -c 'printf hi 2>/dev/null | grep h 2> /dev/null' (shell_parts=2)\n"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn shell_dry_run_allows_stderr_dev_null_only_payload_without_parts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow:\n  - /bin/true\nask:\n  - '**'\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args(["--dry-run", "--", "bash", "-c", "2>/dev/null"])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"ALLOW bash -c '2>/dev/null' (shell_parts=0)\n"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn shell_dry_run_keeps_near_miss_stderr_dev_null_redirection_opaque() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['bash -c']\nallow:\n  - printf hi\nask:\n  - '**'\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args(["--dry-run", "--", "bash", "-c", "printf hi 2>>/dev/null"])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"PART 1/1 ASK 'printf hi 2>>/dev/null' (ask='<no matched rule>')\n\
          ASK bash -c 'printf hi 2>>/dev/null' (shell_parts=1)\n"
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
fn direct_nested_saferun_dry_run_is_denied_with_diagnostic() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(&config, "allow:\n  - saferun **\nask:\n  - '**'\n").expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args([
            "--dry-run",
            "--",
            "saferun",
            "--dry-run",
            "--",
            "git",
            "status",
        ])
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(126));
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "saferun: nested saferun invocation is not permitted: saferun --dry-run -- git status\n\
         DENIED saferun --dry-run -- git status\n"
    );
}

#[test]
fn nested_saferun_consumed_by_generic_prefix_dry_run_is_denied_with_diagnostic() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "prefixes: ['env *']\nshell_prefixes: ['bash -c']\nallow:\n  - git status\nask:\n  - '**'\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args([
            "--dry-run",
            "--",
            "env",
            "saferun",
            "bash",
            "-c",
            "git status",
        ])
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(126));
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "saferun: nested saferun invocation is not permitted: saferun bash -c 'git status'\n\
         DENIED env saferun bash -c 'git status'\n"
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
fn nested_saferun_in_shell_payload_after_prefix_is_denied_with_diagnostic() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "prefixes: ['env *']\nshell_prefixes: ['bash -c']\nallow:\n  - saferun **\nask:\n  - '**'\n",
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
            "env A=1 saferun --dry-run -- git status",
        ])
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(126));
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "saferun: nested saferun invocation is not permitted: saferun --dry-run -- git status\n\
         PART 1/1 ASK 'env A=1 saferun --dry-run -- git status' (ask='<no matched rule>')\n\
         DENIED bash -c 'env A=1 saferun --dry-run -- git status' (shell_parts=1)\n"
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

#[test]
fn shell_invocation_executes_original_tilde_expansion_after_literal_authorization() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    std::fs::create_dir(&home).expect("create home");
    let config = temp.path().join("saferun.yaml");
    let target = home.join("tilde-out");
    std::fs::write(
        &config,
        "shell_prefixes: ['/bin/bash -c']\nallow:\n  - printf ok\n  - '> ~/tilde-out'\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .env("HOME", &home)
        .args(["--config"])
        .arg(&config)
        .args(["--", "/bin/bash", "-c", "printf ok > ~/tilde-out"])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(std::fs::read(&target).expect("read target"), b"ok");
}

#[test]
fn shell_invocation_executes_original_stderr_dev_null_redirection_after_parts_are_allowed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    std::fs::write(
        &config,
        "shell_prefixes: ['/bin/bash -c']\nallow:\n  - \"/bin/sh -c 'printf err >&2'\"\n  - printf ok\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args([
            "--",
            "/bin/bash",
            "-c",
            "/bin/sh -c 'printf err >&2' 2>/dev/null; printf ok",
        ])
        .output()
        .expect("run saferun");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"ok");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn denied_redirection_prevents_original_shell_command_execution() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("saferun.yaml");
    let target = temp.path().join("should-not-exist");
    std::fs::write(
        &config,
        "shell_prefixes: ['/bin/bash -c']\nallow:\n  - /bin/printf executed\ndeny:\n  - '> **'\n",
    )
    .expect("write config");
    let output = Command::new(env!("CARGO_BIN_EXE_saferun"))
        .args(["--config"])
        .arg(&config)
        .args([
            "--",
            "/bin/bash",
            "-c",
            &format!("/bin/printf executed > {}", target.display()),
        ])
        .output()
        .expect("run saferun");

    assert_eq!(output.status.code(), Some(126));
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(!target.exists(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PART 2/2 DENIED > "), "{stderr}");
    assert!(stderr.contains("DENIED /bin/bash -c "), "{stderr}");
}
