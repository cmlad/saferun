# saferun

## Introduction

`saferun` is a command wrapper that executes commands only when policy allows them or the user approves an interactive `ask` decision. It is written in Rust and is intended to limit what cooperative AI agents can execute.

The CLI loads allow, ask, deny, and prefix rules, then replaces itself with an authorized command. A separate `saferun-approval` foreground process owns the user confirmation UI and memory-only session grants.

## Setting Up Policy

By default, `saferun` reads:

```text
~/config/saferun.yaml
```

This repository includes a checked-in `saferun.yaml`. Install it as the default user policy with:

```bash
mkdir -p ~/config
cp ./saferun.yaml ~/config/saferun.yaml
```

The config file is YAML with four rule lists:

```yaml
prefixes:
  - "env *"
  - "sudo"

allow:
  - "git status"
  - "git diff **"
  - "cargo test **"

ask:
  - "git push **"
  - "kubectl -n monitoring get pods"

deny:
  - "git reset **"
  - "kubectl delete **"
```

`allow` is required and must contain at least one entry. `prefixes`, `ask`, and `deny` are optional.

Rules are shell-split with `shlex`, then matched against argv parts:

- `*` matches any characters inside one argv part.
- `**` matches zero or more argv parts.
- Matching is case-insensitive.
- Positive rules permit matching commands and trailing args.
- Decision order is: matching `deny` → deny; otherwise matching `ask` → ask; otherwise matching `allow` → allow; an unmatched command → ask.
- A matching prefix strips a leading wrapper before positive `ask`/`allow` matching. Deny checks both the full command and every prefix-stripped remainder.

For example, `*` can match variable text within a single argument:

```yaml
allow:
  - "sed -n *,*p"
```

This rule matches commands such as `sed -n 1,20p` and `sed -n /start/,/end/p`. Both `*` globs stay within the third argv part; they never consume another argument. Quote the complete rule so YAML treats the `*` characters as rule syntax rather than aliases.

`Allow` in the confirmation dialog approves only the current execution. `Allow for session` applies the scope shown in the dialog's non-editable dropdown. The dropdown lists every prefix of the effective command plus, for a configured `ask` rule, the matched rule:

- each successive effective argv prefix, shown as the actual parts with any part longer than 8 characters truncated and suffixed with `…`; the first entry (the effective executable) is selected by default
- `Matched ask rule` — the configured `ask` rule that matched; absent for implicit asks

The effective command is the requested argv with any recognized configured prefix stripped. Prefix scopes therefore compare the stripped argv: `env X=1 python3 -c first` approved at the executable entry also approves `python3 -c second` and `env Y=2 python3 -c third`, but never `ruby -e …`. Shell payloads such as `/bin/zsh -lc 'cargo test'` are opaque: the quoted payload is one argv part and is never parsed, so the only argv scope is that exact payload string.

Every session grant stays scoped to the same agent token, canonical working directory, canonical config path, and unchanged policy bytes while the broker remains running. Broker restart, token/directory/config/policy change, or safe cache eviction prompts again.

## Starting the Agent

Before starting an agent that uses `saferun`, start the approval broker in a logged-in macOS desktop session. From this repository:

```bash
./start-approver.sh
```

With an installed binary, run:

```bash
saferun-approval
```

The broker listens only on `/tmp/saferun-<effective-uid>/approval.sock`. Live `ask` decisions fail closed when the broker is absent or invalid; direct allow/deny decisions and `--dry-run` do not require it. Other Unix systems build both binaries, but live `ask` decisions fail closed because the production UI uses macOS Standard Additions.

Create one unpredictable token file per agent session:

```bash
SAFERUN_TOKEN_FILE="$(saferun session-token)"
```

`saferun session-token` creates a new `0600` file inside the UID-owned `0700` runtime directory and prints only its non-secret path. It does not load the command policy or require an existing session token. Retain that path in `SAFERUN_TOKEN_FILE` for the agent session:

```bash
export SAFERUN_TOKEN_FILE="$(saferun session-token)"
saferun -- git status
saferun -- cargo test
```

`saferun` securely opens the file named by `SAFERUN_TOKEN_FILE`, validates its location, ownership, type, and mode, reads the token, and removes the variable before executing an authorized command. Never put the token contents in the environment, argv, or stdin. Separate agents under the same Unix UID are a cooperative boundary: file permissions prevent access by other UIDs, not a malicious same-UID process.

## Agent Setup

Add the following shell command policy to `~/.codex/AGENTS.md` or `~/.claude/CLAUDE.md`:

````markdown
# Shell Command Policy

Run all shell commands through `saferun` so each command is checked against `~/config/saferun.yaml` first. The launcher supplies `SAFERUN_TOKEN_FILE` when interactive authorization is available.

When printing commands for the user to run, omit the `saferun --` prefix. This exception applies only to displayed commands; commands run by the agent must still use `saferun`.

Use:

```bash
saferun -- git status
saferun -- cargo test
saferun -- kubectl get pods -n monitoring
saferun -- kubectl -n monitoring get pods
saferun -- gcloud compute instances list --project my-project
```

Avoid:

```bash
git status
cargo test
kubectl get pods -n monitoring
gcloud compute instances list
```
````

Configure agent shell permissions so only `saferun` commands are allowed.

For Codex, `~/.codex/rules/default.rules` should only have:

```text
prefix_rule(pattern=["saferun"], decision="allow")
```

For Claude, `~/.claude/settings.json` should only have:

```json
{
  "permissions": {
    "allow": [
      "Bash(saferun *)"
    ]
  }
}
```

The isolation boundary is cooperative sibling agents under one Unix account. Distinct launcher tokens prevent one conforming agent from reusing another's session grants. Arbitrary same-UID code can inspect peer processes or broker traffic, and an agent allowed to substitute `--config` can replace policy; either can bypass this boundary. A stronger threat model needs a code-identity-authenticated service rather than Unix socket modes and bearer tokens.

## Usage

```bash
saferun -- <command> [args...]
```

Examples:

```bash
saferun -- git status
saferun -- cargo test
saferun -- kubectl -n monitoring get pods
```

Use `--config` or `-c` to select another policy:

```bash
saferun --config ./saferun.yaml -- git status
```

Use the repository policy directly while developing:

```bash
saferun --config ./saferun.yaml -- cargo test
```

## Checking Rules

Use `--dry-run` to classify without execution, a session token, or a running broker:

```bash
saferun --dry-run -- git status
saferun --dry-run -- git push origin main
```

Directly allowed commands print `ALLOW ...`; configured ask rules and unmatched commands print `ASK ...`; both exit `0` under `--dry-run`. Explicitly denied commands print `DENIED ...` to stderr and exit `126`.

Use `--explain` to print the matching rule before execution:

```bash
saferun --explain -- git status
saferun --explain -- git push origin main
```

An approved ask prints its ask/prefix match plus `approval='once'` or `approval='session'`. A session grant created through the dropdown still reports `approval='session'`; the chosen scope is not part of the response. The approval panel title is `saferun in <directory>`. Each argv item is a numbered, unquoted, reversible byte-safe line — `Prefix N` for items consumed by a recognized configured prefix and `Command N` for the effective command — followed by the matched ask rule, the matching prefix rule, and the eight-character session fingerprint. The session-scope dropdown sits beside its `Allow for session` button so the scope and the action read as one pair. Control characters, invalid UTF-8, and bidi controls are always escaped and cannot alter what appears to be authorized.

## Build

```bash
cargo build --release
```

The release binaries are:

```text
target/release/saferun
target/release/saferun-approval
```

For development checks:

```bash
cargo check
cargo test
```

## Exit Codes

- `0`: the command completed successfully, or `--dry-run` classified it as `ALLOW`/`ASK`.
- `2`: CLI argument error, invalid config, or invalid session-token input.
- `126`: command denied, approval missing/denied/failed, or execution failed.
- `127`: an authorized command was not found.

An actual ask without `SAFERUN_TOKEN_FILE` fails closed. The referenced token must be an owned `0600` regular file created inside the UID-owned `0700` saferun runtime directory and contain exactly 64 ASCII hexadecimal bytes with an optional final LF and then EOF.

When a command is authorized, `saferun` removes `SAFERUN_TOKEN_FILE` and uses Unix `exec`, so the wrapped command replaces it with the same PID and stdio without inheriting the token-file path.
