# saferun

## Introduction

`saferun` limits what commands AI agents can execute. It support powerful matching rules and interactive prompts on MacOS. It loads `allow`, `ask`, `deny`, and `prefixes` rules, then replaces itself with an authorized command. The separate `saferun-approval` process owns the macOS approval UI and memory-only session grants.

## Setting Up Policy

By default, `saferun` reads `~/config/saferun.yaml`. Install this repository's policy with:

```bash
mkdir -p ~/config
cp ./saferun.yaml ~/config/saferun.yaml
```

The YAML config has four rule lists:

```yaml
prefixes:
  - "env *"
  - "sudo"

allow:
  - "git status"
  - "git diff **"
  - "sed -n *,*p"

ask:
  - "git push **"
  - "cp"

deny:
  - "git reset **"
  - "kubectl delete **"
```

`allow` must contain at least one entry. The other lists are optional:

- `prefixes` recognizes leading wrappers such as `env` or `sudo` and strips them before `ask` and `allow` matching. Deny still checks both the full command and each stripped remainder.
- `allow` executes matching commands without prompting.
- `ask` requires interactive approval before execution.
- `deny` blocks matching commands without prompting.

Precedence is `deny`, `ask`, `allow`, then an implicit `ask` for unmatched commands.

Rules are shell-split with `shlex` and matched case-insensitively against argv:

- `*` matches characters within one argv item.
- `**` matches zero or more argv items.
- `ask` and `allow` rules permit trailing argv items.

The `sed` rule above matches both `sed -n 1,20p` and `sed -n /start/,/end/p`; each `*` stays within one argv item. Quote rules containing `*` so YAML does not treat them as aliases.

## Starting the Approver

Start the broker in a logged-in macOS desktop session:

```bash
./start-approver.sh
```

With an installed binary:

```bash
saferun-approval
```

The broker listens only on `/tmp/saferun-<effective-uid>/approval.sock`. Live `ask` decisions fail closed if the broker is absent or invalid. Direct allow/deny decisions and `--dry-run` do not need it. Other Unix systems build both binaries, but live approval is macOS-only.

## Approval Scopes

`Allow` approves one execution. `Allow for session` applies the dropdown's selected scope. The dropdown contains:

- every prefix of the effective command, starting with its executable
- `Matched ask rule` for a configured `ask` match

The effective command is argv after stripping a recognized configured prefix. Approving the executable for `env X=1 python3 -c first` also approves `python3 -c second` and `env Y=2 python3 -c third`, but not `ruby -e …`.

Shell payloads remain opaque. For `/bin/zsh -lc 'cargo test'`, the quoted payload is one argv item and is never parsed.

Session grants are keyed by agent token, canonical working directory, canonical config path, and policy digest. A broker restart, key change, or cache eviction requires approval again.

## AI Agent Setup

Create one token file per agent session and retain its path:

```bash
export SAFERUN_TOKEN_FILE="$(saferun session-token)"
```

`saferun session-token` creates a `0600` file in the UID-owned `0700` runtime directory and prints only its non-secret path. It does not load policy or require an existing token. `saferun` validates and reads the file, then removes `SAFERUN_TOKEN_FILE` before executing the command. Never put token contents in environment values, argv, or stdin.

Add this policy to `~/.codex/AGENTS.md` or `~/.claude/CLAUDE.md`:

````markdown
# Shell Command Policy

Run every shell command through `saferun` so it is checked against `~/config/saferun.yaml`.

```bash
saferun -- git status
saferun -- cargo test
saferun -- kubectl -n monitoring get pods
```

When printing commands for the user, omit `saferun --`. Commands run by the agent must retain it.
````

Restrict the agent's native shell permissions to `saferun`.

For Codex, `~/.codex/rules/default.rules` should contain only:

```text
prefix_rule(pattern=["saferun"], decision="allow")
```

For Claude, `~/.claude/settings.json` should contain only:

```json
{
  "permissions": {
    "allow": ["Bash(saferun *)"]
  }
}
```

This is a cooperative boundary between sibling agents under one Unix account. Distinct tokens isolate conforming agents, but arbitrary same-UID code can inspect peer processes or broker traffic. An agent allowed to replace `--config` can also replace policy. A stronger threat model requires a code-identity-authenticated service.

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

Select another policy with `--config` or `-c`:

```bash
saferun --config ./saferun.yaml -- git status
```

## Checking Rules

`--dry-run` classifies without execution, a token, or a broker:

```bash
saferun --dry-run -- git status
saferun --dry-run -- git push origin main
```

Allowed commands print `ALLOW`; configured and implicit asks print `ASK`. Both exit `0`. Denied commands print `DENIED` to stderr and exit `126`.

`--explain` prints the matching rule before execution:

```bash
saferun --explain -- git status
saferun --explain -- git push origin main
```

Approved asks report `approval='once'` or `approval='session'`; the selected session scope is not part of the response.

The panel title is `saferun in <directory>`. Its body lists each argv item on a numbered, unquoted, reversible byte-safe line: `Prefix N` for a recognized configured prefix and `Command N` for the effective command. Rule metadata and the eight-character session fingerprint follow. Control characters, invalid UTF-8, and bidi controls are escaped. The scope dropdown sits beside `Allow for session`.

## Build

```bash
cargo build --release
```

Release binaries:

```text
target/release/saferun
target/release/saferun-approval
```

Development checks:

```bash
cargo check
cargo test
```

## Exit Codes

- `0`: command completed, or `--dry-run` classified it as `ALLOW`/`ASK`
- `2`: CLI argument, config, or token error
- `126`: command denied, approval unavailable/denied/failed, or execution failed
- `127`: authorized command not found

An actual ask without `SAFERUN_TOKEN_FILE` fails closed. The token must be an owned `0600` regular file in the UID-owned `0700` runtime directory containing exactly 64 ASCII hexadecimal bytes and an optional final LF.

Authorized commands run through Unix `exec`, preserving PID and stdio without exposing the token-file path.
