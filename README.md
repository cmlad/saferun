# saferun

`saferun` is a simple command wrapper that executes only allowed commands. It is written in Rust and aimed to be used to limit what AI agents can safely execute without a permission prompt.

The program loads allow, deny, and prefix rules from a config file, decides whether the requested command is permitted, and then replaces itself with the requested process.

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

By default, `saferun` reads:

```text
~/config/saferun.yaml
```

Use `--config` or `-c` to point at another config file:

```bash
saferun --config ./saferun.yaml -- git status
```

This repository includes `saferun.yaml`, a checked-in policy file that mirrors
the current local command allowlist. Use it directly while developing:

```bash
saferun --config ./saferun.yaml -- cargo test
```

Or install it as the default user policy:

```bash
mkdir -p ~/config
cp ./saferun.yaml ~/config/saferun.yaml
```

## Agent Setup

Place your saferun config at:

```text
~/config/saferun.yaml
```

Add the following shell command policy to `~/.codex/AGENTS.md` or `~/.claude/CLAUDE.md`:

````markdown
# Shell Command Policy

Run all shell commands through `saferun` so each command is checked against `~/config/saferun.yaml` first.

When printing commands for the user to run, omit the `saferun --` prefix. This exception applies only to displayed commands for the user; commands run by Codex must still use `saferun`.

Use:

```bash
saferun -- ls
saferun -- git status
saferun -- kubectl get pods -n monitoring
saferun -- kubectl -n monitoring get pods
saferun -- gcloud compute instances list --project my-project
```

Avoid:

```bash
ls
git status
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

## Config

The config file is YAML with three rule lists:

```yaml
prefixes:
  - "env *"
  - "sudo"

allow:
  - "git status"
  - "git diff **"
  - "cargo test **"
  - "kubectl -n monitoring get pods"

deny:
  - "git reset **"
  - "kubectl delete **"
```

`allow` is required and must contain at least one entry. `prefixes` and `deny` are optional.

Rules are shell-split with `shlex`, then matched against argv parts:

- `*` matches any characters inside one argv part.
- `**` matches zero or more argv parts.
- Matching is case-insensitive.
- An `allow` rule permits matching commands and trailing args.
- A `deny` rule takes precedence over an allow match.
- A `prefixes` rule can authorize leading wrapper commands, then the remaining argv is checked against `allow` and `deny`.

## Checking Rules

Use `--dry-run` to print the decision without executing the command:

```bash
saferun --dry-run -- git status
```

Allowed commands print an `ALLOW ...` line and exit with status `0`. Denied commands print `DENIED ...` to stderr and exit with status `126`.

Use `--explain` to print the matching allow rule before executing an allowed command:

```bash
saferun --explain -- git status
```

## Build

```bash
cargo build --release
```

The release binary is written to:

```text
target/release/saferun
```

For development checks:

```bash
cargo check
cargo test
```

## Exit Codes

- `0`: the command was allowed and completed successfully, or `--dry-run` allowed it.
- `2`: CLI argument error or invalid config.
- `126`: command denied, or execution failed.
- `127`: allowed command was not found.

When a command is allowed and executed, `saferun` uses Unix `exec`, so the wrapped command replaces the `saferun` process.
