//! Run a command only when allowed.
//!
//! A faithful Rust port of the `saferun` Python script. It loads a YAML
//! allowlist (`prefixes` / `allow` / `deny`), matches the requested command
//! against it, and either execs the command or refuses with exit code 126.

use std::env;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde::Deserialize;

const DENIED_EXIT_CODE: i32 = 126;
const PART_DELIMITER: &str = "\u{00b0}"; // "°"

/// An error describing a malformed configuration file.
struct ConfigError(String);

/// A compiled allow/deny/prefix rule.
#[derive(Clone)]
struct Rule {
    source: String,
    /// Matches the joined argv exactly (no trailing parts allowed).
    exact_regex: Regex,
    /// Matches the joined argv allowing extra trailing parts.
    prefix_regex: Regex,
}

/// The result of locating an allow rule that authorises a command.
struct AllowMatch {
    allow: Rule,
    prefix: Option<Rule>,
    prefix_parts_consumed: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaferunConfig {
    #[serde(default)]
    prefixes: Vec<String>,
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

/// Parse a rule source string into a compiled `Rule`.
fn parse_rule(kind: &str, value: &str) -> Result<Rule, ConfigError> {
    let parts = shlex::split(value)
        .ok_or_else(|| ConfigError(format!("invalid {kind} rule {value:?}")))?;

    if parts.is_empty() {
        return Err(ConfigError(format!("{kind} rule cannot be empty")));
    }

    Ok(Rule {
        source: value.to_string(),
        exact_regex: compile_rule(&parts, false),
        prefix_regex: compile_rule(&parts, true),
    })
}

/// Translate a single argv part into a regex fragment, honouring `*` globs and
/// backslash escapes. `*` matches any run of characters except the delimiter.
fn compile_part(part: &str) -> String {
    let delimiter = regex::escape(PART_DELIMITER);
    let chars: Vec<char> = part.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '\\' {
            if index == chars.len() - 1 {
                out.push_str(&regex::escape(&ch.to_string()));
            } else {
                out.push_str(&regex::escape(&chars[index + 1].to_string()));
                index += 1;
            }
            index += 1;
            continue;
        }
        if ch == '*' {
            out.push_str(&format!("[^{delimiter}]*"));
        } else {
            out.push_str(&regex::escape(&ch.to_string()));
        }
        index += 1;
    }
    out
}

/// Collapse runs of consecutive `**` parts into a single `**`.
fn collapse_globstars(parts: &[String]) -> Vec<String> {
    let mut collapsed = Vec::new();
    let mut previous_was_globstar = false;
    for part in parts {
        if part == "**" {
            if !previous_was_globstar {
                collapsed.push(part.clone());
            }
            previous_was_globstar = true;
            continue;
        }
        collapsed.push(part.clone());
        previous_was_globstar = false;
    }
    collapsed
}

/// Compile a sequence of argv parts into an anchored, case-insensitive regex
/// over the delimiter-joined command string.
fn compile_rule(parts: &[String], allow_trailing_parts: bool) -> Regex {
    let delimiter = regex::escape(PART_DELIMITER);
    let any_part = format!("[^{delimiter}]*");
    let mut regex_parts: Vec<String> = Vec::new();

    let collapsed_parts = collapse_globstars(parts);
    let len = collapsed_parts.len();
    for (index, part) in collapsed_parts.iter().enumerate() {
        let is_last = index == len - 1;
        if part == "**" {
            if is_last {
                if regex_parts.last() == Some(&delimiter) {
                    regex_parts.pop();
                    regex_parts.push(format!("(?:{delimiter}{any_part})*"));
                } else {
                    regex_parts.push(format!("(?:{any_part}(?:{delimiter}{any_part})*)?"));
                }
            } else {
                regex_parts.push(format!("(?:{any_part}{delimiter})*"));
            }
            continue;
        }

        regex_parts.push(compile_part(part));
        regex_parts.push(delimiter.clone());
    }

    if regex_parts.last() == Some(&delimiter) {
        regex_parts.pop();
    }

    let mut body = regex_parts.concat();
    if allow_trailing_parts {
        body = format!("{body}(?:{delimiter}.*)?");
    }
    Regex::new(&format!("(?is)^{body}$")).expect("generated regex must be valid")
}

/// Load and validate the YAML config, returning (prefixes, allow, deny) rules.
fn load_config(path: &Path) -> Result<(Vec<Rule>, Vec<Rule>, Vec<Rule>), ConfigError> {
    if !path.exists() {
        return Err(ConfigError(format!(
            "config file does not exist: {}",
            path.display()
        )));
    }

    let text = std::fs::read_to_string(path)
        .map_err(|exc| ConfigError(format!("cannot read {}: {exc}", path.display())))?;
    let config: SaferunConfig =
        serde_yml::from_str(&text).map_err(|exc| ConfigError(exc.to_string()))?;

    if config.allow.is_empty() {
        return Err(ConfigError("allow must contain at least one entry".to_string()));
    }
    for entries in [&config.prefixes, &config.allow, &config.deny] {
        for entry in entries {
            if entry.trim().is_empty() {
                return Err(ConfigError("entries must not be empty".to_string()));
            }
        }
    }

    let prefixes = config
        .prefixes
        .iter()
        .map(|value| parse_rule("prefix", value))
        .collect::<Result<Vec<_>, _>>()?;
    let allow = config
        .allow
        .iter()
        .map(|value| parse_rule("allow", value))
        .collect::<Result<Vec<_>, _>>()?;
    let deny = config
        .deny
        .iter()
        .map(|value| parse_rule("deny", value))
        .collect::<Result<Vec<_>, _>>()?;

    Ok((prefixes, allow, deny))
}

fn join_argv(argv: &[String]) -> String {
    argv.join(PART_DELIMITER)
}

fn rule_matches_command(rule: &Rule, argv: &[String]) -> bool {
    rule.prefix_regex.is_match(&join_argv(argv))
}

/// All prefix lengths `n` such that `argv[..n]` matches the rule exactly.
fn rule_prefix_consumptions(rule: &Rule, argv: &[String]) -> Vec<usize> {
    (0..=argv.len())
        .filter(|&consumed| rule.exact_regex.is_match(&join_argv(&argv[..consumed])))
        .collect()
}

fn find_allow_match(prefixes: &[Rule], allowed: &[Rule], argv: &[String]) -> Option<AllowMatch> {
    let mut prefix_matches: Vec<(&Rule, usize)> = Vec::new();
    for prefix in prefixes {
        for consumed in rule_prefix_consumptions(prefix, argv) {
            prefix_matches.push((prefix, consumed));
        }
    }

    if !prefix_matches.is_empty() {
        for (prefix, consumed) in prefix_matches {
            let rest = &argv[consumed..];
            for allow in allowed {
                if rule_matches_command(allow, rest) {
                    return Some(AllowMatch {
                        allow: allow.clone(),
                        prefix: Some(prefix.clone()),
                        prefix_parts_consumed: consumed,
                    });
                }
            }
        }
        return None;
    }

    for allow in allowed {
        if rule_matches_command(allow, argv) {
            return Some(AllowMatch {
                allow: allow.clone(),
                prefix: None,
                prefix_parts_consumed: 0,
            });
        }
    }

    None
}

fn find_deny_match(prefixes: &[Rule], denied: &[Rule], argv: &[String]) -> Option<Rule> {
    for command in denied {
        if rule_matches_command(command, argv) {
            return Some(command.clone());
        }
    }

    for prefix in prefixes {
        for consumed in rule_prefix_consumptions(prefix, argv) {
            let rest = &argv[consumed..];
            for command in denied {
                if rule_matches_command(command, rest) {
                    return Some(command.clone());
                }
            }
        }
    }

    None
}

/// Render a string the way Python's `repr` does for simple strings: wrapped in
/// single quotes, switching to double quotes only if it contains a single quote.
fn py_repr(value: &str) -> String {
    if value.contains('\'') && !value.contains('"') {
        format!("\"{value}\"")
    } else {
        format!("'{}'", value.replace('\'', "\\'"))
    }
}

fn describe_match(m: &AllowMatch) -> String {
    match &m.prefix {
        None => format!("allow={}", py_repr(&m.allow.source)),
        Some(prefix) => format!(
            "prefix={}, allow={}, prefix_parts_consumed={}",
            py_repr(&prefix.source),
            py_repr(&m.allow.source),
            m.prefix_parts_consumed
        ),
    }
}

/// Quote a single token the way Python's `shlex.quote` does: leave it bare when
/// it only contains "safe" characters, otherwise wrap in single quotes.
fn shlex_quote(token: &str) -> String {
    if token.is_empty() {
        return "''".to_string();
    }
    let safe = token
        .chars()
        .all(|c| c.is_alphanumeric() || "@%+=:,./-_".contains(c));
    if safe {
        token.to_string()
    } else {
        format!("'{}'", token.replace('\'', "'\"'\"'"))
    }
}

/// Quote and join a command for display, matching `shlex.join`.
fn shlex_join(command: &[String]) -> String {
    command
        .iter()
        .map(|token| shlex_quote(token))
        .collect::<Vec<_>>()
        .join(" ")
}

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
    eprintln!("usage: saferun [-h] [--config CONFIG] [--dry-run] [--explain] -- command ...");
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
                    "usage: saferun [-h] [--config CONFIG] [--dry-run] [--explain] -- command ..."
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
    let args = parse_args(env::args().skip(1).collect());

    let (prefixes, allowed, denied) = match load_config(&args.config) {
        Ok(config) => config,
        Err(ConfigError(message)) => {
            eprintln!("saferun: invalid config: {message}");
            return 2;
        }
    };

    let command = args.command;

    if find_deny_match(&prefixes, &denied, &command).is_some() {
        eprintln!("DENIED {}", shlex_join(&command));
        return DENIED_EXIT_CODE;
    }

    let Some(matched) = find_allow_match(&prefixes, &allowed, &command) else {
        eprintln!("DENIED {}", shlex_join(&command));
        return DENIED_EXIT_CODE;
    };

    if args.dry_run {
        println!(
            "ALLOW {} ({})",
            shlex_join(&command),
            describe_match(&matched)
        );
        return 0;
    }

    if args.explain {
        eprintln!(
            "ALLOW {} ({})",
            shlex_join(&command),
            describe_match(&matched)
        );
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

fn main() {
    std::process::exit(run());
}
