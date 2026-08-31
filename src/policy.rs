use std::fmt;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const PART_DELIMITER: &str = "\u{00b0}"; // "°"
pub const IMPLICIT_ASK_SOURCE: &str = "<no matched rule>";

/// An error describing a malformed configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// A compiled policy rule.
#[derive(Debug)]
pub struct Rule {
    source: String,
    implicit: bool,
    /// Matches the joined argv exactly (no trailing parts allowed).
    exact_regex: Regex,
    /// Matches the joined argv allowing extra trailing parts.
    prefix_regex: Regex,
}

impl Rule {
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn is_implicit(&self) -> bool {
        self.implicit
    }
}

/// A positive rule match, optionally exposed through a configured prefix.
#[derive(Debug, Clone, Copy)]
pub struct RuleMatch<'a> {
    rule: &'a Rule,
    prefix: Option<&'a Rule>,
    prefix_parts_consumed: usize,
}

impl<'a> RuleMatch<'a> {
    pub fn rule(&self) -> &'a Rule {
        self.rule
    }

    pub fn rule_source(&self) -> &'a str {
        self.rule.source()
    }

    pub fn prefix(&self) -> Option<&'a Rule> {
        self.prefix
    }

    pub fn prefix_rule_source(&self) -> Option<&'a str> {
        self.prefix.map(Rule::source)
    }

    pub fn prefix_parts_consumed(&self) -> usize {
        self.prefix_parts_consumed
    }

    pub fn is_implicit(&self) -> bool {
        self.rule.is_implicit()
    }
}

/// The result of classifying a command against a policy.
#[derive(Debug, Clone, Copy)]
pub enum PolicyDecision<'a> {
    Deny,
    Ask(RuleMatch<'a>),
    Allow(RuleMatch<'a>),
}

/// A compiled saferun policy and the digest of its exact YAML bytes.
#[derive(Debug)]
pub struct Policy {
    prefixes: Vec<Rule>,
    shell_prefixes: Vec<Rule>,
    ask: Vec<Rule>,
    allow: Vec<Rule>,
    deny: Vec<Rule>,
    implicit_ask: Rule,
    digest: [u8; 32],
}

impl Policy {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn implicit_ask_match(&self) -> RuleMatch<'_> {
        RuleMatch {
            rule: &self.implicit_ask,
            prefix: None,
            prefix_parts_consumed: 0,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaferunConfig {
    #[serde(default)]
    prefixes: Vec<String>,
    #[serde(default)]
    shell_prefixes: Vec<String>,
    allow: Vec<String>,
    #[serde(default)]
    ask: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ShellPrefixMatch<'a> {
    rule: &'a Rule,
    parts_consumed: usize,
}

impl<'a> ShellPrefixMatch<'a> {
    pub fn rule(&self) -> &'a Rule {
        self.rule
    }

    pub fn rule_source(&self) -> &'a str {
        self.rule.source()
    }

    pub fn parts_consumed(&self) -> usize {
        self.parts_consumed
    }
}

/// Parse a rule source string into a compiled `Rule`.
fn parse_rule(kind: &str, value: &str) -> Result<Rule, ConfigError> {
    let parts =
        shlex::split(value).ok_or_else(|| ConfigError(format!("invalid {kind} rule {value:?}")))?;

    if parts.is_empty() {
        return Err(ConfigError(format!("{kind} rule cannot be empty")));
    }

    Ok(Rule {
        source: value.to_string(),
        implicit: false,
        exact_regex: compile_rule(&parts, false),
        prefix_regex: compile_rule(&parts, true),
    })
}

fn implicit_ask_rule() -> Rule {
    let parts = vec!["**".to_string()];
    Rule {
        source: IMPLICIT_ASK_SOURCE.to_string(),
        implicit: true,
        exact_regex: compile_rule(&parts, false),
        prefix_regex: compile_rule(&parts, true),
    }
}

/// Translate one argv part into a regex fragment, honoring `*` and escapes.
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

/// Collapse runs of consecutive `**` parts into one `**`.
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

/// Compile argv parts into an anchored, case-insensitive joined-argv regex.
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

fn parse_policy(text: &str, digest: [u8; 32]) -> Result<Policy, ConfigError> {
    let config: SaferunConfig =
        serde_yml::from_str(text).map_err(|error| ConfigError(error.to_string()))?;

    if config.allow.is_empty() {
        return Err(ConfigError(
            "allow must contain at least one entry".to_string(),
        ));
    }
    for entries in [
        &config.prefixes,
        &config.shell_prefixes,
        &config.ask,
        &config.allow,
        &config.deny,
    ] {
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
    let shell_prefixes = config
        .shell_prefixes
        .iter()
        .map(|value| parse_rule("shell_prefix", value))
        .collect::<Result<Vec<_>, _>>()?;
    let ask = config
        .ask
        .iter()
        .map(|value| parse_rule("ask", value))
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

    Ok(Policy {
        prefixes,
        shell_prefixes,
        ask,
        allow,
        deny,
        implicit_ask: implicit_ask_rule(),
        digest,
    })
}

/// Load, validate, compile, and digest a policy file.
pub fn load_policy(path: &Path) -> Result<Policy, ConfigError> {
    if !path.exists() {
        return Err(ConfigError(format!(
            "config file does not exist: {}",
            path.display()
        )));
    }

    let bytes = std::fs::read(path)
        .map_err(|error| ConfigError(format!("cannot read {}: {error}", path.display())))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| ConfigError(format!("cannot read {}: {error}", path.display())))?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    parse_policy(text, digest)
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

/// Configured prefix matches in policy order, then ascending consumption count.
fn prefix_matches<'a>(prefixes: &'a [Rule], argv: &[String]) -> Vec<(&'a Rule, usize)> {
    let mut matches: Vec<(&'a Rule, usize)> = Vec::new();
    for prefix in prefixes {
        for consumed in rule_prefix_consumptions(prefix, argv) {
            matches.push((prefix, consumed));
        }
    }
    matches
}

fn find_rule_match<'a>(
    prefixes: &'a [Rule],
    rules: &'a [Rule],
    argv: &[String],
) -> Option<RuleMatch<'a>> {
    let prefix_hits = prefix_matches(prefixes, argv);

    if !prefix_hits.is_empty() {
        for (prefix, consumed) in prefix_hits {
            let rest = &argv[consumed..];
            for rule in rules {
                if rule_matches_command(rule, rest) {
                    return Some(RuleMatch {
                        rule,
                        prefix: Some(prefix),
                        prefix_parts_consumed: consumed,
                    });
                }
            }
        }
        return None;
    }

    for rule in rules {
        if rule_matches_command(rule, argv) {
            return Some(RuleMatch {
                rule,
                prefix: None,
                prefix_parts_consumed: 0,
            });
        }
    }

    None
}

fn find_deny_match<'a>(
    prefixes: &'a [Rule],
    denied: &'a [Rule],
    argv: &[String],
) -> Option<RuleMatch<'a>> {
    for command in denied {
        if rule_matches_command(command, argv) {
            return Some(RuleMatch {
                rule: command,
                prefix: None,
                prefix_parts_consumed: 0,
            });
        }
    }

    for prefix in prefixes {
        for consumed in rule_prefix_consumptions(prefix, argv) {
            let rest = &argv[consumed..];
            for command in denied {
                if rule_matches_command(command, rest) {
                    return Some(RuleMatch {
                        rule: command,
                        prefix: Some(prefix),
                        prefix_parts_consumed: consumed,
                    });
                }
            }
        }
    }

    None
}

pub fn is_denied(policy: &Policy, argv: &[String]) -> bool {
    deny_match(policy, argv).is_some()
}

pub fn deny_match<'a>(policy: &'a Policy, argv: &[String]) -> Option<RuleMatch<'a>> {
    find_deny_match(&policy.prefixes, &policy.deny, argv)
}

pub fn configured_prefix_remainders<'a>(policy: &Policy, argv: &'a [String]) -> Vec<&'a [String]> {
    prefix_matches(&policy.prefixes, argv)
        .into_iter()
        .map(|(_, consumed)| &argv[consumed..])
        .collect()
}

pub fn configured_prefix_consumptions(policy: &Policy, argv: &[String]) -> Vec<usize> {
    prefix_matches(&policy.prefixes, argv)
        .into_iter()
        .map(|(_, consumed)| consumed)
        .collect()
}

pub fn shell_prefix_matches<'a>(policy: &'a Policy, argv: &[String]) -> Vec<ShellPrefixMatch<'a>> {
    prefix_matches(&policy.shell_prefixes, argv)
        .into_iter()
        .map(|(rule, parts_consumed)| ShellPrefixMatch {
            rule,
            parts_consumed,
        })
        .collect()
}

/// Classify with precedence `deny > ask > allow > implicit ask`.
pub fn classify<'a>(policy: &'a Policy, argv: &[String]) -> PolicyDecision<'a> {
    if deny_match(policy, argv).is_some() {
        return PolicyDecision::Deny;
    }
    if let Some(matched) = find_rule_match(&policy.prefixes, &policy.ask, argv) {
        return PolicyDecision::Ask(matched);
    }
    if let Some(matched) = find_rule_match(&policy.prefixes, &policy.allow, argv) {
        return PolicyDecision::Allow(matched);
    }
    let (prefix, prefix_parts_consumed) = prefix_matches(&policy.prefixes, argv)
        .into_iter()
        .next()
        .map(|(rule, consumed)| (Some(rule), consumed))
        .unwrap_or((None, 0));
    PolicyDecision::Ask(RuleMatch {
        rule: &policy.implicit_ask,
        prefix,
        prefix_parts_consumed,
    })
}

/// Render a short diagnostic string with quotes.
pub fn display_repr(value: &str) -> String {
    if value.contains('\'') && !value.contains('"') {
        format!("\"{value}\"")
    } else {
        format!("'{}'", value.replace('\'', "\\'"))
    }
}

/// Describe a positive rule match using the given rule kind.
pub fn describe_match(kind: &str, matched: &RuleMatch<'_>) -> String {
    match matched.prefix() {
        None => format!("{kind}={}", display_repr(matched.rule_source())),
        Some(prefix) => format!(
            "prefix={}, {kind}={}, prefix_parts_consumed={}",
            display_repr(prefix.source()),
            display_repr(matched.rule_source()),
            matched.prefix_parts_consumed()
        ),
    }
}

/// Quote one shell token for diagnostic display.
pub fn shlex_quote(token: &str) -> String {
    if token.is_empty() {
        return "''".to_string();
    }
    let safe = token
        .chars()
        .all(|character| character.is_alphanumeric() || "@%+=:,./-_".contains(character));
    if safe {
        token.to_string()
    } else {
        format!("'{}'", token.replace('\'', "'\"'\"'"))
    }
}

/// Quote and join a command for display, matching `shlex.join`.
pub fn shlex_join(command: &[String]) -> String {
    command
        .iter()
        .map(|token| shlex_quote(token))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(text: &str) -> Policy {
        let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        parse_policy(text, digest).expect("test policy must parse")
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn explicit_rules_and_implicit_ask_classify_in_order() {
        let parsed = policy("prefixes:\n  - sudo\nallow:\n  - /bin/echo\ndeny:\n  - /bin/rm\n");
        assert!(matches!(
            classify(&parsed, &argv(&["sudo", "/bin/echo", "hello"])),
            PolicyDecision::Allow(_)
        ));
        assert!(matches!(
            classify(&parsed, &argv(&["sudo", "/bin/rm", "file"])),
            PolicyDecision::Deny
        ));
        let PolicyDecision::Ask(matched) = classify(&parsed, &argv(&["/bin/false"])) else {
            panic!("unmatched command must ask");
        };
        assert!(matched.is_implicit());
        assert_eq!(matched.rule_source(), IMPLICIT_ASK_SOURCE);
    }

    #[test]
    fn invalid_ask_and_unknown_fields_fail() {
        for text in [
            "allow: [/bin/true]\nask: ['   ']\n",
            "allow: [/bin/true]\nask: ['unterminated]\n",
            "allow: [/bin/true]\nunknown: []\n",
        ] {
            let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
            assert!(parse_policy(text, digest).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn precedence_is_deny_then_ask_then_allow() {
        let parsed = policy(
            "allow:\n  - /bin/tool **\nask:\n  - /bin/tool risky\ndeny:\n  - /bin/tool forbidden\n",
        );
        assert!(matches!(
            classify(&parsed, &argv(&["/bin/tool", "safe"])),
            PolicyDecision::Allow(_)
        ));
        assert!(matches!(
            classify(&parsed, &argv(&["/bin/tool", "risky", "extra"])),
            PolicyDecision::Ask(_)
        ));
        assert!(matches!(
            classify(&parsed, &argv(&["/bin/tool", "forbidden"])),
            PolicyDecision::Deny
        ));
        let PolicyDecision::Ask(matched) = classify(&parsed, &argv(&["/completely/unmatched"]))
        else {
            panic!("unmatched command must ask");
        };
        assert!(matched.is_implicit());
    }

    #[test]
    fn direct_and_prefix_ask_preserve_sources_and_order() {
        let direct = policy("allow: [/bin/true]\nask: [/bin/touch]\n");
        let PolicyDecision::Ask(matched) = classify(&direct, &argv(&["/bin/touch", "one", "two"]))
        else {
            panic!("expected direct ask");
        };
        assert_eq!(matched.rule_source(), "/bin/touch");
        assert_eq!(matched.prefix_rule_source(), None);
        assert!(!matched.is_implicit());

        let prefixed = policy(
            "prefixes:\n  - env *\n  - command\nallow: [/bin/true]\nask:\n  - /bin/touch\n  - /bin/*\n",
        );
        let PolicyDecision::Ask(matched) =
            classify(&prefixed, &argv(&["env", "A=1", "/bin/touch", "one"]))
        else {
            panic!("expected prefixed ask");
        };
        assert_eq!(matched.rule_source(), "/bin/touch");
        assert_eq!(matched.prefix_rule_source(), Some("env *"));
        assert_eq!(matched.prefix_parts_consumed(), 2);
    }

    #[test]
    fn consuming_prefix_prevents_full_positive_fallback_but_not_direct_deny() {
        let only_allow = policy("prefixes:\n  - env *\nallow:\n  - env FOO=1 /bin/echo\n");
        let command = argv(&["env", "FOO=1", "/bin/echo"]);
        let PolicyDecision::Ask(matched) = classify(&only_allow, &command) else {
            panic!("failed positive match must fall back to ask");
        };
        assert!(matched.is_implicit());

        let denied = policy(
            "prefixes:\n  - env *\nallow:\n  - env FOO=1 /bin/echo\ndeny:\n  - env FOO=1 /bin/echo\n",
        );
        assert!(matches!(classify(&denied, &command), PolicyDecision::Deny));
    }

    #[test]
    fn prefix_matches_follows_policy_order_then_ascending_consumption() {
        let parsed = policy("prefixes:\n  - a *\n  - a **\nallow:\n  - /bin/true\n");
        let command = argv(&["a", "b", "c"]);
        let order: Vec<(&str, usize)> = prefix_matches(&parsed.prefixes, &command)
            .into_iter()
            .map(|(rule, consumed)| (rule.source(), consumed))
            .collect();
        assert_eq!(
            order,
            vec![("a *", 2), ("a **", 1), ("a **", 2), ("a **", 3)]
        );
    }

    #[test]
    fn implicit_ask_preserves_recognized_prefix_boundary() {
        let parsed = policy("prefixes:\n  - env *\nallow:\n  - /bin/true\n");
        let PolicyDecision::Ask(matched) =
            classify(&parsed, &argv(&["env", "X=1", "python3", "-c", "x"]))
        else {
            panic!("unmatched command must ask");
        };
        assert!(matched.is_implicit());
        assert_eq!(matched.rule_source(), IMPLICIT_ASK_SOURCE);
        assert_eq!(matched.prefix_rule_source(), Some("env *"));
        assert_eq!(matched.prefix_parts_consumed(), 2);

        let PolicyDecision::Ask(unprefixed) = classify(&parsed, &argv(&["python3", "-c", "x"]))
        else {
            panic!("unmatched command must ask");
        };
        assert!(unprefixed.is_implicit());
        assert_eq!(unprefixed.prefix_rule_source(), None);
        assert_eq!(unprefixed.prefix_parts_consumed(), 0);
    }

    #[test]
    fn shell_prefixes_do_not_behave_like_generic_prefixes() {
        let parsed = policy("shell_prefixes:\n  - bash -c\nallow:\n  - cargo test\n");
        let command = argv(&["bash", "-c", "cargo test"]);
        let PolicyDecision::Ask(matched) = classify(&parsed, &command) else {
            panic!("shell prefix must not affect direct classification");
        };
        assert!(matched.is_implicit());
        assert_eq!(matched.prefix_rule_source(), None);

        let shell_matches = shell_prefix_matches(&parsed, &command);
        assert_eq!(shell_matches.len(), 1);
        assert_eq!(shell_matches[0].rule_source(), "bash -c");
        assert_eq!(shell_matches[0].parts_consumed(), 2);
    }

    #[test]
    fn exact_yaml_bytes_determine_digest() {
        let first = "allow: [/bin/true]\n";
        let second = "allow: [/bin/true]\n# changed\n";
        assert_ne!(policy(first).digest(), policy(second).digest());
    }
}
