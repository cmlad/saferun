use agent_shell_parser::parse::{parse_with_substitutions, Operator, ParsedPipeline, ShellSegment};

use crate::policy::{
    configured_prefix_remainders, shell_prefix_matches, shlex_join, shlex_quote, Policy,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellCommandUnit {
    Parsed(Vec<String>),
    Redirection { operator: String, target: String },
    Opaque(String),
}

impl ShellCommandUnit {
    pub fn approval_command(&self) -> Vec<String> {
        match self {
            Self::Parsed(argv) => argv.clone(),
            Self::Redirection { operator, target } => vec![operator.clone(), target.clone()],
            Self::Opaque(command) => vec![command.clone()],
        }
    }

    pub fn display_command(&self) -> String {
        match self {
            Self::Parsed(argv) => shlex_join(argv),
            Self::Redirection { operator, target } => {
                format!("{operator} {}", shlex_quote(target))
            }
            Self::Opaque(command) => command.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShellInvocation {
    pub units: Vec<ShellCommandUnit>,
    pub static_commands: Vec<Vec<String>>,
}

pub fn analyze_shell_invocation(policy: &Policy, argv: &[String]) -> Option<ShellInvocation> {
    let shell_match = find_shell_invocation(policy, argv)?;
    let remainder = shell_match
        .effective_argv
        .get(shell_match.shell_parts_consumed..)
        .unwrap_or(&[]);
    let payload = remainder.first().map(String::as_str);
    let (analysis_payload, removed_ignored_redirects) = payload
        .map(
            |script| match command_without_ignored_stderr_dev_null_redirections(script) {
                Some(normalized) => (normalized, true),
                None => (script.to_string(), false),
            },
        )
        .unwrap_or_default();
    let parsed = parse_with_substitutions(&analysis_payload).ok();
    let static_commands = parsed.as_ref().map(static_commands).unwrap_or_default();

    let units = match remainder {
        [script] => decompose_payload(
            script,
            &analysis_payload,
            removed_ignored_redirects,
            parsed.as_ref(),
        ),
        [] => vec![ShellCommandUnit::Opaque(shlex_join(argv))],
        _ => vec![ShellCommandUnit::Opaque(shlex_join(argv))],
    };

    Some(ShellInvocation {
        units,
        static_commands,
    })
}

struct ShellInvocationMatch<'a> {
    effective_argv: &'a [String],
    shell_parts_consumed: usize,
}

fn find_shell_invocation<'a>(
    policy: &Policy,
    argv: &'a [String],
) -> Option<ShellInvocationMatch<'a>> {
    for candidate in shell_prefix_candidates_for_invocation(policy, argv) {
        if let Some(prefix) = shell_prefix_matches(policy, candidate).into_iter().next() {
            return Some(ShellInvocationMatch {
                effective_argv: candidate,
                shell_parts_consumed: prefix.parts_consumed(),
            });
        }
    }

    None
}

fn shell_prefix_candidates_for_invocation<'a>(
    policy: &Policy,
    argv: &'a [String],
) -> Vec<&'a [String]> {
    shell_prefix_candidates(policy, argv, false)
}

pub(crate) fn shell_prefix_candidates_for_shell_command<'a>(
    policy: &Policy,
    argv: &'a [String],
) -> Vec<&'a [String]> {
    shell_prefix_candidates(policy, argv, true)
}

fn shell_prefix_candidates<'a>(
    policy: &Policy,
    argv: &'a [String],
    include_initial_assignments: bool,
) -> Vec<&'a [String]> {
    let mut candidates = Vec::new();
    push_candidate(&mut candidates, argv);
    if include_initial_assignments {
        push_assignment_stripped_candidate(&mut candidates, argv);
    }

    let mut index = 0;
    while index < candidates.len() {
        let candidate = candidates[index];
        index += 1;

        for remainder in configured_prefix_remainders(policy, candidate) {
            push_candidate(&mut candidates, remainder);
            push_assignment_stripped_candidate(&mut candidates, remainder);
        }
    }

    candidates
}

fn push_candidate<'a>(candidates: &mut Vec<&'a [String]>, candidate: &'a [String]) {
    if candidates.iter().any(|existing| {
        existing.as_ptr() == candidate.as_ptr() && existing.len() == candidate.len()
    }) {
        return;
    }
    candidates.push(candidate);
}

fn push_assignment_stripped_candidate<'a>(
    candidates: &mut Vec<&'a [String]>,
    candidate: &'a [String],
) {
    if let Some(effective) = strip_leading_assignments(candidate) {
        push_candidate(candidates, effective);
    }
}

fn decompose_payload(
    original_payload: &str,
    analysis_payload: &str,
    removed_ignored_redirects: bool,
    parsed: Option<&ParsedPipeline>,
) -> Vec<ShellCommandUnit> {
    let trimmed = original_payload.trim();
    let analysis_trimmed = analysis_payload.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if has_unsupported_shell_analysis_whitespace(original_payload) {
        return vec![opaque(trimmed)];
    }
    if removed_ignored_redirects
        && (analysis_trimmed.is_empty()
            || contains_only_ignored_redirection_separators(analysis_trimmed))
    {
        return Vec::new();
    }
    if analysis_trimmed.is_empty() {
        return vec![opaque(trimmed)];
    }

    let Some(pipeline) = parsed else {
        return vec![opaque(trimmed)];
    };
    if pipeline.has_parse_errors_recursive()
        || !has_only_supported_top_level_operators(pipeline)
        || !matches_source_sequence(analysis_trimmed, pipeline)
    {
        return vec![opaque(trimmed)];
    }

    pipeline
        .segments
        .iter()
        .flat_map(units_from_segment)
        .collect()
}

fn contains_only_ignored_redirection_separators(value: &str) -> bool {
    value
        .chars()
        .all(|character| is_shell_blank(character) || character == ';')
}

fn units_from_segment(segment: &ShellSegment) -> Vec<ShellCommandUnit> {
    let command = segment.command.trim();
    if command.is_empty() {
        return Vec::new();
    }

    let normalized_command = command_without_ignored_stderr_dev_null_redirections(command);
    let analysis_command = normalized_command.as_deref().unwrap_or(command).trim();
    if analysis_command.is_empty() {
        return vec![opaque(command)];
    }

    if !has_literal_command_words(segment) {
        return vec![opaque(command)];
    }

    if segment.redirection.is_none() {
        if is_literal_simple_command_source(analysis_command) {
            if let Some(argv) = shlex::split(analysis_command) {
                return vec![ShellCommandUnit::Parsed(argv)];
            }
        }
        if let Some((argv, redirection)) = supported_static_redirection(segment, analysis_command) {
            return vec![ShellCommandUnit::Parsed(argv), redirection];
        }
        return vec![opaque(command)];
    }

    if let Some((argv, redirection)) = supported_static_redirection(segment, analysis_command) {
        return vec![ShellCommandUnit::Parsed(argv), redirection];
    }

    vec![opaque(command)]
}

fn opaque(command: &str) -> ShellCommandUnit {
    ShellCommandUnit::Opaque(shlex_quote(command))
}

fn has_literal_command_words(segment: &ShellSegment) -> bool {
    segment.substitutions.is_empty()
        && !segment.words.is_empty()
        && !segment
            .words
            .iter()
            .any(|word| word.is_assignment() || word.is_expansion())
}

fn is_literal_simple_command_source(command: &str) -> bool {
    !has_unquoted_brace_expansion(command)
        && !has_unquoted_glob(command)
        && !has_unquoted_redirection(command)
}

fn supported_static_redirection(
    segment: &ShellSegment,
    command: &str,
) -> Option<(Vec<String>, ShellCommandUnit)> {
    if has_unquoted_brace_expansion(command) || has_unquoted_glob(command) {
        return None;
    }

    let split = split_supported_redirection_suffix(command.trim())?;
    let argv = shlex::split(split.command)?;
    if argv.is_empty() {
        return None;
    }
    let target = static_redirection_target(split.target)?;

    match segment.redirection.as_ref() {
        Some(redirection)
            if redirection.fd.is_none()
                && matches!(redirection.operator, ">" | ">>")
                && split.operator == redirection.operator => {}
        None if target == "/dev/null" => {}
        _ => return None,
    }

    Some((
        argv,
        ShellCommandUnit::Redirection {
            operator: split.operator.to_string(),
            target,
        },
    ))
}

fn command_without_ignored_stderr_dev_null_redirections(command: &str) -> Option<String> {
    let mut normalized = String::with_capacity(command.len());
    let mut last_copied = 0;
    let mut search_start = 0;
    let mut removed = false;

    while let Some(redirection) = next_ignored_stderr_dev_null_redirection(command, search_start) {
        normalized.push_str(&command[last_copied..redirection.start]);
        last_copied = redirection.end;
        search_start = redirection.end;
        removed = true;
    }

    if removed {
        normalized.push_str(&command[last_copied..]);
        Some(normalized)
    } else {
        None
    }
}

struct IgnoredRedirection {
    start: usize,
    end: usize,
}

fn next_ignored_stderr_dev_null_redirection(
    command: &str,
    search_start: usize,
) -> Option<IgnoredRedirection> {
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;

    for (offset, character) in command[search_start..].char_indices() {
        let index = search_start + offset;
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if !single_quoted => escaped = true,
            '\'' if !double_quoted => single_quoted = !single_quoted,
            '"' if !single_quoted => double_quoted = !double_quoted,
            '>' if !single_quoted && !double_quoted => {
                if matches!(command[index + 1..].chars().next(), Some('>' | '|' | '&')) {
                    continue;
                }
                let Some((fd_start, fd)) = explicit_redirection_fd(command, index) else {
                    continue;
                };
                if fd != "2" {
                    continue;
                }
                let target_start = skip_horizontal_whitespace(command, index + 1);
                let target_end = redirection_target_end(command, target_start)?;
                let target = &command[target_start..target_end];
                if static_redirection_target(target).as_deref() == Some("/dev/null") {
                    return Some(IgnoredRedirection {
                        start: fd_start,
                        end: target_end,
                    });
                }
            }
            _ => {}
        }
    }

    None
}

fn explicit_redirection_fd(command: &str, operator_index: usize) -> Option<(usize, &str)> {
    let before = &command[..operator_index];
    let trimmed = before.trim_end_matches(|character: char| character.is_ascii_whitespace());
    if trimmed.len() != before.len() {
        return None;
    }

    let mut digit_start = trimmed.len();
    for (index, character) in trimmed.char_indices().rev() {
        if character.is_ascii_digit() {
            digit_start = index;
        } else {
            break;
        }
    }
    if digit_start == trimmed.len() {
        return None;
    }
    if !has_redirection_fd_boundary(&trimmed[..digit_start]) {
        return None;
    }

    Some((digit_start, &trimmed[digit_start..]))
}

fn has_redirection_fd_boundary(before_fd: &str) -> bool {
    let Some(previous) = before_fd.chars().next_back() else {
        return true;
    };
    if is_shell_blank(previous) || matches!(previous, ';' | '|') {
        return true;
    }
    if previous != '&' {
        return false;
    }

    before_fd
        .chars()
        .rev()
        .nth(1)
        .is_some_and(|character| character == '&')
}

fn skip_horizontal_whitespace(command: &str, mut index: usize) -> usize {
    while let Some(character) = command[index..].chars().next() {
        if !is_shell_blank(character) {
            break;
        }
        index += character.len_utf8();
    }
    index
}

fn redirection_target_end(command: &str, target_start: usize) -> Option<usize> {
    if target_start >= command.len() {
        return None;
    }

    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let mut saw_character = false;

    for (offset, character) in command[target_start..].char_indices() {
        let index = target_start + offset;
        if escaped {
            escaped = false;
            saw_character = true;
            continue;
        }
        match character {
            '\\' if !single_quoted => {
                escaped = true;
                saw_character = true;
            }
            '\'' if !double_quoted => {
                single_quoted = !single_quoted;
                saw_character = true;
            }
            '"' if !single_quoted => {
                double_quoted = !double_quoted;
                saw_character = true;
            }
            _ if !single_quoted && !double_quoted && is_shell_blank(character) => {
                return saw_character.then_some(index);
            }
            '|' | '&' | ';' | '(' | ')' | '<' | '>' if !single_quoted && !double_quoted => {
                return saw_character.then_some(index);
            }
            _ => saw_character = true,
        }
    }

    saw_character.then_some(command.len())
}

struct RedirectionSplit<'a> {
    command: &'a str,
    operator: &'static str,
    target: &'a str,
}

fn split_supported_redirection_suffix(command: &str) -> Option<RedirectionSplit<'_>> {
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let mut found = None;

    let mut chars = command.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if !single_quoted => escaped = true,
            '\'' if !double_quoted => single_quoted = !single_quoted,
            '"' if !single_quoted => double_quoted = !double_quoted,
            '<' if !single_quoted && !double_quoted => return None,
            '>' if !single_quoted && !double_quoted => {
                if command[..index].ends_with('&') {
                    return None;
                }
                let operator = match chars.peek().map(|(_, next)| *next) {
                    Some('>') => {
                        chars.next();
                        ">>"
                    }
                    Some('|' | '&') => return None,
                    _ => ">",
                };
                if found.is_some() || has_explicit_redirection_fd(command, index) {
                    return None;
                }
                found = Some((index, operator));
            }
            _ => {}
        }
    }

    let (operator_index, operator) = found?;
    let command_prefix = command[..operator_index].trim();
    let target_start = operator_index + operator.len();
    let target = command[target_start..].trim();
    if command_prefix.is_empty() || target.is_empty() {
        return None;
    }
    Some(RedirectionSplit {
        command: command_prefix,
        operator,
        target,
    })
}

fn has_explicit_redirection_fd(command: &str, operator_index: usize) -> bool {
    explicit_redirection_fd(command, operator_index).is_some()
}

fn static_redirection_target(raw_target: &str) -> Option<String> {
    if has_unsupported_redirection_target_meta(raw_target) {
        return None;
    }

    let target = shlex::split(raw_target)?;
    match target.as_slice() {
        [target] if !target.is_empty() => Some(target.clone()),
        _ => None,
    }
}

fn has_unsupported_redirection_target_meta(value: &str) -> bool {
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let mut word_start = true;
    let mut assignment_tilde_site = false;
    let mut assignment_scan = AssignmentTildeScan::new_word();

    for character in value.chars() {
        if escaped {
            escaped = false;
            word_start = false;
            assignment_tilde_site = false;
            assignment_scan.quoted_character();
            continue;
        }
        match character {
            '\\' if !single_quoted => {
                escaped = true;
                word_start = false;
                assignment_tilde_site = false;
                assignment_scan.quoted_character();
            }
            '\'' if !double_quoted => {
                single_quoted = !single_quoted;
                word_start = false;
                assignment_tilde_site = false;
                assignment_scan.quoted_character();
            }
            '"' if !single_quoted => {
                double_quoted = !double_quoted;
                word_start = false;
                assignment_tilde_site = false;
                assignment_scan.quoted_character();
            }
            '$' | '`' if !single_quoted => return true,
            '*' | '?' | '[' | '{' | '}' | '|' | '&' | ';' | '(' | ')' | '<' | '>'
                if !single_quoted && !double_quoted =>
            {
                return true;
            }
            '~' if !single_quoted && !double_quoted && (word_start || assignment_tilde_site) => {
                return true;
            }
            _ if !single_quoted
                && !double_quoted
                && is_unsupported_shell_analysis_whitespace(character) =>
            {
                return true;
            }
            _ if !single_quoted && !double_quoted && is_shell_blank(character) => {
                word_start = true;
                assignment_tilde_site = false;
                assignment_scan = AssignmentTildeScan::new_word();
            }
            _ if !single_quoted && !double_quoted => {
                word_start = false;
                assignment_tilde_site = assignment_scan.unquoted_character(character);
            }
            _ => {
                word_start = false;
                assignment_tilde_site = false;
            }
        }
    }

    false
}

/// Tracks redirection-target assignment contexts where shells expand `~`.
enum AssignmentTildeScan {
    Candidate(String),
    Value,
    NotAssignment,
}

impl AssignmentTildeScan {
    fn new_word() -> Self {
        Self::Candidate(String::new())
    }

    fn quoted_character(&mut self) {
        if matches!(self, Self::Candidate(_)) {
            *self = Self::NotAssignment;
        }
    }

    fn unquoted_character(&mut self, character: char) -> bool {
        match self {
            Self::Candidate(prefix) => {
                if character == '=' {
                    if is_assignment_lhs(prefix) {
                        *self = Self::Value;
                        true
                    } else {
                        *self = Self::NotAssignment;
                        false
                    }
                } else if is_assignment_lhs_character(character) || character == '+' {
                    prefix.push(character);
                    false
                } else {
                    *self = Self::NotAssignment;
                    false
                }
            }
            Self::Value => character == ':',
            Self::NotAssignment => false,
        }
    }
}

fn is_assignment_lhs(raw: &str) -> bool {
    if is_assignment_key(raw) {
        return true;
    }
    raw.strip_suffix('+').is_some_and(is_assignment_key)
}

fn is_assignment_lhs_character(character: char) -> bool {
    character == '_' || character.is_ascii_alphanumeric()
}

fn is_assignment_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn is_shell_blank(character: char) -> bool {
    matches!(character, ' ' | '\t')
}

fn has_unsupported_shell_analysis_whitespace(value: &str) -> bool {
    value.chars().any(is_unsupported_shell_analysis_whitespace)
}

fn is_unsupported_shell_analysis_whitespace(character: char) -> bool {
    character.is_ascii_whitespace() && !is_shell_blank(character) && character != '\n'
}

fn segment_words(segment: &ShellSegment) -> Vec<String> {
    segment
        .words
        .iter()
        .map(|word| word.as_str().to_string())
        .collect()
}

fn static_commands(pipeline: &ParsedPipeline) -> Vec<Vec<String>> {
    pipeline.filter_segments(&|segment| {
        let words = segment_words(segment);
        if words.is_empty() {
            None
        } else {
            Some(words)
        }
    })
}

fn has_only_supported_top_level_operators(pipeline: &ParsedPipeline) -> bool {
    pipeline
        .operators
        .iter()
        .all(|operator| matches!(operator, Operator::And | Operator::Semi | Operator::Pipe))
}

fn matches_source_sequence(source: &str, pipeline: &ParsedPipeline) -> bool {
    if source.contains('\n') {
        return false;
    }
    if pipeline.segments.is_empty() {
        return source.is_empty();
    }
    if pipeline.operators.len() + 1 != pipeline.segments.len() {
        return false;
    }

    let mut remainder = source;
    for (index, segment) in pipeline.segments.iter().enumerate() {
        remainder = trim_horizontal_start(remainder);
        let command = segment.command.trim();
        let Some(after_command) = remainder.strip_prefix(command) else {
            return false;
        };
        remainder = trim_horizontal_start(after_command);

        if let Some(operator) = pipeline.operators.get(index) {
            let Some(after_operator) = remainder.strip_prefix(operator.as_str()) else {
                return false;
            };
            remainder = after_operator;
        }
    }

    let mut remainder = trim_horizontal_start(remainder);
    while let Some(after_semicolon) = remainder.strip_prefix(';') {
        remainder = trim_horizontal_start(after_semicolon);
    }
    remainder.is_empty()
}

fn trim_horizontal_start(value: &str) -> &str {
    value.trim_start_matches(|character: char| character.is_ascii_whitespace() && character != '\n')
}

fn has_unquoted_glob(value: &str) -> bool {
    has_unquoted_meta(value, &['*', '?', '['])
}

fn has_unquoted_redirection(value: &str) -> bool {
    has_unquoted_meta(value, &['<', '>'])
}

pub(crate) fn strip_leading_assignments(argv: &[String]) -> Option<&[String]> {
    let first_command = argv.iter().position(|part| !is_assignment(part))?;
    if first_command == 0 {
        None
    } else {
        Some(&argv[first_command..])
    }
}

fn is_assignment(value: &str) -> bool {
    let Some((key, _)) = value.split_once('=') else {
        return false;
    };
    is_assignment_key(key)
}

fn has_unquoted_brace_expansion(value: &str) -> bool {
    has_unquoted_meta(value, &['{', '}'])
}

fn has_unquoted_meta(value: &str, metas: &[char]) -> bool {
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;

    for character in value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if !single_quoted => escaped = true,
            '\'' if !double_quoted => single_quoted = !single_quoted,
            '"' if !single_quoted => double_quoted = !double_quoted,
            _ if !single_quoted && !double_quoted && metas.contains(&character) => return true,
            _ => {}
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::load_policy;
    use std::path::Path;

    fn policy() -> crate::policy::Policy {
        let path = Path::new("testdata/missing");
        let text = "shell_prefixes:\n  - bash -c\n  - /bin/bash -c\n  - /bin/zsh -lc\nallow: [/bin/true]\n";
        let directory = tempfile::tempdir().expect("tempdir");
        let policy_path = directory.path().join(path);
        std::fs::create_dir_all(policy_path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&policy_path, text).expect("write policy");
        load_policy(&policy_path).expect("load policy")
    }

    fn analyze(command: &[&str]) -> Option<ShellInvocation> {
        let policy = policy();
        let argv = command
            .iter()
            .map(|part| (*part).to_string())
            .collect::<Vec<_>>();
        analyze_shell_invocation(&policy, &argv)
    }

    fn unit_strings(command: &[&str]) -> Vec<ShellCommandUnit> {
        analyze(command).expect("shell invocation").units
    }

    #[test]
    fn configured_shell_prefixes_parse_payloads() {
        assert_eq!(
            unit_strings(&["bash", "-c", "cargo test;git status"]),
            vec![
                ShellCommandUnit::Parsed(vec!["cargo".into(), "test".into()]),
                ShellCommandUnit::Parsed(vec!["git".into(), "status".into()]),
            ]
        );
        assert!(analyze(&["zsh", "-lc", "cargo test"]).is_none());
    }

    #[test]
    fn configured_generic_prefixes_compose_with_shell_prefixes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let policy_path = directory.path().join("saferun.yaml");
        std::fs::write(
            &policy_path,
            "prefixes:\n  - env *\nshell_prefixes:\n  - bash -c\nallow: [/bin/true]\n",
        )
        .expect("write policy");
        let policy = load_policy(&policy_path).expect("load policy");
        let argv = [
            "env".to_string(),
            "X=1".to_string(),
            "bash".to_string(),
            "-c".to_string(),
            "cargo test; git status".to_string(),
        ];
        let invocation = analyze_shell_invocation(&policy, &argv).expect("shell invocation");

        assert_eq!(
            invocation.units,
            vec![
                ShellCommandUnit::Parsed(vec!["cargo".into(), "test".into()]),
                ShellCommandUnit::Parsed(vec!["git".into(), "status".into()]),
            ]
        );
    }

    #[test]
    fn configured_generic_prefixes_strip_multiple_env_assignments_before_shell_prefixes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let policy_path = directory.path().join("saferun.yaml");
        std::fs::write(
            &policy_path,
            "prefixes:\n  - env *\nshell_prefixes:\n  - bash -c\nallow: [/bin/true]\n",
        )
        .expect("write policy");
        let policy = load_policy(&policy_path).expect("load policy");
        let argv = [
            "env".to_string(),
            "A=1".to_string(),
            "B=2".to_string(),
            "bash".to_string(),
            "-c".to_string(),
            "cargo test".to_string(),
        ];
        let invocation = analyze_shell_invocation(&policy, &argv).expect("shell invocation");

        assert_eq!(
            invocation.units,
            vec![ShellCommandUnit::Parsed(vec![
                "cargo".into(),
                "test".into()
            ])]
        );
    }

    #[test]
    fn stacked_configured_generic_prefixes_compose_with_shell_prefixes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let policy_path = directory.path().join("saferun.yaml");
        std::fs::write(
            &policy_path,
            "prefixes:\n  - command\n  - env *\nshell_prefixes:\n  - bash -c\nallow: [/bin/true]\n",
        )
        .expect("write policy");
        let policy = load_policy(&policy_path).expect("load policy");
        let argv = [
            "command".to_string(),
            "env".to_string(),
            "A=1".to_string(),
            "B=2".to_string(),
            "bash".to_string(),
            "-c".to_string(),
            "git status".to_string(),
        ];
        let invocation = analyze_shell_invocation(&policy, &argv).expect("shell invocation");

        assert_eq!(
            invocation.units,
            vec![ShellCommandUnit::Parsed(vec![
                "git".into(),
                "status".into()
            ])]
        );
    }

    #[test]
    fn quoted_and_escaped_separators_stay_arguments() {
        assert_eq!(
            unit_strings(&["bash", "-c", r#"echo "a && b"; printf c\;d"#]),
            vec![
                ShellCommandUnit::Parsed(vec!["echo".into(), "a && b".into()]),
                ShellCommandUnit::Parsed(vec!["printf".into(), "c;d".into()]),
            ]
        );
    }

    #[test]
    fn quoted_glob_characters_stay_arguments() {
        assert_eq!(
            unit_strings(&["bash", "-c", r#"printf "*?[abc]""#]),
            vec![ShellCommandUnit::Parsed(vec![
                "printf".into(),
                "*?[abc]".into()
            ])]
        );
    }

    #[test]
    fn quoted_brace_and_tilde_characters_stay_arguments() {
        assert_eq!(
            unit_strings(&["bash", "-c", r#"printf "{a,b}" "~""#]),
            vec![ShellCommandUnit::Parsed(vec![
                "printf".into(),
                "{a,b}".into(),
                "~".into(),
            ])]
        );
    }

    #[test]
    fn tilde_forms_stay_literal_arguments() {
        assert_eq!(
            unit_strings(&["bash", "-c", r#"printf ~ ~/src ~root/bin ~+ ~- \~"#]),
            vec![ShellCommandUnit::Parsed(vec![
                "printf".into(),
                "~".into(),
                "~/src".into(),
                "~root/bin".into(),
                "~+".into(),
                "~-".into(),
                "~".into(),
            ])]
        );
    }

    #[test]
    fn tilde_in_command_position_stays_literal() {
        assert_eq!(
            unit_strings(&["bash", "-c", "~/bin/tool --version"]),
            vec![ShellCommandUnit::Parsed(vec![
                "~/bin/tool".into(),
                "--version".into(),
            ])]
        );
    }

    #[test]
    fn supported_chains_and_pipelines_reconstruct_argv() {
        assert_eq!(
            unit_strings(&["bash", "-c", "printf hi|grep h&&cargo test;"]),
            vec![
                ShellCommandUnit::Parsed(vec!["printf".into(), "hi".into()]),
                ShellCommandUnit::Parsed(vec!["grep".into(), "h".into()]),
                ShellCommandUnit::Parsed(vec!["cargo".into(), "test".into()]),
            ]
        );
    }

    #[test]
    fn stdout_redirections_decompose_after_literal_commands() {
        assert_eq!(
            unit_strings(&[
                "bash",
                "-c",
                "printf hi > /tmp/out; git status >> '/tmp/status log'",
            ]),
            vec![
                ShellCommandUnit::Parsed(vec!["printf".into(), "hi".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">".into(),
                    target: "/tmp/out".into(),
                },
                ShellCommandUnit::Parsed(vec!["git".into(), "status".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">>".into(),
                    target: "/tmp/status log".into(),
                },
            ]
        );
    }

    #[test]
    fn dev_null_stdout_redirections_decompose_after_literal_commands() {
        assert_eq!(
            unit_strings(&[
                "bash",
                "-c",
                "printf hi > /dev/null; printf bye >> /dev/null"
            ]),
            vec![
                ShellCommandUnit::Parsed(vec!["printf".into(), "hi".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">".into(),
                    target: "/dev/null".into(),
                },
                ShellCommandUnit::Parsed(vec!["printf".into(), "bye".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">>".into(),
                    target: "/dev/null".into(),
                },
            ]
        );
    }

    #[test]
    fn tilde_expansion_redirection_targets_stay_opaque() {
        assert_eq!(
            unit_strings(&[
                "bash",
                "-c",
                concat!(
                    "printf hi > ~/out; ",
                    "printf bye >> ~root/out; ",
                    "printf ok > ~+/out; ",
                    ": > FOO=~/out; ",
                    ": > FOO+=~/out; ",
                    ": > PATH=abc:~/out; ",
                    ": > PATH+=abc:~root/out",
                ),
            ]),
            vec![
                ShellCommandUnit::Opaque("'printf hi > ~/out'".into()),
                ShellCommandUnit::Opaque("'printf bye >> ~root/out'".into()),
                ShellCommandUnit::Opaque("'printf ok > ~+/out'".into()),
                ShellCommandUnit::Opaque("': > FOO=~/out'".into()),
                ShellCommandUnit::Opaque("': > FOO+=~/out'".into()),
                ShellCommandUnit::Opaque("': > PATH=abc:~/out'".into()),
                ShellCommandUnit::Opaque("': > PATH+=abc:~root/out'".into()),
            ]
        );
    }

    #[test]
    fn redirection_target_tilde_near_misses_stay_static() {
        assert_eq!(
            unit_strings(&[
                "bash",
                "-c",
                "printf hi > x~/out; printf bye >> FOO:~/out; printf ok > FOO=x~y/out",
            ]),
            vec![
                ShellCommandUnit::Parsed(vec!["printf".into(), "hi".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">".into(),
                    target: "x~/out".into(),
                },
                ShellCommandUnit::Parsed(vec!["printf".into(), "bye".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">>".into(),
                    target: "FOO:~/out".into(),
                },
                ShellCommandUnit::Parsed(vec!["printf".into(), "ok".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">".into(),
                    target: "FOO=x~y/out".into(),
                },
            ]
        );
        assert_eq!(
            unit_strings(&[
                "bash",
                "-c",
                r#"printf hi > FOO==~/out; printf bye >> FOO=abc\:\~/out; printf ok > FOO=abc:"~"/out"#,
            ]),
            vec![
                ShellCommandUnit::Parsed(vec!["printf".into(), "hi".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">".into(),
                    target: "FOO==~/out".into(),
                },
                ShellCommandUnit::Parsed(vec!["printf".into(), "bye".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">>".into(),
                    target: "FOO=abc:~/out".into(),
                },
                ShellCommandUnit::Parsed(vec!["printf".into(), "ok".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">".into(),
                    target: "FOO=abc:~/out".into(),
                },
            ]
        );
    }

    #[test]
    fn stderr_dev_null_redirections_are_ignored_after_literal_commands() {
        assert_eq!(
            unit_strings(&[
                "bash",
                "-c",
                "printf hi 2>/dev/null; printf bye 2> /dev/null"
            ]),
            vec![
                ShellCommandUnit::Parsed(vec!["printf".into(), "hi".into()]),
                ShellCommandUnit::Parsed(vec!["printf".into(), "bye".into()]),
            ]
        );
    }

    #[test]
    fn tilde_forms_compose_with_supported_operators_and_ignored_stderr() {
        assert_eq!(
            unit_strings(&[
                "bash",
                "-c",
                "ls ~/.codex/ 2>/dev/null | grep ~; printf ~/src 2> /dev/null",
            ]),
            vec![
                ShellCommandUnit::Parsed(vec!["ls".into(), "~/.codex/".into()]),
                ShellCommandUnit::Parsed(vec!["grep".into(), "~".into()]),
                ShellCommandUnit::Parsed(vec!["printf".into(), "~/src".into()]),
            ]
        );
    }

    #[test]
    fn stderr_dev_null_redirections_can_appear_around_arguments() {
        assert_eq!(
            unit_strings(&["bash", "-c", "2>/dev/null printf hi 2> '/dev/null' bye"]),
            vec![ShellCommandUnit::Parsed(vec![
                "printf".into(),
                "hi".into(),
                "bye".into()
            ])]
        );
    }

    #[test]
    fn stderr_dev_null_redirections_can_start_commands_after_supported_operators() {
        assert_eq!(
            unit_strings(&[
                "bash",
                "-c",
                "printf hi;2>/dev/null printf bye|2>/dev/null grep bye&&2> /dev/null cargo test"
            ]),
            vec![
                ShellCommandUnit::Parsed(vec!["printf".into(), "hi".into()]),
                ShellCommandUnit::Parsed(vec!["printf".into(), "bye".into()]),
                ShellCommandUnit::Parsed(vec!["grep".into(), "bye".into()]),
                ShellCommandUnit::Parsed(vec!["cargo".into(), "test".into()]),
            ]
        );
    }

    #[test]
    fn stderr_dev_null_redirections_compose_with_stdout_redirection_parts() {
        assert_eq!(
            unit_strings(&[
                "bash",
                "-c",
                "printf hi 2>/dev/null > out; printf bye >> out 2> /dev/null"
            ]),
            vec![
                ShellCommandUnit::Parsed(vec!["printf".into(), "hi".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">".into(),
                    target: "out".into(),
                },
                ShellCommandUnit::Parsed(vec!["printf".into(), "bye".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">>".into(),
                    target: "out".into(),
                },
            ]
        );
    }

    #[test]
    fn stderr_dev_null_only_payloads_have_no_authorization_units() {
        assert_eq!(unit_strings(&["bash", "-c", "2>/dev/null"]), Vec::new());
        assert_eq!(
            unit_strings(&["bash", "-c", "2>/dev/null; 2> /dev/null;"]),
            Vec::new()
        );
    }

    #[test]
    fn quoted_expansions_with_ignored_stderr_dev_null_stay_opaque() {
        for script in [
            "echo \"$HOME\" 2>/dev/null",
            "echo \"${VAR}\" 2>/dev/null",
            "echo \"$(date)\" 2>/dev/null",
            "echo \"$((1 + 2))\" 2>/dev/null",
        ] {
            let units = unit_strings(&["bash", "-c", script]);
            assert_eq!(units.len(), 1, "{script:?}");
            assert!(
                matches!(units[0], ShellCommandUnit::Opaque(_)),
                "{script:?}: {units:?}"
            );
        }
    }

    #[test]
    fn quoted_redirection_targets_can_contain_separator_characters() {
        assert_eq!(
            unit_strings(&["bash", "-c", "printf hi >> 'a;b|c&&d'"]),
            vec![
                ShellCommandUnit::Parsed(vec!["printf".into(), "hi".into()]),
                ShellCommandUnit::Redirection {
                    operator: ">>".into(),
                    target: "a;b|c&&d".into(),
                },
            ]
        );
    }

    #[test]
    fn empty_payload_has_no_units() {
        assert_eq!(unit_strings(&["bash", "-c", ""]), Vec::new());
    }

    #[test]
    fn unicode_payload_words_are_preserved() {
        assert_eq!(
            unit_strings(&["bash", "-c", "printf café"]),
            vec![ShellCommandUnit::Parsed(vec![
                "printf".into(),
                "café".into()
            ])]
        );
    }

    #[test]
    fn unsupported_fragments_become_opaque() {
        for script in [
            "echo hi > $OUT",
            "echo hi > \"$OUT\"",
            "echo hi > *.log",
            "echo hi 2> file",
            "echo hi 2>> /dev/null",
            "echo hi 2>/tmp/null",
            "echo hi 2>/dev/nullish",
            "echo hi 20>/dev/null",
            "echo hi 2>&1",
            "echo hi 2> $NULL",
            "echo hi 2> \"$NULL\"",
            "echo hi 2>\r/dev/null",
            "echo hi 2>\x0b/dev/null",
            "echo hi 2>\x0c/dev/null",
            "echo hi 2>/dev/null\r",
            "echo hi 2>",
            "echo hi >| file",
            "echo hi &> file",
            "echo hi &> /dev/null",
            "echo hi > file extra",
            "echo $(date)",
            "echo $HOME",
            "echo ~/$HOME",
            "echo ~/$(date)",
            "~/bin/$TOOL --version",
            "echo {a,b}",
            "r{m,} target",
            "echo ~/*.log",
            "echo *",
            "cargo test || git status",
            "sleep 1 & git status",
            "if true; then echo ok; fi",
            "(echo ok)",
            "f() { echo ok; }",
            "cat <<EOF\nx\nEOF",
            "echo 'unterminated",
        ] {
            let units = unit_strings(&["bash", "-c", script]);
            assert_eq!(units.len(), 1, "{script:?}");
            assert!(
                matches!(units[0], ShellCommandUnit::Opaque(_)),
                "{script:?}: {units:?}"
            );
        }
    }

    #[test]
    fn extra_shell_arguments_make_full_invocation_opaque() {
        assert_eq!(
            unit_strings(&["bash", "-c", "cargo test", "bash"]),
            vec![ShellCommandUnit::Opaque(
                "bash -c 'cargo test' bash".to_string()
            )]
        );
    }

    #[test]
    fn static_commands_include_commands_inside_opaque_constructs() {
        let invocation =
            analyze(&["bash", "-c", "echo $(rm file); git status"]).expect("shell invocation");
        assert_eq!(
            invocation.static_commands,
            vec![
                vec!["rm".to_string(), "file".to_string()],
                vec!["echo".to_string(), "$(rm file)".to_string()],
                vec!["git".to_string(), "status".to_string()],
            ]
        );
    }
}
