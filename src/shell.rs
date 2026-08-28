use agent_shell_parser::parse::{parse_with_substitutions, Operator, ParsedPipeline, ShellSegment};

use crate::policy::{
    configured_prefix_remainders, shell_prefix_matches, shlex_join, shlex_quote, Policy,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellCommandUnit {
    Parsed(Vec<String>),
    Opaque(String),
}

impl ShellCommandUnit {
    pub fn approval_command(&self) -> Vec<String> {
        match self {
            Self::Parsed(argv) => argv.clone(),
            Self::Opaque(command) => vec![command.clone()],
        }
    }

    pub fn display_command(&self) -> String {
        match self {
            Self::Parsed(argv) => shlex_join(argv),
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
    let parsed = payload.and_then(|script| parse_with_substitutions(script).ok());
    let static_commands = parsed.as_ref().map(static_commands).unwrap_or_default();

    let units = match remainder {
        [script] => decompose_payload(script, parsed.as_ref()),
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
    if let Some(prefix) = shell_prefix_matches(policy, argv).into_iter().next() {
        return Some(ShellInvocationMatch {
            effective_argv: argv,
            shell_parts_consumed: prefix.parts_consumed(),
        });
    }

    for remainder in configured_prefix_remainders(policy, argv) {
        if let Some(prefix) = shell_prefix_matches(policy, remainder).into_iter().next() {
            return Some(ShellInvocationMatch {
                effective_argv: remainder,
                shell_parts_consumed: prefix.parts_consumed(),
            });
        }
    }

    None
}

fn decompose_payload(payload: &str, parsed: Option<&ParsedPipeline>) -> Vec<ShellCommandUnit> {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Some(pipeline) = parsed else {
        return vec![opaque(trimmed)];
    };
    if pipeline.has_parse_errors_recursive()
        || !has_only_supported_top_level_operators(pipeline)
        || !matches_source_sequence(trimmed, pipeline)
    {
        return vec![opaque(trimmed)];
    }

    pipeline
        .segments
        .iter()
        .filter_map(unit_from_segment)
        .collect()
}

fn unit_from_segment(segment: &ShellSegment) -> Option<ShellCommandUnit> {
    let command = segment.command.trim();
    if command.is_empty() {
        return None;
    }

    if is_literal_simple_command(segment) {
        shlex::split(command).map(ShellCommandUnit::Parsed)
    } else {
        Some(opaque(command))
    }
}

fn opaque(command: &str) -> ShellCommandUnit {
    ShellCommandUnit::Opaque(shlex_quote(command))
}

fn is_literal_simple_command(segment: &ShellSegment) -> bool {
    segment.redirection.is_none()
        && segment.substitutions.is_empty()
        && !segment.words.is_empty()
        && !segment
            .words
            .iter()
            .any(|word| word.is_assignment() || word.is_expansion())
        && !has_unquoted_brace_expansion(segment.command.as_str())
        && !has_unquoted_tilde_expansion(segment.command.as_str())
        && !has_unquoted_glob(segment.command.as_str())
        && !has_unquoted_redirection(segment.command.as_str())
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

fn has_unquoted_brace_expansion(value: &str) -> bool {
    has_unquoted_meta(value, &['{', '}'])
}

fn has_unquoted_tilde_expansion(value: &str) -> bool {
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let mut word_start = true;

    for character in value.chars() {
        if escaped {
            escaped = false;
            word_start = false;
            continue;
        }
        match character {
            '\\' if !single_quoted => escaped = true,
            '\'' if !double_quoted => {
                single_quoted = !single_quoted;
                word_start = false;
            }
            '"' if !single_quoted => {
                double_quoted = !double_quoted;
                word_start = false;
            }
            _ if !single_quoted && !double_quoted && character.is_ascii_whitespace() => {
                word_start = true;
            }
            '~' if !single_quoted && !double_quoted && word_start => return true,
            _ => word_start = false,
        }
    }

    false
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
            "echo hi > file",
            "echo $(date)",
            "echo $HOME",
            "echo {a,b}",
            "r{m,} target",
            "~/bin/tool --version",
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
