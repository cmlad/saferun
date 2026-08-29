use crate::approval::{
    read_request_frame, write_response_frame, ApprovalDecision, ApprovalRequest, ApprovalResponse,
    ApprovalScope, ProtocolError, PROTOCOL_VERSION,
};
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::sync::Mutex;

const MAX_PROMPT_LEN: usize = 16 * 1024;
const ALL_COMMANDS_SESSION_TITLE: &str = "Allow all commands in this session";

/// The session scope a user selected on the approval panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSelection {
    EffectiveCommandPrefix { parts: usize },
    MatchedAskRule,
    AllCommands,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SessionGrantTarget {
    EffectiveCommandPrefix(Vec<String>),
    MatchedAskRule(String),
    AllCommands,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionGrantKey {
    session_digest: String,
    policy_digest: String,
    target: SessionGrantTarget,
}

impl SessionGrantKey {
    fn for_target(request: &ApprovalRequest, target: SessionGrantTarget) -> Self {
        Self {
            session_digest: request.session_digest.clone(),
            policy_digest: request.policy_digest.clone(),
            target,
        }
    }
}

/// The effective argv left after stripping a recognized configured prefix.
///
/// Exact string equality is intentional: executables are not resolved through
/// `PATH`, tokens are not canonicalized, and shell payloads stay opaque.
fn effective_command(request: &ApprovalRequest) -> &[String] {
    let consumed = usize::try_from(request.prefix_parts_consumed).unwrap_or(0);
    request.command.get(consumed..).unwrap_or(&[])
}

/// Candidate grant keys for a request: longest effective prefix first, then
/// matched ask rule, then the blanket all-commands grant.
fn session_probe_keys(request: &ApprovalRequest) -> Vec<SessionGrantKey> {
    let effective = effective_command(request);
    let mut keys = Vec::with_capacity(effective.len() + 2);
    for parts in effective_command_session_parts(effective).rev() {
        keys.push(SessionGrantKey::for_target(
            request,
            SessionGrantTarget::EffectiveCommandPrefix(effective[..parts].to_vec()),
        ));
    }
    if !request.implicit_ask {
        keys.push(SessionGrantKey::for_target(
            request,
            SessionGrantTarget::MatchedAskRule(request.ask_rule_source.clone()),
        ));
    }
    keys.push(SessionGrantKey::for_target(
        request,
        SessionGrantTarget::AllCommands,
    ));
    keys
}

/// Resolve a panel selection to a concrete grant target, rejecting impossible
/// scopes so a confused UI fails closed.
fn session_grant_target(
    request: &ApprovalRequest,
    selection: SessionSelection,
) -> Option<SessionGrantTarget> {
    match selection {
        SessionSelection::EffectiveCommandPrefix { parts } => {
            let effective = effective_command(request);
            if !effective_command_session_parts(effective).contains(&parts) {
                return None;
            }
            Some(SessionGrantTarget::EffectiveCommandPrefix(
                effective[..parts].to_vec(),
            ))
        }
        SessionSelection::MatchedAskRule => {
            if request.implicit_ask {
                None
            } else {
                Some(SessionGrantTarget::MatchedAskRule(
                    request.ask_rule_source.clone(),
                ))
            }
        }
        SessionSelection::AllCommands => Some(SessionGrantTarget::AllCommands),
    }
}

fn effective_command_session_parts(effective: &[String]) -> std::ops::RangeInclusive<usize> {
    if is_redirection_effective_command(effective) {
        effective.len()..=effective.len()
    } else {
        1..=effective.len()
    }
}

fn is_redirection_effective_command(effective: &[String]) -> bool {
    effective
        .first()
        .is_some_and(|operator| matches!(operator.as_str(), ">" | ">>"))
        && effective.len() >= 2
}

#[derive(Debug)]
pub struct SessionCache {
    grants: HashMap<SessionGrantKey, u64>,
    generation: u64,
    capacity: usize,
}

impl SessionCache {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            grants: HashMap::new(),
            generation: 0,
            capacity,
        }
    }

    fn next_generation(&mut self) -> u64 {
        if self.generation == u64::MAX {
            self.grants.clear();
            self.generation = 1;
        } else {
            self.generation += 1;
        }
        self.generation
    }

    fn lookup(&mut self, key: &SessionGrantKey) -> bool {
        if !self.grants.contains_key(key) {
            return false;
        }
        let generation = self.next_generation();
        let Some(stored_generation) = self.grants.get_mut(key) else {
            return false;
        };
        *stored_generation = generation;
        true
    }

    fn insert(&mut self, key: SessionGrantKey) -> bool {
        if self.capacity == 0 {
            return false;
        }
        let generation = self.next_generation();
        if let Some(stored_generation) = self.grants.get_mut(&key) {
            *stored_generation = generation;
            return false;
        }
        if self.grants.len() >= self.capacity {
            if let Some(oldest) = self
                .grants
                .iter()
                .min_by_key(|(_, generation)| *generation)
                .map(|(key, _)| key.clone())
            {
                self.grants.remove(&oldest);
            }
        }
        self.grants.insert(key, generation);
        true
    }

    fn remove(&mut self, key: &SessionGrantKey) {
        self.grants.remove(key);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptChoice {
    Deny,
    AllowOnce,
    AllowSession(SessionSelection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptError(String);

impl PromptError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for PromptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PromptError {}

pub trait Prompter {
    fn prompt(&mut self, request: &ApprovalRequest) -> Result<PromptChoice, PromptError>;
}

#[derive(Debug)]
pub enum BrokerError {
    Response(ProtocolError),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Response(error) => write!(formatter, "cannot send approval response: {error}"),
        }
    }
}

impl std::error::Error for BrokerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Response(error) => Some(error),
        }
    }
}

fn lock_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

/// Handle exactly one framed client request and response.
pub fn handle_connection<S: Read + Write, P: Prompter>(
    stream: &mut S,
    cache: &Mutex<SessionCache>,
    prompter: &Mutex<P>,
) -> Result<(), BrokerError> {
    let request = match read_request_frame(stream) {
        Ok(request) => request,
        Err(_) => {
            eprintln!("saferun-approval: rejected malformed request");
            let response = ApprovalResponse {
                version: PROTOCOL_VERSION,
                decision: ApprovalDecision::Denied,
            };
            return write_response_frame(stream, &response).map_err(BrokerError::Response);
        }
    };

    eprintln!(
        "saferun-approval: request session={} implicit={} prefix={} consumed={} cmd={}",
        request.session_digest.get(..8).unwrap_or("?"),
        request.implicit_ask,
        request.prefix_rule_source.as_deref().unwrap_or("-"),
        request.prefix_parts_consumed,
        request.command.join(" ")
    );

    let mut inserted_key = None;
    let cached = lookup_session(cache, &request);
    let decision = match cached {
        Some(decision) => decision,
        None => {
            let mut prompter = lock_mutex(prompter);
            if let Some(decision) = lookup_session(cache, &request) {
                decision
            } else {
                match prompter.prompt(&request) {
                    Ok(PromptChoice::Deny) => {
                        eprintln!("saferun-approval: deny");
                        ApprovalDecision::Denied
                    }
                    Ok(PromptChoice::AllowOnce) => {
                        eprintln!("saferun-approval: allow once");
                        ApprovalDecision::Approved {
                            scope: ApprovalScope::Once,
                        }
                    }
                    Ok(PromptChoice::AllowSession(selection)) => {
                        match session_grant_target(&request, selection) {
                            Some(target) => {
                                eprintln!(
                                    "saferun-approval: session insert {}",
                                    describe_target(&target)
                                );
                                let key = SessionGrantKey::for_target(&request, target);
                                let mut cache = lock_mutex(cache);
                                if cache.insert(key.clone()) {
                                    inserted_key = Some(key);
                                }
                                ApprovalDecision::Approved {
                                    scope: ApprovalScope::Session,
                                }
                            }
                            None => {
                                eprintln!("saferun-approval: UI failure: invalid session scope");
                                ApprovalDecision::Denied
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("saferun-approval: UI failure: {error}");
                        ApprovalDecision::Denied
                    }
                }
            }
        }
    };

    let response = ApprovalResponse {
        version: PROTOCOL_VERSION,
        decision,
    };
    if let Err(error) = write_response_frame(stream, &response) {
        let peer_closed = matches!(
            &error,
            ProtocolError::Io(io) if matches!(
                io.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            )
        );
        if peer_closed && inserted_key.is_some() {
            eprintln!("saferun-approval: peer closed after session insert; keeping grant");
        } else if let Some(key) = inserted_key {
            eprintln!("saferun-approval: response write failed: {error}; rolling back grant");
            lock_mutex(cache).remove(&key);
        } else {
            eprintln!("saferun-approval: response write failed: {error}");
        }
        return Err(BrokerError::Response(error));
    }
    Ok(())
}

fn lookup_session(
    cache: &Mutex<SessionCache>,
    request: &crate::approval::ApprovalRequest,
) -> Option<ApprovalDecision> {
    let mut cache = lock_mutex(cache);
    for key in session_probe_keys(request) {
        if cache.lookup(&key) {
            eprintln!(
                "saferun-approval: session hit {}",
                describe_target(&key.target)
            );
            return Some(ApprovalDecision::Approved {
                scope: ApprovalScope::Session,
            });
        }
    }
    None
}

/// Append arbitrary bytes reversibly using printable ASCII only.
fn push_authorization_bytes(rendered: &mut String, value: &[u8], quoted: bool) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    if quoted {
        rendered.push('"');
    }
    for byte in value {
        match byte {
            b'"' => rendered.push_str("\\\""),
            b'\\' => rendered.push_str("\\\\"),
            0x20..=0x7e => rendered.push(*byte as char),
            _ => {
                rendered.push_str("\\x");
                rendered.push(HEX[(byte >> 4) as usize] as char);
                rendered.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    if quoted {
        rendered.push('"');
    }
}

/// Render arbitrary bytes reversibly as a quoted printable ASCII value.
pub fn render_authorization_bytes(value: &[u8]) -> String {
    let mut rendered = String::with_capacity(value.len() + 2);
    push_authorization_bytes(&mut rendered, value, true);
    rendered
}

fn render_authorization_bytes_unquoted(value: &[u8]) -> String {
    let mut rendered = String::with_capacity(value.len());
    push_authorization_bytes(&mut rendered, value, false);
    rendered
}

pub fn build_prompt(request: &ApprovalRequest) -> String {
    let mut prompt = String::new();
    let consumed = usize::try_from(request.prefix_parts_consumed).unwrap_or(0);
    for (index, part) in request.command.iter().enumerate() {
        let (role, number) = if index < consumed {
            ("Prefix", index + 1)
        } else {
            ("Command", index + 1 - consumed)
        };
        prompt.push_str(&format!(
            "{role} {number}: {}\n",
            render_authorization_bytes_unquoted(part.as_bytes())
        ));
    }
    if request.implicit_ask {
        prompt.push_str("\nNo matched rule\n");
    } else {
        prompt.push_str(&format!(
            "\nAsk rule: {}\n",
            render_authorization_bytes_unquoted(request.ask_rule_source.as_bytes())
        ));
    }
    match &request.prefix_rule_source {
        Some(prefix) => {
            let unit = if request.prefix_parts_consumed == 1 {
                "part"
            } else {
                "parts"
            };
            prompt.push_str(&format!(
                "Prefix rule: {} ({} {unit} consumed)\n",
                render_authorization_bytes_unquoted(prefix.as_bytes()),
                request.prefix_parts_consumed
            ));
        }
        None => prompt.push_str("No prefix rule\n"),
    }
    let fingerprint = request.session_digest.get(..8).unwrap_or("invalid");
    prompt.push_str(&format!("Session: {fingerprint}"));
    prompt
}

/// Panel title carrying the canonical working directory.
fn build_prompt_title(request: &ApprovalRequest) -> String {
    format!(
        "saferun in {}",
        render_authorization_bytes_unquoted(&request.cwd)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionScopeOption {
    title: String,
    selection: SessionSelection,
}

/// Session-scope menu entries in display order; the first entry is the
/// effective executable and therefore the default grant.
fn session_scope_options(request: &ApprovalRequest) -> Vec<SessionScopeOption> {
    let effective = effective_command(request);
    let mut options = Vec::with_capacity(effective.len() + 2);
    for parts in effective_command_session_parts(effective) {
        options.push(SessionScopeOption {
            title: session_scope_title(&effective[..parts]),
            selection: SessionSelection::EffectiveCommandPrefix { parts },
        });
    }
    if !request.implicit_ask {
        options.push(SessionScopeOption {
            title: "Matched ask rule".to_string(),
            selection: SessionSelection::MatchedAskRule,
        });
    }
    options.push(SessionScopeOption {
        title: ALL_COMMANDS_SESSION_TITLE.to_string(),
        selection: SessionSelection::AllCommands,
    });
    options
}

/// Join effective argv parts for a menu title, truncating each to 8 chars + ellipsis.
fn session_scope_title(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| {
            let rendered = render_authorization_bytes_unquoted(part.as_bytes());
            let mut chars = rendered.chars();
            let head: String = chars.by_ref().take(8).collect();
            if chars.next().is_some() {
                format!("{head}…")
            } else {
                head
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Default)]
pub struct SystemPrompter;

impl SystemPrompter {
    pub fn new() -> Self {
        Self
    }
}

/// Map osascript output to a choice; unknown output fails closed.
fn parse_prompt_choice(
    stdout: &[u8],
    options: &[SessionScopeOption],
) -> Result<PromptChoice, PromptError> {
    let trimmed = trim_osascript_stdout(stdout);
    match trimmed {
        b"Deny" => Ok(PromptChoice::Deny),
        b"Allow" => Ok(PromptChoice::AllowOnce),
        _ => {
            let Some(rest) = trimmed.strip_prefix(b"Allow for session") else {
                return Err(PromptError::new("osascript returned an invalid choice"));
            };
            let Some(digits) = rest.strip_prefix(b" ") else {
                return Err(PromptError::new(
                    "osascript returned an invalid session scope",
                ));
            };
            if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                return Err(PromptError::new(
                    "osascript returned an invalid session scope",
                ));
            }
            let digits = std::str::from_utf8(digits)
                .map_err(|_| PromptError::new("osascript returned an invalid session scope"))?;
            let index: usize = digits
                .parse()
                .map_err(|_| PromptError::new("osascript returned an invalid session scope"))?;
            let Some(option) = options.get(index) else {
                return Err(PromptError::new(
                    "osascript returned an invalid session scope",
                ));
            };
            Ok(PromptChoice::AllowSession(option.selection))
        }
    }
}

fn trim_osascript_stdout(stdout: &[u8]) -> &[u8] {
    let mut bytes = stdout;
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        bytes = &bytes[1..bytes.len() - 1];
    }
    bytes
}

fn describe_target(target: &SessionGrantTarget) -> String {
    match target {
        SessionGrantTarget::EffectiveCommandPrefix(parts) => {
            format!("prefix[{}]", parts.join(" "))
        }
        SessionGrantTarget::MatchedAskRule(source) => format!("rule[{source}]"),
        SessionGrantTarget::AllCommands => "all-commands".to_string(),
    }
}

#[cfg(target_os = "macos")]
impl Prompter for SystemPrompter {
    fn prompt(&mut self, request: &ApprovalRequest) -> Result<PromptChoice, PromptError> {
        use std::process::{Command, Stdio};

        let prompt = build_prompt(request);
        if prompt.len() > MAX_PROMPT_LEN {
            return Err(PromptError::new("approval display exceeds 16 KiB"));
        }
        let prompt_json = serde_json::to_string(&prompt)
            .map_err(|_| PromptError::new("cannot encode approval display"))?;
        let title_json = serde_json::to_string(&build_prompt_title(request))
            .map_err(|_| PromptError::new("cannot encode approval display"))?;
        let options = session_scope_options(request);
        let mut popup_setup = String::new();
        if options.is_empty() {
            popup_setup.push_str("    popup.addItemWithTitle(\"No session scope available\");\n");
        } else {
            for option in &options {
                let title = serde_json::to_string(&option.title)
                    .map_err(|_| PromptError::new("cannot encode approval display"))?;
                popup_setup.push_str(&format!("    popup.addItemWithTitle({title});\n"));
            }
        }
        let disable_controls = if options.is_empty() {
            "    sessionButton.setEnabled(false);\n    popup.setEnabled(false);\n"
        } else {
            ""
        };
        let program = format!(
            r#"ObjC.import("Cocoa");
const app = $.NSApplication.sharedApplication;
const prompt = {prompt_json};
const windowTitle = {title_json};
let choice = "Deny";
try {{
    if (!app.setActivationPolicy($.NSApplicationActivationPolicyAccessory)) {{
        throw new Error("cannot activate approval UI");
    }}
    ObjC.registerSubclass({{
        name: "SaferunApprovalController",
        methods: {{
            "choose:": {{
                types: ["void", ["id"]],
                implementation: function(sender) {{
                    app.stopModalWithCode(sender.tag);
                }}
            }}
        }}
    }});
    const controller = $.SaferunApprovalController.alloc.init;
    const width = 720;
    const textWidth = width - 28;
    const textView = $.NSTextView.alloc.initWithFrame(
        $.NSMakeRect(0, 0, textWidth, 1)
    );
    textView.setString(prompt);
    textView.setEditable(false);
    textView.setDrawsBackground(false);
    textView.setSelectable(true);
    textView.setFont($.NSFont.userFixedPitchFontOfSize(13));
    textView.setTextContainerInset($.NSMakeSize(4, 4));
    textView.setHorizontallyResizable(false);
    textView.setVerticallyResizable(true);
    textView.textContainer.setContainerSize($.NSMakeSize(textWidth - 8, 1000000));
    textView.textContainer.setWidthTracksTextView(true);
    textView.layoutManager.ensureLayoutForTextContainer(textView.textContainer);
    const usedTextHeight = Number(
        textView.layoutManager.usedRectForTextContainer(textView.textContainer).size.height
    );
    const textHeight = Math.min(420, Math.ceil(usedTextHeight + 10));
    textView.setFrameSize($.NSMakeSize(textWidth, textHeight));
    const window = $.NSPanel.alloc.initWithContentRectStyleMaskBackingDefer(
        $.NSMakeRect(0, 0, width, textHeight + 64),
        $.NSWindowStyleMaskTitled,
        $.NSBackingStoreBuffered,
        false
    );
    window.setTitle(windowTitle);
    window.setDefaultButtonCell($());

    const scrollView = $.NSScrollView.alloc.initWithFrame(
        $.NSMakeRect(14, 50, textWidth, textHeight)
    );
    scrollView.setBorderType($.NSNoBorder);
    scrollView.setHasVerticalScroller(true);
    scrollView.setAutohidesScrollers(true);
    scrollView.setDrawsBackground(false);
    scrollView.setDocumentView(textView);
    window.contentView.addSubview(scrollView);

    const focusSink = $.NSTextView.alloc.initWithFrame($.NSMakeRect(1, 1, 1, 1));
    focusSink.setDrawsBackground(false);
    focusSink.setTextColor($.NSColor.clearColor);
    focusSink.setInsertionPointColor($.NSColor.clearColor);
    window.contentView.addSubview(focusSink);

    function addButton(buttonTitle, x, buttonWidth, code, keyEquivalent) {{
        const button = $.NSButton.alloc.initWithFrame(
            $.NSMakeRect(x, 10, buttonWidth, 32)
        );
        button.setTitle(buttonTitle);
        button.setBezelStyle($.NSBezelStyleRounded);
        button.setTarget(controller);
        button.setAction("choose:");
        button.setTag(code);
        button.setKeyEquivalent(keyEquivalent);
        window.contentView.addSubview(button);
        return button;
    }}
    const popup = $.NSPopUpButton.alloc.initWithFramePullsDown(
        $.NSMakeRect(14, 10, 306, 32),
        false
    );
    const sessionButton = addButton("Allow for session", 328, 148, 1000, "");
    addButton("Deny", 494, 100, 1002, "");
    addButton("Allow", 606, 100, 1001, "");
{popup_setup}    window.contentView.addSubview(popup);
{disable_controls}
    window.setInitialFirstResponder(focusSink);
    app.activateIgnoringOtherApps(true);
    window.center;
    window.makeKeyAndOrderFront($());
    window.makeFirstResponder(focusSink);
    const response = Number(app.runModalForWindow(window));
    window.orderOut($());
    if (response === 1000) {{
        const selectedIndex = Number(popup.indexOfSelectedItem);
        choice = "Allow for session "
            + (Number.isNaN(selectedIndex) ? "invalid" : String(selectedIndex));
    }} else if (response === 1001) {{
        choice = "Allow";
    }}
}} catch (error) {{
    throw error;
}}
choice;
"#
        );

        let mut child = Command::new("/usr/bin/osascript")
            .args(["-l", "JavaScript", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| PromptError::new("cannot start /usr/bin/osascript"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| PromptError::new("cannot open osascript stdin"))?;
        stdin
            .write_all(program.as_bytes())
            .map_err(|_| PromptError::new("cannot write osascript program"))?;
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|_| PromptError::new("cannot wait for osascript"))?;
        if !output.status.success() {
            eprintln!(
                "saferun-approval: osascript failed status={:?} stderr={:?}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(PromptError::new("osascript exited unsuccessfully"));
        }
        eprintln!(
            "saferun-approval: osascript stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        parse_prompt_choice(&output.stdout, &options)
    }
}

#[cfg(not(target_os = "macos"))]
impl Prompter for SystemPrompter {
    fn prompt(&mut self, _request: &ApprovalRequest) -> Result<PromptChoice, PromptError> {
        Err(PromptError::new(
            "interactive approval UI is unsupported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{self, Cursor};

    use super::*;
    use crate::approval::{read_response_frame, write_request_frame};
    use crate::policy::IMPLICIT_ASK_SOURCE;

    struct QueuePrompter {
        choices: VecDeque<Result<PromptChoice, PromptError>>,
        calls: usize,
    }

    impl QueuePrompter {
        fn new(choices: impl IntoIterator<Item = PromptChoice>) -> Self {
            Self {
                choices: choices.into_iter().map(Ok).collect(),
                calls: 0,
            }
        }
    }

    impl Prompter for QueuePrompter {
        fn prompt(&mut self, _request: &ApprovalRequest) -> Result<PromptChoice, PromptError> {
            self.calls += 1;
            self.choices
                .pop_front()
                .expect("fake prompt choice must be queued")
        }
    }

    struct MemoryStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        write_failure: Option<io::ErrorKind>,
        flush_failure: Option<io::ErrorKind>,
    }

    impl Read for MemoryStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if let Some(kind) = self.write_failure {
                Err(io::Error::new(kind, "injected failure"))
            } else {
                self.output.extend_from_slice(buffer);
                Ok(buffer.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            if let Some(kind) = self.flush_failure {
                Err(io::Error::new(kind, "injected failure"))
            } else {
                Ok(())
            }
        }
    }

    fn handle(
        stream: &mut MemoryStream,
        cache: &mut SessionCache,
        prompter: &mut QueuePrompter,
    ) -> Result<(), BrokerError> {
        let cache_mu = Mutex::new(std::mem::replace(
            cache,
            SessionCache::with_capacity(cache.capacity),
        ));
        let prompter_mu = Mutex::new(std::mem::replace(prompter, QueuePrompter::new([])));
        let result = handle_connection(stream, &cache_mu, &prompter_mu);
        *cache = cache_mu
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *prompter = prompter_mu
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        result
    }

    fn exchange(
        request: &ApprovalRequest,
        cache: &mut SessionCache,
        prompter: &mut QueuePrompter,
    ) -> ApprovalDecision {
        let mut input = Vec::new();
        write_request_frame(&mut input, request).expect("frame request");
        let mut stream = MemoryStream {
            input: Cursor::new(input),
            output: Vec::new(),
            write_failure: None,
            flush_failure: None,
        };
        handle(&mut stream, cache, prompter).expect("handle request");
        read_response_frame(&mut Cursor::new(stream.output))
            .expect("response")
            .decision
    }

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            version: PROTOCOL_VERSION,
            session_digest: "a".repeat(64),
            command: vec!["/usr/bin/touch".to_string(), "/tmp/file".to_string()],
            cwd: b"/tmp/work".to_vec(),
            config_path: b"/tmp/work/saferun.yaml".to_vec(),
            policy_digest: "b".repeat(64),
            ask_rule_source: "/usr/bin/touch".to_string(),
            implicit_ask: false,
            prefix_rule_source: None,
            prefix_parts_consumed: 0,
        }
    }

    #[test]
    fn executable_prefix_grant_matches_across_prefix_forms() {
        let mut cache = SessionCache::with_capacity(32);
        let mut prompter = QueuePrompter::new([
            PromptChoice::AllowSession(SessionSelection::EffectiveCommandPrefix { parts: 1 }),
            PromptChoice::Deny,
        ]);
        let mut base = request();
        base.command = vec!["python3".into(), "-c".into(), "first".into()];
        base.ask_rule_source = "python3 **".into();
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );

        let mut unprefixed = base.clone();
        unprefixed.command = vec!["python3".into(), "-c".into(), "second".into()];
        let mut wrapped = base.clone();
        wrapped.command = vec![
            "env".into(),
            "Y=2".into(),
            "python3".into(),
            "-c".into(),
            "third".into(),
        ];
        wrapped.prefix_rule_source = Some("env *".into());
        wrapped.prefix_parts_consumed = 2;
        let mut deeper = base.clone();
        deeper.command = vec![
            "env".into(),
            "A=1".into(),
            "B=2".into(),
            "python3".into(),
            "--version".into(),
        ];
        deeper.prefix_rule_source = Some("env **".into());
        deeper.prefix_parts_consumed = 3;
        for changed in [unprefixed, wrapped, deeper] {
            assert_eq!(
                exchange(&changed, &mut cache, &mut prompter),
                ApprovalDecision::Approved {
                    scope: ApprovalScope::Session
                }
            );
        }
        assert_eq!(prompter.calls, 1);

        let mut other_executable = base.clone();
        other_executable.command = vec!["ruby".into(), "-e".into(), "puts 1".into()];
        assert_eq!(
            exchange(&other_executable, &mut cache, &mut prompter),
            ApprovalDecision::Denied
        );
        assert_eq!(prompter.calls, 2);
    }

    #[test]
    fn intermediate_prefix_grant_matches_only_that_prefix() {
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter = QueuePrompter::new([
            PromptChoice::AllowSession(SessionSelection::EffectiveCommandPrefix { parts: 2 }),
            PromptChoice::Deny,
        ]);
        let mut base = request();
        base.command = vec!["python3".into(), "-c".into(), "first".into()];
        base.ask_rule_source = "python3 **".into();
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );

        let mut same_scope = base.clone();
        same_scope.command = vec!["python3".into(), "-c".into(), "second".into()];
        assert_eq!(
            exchange(&same_scope, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );
        assert_eq!(prompter.calls, 1);

        let mut narrowed = base.clone();
        narrowed.command = vec!["python3".into(), "--version".into()];
        assert_eq!(
            exchange(&narrowed, &mut cache, &mut prompter),
            ApprovalDecision::Denied
        );
        assert_eq!(prompter.calls, 2);
    }

    #[test]
    fn exact_command_grant_rejects_changed_final_argument() {
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter = QueuePrompter::new([
            PromptChoice::AllowSession(SessionSelection::EffectiveCommandPrefix { parts: 3 }),
            PromptChoice::Deny,
        ]);
        let mut base = request();
        base.command = vec!["python3".into(), "-c".into(), "first".into()];
        base.ask_rule_source = "python3 **".into();
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );
        assert_eq!(prompter.calls, 1);

        let mut changed = base;
        changed.command[2] = "second".to_string();
        assert_eq!(
            exchange(&changed, &mut cache, &mut prompter),
            ApprovalDecision::Denied
        );
        assert_eq!(prompter.calls, 2);
    }

    #[test]
    fn redirection_session_grant_defaults_to_exact_target() {
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter = QueuePrompter::new([
            PromptChoice::AllowSession(SessionSelection::EffectiveCommandPrefix { parts: 2 }),
            PromptChoice::Deny,
        ]);
        let mut base = request();
        base.command = vec![">".into(), "out.log".into()];
        base.ask_rule_source = "> **".into();
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );
        assert_eq!(prompter.calls, 1);

        let mut different_target = base;
        different_target.command[1] = "other.log".to_string();
        assert_eq!(
            exchange(&different_target, &mut cache, &mut prompter),
            ApprovalDecision::Denied
        );
        assert_eq!(prompter.calls, 2);
    }

    #[test]
    fn redirection_operator_session_scope_is_rejected() {
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter = QueuePrompter::new([PromptChoice::AllowSession(
            SessionSelection::EffectiveCommandPrefix { parts: 1 },
        )]);
        let mut base = request();
        base.command = vec![">>".into(), "out.log".into()];
        base.ask_rule_source = ">> **".into();

        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Denied
        );
        assert_eq!(prompter.calls, 1);
        assert!(cache.grants.is_empty());
    }

    #[test]
    fn matched_rule_grant_preserves_rule_reuse() {
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter = QueuePrompter::new([
            PromptChoice::AllowSession(SessionSelection::MatchedAskRule),
            PromptChoice::Deny,
        ]);
        let base = request();
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );

        let mut changed_args = base.clone();
        changed_args.command[1] = "/tmp/other-file".to_string();
        let mut wrapped = base.clone();
        wrapped.command = vec![
            "env".into(),
            "A=1".into(),
            "/usr/bin/touch".into(),
            "x".into(),
        ];
        wrapped.prefix_rule_source = Some("env *".into());
        wrapped.prefix_parts_consumed = 2;
        for changed in [changed_args, wrapped] {
            assert_eq!(
                exchange(&changed, &mut cache, &mut prompter),
                ApprovalDecision::Approved {
                    scope: ApprovalScope::Session
                }
            );
        }
        assert_eq!(prompter.calls, 1);

        let mut other_rule = base;
        other_rule.ask_rule_source = "/usr/bin/touch **".to_string();
        assert_eq!(
            exchange(&other_rule, &mut cache, &mut prompter),
            ApprovalDecision::Denied
        );
        assert_eq!(prompter.calls, 2);
    }

    #[test]
    fn all_commands_grant_approves_different_command_targets() {
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter = QueuePrompter::new([
            PromptChoice::AllowSession(SessionSelection::AllCommands),
            PromptChoice::Deny,
        ]);
        let mut base = request();
        base.command = vec!["python3".into(), "-c".into(), "first".into()];
        base.ask_rule_source = "python3 **".into();
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );

        let mut different_target = base.clone();
        different_target.command = vec!["cargo".into(), "publish".into()];
        different_target.ask_rule_source = "cargo publish **".to_string();
        assert_eq!(
            exchange(&different_target, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );
        assert_eq!(prompter.calls, 1);
    }

    #[test]
    fn matching_narrower_grant_refreshes_before_all_commands_grant() {
        let base = request();
        let all_key = SessionGrantKey::for_target(&base, SessionGrantTarget::AllCommands);
        let prefix_key = SessionGrantKey::for_target(
            &base,
            SessionGrantTarget::EffectiveCommandPrefix(vec![base.command[0].clone()]),
        );

        let mut seeded = SessionCache::with_capacity(4);
        assert!(seeded.insert(all_key.clone()));
        assert!(seeded.insert(prefix_key.clone()));
        let before_all = *seeded.grants.get(&all_key).expect("all grant");
        let before_prefix = *seeded.grants.get(&prefix_key).expect("prefix grant");

        let cache = Mutex::new(seeded);
        assert_eq!(
            lookup_session(&cache, &base),
            Some(ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            })
        );
        let cache = cache
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let after_all = *cache.grants.get(&all_key).expect("all grant");
        let after_prefix = *cache.grants.get(&prefix_key).expect("prefix grant");

        assert_eq!(after_all, before_all);
        assert!(after_prefix > before_prefix);
    }

    #[test]
    fn executable_session_grant_follows_agent_across_directories_and_equivalent_configs() {
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter = QueuePrompter::new([PromptChoice::AllowSession(
            SessionSelection::EffectiveCommandPrefix { parts: 1 },
        )]);
        let mut base = request();
        base.command = vec!["uv".into(), "run".into(), "first.py".into()];
        base.ask_rule_source = IMPLICIT_ASK_SOURCE.to_string();
        base.implicit_ask = true;
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );

        let mut changed_directory = base.clone();
        changed_directory.cwd = b"/tmp/elsewhere".to_vec();
        changed_directory.command[2] = "second.py".to_string();
        let mut equivalent_config = base.clone();
        equivalent_config.config_path = b"/tmp/equivalent.yaml".to_vec();
        equivalent_config.command[2] = "third.py".to_string();
        for changed in [changed_directory, equivalent_config] {
            assert_eq!(
                exchange(&changed, &mut cache, &mut prompter),
                ApprovalDecision::Approved {
                    scope: ApprovalScope::Session
                }
            );
        }
        assert_eq!(prompter.calls, 1);
    }

    #[test]
    fn session_grant_isolated_by_token_target_and_policy() {
        let mut cache = SessionCache::with_capacity(32);
        let mut prompter = QueuePrompter::new(
            [PromptChoice::AllowSession(SessionSelection::MatchedAskRule)]
                .into_iter()
                .chain(std::iter::repeat_with(|| PromptChoice::Deny).take(3)),
        );
        let base = request();
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );

        let mut variations = Vec::new();
        let mut token = base.clone();
        token.session_digest = "c".repeat(64);
        variations.push(token);
        let mut target = base.clone();
        target.ask_rule_source = "/usr/bin/touch **".to_string();
        variations.push(target);
        let mut policy = base.clone();
        policy.policy_digest = "d".repeat(64);
        variations.push(policy);

        for variation in variations {
            assert_eq!(
                exchange(&variation, &mut cache, &mut prompter),
                ApprovalDecision::Denied
            );
        }
        assert_eq!(prompter.calls, 4);
    }

    #[test]
    fn all_commands_grant_isolated_by_token_and_policy() {
        let mut cache = SessionCache::with_capacity(32);
        let mut prompter = QueuePrompter::new(
            [PromptChoice::AllowSession(SessionSelection::AllCommands)]
                .into_iter()
                .chain(std::iter::repeat_with(|| PromptChoice::Deny).take(2)),
        );
        let base = request();
        assert_eq!(
            exchange(&base, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );

        let mut token = base.clone();
        token.session_digest = "c".repeat(64);
        assert_eq!(
            exchange(&token, &mut cache, &mut prompter),
            ApprovalDecision::Denied
        );

        let mut policy = base;
        policy.policy_digest = "d".repeat(64);
        assert_eq!(
            exchange(&policy, &mut cache, &mut prompter),
            ApprovalDecision::Denied
        );
        assert_eq!(prompter.calls, 3);
    }

    #[test]
    fn all_commands_grant_from_implicit_ask_covers_later_implicit_and_configured_asks() {
        let mut cache = SessionCache::with_capacity(32);
        let mut prompter = QueuePrompter::new([
            PromptChoice::AllowSession(SessionSelection::AllCommands),
            PromptChoice::Deny,
        ]);
        let mut consumed_all = request();
        consumed_all.command = vec!["env".into(), "X=1".into()];
        consumed_all.ask_rule_source = IMPLICIT_ASK_SOURCE.to_string();
        consumed_all.implicit_ask = true;
        consumed_all.prefix_rule_source = Some("env *".to_string());
        consumed_all.prefix_parts_consumed = 2;
        assert_eq!(
            exchange(&consumed_all, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );

        let mut later_implicit = consumed_all.clone();
        later_implicit.command = vec!["/unknown/tool".into(), "arg".into()];
        later_implicit.prefix_rule_source = None;
        later_implicit.prefix_parts_consumed = 0;
        assert_eq!(
            exchange(&later_implicit, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );

        let mut configured_ask = consumed_all;
        configured_ask.command = vec!["/usr/bin/touch".into(), "/tmp/file".into()];
        configured_ask.ask_rule_source = "/usr/bin/touch".to_string();
        configured_ask.implicit_ask = false;
        configured_ask.prefix_rule_source = None;
        configured_ask.prefix_parts_consumed = 0;
        assert_eq!(
            exchange(&configured_ask, &mut cache, &mut prompter),
            ApprovalDecision::Approved {
                scope: ApprovalScope::Session
            }
        );
        assert_eq!(prompter.calls, 1);
    }

    #[test]
    fn invalid_session_scopes_fail_closed_without_cache_entry() {
        let oversized = request();
        let mut zero = request();
        zero.command = vec!["python3".into(), "-c".into(), "first".into()];
        let mut implicit = request();
        implicit.ask_rule_source = IMPLICIT_ASK_SOURCE.to_string();
        implicit.implicit_ask = true;

        for (fixture, selection) in [
            (zero, SessionSelection::EffectiveCommandPrefix { parts: 0 }),
            (
                oversized,
                SessionSelection::EffectiveCommandPrefix { parts: 3 },
            ),
            (implicit, SessionSelection::MatchedAskRule),
        ] {
            let mut cache = SessionCache::with_capacity(4);
            let mut prompter = QueuePrompter::new([PromptChoice::AllowSession(selection)]);
            assert_eq!(
                exchange(&fixture, &mut cache, &mut prompter),
                ApprovalDecision::Denied
            );
            assert_eq!(prompter.calls, 1);
            assert!(cache.grants.is_empty());
        }
    }

    #[test]
    fn once_and_denial_never_insert() {
        let base = request();
        let mut once_cache = SessionCache::with_capacity(4);
        let mut once_prompter =
            QueuePrompter::new([PromptChoice::AllowOnce, PromptChoice::AllowOnce]);
        for _ in 0..2 {
            assert_eq!(
                exchange(&base, &mut once_cache, &mut once_prompter),
                ApprovalDecision::Approved {
                    scope: ApprovalScope::Once
                }
            );
        }
        assert_eq!(once_prompter.calls, 2);

        let mut deny_cache = SessionCache::with_capacity(4);
        let mut deny_prompter = QueuePrompter::new([PromptChoice::Deny, PromptChoice::Deny]);
        for _ in 0..2 {
            assert_eq!(
                exchange(&base, &mut deny_cache, &mut deny_prompter),
                ApprovalDecision::Denied
            );
        }
        assert_eq!(deny_prompter.calls, 2);
    }

    #[test]
    fn response_write_failure_rolls_back_session_grant() {
        let base = request();
        let key = SessionGrantKey::for_target(
            &base,
            SessionGrantTarget::MatchedAskRule(base.ask_rule_source.clone()),
        );
        let mut input = Vec::new();
        write_request_frame(&mut input, &base).expect("frame request");
        let mut stream = MemoryStream {
            input: Cursor::new(input),
            output: Vec::new(),
            write_failure: Some(io::ErrorKind::Other),
            flush_failure: None,
        };
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter =
            QueuePrompter::new([PromptChoice::AllowSession(SessionSelection::MatchedAskRule)]);
        assert!(handle(&mut stream, &mut cache, &mut prompter).is_err());
        assert!(!cache.grants.contains_key(&key));
        assert!(cache.grants.is_empty());
    }

    #[test]
    fn flush_broken_pipe_after_write_keeps_session_grant() {
        let base = request();
        let key = SessionGrantKey::for_target(
            &base,
            SessionGrantTarget::MatchedAskRule(base.ask_rule_source.clone()),
        );
        let mut input = Vec::new();
        write_request_frame(&mut input, &base).expect("frame request");
        let mut stream = MemoryStream {
            input: Cursor::new(input),
            output: Vec::new(),
            write_failure: None,
            flush_failure: Some(io::ErrorKind::BrokenPipe),
        };
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter =
            QueuePrompter::new([PromptChoice::AllowSession(SessionSelection::MatchedAskRule)]);
        handle(&mut stream, &mut cache, &mut prompter).expect("delivered");
        assert!(cache.grants.contains_key(&key));
    }

    #[test]
    fn write_broken_pipe_after_session_keeps_grant() {
        let base = request();
        let key = SessionGrantKey::for_target(
            &base,
            SessionGrantTarget::MatchedAskRule(base.ask_rule_source.clone()),
        );
        let mut input = Vec::new();
        write_request_frame(&mut input, &base).expect("frame request");
        let mut stream = MemoryStream {
            input: Cursor::new(input),
            output: Vec::new(),
            write_failure: Some(io::ErrorKind::BrokenPipe),
            flush_failure: None,
        };
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter =
            QueuePrompter::new([PromptChoice::AllowSession(SessionSelection::MatchedAskRule)]);
        assert!(handle(&mut stream, &mut cache, &mut prompter).is_err());
        assert!(cache.grants.contains_key(&key));
    }

    #[test]
    fn all_commands_response_write_failure_rolls_back_session_grant() {
        let base = request();
        let key = SessionGrantKey::for_target(&base, SessionGrantTarget::AllCommands);
        let mut input = Vec::new();
        write_request_frame(&mut input, &base).expect("frame request");
        let mut stream = MemoryStream {
            input: Cursor::new(input),
            output: Vec::new(),
            write_failure: Some(io::ErrorKind::Other),
            flush_failure: None,
        };
        let mut cache = SessionCache::with_capacity(4);
        let mut prompter =
            QueuePrompter::new([PromptChoice::AllowSession(SessionSelection::AllCommands)]);
        assert!(handle(&mut stream, &mut cache, &mut prompter).is_err());
        assert!(!cache.grants.contains_key(&key));
        assert!(cache.grants.is_empty());
    }

    #[test]
    fn write_peer_closed_after_all_commands_session_keeps_grant() {
        for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::ConnectionReset] {
            let base = request();
            let key = SessionGrantKey::for_target(&base, SessionGrantTarget::AllCommands);
            let mut input = Vec::new();
            write_request_frame(&mut input, &base).expect("frame request");
            let mut stream = MemoryStream {
                input: Cursor::new(input),
                output: Vec::new(),
                write_failure: Some(kind),
                flush_failure: None,
            };
            let mut cache = SessionCache::with_capacity(4);
            let mut prompter =
                QueuePrompter::new([PromptChoice::AllowSession(SessionSelection::AllCommands)]);
            assert!(handle(&mut stream, &mut cache, &mut prompter).is_err());
            assert!(cache.grants.contains_key(&key));
        }
    }

    #[test]
    fn flush_peer_closed_after_all_commands_session_keeps_grant() {
        for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::ConnectionReset] {
            let base = request();
            let key = SessionGrantKey::for_target(&base, SessionGrantTarget::AllCommands);
            let mut input = Vec::new();
            write_request_frame(&mut input, &base).expect("frame request");
            let mut stream = MemoryStream {
                input: Cursor::new(input),
                output: Vec::new(),
                write_failure: None,
                flush_failure: Some(kind),
            };
            let mut cache = SessionCache::with_capacity(4);
            let mut prompter =
                QueuePrompter::new([PromptChoice::AllowSession(SessionSelection::AllCommands)]);
            handle(&mut stream, &mut cache, &mut prompter).expect("delivered");
            assert!(cache.grants.contains_key(&key));
        }
    }

    #[test]
    fn generation_overflow_clears_safely() {
        let base = request();
        let key = SessionGrantKey::for_target(
            &base,
            SessionGrantTarget::EffectiveCommandPrefix(base.command.clone()),
        );
        let mut cache = SessionCache::with_capacity(4);
        assert!(cache.insert(key.clone()));
        cache.generation = u64::MAX;
        assert!(!cache.lookup(&key));
        assert!(cache.grants.is_empty());
        assert_eq!(cache.generation, 1);
    }

    #[test]
    fn capacity_eviction_only_reprompts_evicted_grant() {
        let mut cache = SessionCache::with_capacity(2);
        let mut prompter = QueuePrompter::new(
            std::iter::repeat_with(|| PromptChoice::AllowSession(SessionSelection::MatchedAskRule))
                .take(4),
        );
        let first = request();
        let mut second = first.clone();
        second.session_digest = "c".repeat(64);
        let mut third = first.clone();
        third.session_digest = "d".repeat(64);

        exchange(&first, &mut cache, &mut prompter);
        exchange(&second, &mut cache, &mut prompter);
        exchange(&first, &mut cache, &mut prompter);
        assert_eq!(prompter.calls, 2);
        exchange(&third, &mut cache, &mut prompter);
        exchange(&second, &mut cache, &mut prompter);
        assert_eq!(prompter.calls, 4);
    }

    #[test]
    fn renderer_is_printable_ascii_and_byte_reversible() {
        let bytes = [b'a', b'\n', 0x1b, 0x7f, b'"', b'\\', 0xe2, 0x80, 0xae, 0xff];
        assert_eq!(
            render_authorization_bytes(&bytes),
            "\"a\\x0A\\x1B\\x7F\\\"\\\\\\xE2\\x80\\xAE\\xFF\""
        );

        let mut unsafe_request = request();
        unsafe_request.command.push("line\n\u{202e}".to_string());
        unsafe_request.cwd = bytes.to_vec();
        let prompt = build_prompt(&unsafe_request);
        assert!(prompt
            .bytes()
            .all(|byte| byte == b'\n' || (0x20..=0x7e).contains(&byte)));
        let title = build_prompt_title(&unsafe_request);
        assert!(title.bytes().all(|byte| (0x20..=0x7e).contains(&byte)));
        assert!(title.contains(&render_authorization_bytes_unquoted(&bytes)));
        assert!(!prompt.contains(&unsafe_request.session_digest));
        assert!(prompt.contains(&unsafe_request.session_digest[..8]));
        assert!(!title.contains(&unsafe_request.session_digest));
    }

    #[test]
    fn prompt_layout_is_concise() {
        let mut request = request();
        request.session_digest = format!("be2f1f14{}", "a".repeat(56));
        request.command = vec![
            "python3".to_string(),
            "-c".to_string(),
            "from datetime import datetime; print(datetime.now())".to_string(),
        ];
        request.ask_rule_source = "python3 **".to_string();
        request.cwd = b"/Users/chris/src/saferun".to_vec();

        assert_eq!(
            build_prompt(&request),
            concat!(
                "Command 1: python3\n",
                "Command 2: -c\n",
                "Command 3: from datetime import datetime; print(datetime.now())\n",
                "\n",
                "Ask rule: python3 **\n",
                "No prefix rule\n",
                "Session: be2f1f14"
            )
        );
        assert_eq!(
            build_prompt_title(&request),
            "saferun in /Users/chris/src/saferun"
        );

        request.command = vec![
            "env".to_string(),
            "X=1".to_string(),
            "python3".to_string(),
            "-c".to_string(),
            "print('x')".to_string(),
        ];
        request.prefix_rule_source = Some("env *".to_string());
        request.prefix_parts_consumed = 2;
        let prompt = build_prompt(&request);
        assert!(prompt.starts_with(concat!(
            "Prefix 1: env\n",
            "Prefix 2: X=1\n",
            "Command 1: python3\n",
            "Command 2: -c\n",
            "Command 3: print('x')\n",
        )));
        assert!(prompt.contains("Prefix rule: env * (2 parts consumed)\n"));

        request.ask_rule_source = IMPLICIT_ASK_SOURCE.to_string();
        request.implicit_ask = true;
        let prompt = build_prompt(&request);
        assert!(prompt.contains("\nNo matched rule\n"));
        assert!(!prompt.contains("Ask rule:"));
    }

    #[test]
    fn session_scope_options_cover_every_effective_prefix_boundary() {
        let direct = request();
        assert_eq!(
            session_scope_options(&direct),
            vec![
                SessionScopeOption {
                    title: "/usr/bin…".to_string(),
                    selection: SessionSelection::EffectiveCommandPrefix { parts: 1 },
                },
                SessionScopeOption {
                    title: "/usr/bin… /tmp/fil…".to_string(),
                    selection: SessionSelection::EffectiveCommandPrefix { parts: 2 },
                },
                SessionScopeOption {
                    title: "Matched ask rule".to_string(),
                    selection: SessionSelection::MatchedAskRule,
                },
                SessionScopeOption {
                    title: ALL_COMMANDS_SESSION_TITLE.to_string(),
                    selection: SessionSelection::AllCommands,
                },
            ]
        );

        let mut one_part = request();
        one_part.command = vec!["python3".to_string()];
        assert_eq!(
            session_scope_options(&one_part),
            vec![
                SessionScopeOption {
                    title: "python3".to_string(),
                    selection: SessionSelection::EffectiveCommandPrefix { parts: 1 },
                },
                SessionScopeOption {
                    title: "Matched ask rule".to_string(),
                    selection: SessionSelection::MatchedAskRule,
                },
                SessionScopeOption {
                    title: ALL_COMMANDS_SESSION_TITLE.to_string(),
                    selection: SessionSelection::AllCommands,
                },
            ]
        );

        let mut wrapped = request();
        wrapped.command = vec![
            "env".to_string(),
            "X=1".to_string(),
            "python3".to_string(),
            "-c".to_string(),
            "x".to_string(),
        ];
        wrapped.prefix_rule_source = Some("env *".to_string());
        wrapped.prefix_parts_consumed = 2;
        let wrapped_options = session_scope_options(&wrapped);
        let wrapped_titles: Vec<&str> = wrapped_options
            .iter()
            .map(|option| option.title.as_str())
            .collect();
        assert_eq!(
            wrapped_titles,
            [
                "python3",
                "python3 -c",
                "python3 -c x",
                "Matched ask rule",
                ALL_COMMANDS_SESSION_TITLE,
            ]
        );

        let mut consumed_all = request();
        consumed_all.command = vec!["env".to_string(), "X=1".to_string()];
        consumed_all.prefix_rule_source = Some("env *".to_string());
        consumed_all.prefix_parts_consumed = 2;
        assert_eq!(
            session_scope_options(&consumed_all),
            vec![
                SessionScopeOption {
                    title: "Matched ask rule".to_string(),
                    selection: SessionSelection::MatchedAskRule,
                },
                SessionScopeOption {
                    title: ALL_COMMANDS_SESSION_TITLE.to_string(),
                    selection: SessionSelection::AllCommands,
                },
            ]
        );

        consumed_all.ask_rule_source = IMPLICIT_ASK_SOURCE.to_string();
        consumed_all.implicit_ask = true;
        assert_eq!(
            session_scope_options(&consumed_all),
            vec![SessionScopeOption {
                title: ALL_COMMANDS_SESSION_TITLE.to_string(),
                selection: SessionSelection::AllCommands,
            }]
        );

        let mut redirection = request();
        redirection.command = vec![">".to_string(), "out.log".to_string()];
        redirection.ask_rule_source = "> **".to_string();
        assert_eq!(
            session_scope_options(&redirection),
            vec![
                SessionScopeOption {
                    title: "> out.log".to_string(),
                    selection: SessionSelection::EffectiveCommandPrefix { parts: 2 },
                },
                SessionScopeOption {
                    title: "Matched ask rule".to_string(),
                    selection: SessionSelection::MatchedAskRule,
                },
                SessionScopeOption {
                    title: ALL_COMMANDS_SESSION_TITLE.to_string(),
                    selection: SessionSelection::AllCommands,
                },
            ]
        );
    }

    #[test]
    fn shell_payload_stays_one_opaque_option() {
        let mut shell = request();
        shell.command = vec![
            "/bin/zsh".to_string(),
            "-lc".to_string(),
            "cargo test".to_string(),
        ];
        shell.prefix_rule_source = Some("/bin/zsh -lc".to_string());
        shell.prefix_parts_consumed = 2;
        shell.ask_rule_source = "cargo test **".to_string();

        let options = session_scope_options(&shell);
        assert_eq!(
            options,
            vec![
                SessionScopeOption {
                    title: "cargo te…".to_string(),
                    selection: SessionSelection::EffectiveCommandPrefix { parts: 1 },
                },
                SessionScopeOption {
                    title: "Matched ask rule".to_string(),
                    selection: SessionSelection::MatchedAskRule,
                },
                SessionScopeOption {
                    title: ALL_COMMANDS_SESSION_TITLE.to_string(),
                    selection: SessionSelection::AllCommands,
                },
            ]
        );
        assert_eq!(options.len(), 3);
    }

    #[test]
    fn prompt_choice_parsing_is_strict() {
        let options = session_scope_options(&request());
        assert_eq!(
            parse_prompt_choice(b"Deny\n", &options),
            Ok(PromptChoice::Deny)
        );
        assert_eq!(
            parse_prompt_choice(b"Allow", &options),
            Ok(PromptChoice::AllowOnce)
        );
        assert_eq!(
            parse_prompt_choice(b"Allow for session 0\n", &options),
            Ok(PromptChoice::AllowSession(
                SessionSelection::EffectiveCommandPrefix { parts: 1 }
            ))
        );
        assert_eq!(
            parse_prompt_choice(b"Allow for session 0\r\n", &options),
            Ok(PromptChoice::AllowSession(
                SessionSelection::EffectiveCommandPrefix { parts: 1 }
            ))
        );
        assert_eq!(
            parse_prompt_choice(b"\"Allow for session 0\"\n", &options),
            Ok(PromptChoice::AllowSession(
                SessionSelection::EffectiveCommandPrefix { parts: 1 }
            ))
        );
        assert_eq!(
            parse_prompt_choice(b"Allow for session 2", &options),
            Ok(PromptChoice::AllowSession(SessionSelection::MatchedAskRule))
        );
        assert_eq!(
            parse_prompt_choice(b"Allow for session 3", &options),
            Ok(PromptChoice::AllowSession(SessionSelection::AllCommands))
        );

        for bad in [
            b"Allow for session\n".as_slice(),
            b"Allow for session \n".as_slice(),
            b"Allow for session 4\n".as_slice(),
            b"Allow for session 0x1\n".as_slice(),
            b"Allow for session -1\n".as_slice(),
        ] {
            assert_eq!(
                parse_prompt_choice(bad, &options).unwrap_err().to_string(),
                "osascript returned an invalid session scope"
            );
        }
        assert!(parse_prompt_choice(b"Allow for session 0\n", &[]).is_err());
        assert_eq!(
            parse_prompt_choice(b"garbage\n", &options)
                .unwrap_err()
                .to_string(),
            "osascript returned an invalid choice"
        );
    }
}
