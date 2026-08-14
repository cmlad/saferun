use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::policy::IMPLICIT_ASK_SOURCE;

pub const PROTOCOL_VERSION: u8 = 3;
pub const MAX_FRAME_LEN: usize = 65_536;
pub const SESSION_TOKEN_FILE_ENV: &str = "SAFERUN_TOKEN_FILE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    Once,
    Session,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Denied,
    Approved { scope: ApprovalScope },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub version: u8,
    pub session_digest: String,
    pub command: Vec<String>,
    pub cwd: Vec<u8>,
    pub config_path: Vec<u8>,
    pub policy_digest: String,
    pub ask_rule_source: String,
    pub implicit_ask: bool,
    pub prefix_rule_source: Option<String>,
    pub prefix_parts_consumed: u32,
}

impl ApprovalRequest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        validate_digest("session", &self.session_digest)?;
        validate_digest("policy", &self.policy_digest)?;
        if self.command.is_empty() {
            return Err(ProtocolError::InvalidMessage(
                "command must not be empty".to_string(),
            ));
        }
        if self.cwd.is_empty() || self.config_path.is_empty() {
            return Err(ProtocolError::InvalidMessage(
                "cwd and config path must not be empty".to_string(),
            ));
        }
        if self.ask_rule_source.is_empty() {
            return Err(ProtocolError::InvalidMessage(
                "ask rule source must not be empty".to_string(),
            ));
        }
        if self
            .prefix_rule_source
            .as_ref()
            .is_some_and(String::is_empty)
        {
            return Err(ProtocolError::InvalidMessage(
                "prefix rule source must not be empty".to_string(),
            ));
        }
        if self.implicit_ask && self.ask_rule_source != IMPLICIT_ASK_SOURCE {
            return Err(ProtocolError::InvalidMessage(
                "implicit ask must use the reserved source".to_string(),
            ));
        }
        if self.prefix_rule_source.is_none() && self.prefix_parts_consumed != 0 {
            return Err(ProtocolError::InvalidMessage(
                "prefix count requires a prefix rule".to_string(),
            ));
        }
        let consumed = usize::try_from(self.prefix_parts_consumed).map_err(|_| {
            ProtocolError::InvalidMessage("prefix count is not representable".to_string())
        })?;
        if consumed > self.command.len() {
            return Err(ProtocolError::InvalidMessage(
                "prefix count exceeds command length".to_string(),
            ));
        }

        let mut decoded_len = self.session_digest.len();
        for part in &self.command {
            decoded_len = decoded_len
                .checked_add(part.len())
                .ok_or(ProtocolError::FrameTooLarge)?;
        }
        for len in [
            self.cwd.len(),
            self.config_path.len(),
            self.policy_digest.len(),
            self.ask_rule_source.len(),
            self.prefix_rule_source.as_ref().map_or(0, String::len),
        ] {
            decoded_len = decoded_len
                .checked_add(len)
                .ok_or(ProtocolError::FrameTooLarge)?;
        }
        if decoded_len > MAX_FRAME_LEN {
            return Err(ProtocolError::FrameTooLarge);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResponse {
    pub version: u8,
    pub decision: ApprovalDecision,
}

impl ApprovalResponse {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    FrameTooLarge,
    TruncatedFrame,
    InvalidJson(serde_json::Error),
    UnsupportedVersion(u8),
    InvalidMessage(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::FrameTooLarge => {
                write!(formatter, "approval frame exceeds {MAX_FRAME_LEN} bytes")
            }
            Self::TruncatedFrame => formatter.write_str("truncated approval frame"),
            Self::InvalidJson(error) => write!(formatter, "invalid approval JSON: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported approval protocol version {version}")
            }
            Self::InvalidMessage(message) => {
                write!(formatter, "invalid approval message: {message}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidJson(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn validate_digest(kind: &str, value: &str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ProtocolError::InvalidMessage(format!(
            "{kind} digest must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn write_frame<T: Serialize, W: Write>(writer: &mut W, value: &T) -> Result<(), ProtocolError> {
    let body = serde_json::to_vec(value).map_err(ProtocolError::InvalidJson)?;
    if body.len() > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge);
    }
    let length = u32::try_from(body.len()).map_err(|_| ProtocolError::FrameTooLarge)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&body)?;
    match writer.flush() {
        Ok(()) => Ok(()),
        // Peer closed after reading the delivered frame.
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn read_frame<T: DeserializeOwned, R: Read>(reader: &mut R) -> Result<T, ProtocolError> {
    let mut length_bytes = [0_u8; 4];
    read_exact_frame(reader, &mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge);
    }
    let mut body = vec![0_u8; length];
    read_exact_frame(reader, &mut body)?;
    serde_json::from_slice(&body).map_err(ProtocolError::InvalidJson)
}

fn read_exact_frame<R: Read>(reader: &mut R, destination: &mut [u8]) -> Result<(), ProtocolError> {
    match reader.read_exact(destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(ProtocolError::TruncatedFrame)
        }
        Err(error) => Err(ProtocolError::Io(error)),
    }
}

pub fn write_request_frame<W: Write>(
    writer: &mut W,
    request: &ApprovalRequest,
) -> Result<(), ProtocolError> {
    request.validate()?;
    write_frame(writer, request)
}

pub fn read_request_frame<R: Read>(reader: &mut R) -> Result<ApprovalRequest, ProtocolError> {
    let request: ApprovalRequest = read_frame(reader)?;
    request.validate()?;
    Ok(request)
}

pub fn write_response_frame<W: Write>(
    writer: &mut W,
    response: &ApprovalResponse,
) -> Result<(), ProtocolError> {
    response.validate()?;
    write_frame(writer, response)
}

pub fn read_response_frame<R: Read>(reader: &mut R) -> Result<ApprovalResponse, ProtocolError> {
    let response: ApprovalResponse = read_frame(reader)?;
    response.validate()?;
    Ok(response)
}

#[derive(Debug)]
pub enum TokenError {
    Read(io::Error),
    TooLong,
    InvalidLength,
    InvalidHex,
    Security(String),
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "cannot read session token: {error}"),
            Self::TooLong => formatter.write_str("session token is too long"),
            Self::InvalidLength => {
                formatter.write_str("session token must contain 64 hexadecimal characters")
            }
            Self::InvalidHex => {
                formatter.write_str("session token contains a non-hexadecimal character")
            }
            Self::Security(message) => write!(formatter, "unsafe session token file: {message}"),
        }
    }
}

impl std::error::Error for TokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            _ => None,
        }
    }
}

fn decode_session_token<R: Read>(mut reader: R) -> Result<[u8; 32], TokenError> {
    let mut input = Vec::with_capacity(66);
    let mut chunk = [0_u8; 66];
    loop {
        let remaining = 66 - input.len();
        if remaining == 0 {
            return Err(TokenError::TooLong);
        }
        match reader.read(&mut chunk[..remaining]) {
            Ok(0) => break,
            Ok(read) => input.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(TokenError::Read(error)),
        }
    }

    let hex = match input.as_slice() {
        bytes if bytes.len() == 64 => bytes,
        bytes if bytes.len() == 65 && bytes[64] == b'\n' => &bytes[..64],
        _ => return Err(TokenError::InvalidLength),
    };

    let mut token = [0_u8; 32];
    for (index, pair) in hex.chunks_exact(2).enumerate() {
        let high = decode_hex(pair[0]).ok_or(TokenError::InvalidHex)?;
        let low = decode_hex(pair[1]).ok_or(TokenError::InvalidHex)?;
        token[index] = (high << 4) | low;
    }
    Ok(token)
}

/// Securely open and read a reusable session-token file created by saferun.
pub fn read_session_token_file(path: &Path) -> Result<[u8; 32], TokenError> {
    let runtime_dir = production_runtime_dir();
    if path.parent() != Some(runtime_dir.as_path()) {
        return Err(TokenError::Security(format!(
            "{} is outside {}",
            path.display(),
            runtime_dir.display()
        )));
    }
    validate_secure_directory(&runtime_dir)
        .map_err(|error| TokenError::Security(error.to_string()))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(TokenError::Read)?;
    let metadata = file.metadata().map_err(TokenError::Read)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(TokenError::Security(format!(
            "{} must be an owned regular file with mode 0600",
            path.display()
        )));
    }
    decode_session_token(file)
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug)]
pub enum SessionTokenFileError {
    Runtime(EndpointError),
    Io(io::Error),
}

impl fmt::Display for SessionTokenFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "session token file I/O error: {error}"),
        }
    }
}

impl std::error::Error for SessionTokenFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<EndpointError> for SessionTokenFileError {
    fn from(error: EndpointError) -> Self {
        Self::Runtime(error)
    }
}

impl From<io::Error> for SessionTokenFileError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Create a new private token file and return its non-secret path.
pub fn create_session_token_file() -> Result<PathBuf, SessionTokenFileError> {
    let runtime_dir = production_runtime_dir();
    ensure_runtime_directory(&runtime_dir)?;
    let mut random = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/urandom")?;

    loop {
        let mut bytes = [0_u8; 48];
        random.read_exact(&mut bytes)?;
        let path = runtime_dir.join(format!("session-{}.token", lowercase_hex(&bytes[32..])));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };

        let result = (|| -> io::Result<()> {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            let metadata = file.metadata()?;
            if !metadata.file_type().is_file()
                || metadata.uid() != effective_uid()
                || metadata.mode() & 0o777 != 0o600
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "new session token is not an owned regular file with mode 0600",
                ));
            }
            file.write_all(lowercase_hex(&bytes[..32]).as_bytes())?;
            file.write_all(b"\n")?;
            file.flush()
        })();
        if let Err(error) = result {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(error.into());
        }
        return Ok(path);
    }
}

pub fn session_digest(token: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"saferun session v1\0");
    hasher.update(token);
    lowercase_hex(&hasher.finalize())
}

pub fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn production_runtime_dir() -> PathBuf {
    PathBuf::from(format!("/tmp/saferun-{}", effective_uid()))
}

pub fn production_socket_path() -> PathBuf {
    production_runtime_dir().join("approval.sock")
}

fn production_lock_path() -> PathBuf {
    production_runtime_dir().join("broker.lock")
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and has no failure mode.
    unsafe { libc::geteuid() }
}

#[derive(Debug)]
pub enum ConnectError {
    Io(io::Error),
    Timeout,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "cannot connect to approval socket: {error}"),
            Self::Timeout => formatter.write_str("approval socket connection timed out"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Timeout => None,
        }
    }
}

fn connect_with_timeout_using<T, F>(timeout: Duration, connector: F) -> Result<T, ConnectError>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    let (sender, receiver) = sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(connector());
    });
    match receiver.recv_timeout(timeout) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(ConnectError::Io(error)),
        Err(RecvTimeoutError::Timeout) => Err(ConnectError::Timeout),
        Err(RecvTimeoutError::Disconnected) => Err(ConnectError::Io(io::Error::new(
            io::ErrorKind::Other,
            "approval connector stopped without a result",
        ))),
    }
}

pub fn connect_with_timeout(path: &Path, timeout: Duration) -> Result<UnixStream, ConnectError> {
    let path = path.to_path_buf();
    connect_with_timeout_using(timeout, move || UnixStream::connect(path))
}

#[derive(Debug)]
pub enum EndpointError {
    AlreadyRunning,
    Security(String),
    Io(io::Error),
    Connect(ConnectError),
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => formatter.write_str("already running"),
            Self::Security(message) => write!(formatter, "unsafe approval endpoint: {message}"),
            Self::Io(error) => write!(formatter, "approval endpoint I/O error: {error}"),
            Self::Connect(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for EndpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Connect(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for EndpointError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn ensure_runtime_directory(path: &Path) -> Result<(), EndpointError> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(EndpointError::Io(error)),
    }
    validate_secure_directory(path)
}

fn validate_secure_directory(path: &Path) -> Result<(), EndpointError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(EndpointError::Security(format!(
            "{} is not a real directory",
            path.display()
        )));
    }
    if metadata.uid() != effective_uid() {
        return Err(EndpointError::Security(format!(
            "{} is not owned by effective uid {}",
            path.display(),
            effective_uid()
        )));
    }
    if metadata.mode() & 0o777 != 0o700 {
        return Err(EndpointError::Security(format!(
            "{} must have mode 0700",
            path.display()
        )));
    }
    Ok(())
}

fn open_broker_lock(path: &Path) -> Result<File, EndpointError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(EndpointError::Security(format!(
            "{} must be an owned regular file with mode 0600",
            path.display()
        )));
    }

    // SAFETY: `file` is a valid open descriptor held for the returned value's lifetime.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err(EndpointError::AlreadyRunning);
        }
        return Err(EndpointError::Io(error));
    }
    Ok(file)
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

fn validate_socket(path: &Path) -> Result<SocketIdentity, EndpointError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(EndpointError::Security(format!(
            "{} is not a Unix socket",
            path.display()
        )));
    }
    if metadata.uid() != effective_uid() {
        return Err(EndpointError::Security(format!(
            "{} is not owned by effective uid {}",
            path.display(),
            effective_uid()
        )));
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(EndpointError::Security(format!(
            "{} must have mode 0600",
            path.display()
        )));
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn remove_same_socket(path: &Path, identity: SocketIdentity) -> Result<(), EndpointError> {
    let current = validate_socket(path)?;
    if current.device != identity.device || current.inode != identity.inode {
        return Err(EndpointError::Security(format!(
            "{} changed while it was being inspected",
            path.display()
        )));
    }
    fs::remove_file(path)?;
    Ok(())
}

pub struct BrokerEndpoint {
    listener: UnixListener,
    _lock: File,
    socket_path: PathBuf,
    socket_identity: SocketIdentity,
}

impl BrokerEndpoint {
    pub fn bind() -> Result<Self, EndpointError> {
        let runtime_dir = production_runtime_dir();
        ensure_runtime_directory(&runtime_dir)?;
        let lock = open_broker_lock(&production_lock_path())?;
        let socket_path = production_socket_path();

        match fs::symlink_metadata(&socket_path) {
            Ok(_) => {
                let identity = validate_socket(&socket_path)?;
                match connect_with_timeout(&socket_path, CONNECT_TIMEOUT) {
                    Ok(_) | Err(ConnectError::Timeout) => {
                        return Err(EndpointError::AlreadyRunning);
                    }
                    Err(ConnectError::Io(error))
                        if error.raw_os_error() == Some(libc::ECONNREFUSED) =>
                    {
                        remove_same_socket(&socket_path, identity)?;
                    }
                    Err(error) => return Err(EndpointError::Connect(error)),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(EndpointError::Io(error)),
        }

        let listener = UnixListener::bind(&socket_path)?;
        if let Err(error) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&socket_path);
            return Err(EndpointError::Io(error));
        }
        let socket_identity = validate_socket(&socket_path)?;
        Ok(Self {
            listener,
            _lock: lock,
            socket_path,
            socket_identity,
        })
    }

    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }

    pub fn path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for BrokerEndpoint {
    fn drop(&mut self) {
        if let Ok(current) = validate_socket(&self.socket_path) {
            if current.device == self.socket_identity.device
                && current.inode == self.socket_identity.inode
            {
                let _ = fs::remove_file(&self.socket_path);
            }
        }
    }
}

#[derive(Debug)]
pub enum ApprovalError {
    Endpoint(EndpointError),
    Connect(ConnectError),
    Protocol(ProtocolError),
    Io(io::Error),
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint(error) => write!(formatter, "{error}"),
            Self::Connect(error) => write!(formatter, "{error}"),
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "approval service I/O error: {error}"),
        }
    }
}

impl std::error::Error for ApprovalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Endpoint(error) => Some(error),
            Self::Connect(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

pub trait ApprovalClient {
    fn request(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalError>;
}

#[derive(Debug, Clone)]
pub struct SocketApprovalClient {
    path: PathBuf,
    connect_timeout: Duration,
}

impl SocketApprovalClient {
    pub fn new() -> Self {
        Self {
            path: production_socket_path(),
            connect_timeout: CONNECT_TIMEOUT,
        }
    }

    /// Construct a client for an injected test/library socket path.
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            connect_timeout: CONNECT_TIMEOUT,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Default for SocketApprovalClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalClient for SocketApprovalClient {
    fn request(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApprovalError> {
        let parent = self.path.parent().ok_or_else(|| {
            ApprovalError::Endpoint(EndpointError::Security(
                "approval socket has no parent directory".to_string(),
            ))
        })?;
        validate_secure_directory(parent).map_err(ApprovalError::Endpoint)?;
        validate_socket(&self.path).map_err(ApprovalError::Endpoint)?;

        let mut stream = connect_with_timeout(&self.path, self.connect_timeout)
            .map_err(ApprovalError::Connect)?;
        stream
            .set_write_timeout(Some(CONNECT_TIMEOUT))
            .map_err(ApprovalError::Io)?;
        write_request_frame(&mut stream, request).map_err(ApprovalError::Protocol)?;
        let response = read_response_frame(&mut stream).map_err(ApprovalError::Protocol)?;
        Ok(response.decision)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            version: PROTOCOL_VERSION,
            session_digest: "a".repeat(64),
            command: vec!["/bin/echo".to_string(), "hello".to_string()],
            cwd: b"/tmp/work".to_vec(),
            config_path: b"/tmp/work/saferun.yaml".to_vec(),
            policy_digest: "b".repeat(64),
            ask_rule_source: "/bin/echo".to_string(),
            implicit_ask: false,
            prefix_rule_source: None,
            prefix_parts_consumed: 0,
        }
    }

    #[test]
    fn token_decoder_accepts_hex_with_optional_lf() {
        let plain = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut with_lf = plain.to_vec();
        with_lf.push(b'\n');

        let plain_token = decode_session_token(Cursor::new(plain)).expect("plain token");
        assert_eq!(
            decode_session_token(Cursor::new(with_lf)).expect("LF token"),
            plain_token
        );
    }

    #[test]
    fn generated_token_file_is_securely_readable() {
        let path = create_session_token_file().expect("create token");
        let token = read_session_token_file(&path).expect("read token");
        assert_ne!(token, [0; 32]);
        fs::remove_file(path).expect("remove token");
    }

    #[test]
    fn invalid_tokens_fail_without_echoing_input() {
        let cases: &[&[u8]] = &[
            b"short",
            b"g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefxx",
        ];
        for input in cases {
            let rendered = decode_session_token(Cursor::new(input))
                .unwrap_err()
                .to_string();
            assert!(!rendered.contains(&String::from_utf8_lossy(input).to_string()));
        }
    }

    #[test]
    fn request_and_response_round_trip_through_unix_pair() {
        let (mut left, mut right) = UnixStream::pair().expect("pair");
        let sent = request();
        write_request_frame(&mut left, &sent).expect("write request");
        assert_eq!(read_request_frame(&mut right).expect("read request"), sent);

        let response = ApprovalResponse {
            version: PROTOCOL_VERSION,
            decision: ApprovalDecision::Approved {
                scope: ApprovalScope::Session,
            },
        };
        write_response_frame(&mut right, &response).expect("write response");
        assert_eq!(
            read_response_frame(&mut left).expect("read response"),
            response
        );
    }

    #[test]
    fn oversized_and_truncated_frames_fail() {
        let mut oversized = Cursor::new(((MAX_FRAME_LEN as u32) + 1).to_be_bytes());
        assert!(matches!(
            read_request_frame(&mut oversized),
            Err(ProtocolError::FrameTooLarge)
        ));

        let mut truncated = Cursor::new([0, 0, 0, 8, b'{', b'}']);
        assert!(matches!(
            read_request_frame(&mut truncated),
            Err(ProtocolError::TruncatedFrame)
        ));

        let mut too_large = request();
        too_large.command.push("x".repeat(MAX_FRAME_LEN));
        assert!(matches!(
            write_request_frame(&mut Vec::new(), &too_large),
            Err(ProtocolError::FrameTooLarge)
        ));
    }

    #[test]
    fn malformed_requests_fail_validation() {
        let invalid_json_values = [
            serde_json::json!({
                "version": PROTOCOL_VERSION + 1,
                "session_digest": "a".repeat(64),
                "command": ["/bin/true"],
                "cwd": [47],
                "config_path": [47, 99],
                "policy_digest": "b".repeat(64),
                "ask_rule_source": "/bin/true",
                "implicit_ask": false,
                "prefix_rule_source": null,
                "prefix_parts_consumed": 0
            }),
            serde_json::json!({
                "version": PROTOCOL_VERSION,
                "session_digest": "A".repeat(64),
                "command": ["/bin/true"],
                "cwd": [47],
                "config_path": [47, 99],
                "policy_digest": "b".repeat(64),
                "ask_rule_source": "/bin/true",
                "implicit_ask": false,
                "prefix_rule_source": null,
                "prefix_parts_consumed": 0
            }),
            serde_json::json!({
                "version": PROTOCOL_VERSION,
                "session_digest": "a".repeat(64),
                "command": [],
                "cwd": [47],
                "config_path": [47, 99],
                "policy_digest": "b".repeat(64),
                "ask_rule_source": "/bin/true",
                "implicit_ask": false,
                "prefix_rule_source": null,
                "prefix_parts_consumed": 0
            }),
        ];
        for value in invalid_json_values {
            let body = serde_json::to_vec(&value).unwrap();
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&body);
            assert!(read_request_frame(&mut Cursor::new(frame)).is_err());
        }

        let mut unknown = serde_json::to_value(request()).unwrap();
        unknown["unknown"] = serde_json::json!(true);
        let body = serde_json::to_vec(&unknown).unwrap();
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        assert!(matches!(
            read_request_frame(&mut Cursor::new(frame)),
            Err(ProtocolError::InvalidJson(_))
        ));

        let mut overflowing = serde_json::to_value(request()).unwrap();
        overflowing["prefix_rule_source"] = serde_json::json!("prefix");
        overflowing["prefix_parts_consumed"] = serde_json::json!(u64::from(u32::MAX) + 1);
        let body = serde_json::to_vec(&overflowing).unwrap();
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        assert!(matches!(
            read_request_frame(&mut Cursor::new(frame)),
            Err(ProtocolError::InvalidJson(_))
        ));
    }

    #[test]
    fn implicit_prefixed_ask_validates_and_round_trips() {
        let mut implicit = request();
        implicit.ask_rule_source = IMPLICIT_ASK_SOURCE.to_string();
        implicit.implicit_ask = true;
        implicit.prefix_rule_source = Some("env *".to_string());
        implicit.prefix_parts_consumed = 2;
        implicit.command = vec![
            "env".to_string(),
            "X=1".to_string(),
            "python3".to_string(),
            "-c".to_string(),
            "x".to_string(),
        ];

        let mut framed = Vec::new();
        write_request_frame(&mut framed, &implicit).expect("write implicit prefixed ask");
        assert_eq!(
            read_request_frame(&mut Cursor::new(framed)).expect("round-trip"),
            implicit
        );

        let mut unsupported = implicit.clone();
        unsupported.version = PROTOCOL_VERSION - 1;
        assert!(matches!(
            unsupported.validate(),
            Err(ProtocolError::UnsupportedVersion(version)) if version == PROTOCOL_VERSION - 1
        ));

        let mut inconsistent = implicit.clone();
        inconsistent.prefix_rule_source = None;
        assert!(matches!(
            inconsistent.validate(),
            Err(ProtocolError::InvalidMessage(message)) if message == "prefix count requires a prefix rule"
        ));

        let mut oversized = implicit.clone();
        oversized.prefix_parts_consumed = u32::try_from(oversized.command.len() + 1).expect("fit");
        assert!(matches!(
            oversized.validate(),
            Err(ProtocolError::InvalidMessage(message)) if message == "prefix count exceeds command length"
        ));

        let mut wrong_source = implicit.clone();
        wrong_source.ask_rule_source = "python3".to_string();
        assert!(matches!(
            wrong_source.validate(),
            Err(ProtocolError::InvalidMessage(message)) if message == "implicit ask must use the reserved source"
        ));
    }

    #[test]
    fn session_digest_is_lowercase_and_domain_separated() {
        let token = [0xabu8; 32];
        let digest = session_digest(&token);
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_ne!(digest, lowercase_hex(&Sha256::digest(token)));
    }

    #[test]
    fn connect_with_timeout_succeeds_for_live_socket() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("live.sock");
        let _listener = UnixListener::bind(&path).expect("bind");
        let stream = connect_with_timeout(&path, Duration::from_secs(1)).expect("connect");
        drop(stream);
    }

    #[test]
    fn connect_with_timeout_reports_refusal() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("stale.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        drop(listener);
        let error = connect_with_timeout(&path, Duration::from_secs(1)).unwrap_err();
        assert!(matches!(
            &error,
            ConnectError::Io(error) if error.raw_os_error() == Some(libc::ECONNREFUSED)
        ));
    }

    #[test]
    fn connect_with_timeout_honors_deadline() {
        let result = connect_with_timeout_using(Duration::from_millis(10), || {
            std::thread::sleep(Duration::from_millis(100));
            Ok(())
        });
        assert!(matches!(result, Err(ConnectError::Timeout)));
    }
}
