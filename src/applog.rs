//! Timestamped log file for the approval broker.
//!
//! The broker's stdout and stderr (including child `osascript` stderr) are
//! routed through a pipe into `~/Library/Logs/saferun/approval.log`. When the
//! broker was started with a terminal on stderr, lines are also echoed there.

use std::ffi::{CStr, OsStr};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;

/// Log file location for a given home directory.
pub fn log_path_for_home(home: &OsStr) -> PathBuf {
    Path::new(home).join("Library/Logs/saferun/approval.log")
}

/// Log file location for the current user, from `$HOME`.
pub fn default_log_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| "HOME is not set".to_string())?;
    Ok(log_path_for_home(&home))
}

/// Open the log file for appending, creating it (0600) and its directory (0700).
pub fn open_log_file(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    // Tighten a pre-existing file too.
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(file)
}

/// Prefix one output line with a timestamp, ensuring it ends with a newline.
pub fn format_line(timestamp: &str, line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(timestamp.len() + line.len() + 2);
    out.extend_from_slice(timestamp.as_bytes());
    out.push(b' ');
    out.extend_from_slice(line);
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out
}

fn local_timestamp() -> String {
    // SAFETY: time/localtime_r/strftime write only into the provided buffers.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return now.to_string();
        }
        let mut buffer = [0 as libc::c_char; 64];
        let written = libc::strftime(
            buffer.as_mut_ptr(),
            buffer.len(),
            c"%Y-%m-%d %H:%M:%S%z".as_ptr(),
            &tm,
        );
        if written == 0 {
            return now.to_string();
        }
        CStr::from_ptr(buffer.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

/// Route this process's stdout and stderr into the log file at `path`.
pub fn redirect_output_to_log(path: &Path) -> Result<(), String> {
    let mut file =
        open_log_file(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;

    // SAFETY: plain fd syscalls on descriptors owned by this function.
    let (read_end, echo) = unsafe {
        let echo = if libc::isatty(libc::STDERR_FILENO) == 1 {
            let copy = libc::dup(libc::STDERR_FILENO);
            (copy >= 0).then(|| File::from_raw_fd(copy))
        } else {
            None
        };
        let mut fds = [0; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(format!("cannot create log pipe: {}", io::Error::last_os_error()));
        }
        libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
        for target in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if libc::dup2(fds[1], target) < 0 {
                return Err(format!(
                    "cannot redirect output to log: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        libc::close(fds[1]);
        (File::from_raw_fd(fds[0]), echo)
    };

    thread::spawn(move || {
        let mut echo = echo;
        let mut reader = BufReader::new(read_end);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let _ = file.write_all(&format_line(&local_timestamp(), &line));
                    if let Some(echo) = echo.as_mut() {
                        let _ = echo.write_all(&line);
                    }
                }
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn log_path_is_under_library_logs() {
        assert_eq!(
            log_path_for_home(OsStr::new("/Users/someone")),
            PathBuf::from("/Users/someone/Library/Logs/saferun/approval.log")
        );
    }

    #[test]
    fn open_log_file_creates_private_dir_and_file() {
        let home = tempfile::tempdir().expect("tempdir");
        let path = log_path_for_home(home.path().as_os_str());
        let mut file = open_log_file(&path).expect("open");
        file.write_all(b"one\n").expect("write");
        drop(file);
        let mut file = open_log_file(&path).expect("reopen");
        file.write_all(b"two\n").expect("append");

        assert_eq!(fs::read(&path).expect("read"), b"one\ntwo\n");
        let file_mode = fs::metadata(&path).expect("meta").permissions().mode();
        let dir_mode = fs::metadata(path.parent().unwrap())
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o777, 0o600);
        assert_eq!(dir_mode & 0o777, 0o700);
    }

    #[test]
    fn format_line_prefixes_timestamp_and_terminates() {
        assert_eq!(format_line("T", b"hello\n"), b"T hello\n");
        assert_eq!(format_line("T", b"partial"), b"T partial\n");
    }
}
