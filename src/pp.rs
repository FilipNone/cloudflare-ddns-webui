//! Pretty-printing of log messages, following the cloudflare-ddns philosophy:
//! configurable emoji prefixes and a quiet mode.

use std::fmt::Display;
use std::io::Write;

pub const EMOJI_ERROR: &str = "❌";
pub const EMOJI_LOCK: &str = "🔒";
pub const EMOJI_GLOBE: &str = "🌍";
pub const EMOJI_WARNING: &str = "⚠️";
pub const EMOJI_STOP: &str = "👋";

#[derive(Debug, Clone, Copy)]
pub struct PP {
    emoji: bool,
    quiet: bool,
}

impl PP {
    pub fn new(emoji: bool, quiet: bool) -> Self {
        PP { emoji, quiet }
    }

    pub fn infof(&self, emoji: &str, msg: impl Display) {
        self.stdout(emoji, msg);
    }

    pub fn successf(&self, emoji: &str, msg: impl Display) {
        self.stdout(emoji, msg);
    }

    pub fn warningf(&self, emoji: &str, msg: impl Display) {
        self.stderr(emoji, msg);
    }

    pub fn errorf(&self, emoji: &str, msg: impl Display) {
        self.stderr(emoji, msg);
    }

    fn stdout(&self, emoji: &str, msg: impl Display) {
        if !self.quiet {
            self.write_line(&mut std::io::stdout().lock(), emoji, msg);
        }
    }

    fn stderr(&self, emoji: &str, msg: impl Display) {
        #[cfg(test)]
        if CAPTURED.with_borrow_mut(|captured| {
            if let Some(out) = captured.as_mut() {
                self.write_line(out, emoji, &msg);
                true
            } else {
                false
            }
        }) {
            return;
        }
        self.write_line(&mut std::io::stderr().lock(), emoji, msg);
    }

    /// Write errors are ignored on purpose. `println!` panics when stdout is a
    /// closed pipe or a full disk, and with `panic = "abort"` a lost log line
    /// would stop the server.
    fn write_line(&self, out: &mut impl Write, emoji: &str, msg: impl Display) {
        let _ = if self.emoji && !emoji.is_empty() {
            writeln!(out, "{emoji} {msg}")
        } else {
            writeln!(out, "{msg}")
        };
    }
}

#[cfg(test)]
thread_local! {
    /// Stderr lines collected by `capture_stderr` on this thread.
    static CAPTURED: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// Runs `call` and returns what it logged to stderr from this thread,
/// so tests can check warnings without reading the real stderr.
#[cfg(test)]
pub fn capture_stderr<R>(call: impl FnOnce() -> R) -> (R, String) {
    CAPTURED.set(Some(Vec::new()));
    let result = call();
    let captured = CAPTURED.take().unwrap_or_default();
    (result, String::from_utf8_lossy(&captured).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stderr_capture_collects_warnings_and_errors() {
        let pp = PP::new(true, true);
        let ((), logged) = capture_stderr(|| {
            pp.warningf(EMOJI_LOCK, "synthetic warning");
            pp.infof(EMOJI_GLOBE, "synthetic info");
            pp.errorf(EMOJI_ERROR, "synthetic error");
        });
        assert_eq!(
            logged,
            format!("{EMOJI_LOCK} synthetic warning\n{EMOJI_ERROR} synthetic error\n")
        );
        let ((), logged) = capture_stderr(|| {});
        assert!(logged.is_empty());
    }

    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn failed_log_writes_are_ignored() {
        PP::new(true, false).write_line(&mut BrokenPipe, EMOJI_ERROR, "synthetic");
        PP::new(false, false).write_line(&mut BrokenPipe, "", 42);
    }

    #[test]
    fn emoji_prefix_follows_the_setting() {
        let mut out = Vec::new();
        PP::new(true, false).write_line(&mut out, EMOJI_LOCK, "with emoji");
        PP::new(true, false).write_line(&mut out, "", "empty emoji");
        PP::new(false, false).write_line(&mut out, EMOJI_LOCK, "emoji off");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "🔒 with emoji\nempty emoji\nemoji off\n"
        );
    }
}
