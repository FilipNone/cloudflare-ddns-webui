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
mod tests {
    use super::*;

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
