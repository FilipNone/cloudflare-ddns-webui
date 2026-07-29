//! Pretty-printing of log messages, following the cloudflare-ddns philosophy:
//! configurable emoji prefixes and a quiet mode.

pub const EMOJI_ERROR: &str = "❌";
pub const EMOJI_LOCK: &str = "🔒";
pub const EMOJI_GLOBE: &str = "🌍";

#[derive(Debug, Clone, Copy)]
pub struct PP {
    emoji: bool,
    quiet: bool,
}

impl PP {
    pub fn new(emoji: bool, quiet: bool) -> Self {
        PP { emoji, quiet }
    }

    fn prefix(&self, emoji: &str) -> String {
        if self.emoji && !emoji.is_empty() {
            format!("{emoji} ")
        } else {
            String::new()
        }
    }

    pub fn infof(&self, emoji: &str, msg: &str) {
        if !self.quiet {
            println!("{}{msg}", self.prefix(emoji));
        }
    }

    pub fn successf(&self, emoji: &str, msg: &str) {
        if !self.quiet {
            println!("{}{msg}", self.prefix(emoji));
        }
    }

    pub fn warningf(&self, emoji: &str, msg: &str) {
        eprintln!("{}{msg}", self.prefix(emoji));
    }

    pub fn errorf(&self, emoji: &str, msg: &str) {
        eprintln!("{}{msg}", self.prefix(emoji));
    }
}
