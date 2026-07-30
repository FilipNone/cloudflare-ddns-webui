//! UI customization: accent color, custom logo and favicon.
//!
//! Heavy processing (PNG resizing) is deliberately avoided to keep the binary
//! tiny: the browser scales the logo via CSS, and for the favicon the raw
//! uploaded image is served directly for PNG/WebP/JPEG/GIF. SVG uploads are
//! sanitized to strip scripts/event handlers before being served.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub const MAX_ICON_BYTES: usize = 512 * 1024; // 512 KB

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct UiSettings {
    accent: Option<String>,
    icon_mime: Option<String>,
}

pub struct UiStore {
    settings: Mutex<UiSettings>,
    icon: Mutex<Option<Vec<u8>>>,
    dir: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UiStatus {
    pub accent: Option<String>,
    pub has_icon: bool,
    pub icon_mime: Option<String>,
}

impl UiStore {
    pub fn new(dir: &str) -> Self {
        let settings_path = format!("{dir}/ui-settings.json");
        let icon_path = format!("{dir}/icon");
        let settings: UiSettings = std::fs::read_to_string(&settings_path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let icon = std::fs::read(&icon_path).ok().filter(|b| !b.is_empty());
        UiStore {
            settings: Mutex::new(settings),
            icon: Mutex::new(icon),
            dir: dir.to_string(),
        }
    }

    pub fn status(&self) -> UiStatus {
        let s = self.settings.lock().unwrap();
        UiStatus {
            accent: s.accent.clone(),
            has_icon: self.icon.lock().unwrap().is_some(),
            icon_mime: s.icon_mime.clone(),
        }
    }

    pub fn accent(&self) -> Option<String> {
        self.settings.lock().unwrap().accent.clone()
    }

    pub fn set_accent(&self, accent: Option<String>) -> Result<(), String> {
        if let Some(a) = &accent {
            if !valid_hex_color(a) {
                return Err("invalid color - expected #RRGGBB".to_string());
            }
        }
        {
            let mut s = self.settings.lock().unwrap();
            s.accent = accent;
        }
        self.save_settings()
    }

    pub fn set_icon(&self, mime: &str, data: Vec<u8>) -> Result<(), String> {
        if data.len() > MAX_ICON_BYTES {
            return Err("image too large - max 512 KB".to_string());
        }
        let (mime_out, data_out) = match mime {
            "image/png" | "image/jpeg" | "image/webp" | "image/gif" => (mime.to_string(), data),
            "image/svg+xml" => {
                let text = String::from_utf8(data).map_err(|_| "invalid SVG".to_string())?;
                let sanitized = sanitize_svg(&text)?;
                ("image/svg+xml".to_string(), sanitized.into_bytes())
            }
            _ => return Err("unsupported format - use PNG, JPEG, WebP, GIF or SVG".to_string()),
        };
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("cannot create data dir: {e}"))?;
        let icon_path = format!("{}/icon", self.dir);
        std::fs::write(&icon_path, &data_out).map_err(|e| format!("cannot save icon: {e}"))?;
        {
            let mut s = self.settings.lock().unwrap();
            s.icon_mime = Some(mime_out);
        }
        *self.icon.lock().unwrap() = Some(data_out);
        self.save_settings()
    }

    pub fn reset_icon(&self) -> Result<(), String> {
        let icon_path = format!("{}/icon", self.dir);
        let _ = std::fs::remove_file(icon_path);
        {
            let mut s = self.settings.lock().unwrap();
            s.icon_mime = None;
        }
        *self.icon.lock().unwrap() = None;
        self.save_settings()
    }

    pub fn icon(&self) -> Option<(String, Vec<u8>)> {
        let mime = self.settings.lock().unwrap().icon_mime.clone()?;
        let data = self.icon.lock().unwrap().clone()?;
        Some((mime, data))
    }

    fn save_settings(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("cannot create data dir: {e}"))?;
        let path = format!("{}/ui-settings.json", self.dir);
        let json = serde_json::to_string_pretty(&*self.settings.lock().unwrap())
            .map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| format!("cannot save settings: {e}"))
    }
}

pub fn valid_hex_color(s: &str) -> bool {
    let s = s.strip_prefix('#').unwrap_or(s);
    s.len() == 6 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Strip scripts, event handlers and foreign content from an SVG upload.
fn sanitize_svg(input: &str) -> Result<String, String> {
    if !input.to_ascii_lowercase().contains("<svg") {
        return Err("not an SVG file".to_string());
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    loop {
        let lower = rest.to_ascii_lowercase();
        // Find the next dangerous construct.
        let mut cut: Option<(usize, usize)> = None;
        for (needle, closing) in [
            ("<script", "</script>"),
            ("<foreignobject", "</foreignobject>"),
        ] {
            if let Some(start) = lower.find(needle) {
                let end = lower
                    .find(closing)
                    .map(|e| e + closing.len())
                    .unwrap_or_else(|| {
                        lower[start..]
                            .find("/>")
                            .map(|e| start + e + 2)
                            .unwrap_or(rest.len())
                    });
                cut = Some(match cut {
                    Some((cs, ce)) if cs < start => (cs, ce),
                    _ => (start, end),
                });
            }
        }
        // Event handler attributes on*="..." are removed line-wise below.
        match cut {
            Some((start, end)) => {
                out.push_str(&rest[..start]);
                rest = &rest[end..];
            }
            None => {
                out.push_str(rest);
                break;
            }
        }
    }
    // Remove on*="..." attributes and javascript: URLs.
    let mut cleaned = String::with_capacity(out.len());
    for word in out.split_inclusive(|c: char| c.is_whitespace() || c == '>') {
        let lw = word.to_ascii_lowercase();
        let trimmed = lw.trim_start();
        if trimmed.starts_with("on") && trimmed.contains('=') {
            continue;
        }
        if lw.contains("javascript:") {
            continue;
        }
        cleaned.push_str(word);
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_sanitizer_strips_scripts() {
        let bad = r#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(2)</script><rect width="10" height="10" onclick="alert(3)"/><a href="javascript:alert(4)">x</a></svg>"#;
        let clean = sanitize_svg(bad).unwrap();
        let l = clean.to_ascii_lowercase();
        assert!(!l.contains("<script"));
        assert!(!l.contains("onload"));
        assert!(!l.contains("onclick"));
        assert!(!l.contains("javascript:"));
        assert!(l.contains("<rect"));
    }

    #[test]
    fn hex_color_validation() {
        assert!(valid_hex_color("#f6821f"));
        assert!(valid_hex_color("f6821f"));
        assert!(!valid_hex_color("#12345"));
        assert!(!valid_hex_color("#gggggg"));
    }
}
