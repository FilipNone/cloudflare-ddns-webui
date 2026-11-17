//! UI customization: accent color, custom logo and favicon.
//!
//! Heavy processing (PNG resizing) is deliberately avoided to keep the binary
//! tiny: the browser scales the logo via CSS, and for the favicon the raw
//! uploaded image is served directly for PNG/WebP/JPEG/GIF after bounded
//! format checks. Uploaded SVG is not supported.
//!
//! `ui-settings.json` in the data directory holds the accent and the icon's
//! MIME type and file name. The icon bytes live in their own `icon-<hex>`
//! file, so changing the accent does not rewrite them.

use crate::persist::{random_hex, replace_file, SaveOutcome};
use crate::pp::{self, PP};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

pub const MAX_ICON_BYTES: usize = 512 * 1024; // 512 KB
const MAX_ICON_DIMENSION: u32 = 4096;
const MAX_ICON_PIXELS: u64 = 4 * 1024 * 1024;
// Older versions stored the icon inside the settings as a JSON number array.
const MAX_SETTINGS_BYTES: usize = MAX_ICON_BYTES * 4 + 1024;
const SETTINGS_FILE: &str = "ui-settings.json";
const INVALID_SETTINGS_FILE: &str = "ui-settings.json.invalid";
/// Where versions before the inline format kept the icon bytes.
const LEGACY_ICON_FILE: &str = "icon";
const ICON_PREFIX: &str = "icon-";

/// `ui-settings.json` as stored on disk.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct StoredSettings {
    accent: Option<String>,
    icon_mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon_file: Option<String>,
    /// Icon bytes stored inline by older versions. Read, never written.
    #[serde(skip_serializing)]
    icon_data: Option<Vec<u8>>,
}

#[derive(Clone, Default)]
struct UiSettings {
    accent: Option<String>,
    icon: Option<Icon>,
}

#[derive(Clone)]
struct Icon {
    mime: String,
    data: Vec<u8>,
    /// The file in the data directory that holds `data`. Icons loaded from
    /// an older format get a new `icon-<hex>` file on the next save.
    file: Option<String>,
}

pub struct UiStore {
    /// Held only briefly, never during disk I/O, so requests that read the
    /// settings do not wait for a save.
    settings: Mutex<UiSettings>,
    /// Held for a whole save, so saves happen one at a time.
    saving: Mutex<()>,
    dir: PathBuf,
    pp: PP,
}

pub struct UiStatus {
    pub accent: Option<String>,
    pub has_icon: bool,
}

/// Why a change was not applied.
#[derive(Debug)]
pub enum UiError {
    /// The request was invalid. The message can be shown to the user.
    Invalid(String),
    /// Saving failed. The message is for the server log.
    Save(String),
}

enum LoadError {
    /// The content is unusable. The file is moved aside and defaults apply.
    Invalid(String),
    /// The file could not be read, so startup stops.
    Unreadable(String),
}

impl UiStore {
    /// Loads the saved settings. A missing file means defaults. A file that
    /// cannot be read stops startup, and one with invalid content is renamed
    /// to `ui-settings.json.invalid`, so a later save cannot silently drop
    /// what it held.
    pub fn new(dir: &str, pp: PP) -> Result<Self, String> {
        let dir = PathBuf::from(dir);
        let settings = match load(&dir) {
            Ok(settings) => {
                let in_use = settings.icon.as_ref().and_then(|icon| icon.file.clone());
                // A set-aside file may name an icon the operator wants back.
                let keep_icons = dir.join(INVALID_SETTINGS_FILE).symlink_metadata().is_ok();
                remove_leftovers(&dir, |name| {
                    !keep_icons && valid_icon_file(name) && in_use.as_deref() != Some(name)
                });
                settings
            }
            Err(LoadError::Invalid(reason)) => {
                set_aside(&dir, &reason, pp)?;
                // The renamed file may point to an icon the operator wants back.
                remove_leftovers(&dir, |_| false);
                UiSettings::default()
            }
            Err(LoadError::Unreadable(error)) => return Err(error),
        };
        Ok(UiStore {
            settings: Mutex::new(settings),
            saving: Mutex::new(()),
            dir,
            pp,
        })
    }

    pub fn status(&self) -> UiStatus {
        let settings = lock(&self.settings);
        UiStatus {
            accent: settings.accent.clone(),
            has_icon: settings.icon.is_some(),
        }
    }

    pub fn accent(&self) -> Option<String> {
        lock(&self.settings).accent.clone()
    }

    pub fn icon(&self) -> Option<(String, Vec<u8>)> {
        let settings = lock(&self.settings);
        let icon = settings.icon.as_ref()?;
        Some((icon.mime.clone(), icon.data.clone()))
    }

    /// Saves to disk, so call it from the blocking thread pool.
    pub fn set_accent(&self, accent: Option<String>) -> Result<(), UiError> {
        if accent.as_deref().is_some_and(|a| !valid_hex_color(a)) {
            return Err(UiError::Invalid(
                "invalid color - expected #RRGGBB".to_string(),
            ));
        }
        let accent = accent.map(|a| normalize_accent(&a));
        self.update(|settings| settings.accent = accent)
    }

    /// Saves to disk, so call it from the blocking thread pool.
    pub fn set_icon(&self, mime: &str, data: Vec<u8>) -> Result<(), UiError> {
        validate_raster(mime, &data).map_err(UiError::Invalid)?;
        let icon = Icon {
            mime: mime.to_string(),
            data,
            file: None,
        };
        self.update(|settings| settings.icon = Some(icon))
    }

    /// Saves to disk, so call it from the blocking thread pool.
    pub fn reset_icon(&self) -> Result<(), UiError> {
        self.update(|settings| settings.icon = None)
    }

    /// Applies `change` and saves it. The in-memory settings only change
    /// once the save has worked.
    fn update(&self, change: impl FnOnce(&mut UiSettings)) -> Result<(), UiError> {
        let _saving = lock(&self.saving);
        let old = lock(&self.settings).clone();
        let mut new = old.clone();
        change(&mut new);
        self.save(&old, &mut new).map_err(UiError::Save)?;
        *lock(&self.settings) = new;
        Ok(())
    }

    fn save(&self, old: &UiSettings, new: &mut UiSettings) -> Result<(), String> {
        // The icon file has to exist before the settings point to it.
        let mut written = None;
        if let Some(icon) = new
            .icon
            .as_mut()
            .filter(|icon| !icon.file.as_deref().is_some_and(valid_icon_file))
        {
            let name = format!("{ICON_PREFIX}{}", random_hex()?);
            self.write(&name, &icon.data)?;
            icon.file = Some(name.clone());
            written = Some(name);
        }
        let stored = StoredSettings {
            accent: new.accent.clone(),
            icon_mime: new.icon.as_ref().map(|icon| icon.mime.clone()),
            icon_file: new.icon.as_ref().and_then(|icon| icon.file.clone()),
            icon_data: None,
        };
        let saved = serde_json::to_vec(&stored)
            .map_err(|e| format!("cannot serialize settings: {e}"))
            .and_then(|json| self.write(SETTINGS_FILE, &json));
        if let Err(error) = saved {
            if let Some(name) = written {
                let _ = std::fs::remove_file(self.dir.join(name));
            }
            return Err(error);
        }
        // Nothing points to the previous icon file any more.
        let new_file = new.icon.as_ref().and_then(|icon| icon.file.as_deref());
        if let Some(old_file) = old.icon.as_ref().and_then(|icon| icon.file.as_deref()) {
            if new_file != Some(old_file) {
                let _ = std::fs::remove_file(self.dir.join(old_file));
            }
        }
        Ok(())
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let outcome = replace_file(&self.dir.join(name), bytes)
            .map_err(|e| format!("cannot save {name}: {e}"))?;
        if outcome == SaveOutcome::DirectoryNotSynced {
            self.pp.warningf(
                pp::EMOJI_WARNING,
                format!(
                    "Saved {name}, but could not sync the data directory; \
                     a power loss may undo the change"
                ),
            );
        }
        Ok(())
    }
}

/// Locks a mutex even if an earlier holder panicked. Release builds abort on
/// panic, so a poisoned lock can only appear in tests.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn load(dir: &Path) -> Result<UiSettings, LoadError> {
    let Some(bytes) = read_file(&dir.join(SETTINGS_FILE), MAX_SETTINGS_BYTES)? else {
        return Ok(UiSettings::default());
    };
    // The position is enough to find the problem; the error text could
    // quote the file.
    let stored: StoredSettings = serde_json::from_slice(&bytes).map_err(|e| {
        LoadError::Invalid(format!(
            "unexpected content at line {}, column {}",
            e.line(),
            e.column()
        ))
    })?;
    let accent = match stored.accent {
        Some(accent) if !valid_hex_color(&accent) => {
            return Err(LoadError::Invalid("invalid accent color".to_string()))
        }
        accent => accent.map(|a| normalize_accent(&a)),
    };
    let icon = match (stored.icon_mime, stored.icon_file, stored.icon_data) {
        (None, None, None) => None,
        (Some(mime), Some(file), None) if valid_icon_file(&file) => {
            Some(load_icon(dir, mime, file)?)
        }
        (Some(mime), None, Some(data)) => {
            validate_raster(&mime, &data).map_err(LoadError::Invalid)?;
            Some(Icon {
                mime,
                data,
                file: None,
            })
        }
        (Some(mime), None, None) => Some(load_icon(dir, mime, LEGACY_ICON_FILE.to_string())?),
        _ => return Err(LoadError::Invalid("invalid icon fields".to_string())),
    };
    Ok(UiSettings { accent, icon })
}

fn load_icon(dir: &Path, mime: String, file: String) -> Result<Icon, LoadError> {
    let data = read_file(&dir.join(&file), MAX_ICON_BYTES)?
        .ok_or_else(|| LoadError::Invalid(format!("icon file {file} is missing")))?;
    validate_raster(&mime, &data).map_err(LoadError::Invalid)?;
    Ok(Icon {
        mime,
        data,
        file: Some(file),
    })
}

/// Reads a whole file of at most `limit` bytes. A missing file gives None.
fn read_file(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, LoadError> {
    let unreadable = |error: std::io::Error| {
        LoadError::Unreadable(format!(
            "cannot read {}: {error}; fix its permissions or move it out of the data directory",
            path.display()
        ))
    };
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(unreadable(error)),
    };
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() > limit {
        return Err(LoadError::Unreadable(format!(
            "{} is larger than {limit} bytes; move it out of the data directory \
             to start with the default appearance",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

/// Renames invalid settings to `ui-settings.json.invalid` for inspection.
/// An earlier set-aside file is never replaced, so startup stops instead.
fn set_aside(dir: &Path, reason: &str, pp: PP) -> Result<(), String> {
    let path = dir.join(SETTINGS_FILE);
    let aside = dir.join(INVALID_SETTINGS_FILE);
    if aside.symlink_metadata().is_ok() {
        return Err(format!(
            "{} is invalid ({reason}), and {} from an earlier start is still there; \
             move it out of the data directory, then start again",
            path.display(),
            aside.display()
        ));
    }
    std::fs::rename(&path, &aside).map_err(|error| {
        format!(
            "{} is invalid ({reason}) and cannot be renamed to {}: {error}",
            path.display(),
            aside.display()
        )
    })?;
    pp.warningf(
        pp::EMOJI_WARNING,
        format!(
            "{} is invalid ({reason}); renamed it to {} and started with the default appearance",
            path.display(),
            aside.display()
        ),
    );
    Ok(())
}

/// Deletes temporary files from interrupted saves, and the icon files for
/// which `unused_icon` returns true.
fn remove_leftovers(dir: &Path, unused_icon: impl Fn(&str) -> bool) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        // `.ui-settings-*.tmp` is the name older versions used.
        let temp = name.ends_with(".tmp")
            && [".ui-settings-", "ui-settings.json.", ICON_PREFIX]
                .iter()
                .any(|prefix| name.starts_with(prefix));
        if temp || unused_icon(name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// True for the names `save` gives icon files: the prefix and 32 lowercase
/// hex digits, so the name can never point outside the data directory.
fn valid_icon_file(name: &str) -> bool {
    name.strip_prefix(ICON_PREFIX).is_some_and(|id| {
        id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

pub fn valid_hex_color(s: &str) -> bool {
    let s = s.strip_prefix('#').unwrap_or(s);
    s.len() == 6 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn normalize_accent(accent: &str) -> String {
    format!("#{}", accent.strip_prefix('#').unwrap_or(accent))
}

fn valid_dimensions(width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width <= MAX_ICON_DIMENSION
        && height <= MAX_ICON_DIMENSION
        && u64::from(width) * u64::from(height) <= MAX_ICON_PIXELS
}

fn validate_raster(mime: &str, data: &[u8]) -> Result<(), String> {
    if data.len() > MAX_ICON_BYTES {
        return Err("image too large - max 512 KB".to_string());
    }
    // These checks bound containers and dimensions, not compressed-pixel decoding.
    let valid = match mime {
        "image/png" => valid_png(data),
        "image/jpeg" => valid_jpeg(data),
        "image/gif" => valid_gif(data),
        "image/webp" => valid_webp(data),
        _ => return Err("unsupported format - use PNG, JPEG, WebP or GIF".to_string()),
    };
    if valid {
        Ok(())
    } else {
        Err("invalid image or dimensions - max 4096 per side and 4 megapixels".to_string())
    }
}

fn valid_png(data: &[u8]) -> bool {
    if !data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return false;
    }
    let mut rest = &data[8..];
    let mut header = false;
    let mut pixels = false;
    while rest.len() >= 12 {
        let length = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if length > rest.len() - 12 {
            return false;
        }
        let kind = &rest[4..8];
        let body = &rest[8..8 + length];
        if !header {
            if kind != b"IHDR"
                || length != 13
                || !valid_dimensions(
                    u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                    u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
                )
                || !matches!(
                    (body[8], body[9]),
                    (1 | 2 | 4 | 8 | 16, 0) | (8 | 16, 2 | 4 | 6) | (1 | 2 | 4 | 8, 3)
                )
                || body[10] != 0
                || body[11] != 0
                || body[12] > 1
            {
                return false;
            }
            header = true;
        } else if matches!(kind, b"IHDR" | b"acTL" | b"fcTL" | b"fdAT") {
            return false;
        }
        if kind == b"IDAT" && length > 0 {
            pixels = true;
        }
        if kind == b"IEND" {
            return length == 0 && rest.len() == 12 && pixels;
        }
        rest = &rest[12 + length..];
    }
    false
}

fn valid_jpeg(data: &[u8]) -> bool {
    if !data.starts_with(b"\xff\xd8") || !data.ends_with(b"\xff\xd9") {
        return false;
    }
    let mut rest = &data[2..];
    let mut dimensions = false;
    let mut scan = false;
    while rest.len() >= 2 {
        if rest[0] != 0xff {
            return false;
        }
        if rest[1] == 0xff {
            rest = &rest[1..];
            continue;
        }
        let marker = rest[1];
        if marker == 0xd9 {
            return rest.len() == 2 && dimensions && scan;
        }
        if matches!(marker, 0x00 | 0xd0..=0xd8) || rest.len() < 4 {
            return false;
        }
        let length = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if length < 2 || length > rest.len() - 2 {
            return false;
        }
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            if length < 8
                || !matches!(marker, 0xc0 | 0xc2)
                || rest[4] != 8
                || !(1..=4).contains(&rest[9])
                || length != 8 + 3 * usize::from(rest[9])
                || !valid_dimensions(
                    u32::from(u16::from_be_bytes([rest[7], rest[8]])),
                    u32::from(u16::from_be_bytes([rest[5], rest[6]])),
                )
            {
                return false;
            }
            dimensions = true;
        }
        if marker == 0xda
            && (!dimensions
                || length < 6
                || !(1..=4).contains(&rest[4])
                || length != 6 + 2 * usize::from(rest[4]))
        {
            return false;
        }
        rest = &rest[2 + length..];
        if marker == 0xda {
            scan = true;
            let mut offset = 0;
            while offset + 1 < rest.len() {
                if rest[offset] == 0xff && !matches!(rest[offset + 1], 0x00 | 0xd0..=0xd7) {
                    break;
                }
                offset += if rest[offset] == 0xff { 2 } else { 1 };
            }
            if offset == 0 {
                return false;
            }
            rest = &rest[offset..];
        }
    }
    false
}

fn valid_gif(data: &[u8]) -> bool {
    if data.len() < 14
        || !(data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a"))
        || !valid_dimensions(
            u32::from(u16::from_le_bytes([data[6], data[7]])),
            u32::from(u16::from_le_bytes([data[8], data[9]])),
        )
    {
        return false;
    }
    let table_size = |packed: u8| {
        if packed & 0x80 != 0 {
            3usize << ((packed & 7) + 1)
        } else {
            0
        }
    };
    let Some(mut rest) = data.get(13 + table_size(data[10])..) else {
        return false;
    };
    let canvas_pixels = u64::from(u16::from_le_bytes([data[6], data[7]]))
        * u64::from(u16::from_le_bytes([data[8], data[9]]));
    let mut pixels = 0u64;
    let mut image = false;
    let mut frames = 0;
    while !rest.is_empty() {
        match rest[0] {
            0x3b => return rest.len() == 1 && image,
            0x21 if rest.len() >= 2 => rest = &rest[2..],
            0x2c if rest.len() >= 10 => {
                let width = u32::from(u16::from_le_bytes([rest[5], rest[6]]));
                let height = u32::from(u16::from_le_bytes([rest[7], rest[8]]));
                if !valid_dimensions(width, height) {
                    return false;
                }
                pixels += canvas_pixels.max(u64::from(width) * u64::from(height));
                frames += 1;
                if pixels > MAX_ICON_PIXELS || frames > 64 {
                    return false;
                }
                let Some(body) = rest.get(10 + table_size(rest[9])..) else {
                    return false;
                };
                if body.is_empty() || !(2..=8).contains(&body[0]) {
                    return false;
                }
                rest = &body[1..];
                image = true;
            }
            _ => return false,
        }
        loop {
            let Some(&length) = rest.first() else {
                return false;
            };
            let Some(body) = rest.get(1 + usize::from(length)..) else {
                return false;
            };
            rest = body;
            if length == 0 {
                break;
            }
        }
    }
    false
}

fn valid_webp(data: &[u8]) -> bool {
    if data.len() < 20
        || &data[..4] != b"RIFF"
        || &data[8..12] != b"WEBP"
        || u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize != data.len() - 8
    {
        return false;
    }
    let mut rest = &data[12..];
    let mut image = false;
    while rest.len() >= 8 {
        let length = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
        if length > rest.len() - 8 {
            return false;
        }
        let body = &rest[8..8 + length];
        let dimensions = match &rest[..4] {
            b"VP8 " if body.len() >= 10 && body[0] & 1 == 0 && &body[3..6] == b"\x9d\x01\x2a" => {
                image = true;
                Some((
                    u32::from(u16::from_le_bytes([body[6], body[7]]) & 0x3fff),
                    u32::from(u16::from_le_bytes([body[8], body[9]]) & 0x3fff),
                ))
            }
            b"VP8L" if body.len() >= 5 && body[0] == 0x2f && body[4] & 0xe0 == 0 => {
                image = true;
                let bits = u32::from_le_bytes([body[1], body[2], body[3], body[4]]);
                Some(((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1))
            }
            b"VP8X" if body.len() == 10 && body[0] & 0x02 == 0 => Some((
                1 + u32::from_le_bytes([body[4], body[5], body[6], 0]),
                1 + u32::from_le_bytes([body[7], body[8], body[9], 0]),
            )),
            b"VP8 " | b"VP8L" | b"VP8X" | b"ANIM" | b"ANMF" => return false,
            _ => None,
        };
        if dimensions.is_some_and(|(width, height)| !valid_dimensions(width, height)) {
            return false;
        }
        let Some(body) = rest.get(8 + length + (length & 1)..) else {
            return false;
        };
        rest = body;
    }
    rest.is_empty() && image
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "ddns-customize-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }

        fn store(&self) -> UiStore {
            self.load().unwrap()
        }

        fn load(&self) -> Result<UiStore, String> {
            UiStore::new(self.0.to_str().unwrap(), PP::new(false, true))
        }

        fn write(&self, name: &str, contents: impl AsRef<[u8]>) {
            std::fs::write(self.0.join(name), contents).unwrap();
        }

        fn settings(&self) -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(self.0.join(SETTINGS_FILE)).unwrap()).unwrap()
        }

        fn files(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }

        fn icon_files(&self) -> Vec<String> {
            self.files()
                .into_iter()
                .filter(|name| name.starts_with(ICON_PREFIX))
                .collect()
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn png() -> Vec<u8> {
        vec![
            137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1,
            8, 4, 0, 0, 0, 181, 28, 12, 2, 0, 0, 0, 11, 73, 68, 65, 84, 120, 218, 99, 100, 248, 15,
            0, 1, 5, 1, 1, 39, 24, 227, 102, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
        ]
    }

    fn raster_fixtures() -> [(&'static str, Vec<u8>); 4] {
        let mut jpeg = vec![
            255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 255, 219, 0,
            67, 0, 8, 6, 6, 7, 6, 5, 8, 7, 7, 7, 9, 9, 8, 10, 12, 20, 13, 12, 11, 11, 12, 25, 18,
            19, 15, 20, 29, 26, 31, 30, 29, 26, 28, 28, 32, 36, 46, 39, 32, 34, 44, 35, 28, 28, 40,
            55, 41, 44, 48, 49, 52, 52, 52, 31, 39, 57, 61, 56, 50, 60, 46, 51, 52, 50, 255, 192,
            0, 11, 8, 0, 1, 0, 1, 1, 1, 17, 0,
        ];
        jpeg.extend_from_slice(&[255, 196, 0, 20, 0, 1]);
        jpeg.extend_from_slice(&[0; 15]);
        jpeg.push(7);
        jpeg.extend_from_slice(&[255, 196, 0, 20, 16, 1]);
        jpeg.extend_from_slice(&[0; 16]);
        jpeg.extend_from_slice(&[255, 218, 0, 8, 1, 1, 0, 0, 63, 0, 127, 127, 255, 217]);
        [
            ("image/png", png()),
            ("image/jpeg", jpeg),
            (
                "image/webp",
                vec![
                    82, 73, 70, 70, 34, 0, 0, 0, 87, 69, 66, 80, 86, 80, 56, 32, 22, 0, 0, 0, 48,
                    1, 0, 157, 1, 42, 1, 0, 1, 0, 14, 192, 254, 37, 164, 0, 3, 112, 0, 0, 0, 0,
                ],
            ),
            (
                "image/gif",
                vec![
                    71, 73, 70, 56, 55, 97, 1, 0, 1, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 44, 0, 0, 0,
                    0, 1, 0, 1, 0, 0, 8, 4, 0, 1, 4, 4, 0, 59,
                ],
            ),
        ]
    }

    #[test]
    fn accepts_supported_rasters_and_rejects_every_truncated_prefix() {
        let dir = TestDir::new();
        let store = dir.store();
        for (mime, bytes) in raster_fixtures() {
            assert!(validate_raster(mime, &bytes).is_ok(), "rejected {mime}");
            for end in 0..bytes.len() {
                assert!(
                    validate_raster(mime, &bytes[..end]).is_err(),
                    "accepted {mime} prefix {end}"
                );
            }
            store.set_icon(mime, bytes.clone()).unwrap();
            assert_eq!(dir.store().icon(), Some((mime.to_string(), bytes.clone())));
            let mut trailing = bytes.clone();
            trailing.extend_from_slice(b"<svg onload='alert(1)'/>");
            assert!(validate_raster(mime, &trailing).is_err());
            for length in 0..bytes.len() {
                let mut corrupt = bytes.clone();
                corrupt[length] = 0xff;
                let _ = validate_raster(mime, &corrupt);
            }
        }
    }

    #[test]
    fn rejects_oversized_dimensions_for_each_raster_format() {
        for (mime, mut bytes) in raster_fixtures() {
            match mime {
                "image/png" => {
                    bytes[16..20].copy_from_slice(&4096u32.to_be_bytes());
                    bytes[20..24].copy_from_slice(&4096u32.to_be_bytes());
                }
                "image/jpeg" => {
                    let marker = bytes.windows(2).position(|p| p == [0xff, 0xc0]).unwrap();
                    bytes[marker + 5..marker + 7].copy_from_slice(&4096u16.to_be_bytes());
                    bytes[marker + 7..marker + 9].copy_from_slice(&4096u16.to_be_bytes());
                }
                "image/webp" => {
                    bytes[26..28].copy_from_slice(&4096u16.to_le_bytes());
                    bytes[28..30].copy_from_slice(&4096u16.to_le_bytes());
                }
                "image/gif" => {
                    bytes[6..8].copy_from_slice(&4096u16.to_le_bytes());
                    bytes[8..10].copy_from_slice(&4096u16.to_le_bytes());
                }
                _ => unreachable!(),
            }
            assert!(
                validate_raster(mime, &bytes).is_err(),
                "accepted oversized {mime}"
            );
        }
    }

    #[test]
    fn gif_animation_has_frame_and_total_canvas_limits() {
        let (_, gif) = raster_fixtures().into_iter().last().unwrap();
        let mut animation = gif[..19].to_vec();
        for _ in 0..65 {
            animation.extend_from_slice(&gif[19..gif.len() - 1]);
        }
        animation.push(0x3b);
        assert!(validate_raster("image/gif", &animation).is_err());
        let mut animation = gif[..19].to_vec();
        animation[6..8].copy_from_slice(&4096u16.to_le_bytes());
        animation[8..10].copy_from_slice(&1024u16.to_le_bytes());
        animation.extend_from_slice(&gif[19..gif.len() - 1]);
        animation.push(0x3b);
        assert!(validate_raster("image/gif", &animation).is_ok());
        animation.pop();
        animation.extend_from_slice(&gif[19..]);
        assert!(validate_raster("image/gif", &animation).is_err());
    }

    #[test]
    fn rejects_svg_xss_and_reordered_closing_tag_without_panicking() {
        let dir = TestDir::new();
        let store = dir.store();
        for svg in [
            r#"<svg><a href="java&#x73;cript:alert(1)">x</a></svg>"#,
            r#"<svg><animate attributeName="href" values="javascript:alert(1)"/></svg>"#,
            r#"<svg xmlns:s="http://www.w3.org/2000/svg" onload = "alert(1)"><s:script>alert(1)</s:script></svg>"#,
            "<svg></script><script>alert(1)</script></svg>",
            "<svg></foreignObject><foreignObject><p>unsafe</p></foreignObject></svg>",
        ] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                store.set_icon("image/svg+xml", svg.as_bytes().to_vec())
            }));
            assert!(result.is_ok(), "SVG upload must never panic");
            assert!(result.unwrap().is_err(), "SVG upload must be rejected");
        }
        assert!(store.icon().is_none());
    }

    #[test]
    fn rejects_mime_spoof_invalid_and_truncated_rasters() {
        let dir = TestDir::new();
        let store = dir.store();
        for mime in ["image/png", "image/jpeg", "image/webp", "image/gif"] {
            for data in [
                Vec::new(),
                b"not an image".to_vec(),
                b"<svg onload='alert(1)'/>".to_vec(),
                b"<html><script>alert(1)</script></html>".to_vec(),
            ] {
                assert!(store.set_icon(mime, data).is_err(), "accepted {mime}");
            }
        }
        assert!(store.set_icon("image/jpeg", png()).is_err());
        assert!(store.set_icon("image/png", png()[..33].to_vec()).is_err());
        assert!(store
            .set_icon("image/png", vec![0; MAX_ICON_BYTES + 1])
            .is_err());
    }

    #[test]
    fn missing_settings_start_with_defaults() {
        let dir = TestDir::new();
        let store = dir.store();
        assert!(store.accent().is_none() && store.icon().is_none());
        assert!(!store.status().has_icon);
        assert!(dir.files().is_empty());
    }

    #[test]
    fn unsafe_or_invalid_settings_are_set_aside_and_not_loaded() {
        let dir = TestDir::new();
        let svg = b"<svg onload='alert(1)'/>".to_vec();
        let icon_name = format!("{ICON_PREFIX}{}", "a".repeat(32));
        let legacy = |mime: &str| serde_json::json!({"accent": "#123456", "icon_mime": mime});
        let inline = |mime: &str| serde_json::json!({"accent": "#123456", "icon_mime": mime, "icon_data": svg.clone()});
        let cases = [
            (b"{\"accent\":".to_vec(), None),
            (
                b"{\"accent\":\"#123456\",\"icon_data\":[256]}".to_vec(),
                None,
            ),
            (
                serde_json::to_vec(
                    &serde_json::json!({"accent": "red;}</style><script>alert(1)</script>"}),
                )
                .unwrap(),
                None,
            ),
            (
                serde_json::to_vec(&legacy("image/svg+xml")).unwrap(),
                Some(svg.clone()),
            ),
            (
                serde_json::to_vec(&legacy("text/html")).unwrap(),
                Some(b"<script>alert(1)</script>".to_vec()),
            ),
            (
                serde_json::to_vec(&legacy("image/png")).unwrap(),
                Some(svg.clone()),
            ),
            (serde_json::to_vec(&legacy("image/png")).unwrap(), None),
            (serde_json::to_vec(&inline("image/svg+xml")).unwrap(), None),
            (serde_json::to_vec(&inline("image/png")).unwrap(), None),
            (serde_json::to_vec(&inline("text/html")).unwrap(), None),
            (
                serde_json::to_vec(&serde_json::json!(
                    {"icon_mime": "image/png", "icon_file": format!("../{icon_name}")}
                ))
                .unwrap(),
                None,
            ),
            (
                serde_json::to_vec(&serde_json::json!(
                    {"icon_mime": "image/png", "icon_file": icon_name}
                ))
                .unwrap(),
                None,
            ),
            (
                serde_json::to_vec(&serde_json::json!({"icon_file": icon_name})).unwrap(),
                None,
            ),
        ];
        for (settings, legacy_icon) in cases {
            dir.write(SETTINGS_FILE, &settings);
            if let Some(bytes) = &legacy_icon {
                dir.write(LEGACY_ICON_FILE, bytes);
            }
            let store = dir.store();
            assert!(store.accent().is_none() && store.icon().is_none());
            assert!(!dir.0.join(SETTINGS_FILE).exists());
            let aside = dir.0.join(INVALID_SETTINGS_FILE);
            assert_eq!(std::fs::read(&aside).unwrap(), settings);
            store.set_accent(Some("#abcdef".to_string())).unwrap();
            assert_eq!(std::fs::read(&aside).unwrap(), settings);
            std::fs::remove_file(aside).unwrap();
            std::fs::remove_file(dir.0.join(SETTINGS_FILE)).unwrap();
            let _ = std::fs::remove_file(dir.0.join(LEGACY_ICON_FILE));
        }
    }

    #[test]
    fn set_aside_settings_keep_their_icon_and_are_never_overwritten() {
        let dir = TestDir::new();
        let icon_name = format!("{ICON_PREFIX}{}", "b".repeat(32));
        dir.write(&icon_name, b"synthetic icon bytes");
        let first = format!(r#"{{"icon_mime":"image/png","icon_file":"{icon_name}","bogus":1"#);
        dir.write(SETTINGS_FILE, &first);
        dir.store();
        // A restart with no settings file must not treat the icon the set-aside
        // file names as unused.
        dir.store();
        assert!(dir.0.join(&icon_name).exists());

        dir.write(SETTINGS_FILE, b"{second incident");
        let error = dir.load().err().unwrap();
        assert!(error.contains(INVALID_SETTINGS_FILE), "{error}");
        assert_eq!(
            std::fs::read_to_string(dir.0.join(INVALID_SETTINGS_FILE)).unwrap(),
            first
        );
        assert!(dir.0.join(SETTINGS_FILE).exists());
    }

    #[test]
    fn unreadable_settings_stop_startup() {
        let dir = TestDir::new();
        dir.write(SETTINGS_FILE, vec![b' '; MAX_SETTINGS_BYTES + 1]);
        let error = dir.load().err().unwrap();
        assert!(
            error.contains(SETTINGS_FILE) && error.contains("larger than"),
            "{error}"
        );
        assert!(!dir.0.join(INVALID_SETTINGS_FILE).exists());

        dir.write(SETTINGS_FILE, br#"{"icon_mime":"image/png"}"#);
        dir.write(LEGACY_ICON_FILE, vec![0; MAX_ICON_BYTES + 1]);
        let error = dir.load().err().unwrap();
        assert!(error.contains("larger than"), "{error}");
        std::fs::remove_file(dir.0.join(LEGACY_ICON_FILE)).unwrap();

        // Reading a directory fails with an I/O error, even for root.
        std::fs::remove_file(dir.0.join(SETTINGS_FILE)).unwrap();
        std::fs::create_dir(dir.0.join(SETTINGS_FILE)).unwrap();
        let error = dir.load().err().unwrap();
        assert!(
            error.contains("cannot read") && error.contains(SETTINGS_FILE),
            "{error}"
        );
        std::fs::remove_dir(dir.0.join(SETTINGS_FILE)).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            dir.write(SETTINGS_FILE, br##"{"accent":"#123456"}"##);
            let path = dir.0.join(SETTINGS_FILE);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            // Root ignores file modes, so the check only runs as a normal user.
            if std::fs::File::open(&path).is_err() {
                assert!(dir.load().err().unwrap().contains("cannot read"));
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(dir.store().accent().as_deref(), Some("#123456"));
        }
    }

    #[test]
    fn invalid_settings_that_cannot_be_set_aside_stop_startup() {
        let dir = TestDir::new();
        dir.write(SETTINGS_FILE, b"not json");
        std::fs::create_dir(dir.0.join(INVALID_SETTINGS_FILE)).unwrap();
        dir.write(&format!("{INVALID_SETTINGS_FILE}/keep"), b"x");
        let error = dir.load().err().unwrap();
        assert!(error.contains(INVALID_SETTINGS_FILE), "{error}");
        assert_eq!(
            std::fs::read(dir.0.join(SETTINGS_FILE)).unwrap(),
            b"not json"
        );
    }

    #[test]
    fn icon_has_its_own_file_and_accent_changes_keep_it() {
        let dir = TestDir::new();
        let store = dir.store();
        store.set_icon("image/png", png()).unwrap();
        let settings = dir.settings();
        assert!(settings.get("icon_data").is_none(), "{settings}");
        let name = settings["icon_file"].as_str().unwrap().to_owned();
        assert!(valid_icon_file(&name));
        assert_eq!(dir.icon_files(), std::slice::from_ref(&name));
        assert_eq!(std::fs::read(dir.0.join(&name)).unwrap(), png());
        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(dir.0.join(&name)).unwrap().ino()
        };
        store.set_accent(Some("#123456".to_string())).unwrap();
        store.set_accent(None).unwrap();
        assert_eq!(dir.settings()["icon_file"], name.as_str());
        assert_eq!(dir.icon_files(), std::slice::from_ref(&name));
        // Every write replaces the file, so the same inode means no rewrite.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(dir.0.join(&name)).unwrap().ino(), inode);
        }
        let (gif_mime, gif) = raster_fixtures().into_iter().last().unwrap();
        store.set_icon(gif_mime, gif.clone()).unwrap();
        let replaced = dir.settings()["icon_file"].as_str().unwrap().to_owned();
        assert_ne!(replaced, name);
        assert_eq!(dir.icon_files(), std::slice::from_ref(&replaced));
        assert_eq!(dir.store().icon(), Some((gif_mime.to_string(), gif)));
        store.reset_icon().unwrap();
        assert!(dir.icon_files().is_empty());
        assert!(dir.settings().get("icon_file").is_none());
    }

    #[test]
    fn older_formats_move_the_icon_to_its_own_file_on_the_next_save() {
        let dir = TestDir::new();
        dir.write(
            SETTINGS_FILE,
            serde_json::to_vec(&serde_json::json!(
                {"accent": "abcdef", "icon_mime": "image/png", "icon_data": png()}
            ))
            .unwrap(),
        );
        let store = dir.store();
        assert_eq!(store.icon(), Some(("image/png".to_string(), png())));
        assert!(dir.icon_files().is_empty());
        store.set_accent(Some("#123456".to_string())).unwrap();
        let settings = dir.settings();
        assert!(settings.get("icon_data").is_none(), "{settings}");
        let name = settings["icon_file"].as_str().unwrap();
        assert_eq!(std::fs::read(dir.0.join(name)).unwrap(), png());
        assert_eq!(dir.store().icon(), Some(("image/png".to_string(), png())));

        let dir = TestDir::new();
        dir.write(SETTINGS_FILE, br#"{"accent":null,"icon_mime":"image/png"}"#);
        dir.write(LEGACY_ICON_FILE, png());
        let store = dir.store();
        assert_eq!(store.icon(), Some(("image/png".to_string(), png())));
        store.set_accent(Some("#123456".to_string())).unwrap();
        assert!(!dir.0.join(LEGACY_ICON_FILE).exists());
        let name = dir.settings()["icon_file"].as_str().unwrap().to_owned();
        assert_eq!(dir.icon_files(), std::slice::from_ref(&name));
        assert_eq!(std::fs::read(dir.0.join(name)).unwrap(), png());
        assert_eq!(dir.store().icon(), Some(("image/png".to_string(), png())));
    }

    #[test]
    fn crash_leftovers_are_removed_at_startup() {
        let dir = TestDir::new();
        dir.store().set_icon("image/png", png()).unwrap();
        let in_use = dir.settings()["icon_file"].as_str().unwrap().to_owned();
        let orphan = format!("{ICON_PREFIX}{}", "b".repeat(32));
        let leftovers = [
            orphan.clone(),
            format!("{orphan}.{}.tmp", "c".repeat(32)),
            format!("{SETTINGS_FILE}.{}.tmp", "d".repeat(32)),
            ".ui-settings-1-0.tmp".to_string(),
        ];
        for name in &leftovers {
            dir.write(name, b"partial");
        }
        dir.write("state.json", b"{}");
        dir.write("icon-notes.txt", b"kept");
        let store = dir.store();
        assert_eq!(store.icon(), Some(("image/png".to_string(), png())));
        let mut expected = vec![
            "icon-notes.txt".to_string(),
            in_use,
            "state.json".to_string(),
            SETTINGS_FILE.to_string(),
        ];
        expected.sort();
        assert_eq!(dir.files(), expected);

        // Invalid settings may point to an icon worth keeping.
        dir.write(&orphan, png());
        dir.write(&leftovers[2], b"partial");
        dir.write(SETTINGS_FILE, b"not json");
        dir.store();
        assert!(dir.0.join(&orphan).exists());
        assert!(!dir.0.join(&leftovers[2]).exists());
    }

    #[test]
    fn safe_legacy_settings_load_and_new_settings_survive_restart() {
        let dir = TestDir::new();
        std::fs::write(
            dir.0.join("ui-settings.json"),
            br##"{"accent":"abcdef","icon_mime":"image/png"}"##,
        )
        .unwrap();
        std::fs::write(dir.0.join("icon"), png()).unwrap();
        let store = dir.store();
        assert_eq!(store.accent().as_deref(), Some("#abcdef"));
        assert_eq!(store.icon(), Some(("image/png".to_string(), png())));
        store.set_accent(Some("123ABC".to_string())).unwrap();
        store.set_icon("image/png", png()).unwrap();
        // The legacy path is no longer read once the icon has its own file.
        std::fs::write(dir.0.join("icon"), b"<svg onload='alert(1)'/>").unwrap();
        let reloaded = dir.store();
        assert_eq!(reloaded.accent().as_deref(), Some("#123ABC"));
        assert_eq!(reloaded.icon(), store.icon());
        reloaded.reset_icon().unwrap();
        assert!(dir.store().icon().is_none());
    }

    #[test]
    fn failed_saves_preserve_in_memory_and_persisted_settings() {
        let dir = TestDir::new();
        let store = dir.store();
        store.set_accent(Some("#123456".to_string())).unwrap();
        store.set_icon("image/png", png()).unwrap();
        let path = dir.0.join("ui-settings.json");
        let saved = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(store.set_accent(Some("#abcdef".to_string())).is_err());
        assert_eq!(store.accent().as_deref(), Some("#123456"));
        assert!(store.reset_icon().is_err());
        assert_eq!(store.icon(), Some(("image/png".to_string(), png())));
        let (mime, bytes) = raster_fixtures().into_iter().last().unwrap();
        assert!(store.set_icon(mime, bytes).is_err());
        assert_eq!(store.icon(), Some(("image/png".to_string(), png())));
        // The icon written for the failed upload was removed again.
        assert_eq!(dir.icon_files().len(), 1);
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(path, saved).unwrap();
        assert_eq!(dir.store().icon(), store.icon());
        assert_eq!(dir.store().accent(), store.accent());
        assert!(std::fs::read_dir(&dir.0).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }

    #[cfg(unix)]
    #[test]
    fn saved_snapshot_is_private_and_does_not_follow_settings_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = TestDir::new();
        let target = dir.0.join("synthetic-target.json");
        std::fs::write(&target, b"{}").unwrap();
        symlink(&target, dir.0.join("ui-settings.json")).unwrap();
        dir.store().set_accent(Some("#123456".to_string())).unwrap();
        assert_eq!(std::fs::read(target).unwrap(), b"{}");
        let metadata = std::fs::metadata(dir.0.join("ui-settings.json")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(dir.store().accent().as_deref(), Some("#123456"));
    }

    #[test]
    fn temp_files_left_by_a_crash_do_not_block_the_next_save() {
        let dir = TestDir::new();
        // The old names were fixed per process and counter, so these are the
        // ones a restarted server would try first.
        for n in 0..256 {
            let name = format!(".ui-settings-{}-{n}.tmp", std::process::id());
            std::fs::write(dir.0.join(name), b"partial").unwrap();
        }
        let store = dir.store();
        store.set_accent(Some("#123456".to_string())).unwrap();
        assert_eq!(dir.store().accent().as_deref(), Some("#123456"));
        assert!(std::fs::read_dir(&dir.0).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }

    #[test]
    fn hex_color_validation() {
        assert!(valid_hex_color("#f6821f"));
        assert!(valid_hex_color("f6821f"));
        assert!(!valid_hex_color("#12345"));
        assert!(!valid_hex_color("#gggggg"));
    }
}
