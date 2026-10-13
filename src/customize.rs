//! UI customization: accent color, custom logo and favicon.
//!
//! Heavy processing (PNG resizing) is deliberately avoided to keep the binary
//! tiny: the browser scales the logo via CSS, and for the favicon the raw
//! uploaded image is served directly for PNG/WebP/JPEG/GIF after bounded
//! format checks. Uploaded SVG is not supported.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::Mutex;

pub const MAX_ICON_BYTES: usize = 512 * 1024; // 512 KB
const MAX_ICON_DIMENSION: u32 = 4096;
const MAX_ICON_PIXELS: u64 = 4 * 1024 * 1024;
const MAX_SETTINGS_BYTES: usize = MAX_ICON_BYTES * 4 + 1024;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct UiSettings {
    accent: Option<String>,
    icon_mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon_data: Option<Vec<u8>>,
}

pub struct UiStore {
    settings: Mutex<UiSettings>,
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
        let mut settings: UiSettings = read_bounded(&settings_path, MAX_SETTINGS_BYTES)
            .and_then(|t| serde_json::from_slice(&t).ok())
            .unwrap_or_default();
        settings.accent = settings
            .accent
            .filter(|a| valid_hex_color(a))
            .map(|a| format!("#{}", a.strip_prefix('#').unwrap_or(&a)));
        if settings.icon_data.is_none() && settings.icon_mime.is_some() {
            settings.icon_data = read_bounded(&icon_path, MAX_ICON_BYTES);
        }
        if !matches!(
            (&settings.icon_mime, &settings.icon_data),
            (Some(mime), Some(data)) if validate_raster(mime, data).is_ok()
        ) {
            settings.icon_mime = None;
            settings.icon_data = None;
        }
        UiStore {
            settings: Mutex::new(settings),
            dir: dir.to_string(),
        }
    }

    pub fn status(&self) -> UiStatus {
        let s = self.settings.lock().unwrap();
        UiStatus {
            accent: s.accent.clone(),
            has_icon: s.icon_data.is_some(),
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
        let mut settings = self.settings.lock().unwrap();
        let mut updated = settings.clone();
        updated.accent = accent.map(|a| format!("#{}", a.strip_prefix('#').unwrap_or(&a)));
        self.save_settings(&updated)?;
        *settings = updated;
        Ok(())
    }

    pub fn set_icon(&self, mime: &str, data: Vec<u8>) -> Result<(), String> {
        validate_raster(mime, &data)?;
        let mut settings = self.settings.lock().unwrap();
        let mut updated = settings.clone();
        updated.icon_mime = Some(mime.to_string());
        updated.icon_data = Some(data);
        self.save_settings(&updated)?;
        *settings = updated;
        Ok(())
    }

    pub fn reset_icon(&self) -> Result<(), String> {
        let mut settings = self.settings.lock().unwrap();
        let mut updated = settings.clone();
        updated.icon_mime = None;
        updated.icon_data = None;
        self.save_settings(&updated)?;
        *settings = updated;
        Ok(())
    }

    pub fn icon(&self) -> Option<(String, Vec<u8>)> {
        let settings = self.settings.lock().unwrap();
        let mime = settings.icon_mime.clone()?;
        let data = settings.icon_data.clone()?;
        Some((mime, data))
    }

    fn save_settings(&self, settings: &UiSettings) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("cannot create data dir: {e}"))?;
        let path = format!("{}/ui-settings.json", self.dir);
        let json = serde_json::to_vec(settings).map_err(|e| e.to_string())?;
        // Keep icon bytes and metadata in one snapshot so replacement is atomic.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let temp = format!(
            "{}/.ui-settings-{}-{}.tmp",
            self.dir,
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|e| format!("cannot save settings: {e}"))?;
        let result = file
            .write_all(&json)
            .and_then(|()| file.sync_all())
            .and_then(|()| std::fs::rename(&temp, &path));
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result.map_err(|e| format!("cannot save settings: {e}"))
    }
}

pub fn valid_hex_color(s: &str) -> bool {
    let s = s.strip_prefix('#').unwrap_or(s);
    s.len() == 6 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn read_bounded(path: &str, limit: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= limit).then_some(bytes)
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
        let length = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        if length > rest.len() - 12 {
            return false;
        }
        let kind = &rest[4..8];
        let body = &rest[8..8 + length];
        if !header {
            if kind != b"IHDR"
                || length != 13
                || !valid_dimensions(
                    u32::from_be_bytes(body[..4].try_into().unwrap()),
                    u32::from_be_bytes(body[4..8].try_into().unwrap()),
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
        || u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize != data.len() - 8
    {
        return false;
    }
    let mut rest = &data[12..];
    let mut image = false;
    while rest.len() >= 8 {
        let length = u32::from_le_bytes(rest[4..8].try_into().unwrap()) as usize;
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
                let bits = u32::from_le_bytes(body[1..5].try_into().unwrap());
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
            UiStore::new(self.0.to_str().unwrap())
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
    fn legacy_unsafe_content_and_accent_are_not_loaded() {
        let dir = TestDir::new();
        for (mime, bytes) in [
            ("image/svg+xml", b"<svg onload='alert(1)'/>".to_vec()),
            ("text/html", b"<script>alert(1)</script>".to_vec()),
            ("image/png", b"<svg onload='alert(1)'/>".to_vec()),
            ("image/png", vec![0; MAX_ICON_BYTES + 1]),
        ] {
            std::fs::write(
                dir.0.join("ui-settings.json"),
                serde_json::to_vec(&serde_json::json!({
                    "accent": "red;}</style><script>alert(1)</script>",
                    "icon_mime": mime
                }))
                .unwrap(),
            )
            .unwrap();
            std::fs::write(dir.0.join("icon"), bytes).unwrap();
            let store = dir.store();
            assert!(store.accent().is_none());
            assert!(store.icon().is_none());
            assert!(!store.status().has_icon);
            assert!(store.status().icon_mime.is_none());
        }
    }

    #[test]
    fn unsafe_embedded_snapshots_and_oversized_settings_are_not_loaded() {
        let dir = TestDir::new();
        for mime in ["image/svg+xml", "image/png", "text/html"] {
            std::fs::write(
                dir.0.join("ui-settings.json"),
                serde_json::to_vec(&serde_json::json!({
                    "accent": "#123456", "icon_mime": mime,
                    "icon_data": b"<svg onload='alert(1)'/>".to_vec()
                }))
                .unwrap(),
            )
            .unwrap();
            assert!(dir.store().icon().is_none());
            assert_eq!(dir.store().accent().as_deref(), Some("#123456"));
        }
        std::fs::write(
            dir.0.join("ui-settings.json"),
            vec![b' '; MAX_SETTINGS_BYTES + 1],
        )
        .unwrap();
        assert!(dir.store().icon().is_none());
        assert!(dir.store().accent().is_none());
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
    fn hex_color_validation() {
        assert!(valid_hex_color("#f6821f"));
        assert!(valid_hex_color("f6821f"));
        assert!(!valid_hex_color("#12345"));
        assert!(!valid_hex_color("#gggggg"));
    }
}
