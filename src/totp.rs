//! TOTP (RFC 6238) and base32 (RFC 4648) implemented on `ring::hmac`.
//! QR codes are rendered with the `qrcodegen` crate (Nayuki's reference
//! implementation), the same generator used by the `totp-rs` crate.

use ring::hmac;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32-encode without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = u64::from(buf[0]) << 32
            | u64::from(buf[1]) << 24
            | u64::from(buf[2]) << 16
            | u64::from(buf[3]) << 8
            | u64::from(buf[4]);
        let chars = match chunk.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };
        for i in 0..chars {
            let shift = 35 - i * 5;
            out.push(BASE32_ALPHABET[((n >> shift) & 0x1f) as usize] as char);
        }
    }
    out
}

/// Base32-decode, ignoring padding and case.
pub fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::new();
    let mut symbols = 0;
    for c in input.chars() {
        let c = c.to_ascii_uppercase();
        if c == '=' || c == ' ' {
            continue;
        }
        if !c.is_ascii() {
            return Err("invalid base32 character".to_string());
        }
        let val = BASE32_ALPHABET
            .iter()
            .position(|&a| a == c as u8)
            .ok_or_else(|| format!("invalid base32 character '{c}'"))? as u64;
        bits = (bits << 5) | val;
        symbols += 1;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    if matches!(symbols % 8, 1 | 3 | 6) || (bits & ((1 << bit_count) - 1)) != 0 {
        return Err("invalid base32 trailing bits".to_string());
    }
    Ok(out)
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = (bytes[19] & 0x0f) as usize;
    let code = (u32::from(bytes[offset] & 0x7f) << 24)
        | (u32::from(bytes[offset + 1]) << 16)
        | (u32::from(bytes[offset + 2]) << 8)
        | u32::from(bytes[offset + 3]);
    code % 1_000_000
}

/// Generate the TOTP code for a unix timestamp (30s step, 6 digits).
#[cfg(test)]
pub fn totp_at(secret: &[u8], timestamp_secs: u64) -> u32 {
    hotp(secret, timestamp_secs / 30)
}

/// Verify a user-supplied 6-digit code, allowing ±1 time step drift.
pub fn totp_verify(secret: &[u8], code: &str, timestamp_secs: u64) -> bool {
    if secret.is_empty() || code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let code: u32 = match code.parse() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let step = timestamp_secs / 30;
    for drift in [0i64, -1, 1] {
        let s = step as i64 + drift;
        if s >= 0 && hotp(secret, s as u64) == code {
            return true;
        }
    }
    false
}

/// otpauth:// URI for authenticator apps.
pub fn otpauth_uri(secret_b32: &str, issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&digits=6&period=30",
        crate::cloudflare::url_encode(issuer),
        crate::cloudflare::url_encode(account),
        secret_b32,
        crate::cloudflare::url_encode(issuer),
    )
}

/// Render the otpauth URI as a QR code (SVG markup with a 4-module quiet
/// zone), or `None` if the data does not fit in a QR symbol.
pub fn qr_svg(data: &str) -> Option<String> {
    let qr = qrcodegen::QrCode::encode_text(data, qrcodegen::QrCodeEcc::Medium).ok()?;
    let size = qr.size();
    let mut paths = String::new();
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                paths.push_str(&format!("M{x},{y}h1v1h-1z"));
            }
        }
    }
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"-4 -4 {} {}\" shape-rendering=\"crispEdges\"><rect x=\"-4\" y=\"-4\" width=\"{}\" height=\"{}\" fill=\"#fff\"/><path d=\"{}\" fill=\"#000\"/></svg>",
        size + 8,
        size + 8,
        size + 8,
        size + 8,
        paths
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip() {
        let data = b"Hello, world!";
        let enc = base32_encode(data);
        let dec = base32_decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn base32_decode_known() {
        // RFC 4648 test vector: "f" -> "MY======"
        assert_eq!(base32_decode("MY======").unwrap(), b"f");
        assert_eq!(base32_encode(b"f"), "MY");
    }

    #[test]
    fn security_base32_rejects_non_ascii_aliases_and_partial_bytes() {
        for input in ["\u{141}\u{141}", "A", "MZ", "AAA", "AAAAAA"] {
            assert!(base32_decode(input).is_err(), "invalid base32 accepted");
        }
    }

    #[test]
    fn security_totp_requires_six_ascii_digits() {
        let secret = b"12345678901234567890";
        let timestamp = 1111111109;
        let code = format!("{:06}", totp_at(secret, timestamp));
        assert!(code.starts_with('0'));
        assert!(totp_verify(secret, &code, timestamp));
        for malformed in [
            code[1..].to_string(),
            format!("+{code}"),
            format!("0{code}"),
            format!(" {code} "),
        ] {
            assert!(!totp_verify(secret, &malformed, timestamp));
        }
    }

    // RFC 6238 Appendix B test vectors (SHA-1, 8-digit codes).
    // We produce 6-digit codes, so compare against the last 6 digits.
    #[test]
    fn totp_rfc6238() {
        let secret = b"12345678901234567890";
        let cases = [
            (59u64, 94287082u32),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ];
        for (ts, expected8) in cases {
            let code = totp_at(secret, ts);
            assert_eq!(code, expected8 % 1_000_000, "timestamp {ts}");
        }
    }

    #[test]
    fn totp_verify_accepts_current_and_neighbors() {
        let secret = b"12345678901234567890";
        let ts = 1_700_000_000u64;
        let code = format!("{:06}", totp_at(secret, ts));
        assert!(totp_verify(secret, &code, ts));
        // ±30s drift accepted
        assert!(totp_verify(
            secret,
            &format!("{:06}", totp_at(secret, ts - 30)),
            ts
        ));
        assert!(totp_verify(
            secret,
            &format!("{:06}", totp_at(secret, ts + 30)),
            ts
        ));
        // Wrong code rejected
        assert!(!totp_verify(secret, "000000", ts) || totp_at(secret, ts) == 0);
    }

    #[test]
    fn qr_generates_scannable_matrix() {
        let uri = otpauth_uri("JBSWY3DPEHPK3PXP", "CF DDNS", "admin");
        let svg = qr_svg(&uri).expect("otpauth URI fits in a QR symbol");
        assert!(svg.contains("<svg"));
        assert!(svg.contains("path"));
        // 4-module quiet zone in the viewBox (ISO/IEC 18004).
        assert!(svg.contains("viewBox=\"-4 -4"));
        // Structural sanity of the underlying matrix: finder patterns,
        // separators and the fixed dark module.
        let qr = qrcodegen::QrCode::encode_text(&uri, qrcodegen::QrCodeEcc::Medium).unwrap();
        let size = qr.size();
        assert!(qr.get_module(0, 0));
        assert!(!qr.get_module(7, 0));
        assert!(qr.get_module(size - 1, 0));
        assert!(qr.get_module(0, size - 1));
        assert!(qr.get_module(8, size - 8));
    }
}
