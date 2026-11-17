use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

const MAX_RECORDS: usize = 10_000;
const MAX_PAREN_DEPTH: u32 = 16;
const INVALID_RDATA: &str = "unsupported record type or invalid record data";

pub fn validate(input: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(input).map_err(|_| "zone file must be UTF-8")?;
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err("zone file contains a control character".to_string());
    }
    let mut zone = ZoneCheck::default();
    for statement in statements(text)? {
        let line = statement.line;
        zone.statement(&statement)
            .map_err(|msg| format!("line {line}: {msg}"))?;
        if zone.records > MAX_RECORDS {
            return Err(format!("line {line}: too many records (max {MAX_RECORDS})"));
        }
    }
    if zone.records == 0 {
        return Err("zone file contains no importable records".to_string());
    }
    Ok(())
}

/// One record or directive, with parenthesised continuation lines joined
/// and comments removed.
struct Statement {
    line: usize,
    omitted_owner: bool,
    fields: Vec<String>,
}

/// Split a zone file into statements. Quotes and escapes stay in the fields
/// so the rdata checks can decode them later.
fn statements(text: &str) -> Result<Vec<Statement>, String> {
    let mut statements = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut comment = false;
    let mut depth = 0u32;
    let mut line = 1;
    let mut start = 1;
    let mut leading_space = false;
    for c in text.chars().chain(std::iter::once('\n')) {
        if c == '\n' {
            comment = false;
            if quoted || escaped {
                return Err(format!("line {line}: unterminated quoted value or escape"));
            }
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            if depth == 0 {
                if !words.is_empty() {
                    statements.push(Statement {
                        line: start,
                        omitted_owner: leading_space,
                        fields: std::mem::take(&mut words),
                    });
                }
                start = line + 1;
                leading_space = false;
            }
            line += 1;
            continue;
        }
        if comment {
            continue;
        }
        if escaped {
            word.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            word.push(c);
            escaped = true;
            continue;
        }
        if c == '"' {
            word.push(c);
            quoted = !quoted;
            continue;
        }
        if quoted {
            word.push(c);
            continue;
        }
        if c == ';' {
            comment = true;
            continue;
        }
        if matches!(c, '(' | ')') {
            if c == '(' {
                depth += 1;
            } else {
                depth = depth
                    .checked_sub(1)
                    .ok_or("unmatched closing parenthesis")?;
            }
            if depth > MAX_PAREN_DEPTH {
                return Err("zone-file parentheses are nested too deeply".to_string());
            }
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        if c.is_whitespace() {
            if words.is_empty() && word.is_empty() && depth == 0 {
                leading_space = true;
            }
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if depth != 0 {
        return Err("unclosed zone-file parenthesis".to_string());
    }
    Ok(statements)
}

/// State carried from one statement to the next.
#[derive(Default)]
struct ZoneCheck {
    origin: String,
    owner: Option<String>,
    default_ttl: bool,
    inherited_ttl: bool,
    seen: HashSet<(String, String, Vec<Vec<u8>>)>,
    records: usize,
}

impl ZoneCheck {
    fn statement(&mut self, statement: &Statement) -> Result<(), &'static str> {
        let fields = statement.fields.as_slice();
        if fields.first().is_some_and(|field| field.starts_with('$')) {
            return self.directive(fields);
        }
        let (owner, fields) = self.record_owner(fields, statement.omitted_owner)?;
        let fields = self.ttl_and_class(fields)?;
        let [kind, data @ ..] = fields else {
            return Err("missing record type");
        };
        let kind = kind.to_ascii_uppercase();
        let rdata = canonical_rdata(&kind, data, &self.origin)?;
        let counted = kind != "SOA";
        if !self.seen.insert((owner, kind, rdata)) {
            return Err("duplicate record in zone file");
        }
        if counted {
            self.records += 1;
        }
        Ok(())
    }

    fn directive(&mut self, fields: &[String]) -> Result<(), &'static str> {
        match fields {
            [name, ttl] if name.eq_ignore_ascii_case("$TTL") && valid_ttl(ttl) => {
                self.default_ttl = true;
            }
            [name, origin] if name.eq_ignore_ascii_case("$ORIGIN") && valid_name(origin) => {
                self.origin =
                    canonical_name(origin, &self.origin).ok_or("invalid resolved origin")?;
            }
            _ => {
                return Err("unsupported or invalid directive; only $TTL and $ORIGIN are supported")
            }
        }
        Ok(())
    }

    /// Return the record owner and the fields after it. A line that starts
    /// with whitespace reuses the previous owner.
    fn record_owner<'a>(
        &mut self,
        fields: &'a [String],
        omitted: bool,
    ) -> Result<(String, &'a [String]), &'static str> {
        if omitted {
            let owner = self
                .owner
                .clone()
                .ok_or("omitted owner has no preceding record")?;
            return Ok((owner, fields));
        }
        let [owner, rest @ ..] = fields else {
            return Err("invalid record owner");
        };
        if !valid_name(owner) {
            return Err("invalid record owner");
        }
        let owner = canonical_name(owner, &self.origin)
            .ok_or("invalid owner name after applying $ORIGIN")?;
        self.owner = Some(owner.clone());
        Ok((owner, rest))
    }

    /// Skip the optional TTL and class, which may come in either order, and
    /// return the fields that follow them.
    fn ttl_and_class<'a>(
        &mut self,
        mut fields: &'a [String],
    ) -> Result<&'a [String], &'static str> {
        let mut class = false;
        let mut ttl = false;
        loop {
            match fields {
                [field, rest @ ..] if !class && field.eq_ignore_ascii_case("IN") => {
                    class = true;
                    fields = rest;
                }
                [field, rest @ ..] if !ttl && valid_ttl(field) => {
                    ttl = true;
                    fields = rest;
                }
                _ => break,
            }
        }
        if ttl {
            // Later records without a TTL reuse the last explicit one.
            self.inherited_ttl = true;
        } else if !self.default_ttl && !self.inherited_ttl {
            return Err("record needs a TTL or a $TTL default");
        }
        Ok(fields)
    }
}

/// Check one record's data and return it in canonical form, so that two
/// spellings of the same record are caught by the duplicate check. Fields
/// that are not normalised here keep their decoded text.
fn canonical_rdata(
    kind: &str,
    data: &[String],
    origin: &str,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let name = |s: &str| rdata_name(s, origin);
    let rdata = match (kind, data) {
        ("A", [address]) => vec![canonical::<Ipv4Addr>(address)?],
        ("AAAA", [address]) => vec![canonical::<Ipv6Addr>(address)?],
        ("CNAME" | "NS" | "PTR", [target]) => vec![name(target)?],
        ("MX", [preference, exchange]) => vec![canonical::<u16>(preference)?, name(exchange)?],
        ("SRV", [priority, weight, port, target]) => vec![
            canonical::<u16>(priority)?,
            canonical::<u16>(weight)?,
            canonical::<u16>(port)?,
            name(target)?,
        ],
        ("CAA", [flags, tag, value]) => {
            vec![canonical::<u8>(flags)?, caa_tag(tag)?, text(value)?]
        }
        ("TXT", [_, ..]) => data
            .iter()
            .map(|s| character_string(s))
            .collect::<Result<_, _>>()?,
        ("HTTPS" | "SVCB", [priority, target, params @ ..]) => {
            if !valid_service_params(params) {
                return Err(INVALID_RDATA);
            }
            // Parameter order carries no meaning.
            let mut params: Vec<Vec<u8>> = params.iter().map(|s| raw(s)).collect();
            params.sort();
            [vec![canonical::<u16>(priority)?, name(target)?], params].concat()
        }
        ("SOA", [mname, rname, serial, refresh, retry, expire, minimum]) => vec![
            name(mname)?,
            name(rname)?,
            checked::<u32>(serial)?,
            ttl_field(refresh)?,
            ttl_field(retry)?,
            ttl_field(expire)?,
            ttl_field(minimum)?,
        ],
        ("URI", [priority, weight, target]) => vec![
            checked::<u16>(priority)?,
            checked::<u16>(weight)?,
            text(target)?,
        ],
        ("NAPTR", [order, preference, flags, services, regexp, replacement]) => vec![
            checked::<u16>(order)?,
            checked::<u16>(preference)?,
            text(flags)?,
            text(services)?,
            text(regexp)?,
            name(replacement)?,
        ],
        ("DS", [key_tag, algorithm, digest_type, digest @ ..]) => [
            vec![
                checked::<u16>(key_tag)?,
                checked::<u8>(algorithm)?,
                checked::<u8>(digest_type)?,
            ],
            hex_fields(digest)?,
        ]
        .concat(),
        ("SSHFP", [algorithm, fingerprint_type, fingerprint @ ..]) => [
            vec![checked::<u8>(algorithm)?, checked::<u8>(fingerprint_type)?],
            hex_fields(fingerprint)?,
        ]
        .concat(),
        ("TLSA" | "SMIMEA", [usage, selector, matching_type, association @ ..]) => [
            vec![
                checked::<u8>(usage)?,
                checked::<u8>(selector)?,
                checked::<u8>(matching_type)?,
            ],
            hex_fields(association)?,
        ]
        .concat(),
        // DNSKEY protocol is always 3 (RFC 4034).
        ("DNSKEY", [flags, protocol, algorithm, key @ ..]) if protocol == "3" => [
            vec![
                checked::<u16>(flags)?,
                raw(protocol),
                checked::<u8>(algorithm)?,
            ],
            base64_fields(key)?,
        ]
        .concat(),
        ("CERT", [cert_type, key_tag, algorithm, certificate @ ..]) => [
            vec![
                cert_type_field(cert_type)?,
                checked::<u16>(key_tag)?,
                checked::<u8>(algorithm)?,
            ],
            base64_fields(certificate)?,
        ]
        .concat(),
        _ => return Err(INVALID_RDATA),
    };
    Ok(rdata)
}

/// Decoded field text, or the field as written when it does not decode.
fn raw(s: &str) -> Vec<u8> {
    decode_value(s).unwrap_or_else(|| s.as_bytes().to_vec())
}

/// Parse a field and keep the parsed value's spelling, so 010 and 10 match.
fn canonical<T: FromStr + ToString>(s: &str) -> Result<Vec<u8>, &'static str> {
    s.parse::<T>()
        .map(|value| value.to_string().into_bytes())
        .map_err(|_| INVALID_RDATA)
}

/// Check that a field parses, keeping it as written.
fn checked<T: FromStr>(s: &str) -> Result<Vec<u8>, &'static str> {
    s.parse::<T>().map(|_| raw(s)).map_err(|_| INVALID_RDATA)
}

fn text(s: &str) -> Result<Vec<u8>, &'static str> {
    decode_value(s).ok_or(INVALID_RDATA)
}

fn character_string(s: &str) -> Result<Vec<u8>, &'static str> {
    decode_value(s)
        .filter(|value| value.len() <= 255)
        .ok_or(INVALID_RDATA)
}

fn caa_tag(s: &str) -> Result<Vec<u8>, &'static str> {
    decode_value(s)
        .filter(|tag| {
            !tag.is_empty() && tag.len() <= 15 && tag.iter().all(u8::is_ascii_alphanumeric)
        })
        .ok_or(INVALID_RDATA)
}

fn ttl_field(s: &str) -> Result<Vec<u8>, &'static str> {
    if valid_ttl(s) {
        Ok(raw(s))
    } else {
        Err(INVALID_RDATA)
    }
}

fn cert_type_field(s: &str) -> Result<Vec<u8>, &'static str> {
    const MNEMONICS: [&str; 10] = [
        "PKIX", "SPKI", "PGP", "IPKIX", "ISPKI", "IPGP", "ACPKIX", "IACPKIX", "URI", "OID",
    ];
    if s.parse::<u16>().is_ok() || MNEMONICS.contains(&s) {
        Ok(raw(s))
    } else {
        Err(INVALID_RDATA)
    }
}

fn hex_fields(data: &[String]) -> Result<Vec<Vec<u8>>, &'static str> {
    if valid_hex_data(data) {
        Ok(data.iter().map(|s| raw(s)).collect())
    } else {
        Err(INVALID_RDATA)
    }
}

fn base64_fields(data: &[String]) -> Result<Vec<Vec<u8>>, &'static str> {
    if valid_base64_data(data) {
        Ok(data.iter().map(|s| raw(s)).collect())
    } else {
        Err(INVALID_RDATA)
    }
}

/// A domain name inside rdata, made absolute with the current $ORIGIN.
fn rdata_name(s: &str, origin: &str) -> Result<Vec<u8>, &'static str> {
    if !valid_name(s) {
        return Err(INVALID_RDATA);
    }
    canonical_name(s, origin)
        .map(String::into_bytes)
        .ok_or("invalid origin-relative DNS name")
}

fn valid_hex_data(data: &[String]) -> bool {
    let length = data.iter().map(String::len).sum::<usize>();
    length > 0
        && length % 2 == 0
        && data
            .iter()
            .all(|s| s.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn valid_base64_data(data: &[String]) -> bool {
    let encoded = data.concat();
    let content = encoded.trim_end_matches('=');
    !content.is_empty()
        && encoded.len().is_multiple_of(4)
        && encoded.len() - content.len() <= 2
        && content
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
}

fn valid_name(s: &str) -> bool {
    canonical_name(s, "").is_some()
}

fn canonical_name(s: &str, origin: &str) -> Option<String> {
    if s == "@" {
        return Some(if origin.is_empty() {
            "@".into()
        } else {
            origin.into()
        });
    }
    if s == "." {
        return Some(".".into());
    }
    let bytes = s.as_bytes();
    let mut labels = Vec::new();
    let mut label = String::new();
    let mut label_len = 0;
    let mut wire_len = 1;
    let mut absolute = false;
    let mut i = 0;
    while i < bytes.len() {
        let mut b = bytes[i];
        let escaped = b == b'\\';
        if escaped {
            i += 1;
            b = *bytes.get(i)?;
            if b.is_ascii_digit() {
                let digits = bytes.get(i..i + 3)?;
                if !digits.iter().all(u8::is_ascii_digit) {
                    return None;
                }
                b = std::str::from_utf8(digits).ok()?.parse::<u8>().ok()?;
                i += 2;
            }
        } else if b == b'.' {
            if label.is_empty() {
                return None;
            }
            wire_len += label_len + 1;
            labels.push(std::mem::take(&mut label));
            label_len = 0;
            absolute = i + 1 == bytes.len();
            i += 1;
            continue;
        } else if !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_' | b'*') {
            return None;
        }
        b = b.to_ascii_lowercase();
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'*') {
            label.push(b as char);
        } else {
            label.push_str(&format!("\\{b:03}"));
        }
        label_len += 1;
        if label_len > 63 {
            return None;
        }
        i += 1;
    }
    if !label.is_empty() {
        wire_len += label_len + 1;
        labels.push(label);
    }
    if labels.is_empty() || wire_len > 255 {
        return None;
    }
    let mut name = labels.join(".");
    if !absolute && !origin.is_empty() && origin != "." {
        if wire_len + decode_value(origin)?.len() + 1 > 255 {
            return None;
        }
        name.push('.');
        name.push_str(origin);
    }
    if name.len() > 1024 {
        return None;
    }
    Some(name)
}

fn decode_value(s: &str) -> Option<Vec<u8>> {
    let s = if s.starts_with('"') {
        s.strip_prefix('"')?.strip_suffix('"')?
    } else {
        s
    };
    let bytes = s.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let mut b = bytes[i];
        if b == b'\\' {
            i += 1;
            b = *bytes.get(i)?;
            if b.is_ascii_digit() {
                let digits = bytes.get(i..i + 3)?;
                if !digits.iter().all(u8::is_ascii_digit) {
                    return None;
                }
                b = std::str::from_utf8(digits).ok()?.parse::<u8>().ok()?;
                i += 2;
            }
        } else if b == b'"' {
            return None;
        }
        result.push(b);
        i += 1;
    }
    Some(result)
}

fn valid_service_params(params: &[String]) -> bool {
    let mut keys = HashSet::new();
    for param in params {
        let (key, value) = param.split_once('=').unwrap_or((param, ""));
        if !valid_service_key(key) || !keys.insert(key) {
            return false;
        }
        let Some(decoded) = decode_value(value) else {
            return false;
        };
        let Ok(value) = String::from_utf8(decoded) else {
            return false;
        };
        match key {
            "port" if value.parse::<u16>().is_err() => return false,
            "ipv4hint"
                if value.is_empty()
                    || !value
                        .split(',')
                        .all(|v| v.parse::<std::net::Ipv4Addr>().is_ok()) =>
            {
                return false
            }
            "ipv6hint"
                if value.is_empty()
                    || !value
                        .split(',')
                        .all(|v| v.parse::<std::net::Ipv6Addr>().is_ok()) =>
            {
                return false
            }
            "no-default-alpn" if !value.is_empty() => return false,
            "alpn" | "mandatory" | "ech" if value.is_empty() => return false,
            _ => {}
        }
    }
    true
}

/// RFC 9460 section 2.1: 1 to 63 characters from a-z, 0-9 and "-". Keys
/// without a name are written keyNNNNN, a number up to 65535 without
/// leading zeros.
fn valid_service_key(key: &str) -> bool {
    if key.is_empty()
        || key.len() > 63
        || !key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return false;
    }
    match key.strip_prefix("key") {
        Some(number) if number.starts_with(|c: char| c.is_ascii_digit()) => {
            number.parse::<u16>().is_ok() && (number == "0" || !number.starts_with('0'))
        }
        _ => true,
    }
}

fn valid_ttl(s: &str) -> bool {
    let mut number = 0u64;
    let mut total = 0u64;
    let mut digits = false;
    let mut saw_digits = false;
    for b in s.bytes() {
        if b.is_ascii_digit() {
            let Some(n) = number
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(b - b'0')))
            else {
                return false;
            };
            number = n;
            digits = true;
            saw_digits = true;
        } else {
            let multiplier = match b.to_ascii_lowercase() {
                b's' => 1,
                b'm' => 60,
                b'h' => 3600,
                b'd' => 86400,
                b'w' => 604800,
                _ => return false,
            };
            if !digits {
                return false;
            }
            let Some(n) = number
                .checked_mul(multiplier)
                .and_then(|n| total.checked_add(n))
            else {
                return false;
            };
            total = n;
            number = 0;
            digits = false;
        }
    }
    (!s.is_empty())
        && total
            .checked_add(number)
            .is_some_and(|n| n <= i32::MAX as u64)
        && saw_digits
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inherited_ttl_and_escaped_names_are_valid() {
        for file in [
            "example.com. 300 IN A 192.0.2.1\nwww.example.com. IN A 192.0.2.2\n",
            "$TTL 300\nfoo\\046bar.example.com. A 192.0.2.1\n",
        ] {
            assert!(validate(file.as_bytes()).is_ok(), "{file}");
        }
    }

    #[test]
    fn semantic_duplicates_and_malformed_data_fail_preflight() {
        for file in [
            "$TTL 300\n@ AAAA 2001:db8::1\n@ AAAA 2001:0db8:0:0:0:0:0:1\n",
            "$TTL 300\n@ CNAME EXAMPLE.com.\n@ CNAME example.COM.\n",
            "$TTL 300\n@ TXT \"A\"\n@ TXT \"\\065\"\n",
            "$ORIGIN example.com.\n$TTL 300\nfoo.sub A 192.0.2.1\n$ORIGIN sub\nfoo A 192.0.2.1\n",
            "$TTL 300\nfoo..example.com. A 192.0.2.1\n",
            "$TTL 300\n@ CAA 0 !!! \"issuer.example\"\n",
            "$TTL 300\n@ HTTPS 1 . port=banana\n",
        ] {
            assert!(validate(file.as_bytes()).is_err(), "{file}");
        }
    }

    #[test]
    fn canonical_rdata_catches_respelled_duplicates() {
        for file in [
            "$TTL 300\n@ MX 010 mail.example.com.\n@ MX 10 MAIL.example.com.\n",
            "$TTL 300\n@ SRV 01 2 3 a.example.com.\n@ SRV 1 02 3 A.example.com.\n",
            "$TTL 300\n@ HTTPS 1 . alpn=h2 port=443\n@ HTTPS 01 . port=443 alpn=h2\n",
            "$TTL 300\n@ CAA 00 issue \"ca.example\"\n@ CAA 0 \"issue\" ca.example\n",
            "$ORIGIN example.com.\n$TTL 300\n@ NS ns1\n@ NS ns1.example.com.\n",
            "$TTL 300\n@ SOA ns.example.com. h.example.com. 1 1h 2h 3d 300\n@ SOA NS.example.com. h.example.com. 1 1h 2h 3d 300\n",
        ] {
            let error = validate(file.as_bytes()).unwrap_err();
            assert!(error.contains("duplicate record"), "{file}: {error}");
        }
    }

    #[test]
    fn distinct_spellings_that_are_not_canonicalised_stay_distinct() {
        // Only some numeric fields are canonicalised; these must not collide.
        for file in [
            "$TTL 300\n@ DS 12345 8 2 ABCD\n@ DS 12345 08 2 ABCD\n",
            "$TTL 300\n@ URI 10 1 \"https://example.com/\"\n@ URI 010 1 \"https://example.com/\"\n",
            "$TTL 300\n@ A 192.0.2.1\n@ A 192.0.2.2\n@ AAAA 2001:db8::1\n",
        ] {
            assert!(validate(file.as_bytes()).is_ok(), "{file}");
        }
    }

    #[test]
    fn long_resolved_origins_are_errors_not_panics() {
        let origin = format!(
            "{}.{}.{}.com.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63)
        );
        for suffix in [
            format!("$ORIGIN {}\n$TTL 300\n@ A 192.0.2.1", "d".repeat(63)),
            format!("$TTL 300\n@ CNAME {}", "d".repeat(63)),
        ] {
            let file = format!("$ORIGIN {origin}\n{suffix}");
            assert!(validate(file.as_bytes()).is_err());
        }
    }

    #[test]
    fn overlong_owner_reports_an_invalid_owner_name() {
        let origin = format!(
            "{}.{}.{}.com.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63)
        );
        let file = format!(
            "$ORIGIN {origin}\n$TTL 300\n{} A 192.0.2.1\n",
            "d".repeat(63)
        );
        let error = validate(file.as_bytes()).unwrap_err();
        assert!(error.contains("invalid owner name"), "{error}");
        assert!(!error.contains("omitted owner"), "{error}");
    }

    #[test]
    fn svc_param_keys_follow_rfc_9460() {
        let longest = format!("{}=1", "a".repeat(63));
        for params in [
            "alpn=h2",
            "no-default-alpn",
            "ech=AAAA",
            "key0=x",
            "key65535=x",
            longest.as_str(),
        ] {
            let file = format!("$TTL 300\n@ HTTPS 1 . {params}\n");
            assert!(validate(file.as_bytes()).is_ok(), "{params}");
        }
        let too_long = format!("{}=1", "a".repeat(64));
        for params in [
            "ALPN=h2",
            "Port=443",
            "key65536=x",
            "key007=x",
            "key1a=x",
            "a_b=1",
            "=1",
            too_long.as_str(),
        ] {
            let file = format!("$TTL 300\n@ HTTPS 1 . {params}\n");
            assert!(validate(file.as_bytes()).is_err(), "{params}");
        }
    }

    #[test]
    fn additional_cloudflare_types_and_zero_ttl_units_are_valid() {
        for record in [
            "@ URI 10 1 \"https://example.com/\"",
            "@ NAPTR 10 20 \"U\" \"E2U+sip\" \"!^.*$!sip:info@example.com!\" .",
            "@ DS 12345 8 2 ABCD",
            "@ DNSKEY 256 3 8 AQID",
            "@ SSHFP 1 1 ABCD",
            "@ TLSA 3 1 1 ABCD",
            "@ SMIMEA 3 1 1 ABCD",
            "@ CERT PKIX 1 8 AQID",
        ] {
            assert!(
                validate(format!("$TTL 0s\n{record}").as_bytes()).is_ok(),
                "{record}"
            );
        }
    }
    #[test]
    fn default_ttl_class_order_omitted_owner_and_quotes() {
        for file in [
            "$ORIGIN example.com.\n$TTL 1h\n@ IN A 192.0.2.1\n  AAAA 2001:db8::1\nwww IN 300 CNAME example.com.\ntext TXT \"semi; colon\" \"second\"\n",
            "example.com. 300 IN A 192.0.2.1\nexample.com. IN 1h30m AAAA 2001:db8::1\n",
            "$TTL 300\n@ SOA ns.example.com. hostmaster.example.com. (1 1h 2h 3d 300)\n@ A 192.0.2.1\n",
        ] { assert!(validate(file.as_bytes()).is_ok(), "{file}"); }
    }
    #[test]
    fn invalid_and_duplicate_records_are_rejected() {
        for file in [
            "",
            "$INCLUDE private.file",
            " 300 IN A 192.0.2.1",
            "@ A 192.0.2.1",
            "$TTL 300\n@ A not-an-ip",
            "$TTL 300\n@ A 192.0.2.1\n@ A 192.0.2.1",
            "$TTL 300\n@ TXT \"unterminated",
            "$TTL 300\n@ SOA (",
            "$TTL 300\n@ MX 65536 example.com.",
            "$TTL 18446744073709551615h\n@ A 192.0.2.1",
        ] {
            assert!(validate(file.as_bytes()).is_err(), "{file}");
        }
        assert!(validate(&[0xff]).is_err());
    }
}
