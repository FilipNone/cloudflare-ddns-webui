use std::collections::HashSet;

pub fn validate(input: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(input).map_err(|_| "zone file must be UTF-8")?;
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err("zone file contains a control character".to_string());
    }
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
                    statements.push((start, leading_space, std::mem::take(&mut words)));
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
            if depth > 16 {
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
    let mut origin = String::new();
    let mut owner = None;
    let mut default_ttl = false;
    let mut inherited_ttl = false;
    let mut seen = HashSet::new();
    let mut count = 0;
    for (line, omitted_owner, fields) in statements {
        let error = |msg: &str| format!("line {line}: {msg}");
        if fields[0].starts_with('$') {
            match fields[0].to_ascii_uppercase().as_str() {
                "$TTL" if fields.len() == 2 && valid_ttl(&fields[1]) => default_ttl = true,
                "$ORIGIN" if fields.len() == 2 && valid_name(&fields[1]) => {
                    origin = canonical_name(&fields[1], &origin)
                        .ok_or_else(|| error("invalid resolved origin"))?;
                }
                _ => {
                    return Err(error(
                        "unsupported or invalid directive; only $TTL and $ORIGIN are supported",
                    ))
                }
            }
            continue;
        }
        let mut i = 0;
        if !omitted_owner {
            if !valid_name(&fields[0]) {
                return Err(error("invalid record owner"));
            }
            owner = canonical_name(&fields[0], &origin);
            i += 1;
        }
        let name = owner
            .as_ref()
            .ok_or_else(|| error("omitted owner has no preceding record"))?;
        let mut ttl = default_ttl || inherited_ttl;
        let mut explicit_ttl = false;
        let mut class = false;
        while let Some(field) = fields.get(i) {
            if field.eq_ignore_ascii_case("IN") && !class {
                class = true;
                i += 1;
            } else if valid_ttl(field) && !explicit_ttl {
                ttl = true;
                explicit_ttl = true;
                i += 1;
            } else {
                break;
            }
        }
        if !ttl {
            return Err(error("record needs a TTL or a $TTL default"));
        }
        if explicit_ttl {
            inherited_ttl = true;
        }
        let kind = fields
            .get(i)
            .ok_or_else(|| error("missing record type"))?
            .to_ascii_uppercase();
        i += 1;
        let data = &fields[i..];
        let valid = match kind.as_str() {
            "A" => data.len() == 1 && data[0].parse::<std::net::Ipv4Addr>().is_ok(),
            "AAAA" => data.len() == 1 && data[0].parse::<std::net::Ipv6Addr>().is_ok(),
            "CNAME" | "NS" | "PTR" => data.len() == 1 && valid_name(&data[0]),
            "MX" => data.len() == 2 && data[0].parse::<u16>().is_ok() && valid_name(&data[1]),
            "SRV" => {
                data.len() == 4
                    && data[..3].iter().all(|s| s.parse::<u16>().is_ok())
                    && valid_name(&data[3])
            }
            "CAA" => {
                data.len() == 3
                    && data[0].parse::<u8>().is_ok()
                    && decode_value(&data[1]).is_some_and(|s| {
                        !s.is_empty() && s.len() <= 15 && s.iter().all(u8::is_ascii_alphanumeric)
                    })
                    && decode_value(&data[2]).is_some()
            }
            "TXT" => {
                !data.is_empty()
                    && data
                        .iter()
                        .all(|s| decode_value(s).is_some_and(|s| s.len() <= 255))
            }
            "HTTPS" | "SVCB" => {
                data.len() >= 2
                    && data[0].parse::<u16>().is_ok()
                    && valid_name(&data[1])
                    && valid_service_params(&data[2..])
            }
            "SOA" => {
                data.len() == 7
                    && data[..2].iter().all(|s| valid_name(s))
                    && data[2].parse::<u32>().is_ok()
                    && data[3..].iter().all(|s| valid_ttl(s))
            }
            "URI" => {
                data.len() == 3
                    && data[..2].iter().all(|s| s.parse::<u16>().is_ok())
                    && decode_value(&data[2]).is_some()
            }
            "NAPTR" => {
                data.len() == 6
                    && data[..2].iter().all(|s| s.parse::<u16>().is_ok())
                    && data[2..5].iter().all(|s| decode_value(s).is_some())
                    && valid_name(&data[5])
            }
            "DS" => {
                data.len() >= 4
                    && data[0].parse::<u16>().is_ok()
                    && data[1..3].iter().all(|s| s.parse::<u8>().is_ok())
                    && valid_hex_data(&data[3..])
            }
            "SSHFP" => {
                data.len() >= 3
                    && data[..2].iter().all(|s| s.parse::<u8>().is_ok())
                    && valid_hex_data(&data[2..])
            }
            "TLSA" | "SMIMEA" => {
                data.len() >= 4
                    && data[..3].iter().all(|s| s.parse::<u8>().is_ok())
                    && valid_hex_data(&data[3..])
            }
            "DNSKEY" => {
                data.len() >= 4
                    && data[0].parse::<u16>().is_ok()
                    && data[1] == "3"
                    && data[2].parse::<u8>().is_ok()
                    && valid_base64_data(&data[3..])
            }
            "CERT" => {
                data.len() >= 4
                    && (data[0].parse::<u16>().is_ok()
                        || matches!(
                            data[0].as_str(),
                            "PKIX"
                                | "SPKI"
                                | "PGP"
                                | "IPKIX"
                                | "ISPKI"
                                | "IPGP"
                                | "ACPKIX"
                                | "IACPKIX"
                                | "URI"
                                | "OID"
                        ))
                    && data[1].parse::<u16>().is_ok()
                    && data[2].parse::<u8>().is_ok()
                    && valid_base64_data(&data[3..])
            }
            _ => false,
        };
        if !valid {
            return Err(error("unsupported record type or invalid record data"));
        }
        let resolve = |s: &str| {
            canonical_name(s, &origin).ok_or_else(|| error("invalid origin-relative DNS name"))
        };
        let mut canonical_data: Vec<Vec<u8>> = data
            .iter()
            .map(|s| decode_value(s).unwrap_or_else(|| s.as_bytes().to_vec()))
            .collect();
        match kind.as_str() {
            "A" | "AAAA" => {
                canonical_data[0] = data[0]
                    .parse::<std::net::IpAddr>()
                    .unwrap()
                    .to_string()
                    .into_bytes()
            }
            "CNAME" | "NS" | "PTR" => canonical_data[0] = resolve(&data[0])?.into_bytes(),
            "MX" => {
                canonical_data[0] = data[0].parse::<u16>().unwrap().to_string().into_bytes();
                canonical_data[1] = resolve(&data[1])?.into_bytes();
            }
            "SRV" => {
                for i in 0..3 {
                    canonical_data[i] = data[i].parse::<u16>().unwrap().to_string().into_bytes();
                }
                canonical_data[3] = resolve(&data[3])?.into_bytes();
            }
            "HTTPS" | "SVCB" => {
                canonical_data[0] = data[0].parse::<u16>().unwrap().to_string().into_bytes();
                canonical_data[1] = resolve(&data[1])?.into_bytes();
                canonical_data[2..].sort();
            }
            "CAA" => canonical_data[0] = data[0].parse::<u8>().unwrap().to_string().into_bytes(),
            "SOA" => {
                canonical_data[0] = resolve(&data[0])?.into_bytes();
                canonical_data[1] = resolve(&data[1])?.into_bytes();
            }
            "NAPTR" => canonical_data[5] = resolve(&data[5])?.into_bytes(),
            _ => {}
        }
        if !seen.insert((name.clone(), kind.clone(), canonical_data)) {
            return Err(error("duplicate record in zone file"));
        }
        if kind != "SOA" {
            count += 1;
        }
        if count > 10000 {
            return Err(error("too many records (max 10000)"));
        }
    }
    if count == 0 {
        return Err("zone file contains no importable records".to_string());
    }
    Ok(())
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
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !keys.insert(key)
        {
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
