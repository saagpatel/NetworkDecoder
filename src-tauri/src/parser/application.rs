use super::cipher_suites;
use super::types::{DnsFields, DnsQuestion, DnsRecord, HttpFields, TlsFields};

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"PATCH ",
    b"OPTIONS ",
    b"CONNECT ",
];

const HTTP_RESPONSE_PREFIXES: &[&[u8]] = &[b"HTTP/1.", b"HTTP/2"];

pub fn try_parse_http(payload: &[u8]) -> Option<HttpFields> {
    let is_request = HTTP_METHODS.iter().any(|m| payload.starts_with(m));
    let is_response = HTTP_RESPONSE_PREFIXES
        .iter()
        .any(|p| payload.starts_with(p));

    if !is_request && !is_response {
        return None;
    }

    let text = String::from_utf8_lossy(payload);
    let mut lines = text.split("\r\n");

    let first_line = lines.next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }

    let (method, path, status_code, status_text, version) = if is_request {
        let method = parts[0].to_string();
        let path = parts[1].to_string();
        let version = parts.get(2).unwrap_or(&"HTTP/1.1").to_string();
        (Some(method), Some(path), None, None, version)
    } else {
        let version = parts[0].to_string();
        let code: u16 = parts[1].parse().ok()?;
        let text = parts.get(2).map(|s| s.to_string());
        (None, None, Some(code), text, version)
    };

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    Some(HttpFields {
        method,
        path,
        status_code,
        status_text,
        version,
        headers,
        is_request,
    })
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        255 => "ANY".to_string(),
        other => format!("TYPE{}", other),
    }
}

/// Read a DNS name from `data` starting at `offset`.
/// Returns `(name, bytes_consumed)` where bytes_consumed is the number of
/// bytes advanced in the *current* position (not following pointers).
fn read_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut bytes_consumed: Option<usize> = None;
    let mut jumps = 0u8;

    loop {
        if jumps > 30 {
            return None; // prevent infinite pointer loops
        }
        if pos >= data.len() {
            return None;
        }

        let len_byte = data[pos];

        if len_byte == 0 {
            // End of name
            if bytes_consumed.is_none() {
                bytes_consumed = Some(pos + 1 - offset);
            }
            break;
        }

        if len_byte & 0xC0 == 0xC0 {
            // Compression pointer
            if pos + 1 >= data.len() {
                return None;
            }
            if bytes_consumed.is_none() {
                bytes_consumed = Some(pos + 2 - offset);
            }
            let ptr = ((len_byte as usize & 0x3F) << 8) | data[pos + 1] as usize;
            if ptr >= data.len() {
                return None;
            }
            pos = ptr;
            jumps += 1;
        } else {
            // Normal label
            let label_len = len_byte as usize;
            if pos + 1 + label_len > data.len() {
                return None;
            }
            let label = String::from_utf8_lossy(&data[pos + 1..pos + 1 + label_len]).to_string();
            labels.push(label);
            pos += 1 + label_len;
        }
    }

    let consumed = match bytes_consumed {
        Some(c) => c,
        None => {
            if pos < offset {
                return None;
            }
            pos - offset
        }
    };
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Some((name, consumed))
}

pub fn try_parse_dns(payload: &[u8]) -> Option<DnsFields> {
    if payload.len() < 12 {
        return None;
    }

    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

    let mut pos = 12usize;
    let mut questions = Vec::new();

    for _ in 0..qdcount {
        let (name, consumed) = read_dns_name(payload, pos)?;
        pos += consumed;
        if pos + 4 > payload.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        // skip QCLASS
        pos += 4;
        questions.push(DnsQuestion {
            name,
            qtype: qtype_name(qtype),
        });
    }

    let mut answers = Vec::new();

    for _ in 0..ancount {
        let (name, consumed) = read_dns_name(payload, pos)?;
        pos += consumed;
        if pos + 10 > payload.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        // skip CLASS (2 bytes)
        let ttl = u32::from_be_bytes([
            payload[pos + 4],
            payload[pos + 5],
            payload[pos + 6],
            payload[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([payload[pos + 8], payload[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > payload.len() {
            return None;
        }

        let data = match rtype {
            1 if rdlength == 4 => {
                // A record
                format!(
                    "{}.{}.{}.{}",
                    payload[pos],
                    payload[pos + 1],
                    payload[pos + 2],
                    payload[pos + 3]
                )
            }
            28 if rdlength == 16 => {
                // AAAA record
                let mut parts = Vec::with_capacity(8);
                for i in 0..8 {
                    let word = u16::from_be_bytes([payload[pos + i * 2], payload[pos + i * 2 + 1]]);
                    parts.push(format!("{:x}", word));
                }
                parts.join(":")
            }
            5 | 2 | 12 => {
                // CNAME, NS, PTR — domain name
                read_dns_name(payload, pos)
                    .map(|(n, _)| n)
                    .unwrap_or_else(|| format!("<rdata {} bytes>", rdlength))
            }
            _ => format!("<rdata {} bytes>", rdlength),
        };

        pos += rdlength;

        answers.push(DnsRecord {
            name,
            rtype: qtype_name(rtype),
            ttl,
            data,
        });
    }

    Some(DnsFields {
        transaction_id,
        is_response,
        questions,
        answers,
    })
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

fn tls_version_string(major: u8, minor: u8) -> String {
    match (major, minor) {
        (3, 1) => "TLS 1.0".to_string(),
        (3, 2) => "TLS 1.1".to_string(),
        (3, 3) => "TLS 1.2".to_string(),
        (3, 4) => "TLS 1.3".to_string(),
        (3, 0) => "SSL 3.0".to_string(),
        _ => format!("TLS {:02X}.{:02X}", major, minor),
    }
}

pub fn try_parse_tls(payload: &[u8]) -> Option<TlsFields> {
    // TLS record header: 5 bytes minimum
    if payload.len() < 6 {
        return None;
    }

    let content_type = payload[0];
    if content_type != 22 {
        // Only parse Handshake records
        return None;
    }

    let record_version_major = payload[1];
    let record_version_minor = payload[2];
    let record_length = u16::from_be_bytes([payload[3], payload[4]]) as usize;

    // Sanity check record length
    if payload.len() < 5 + record_length.min(payload.len()) {
        // Truncated, but try to parse what we have
    }

    // Handshake header at byte 5
    if payload.len() < 9 {
        return None;
    }

    let handshake_type = payload[5];
    let _handshake_length =
        ((payload[6] as usize) << 16) | ((payload[7] as usize) << 8) | (payload[8] as usize);

    let record_type = match handshake_type {
        1 => "ClientHello",
        2 => "ServerHello",
        _ => return None, // Only parse Hello messages
    };

    if handshake_type == 1 {
        parse_client_hello(
            payload,
            record_type,
            record_version_major,
            record_version_minor,
        )
    } else {
        parse_server_hello(
            payload,
            record_type,
            record_version_major,
            record_version_minor,
        )
    }
}

fn parse_client_hello(
    payload: &[u8],
    record_type: &str,
    _record_major: u8,
    _record_minor: u8,
) -> Option<TlsFields> {
    // ClientHello body starts at byte 9
    if payload.len() < 44 {
        return None;
    }

    let client_major = payload[9];
    let client_minor = payload[10];
    // bytes 11..43: 32 bytes random (skip)

    let mut pos = 43usize;

    // Session ID
    if pos >= payload.len() {
        return None;
    }
    let session_id_len = payload[pos] as usize;
    pos += 1;
    let session_id = if session_id_len > 0 {
        if pos + session_id_len > payload.len() {
            return None;
        }
        let hex: String = payload[pos..pos + session_id_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        pos += session_id_len;
        Some(hex)
    } else {
        None
    };

    // Cipher suites
    if pos + 2 > payload.len() {
        return None;
    }
    let cs_length = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_length > payload.len() {
        return None;
    }

    let mut cipher_suites = Vec::new();
    let cs_end = pos + cs_length;
    while pos + 1 < cs_end {
        let suite_id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        cipher_suites.push(cipher_suites::cipher_suite_name(suite_id));
        pos += 2;
    }
    pos = cs_end;

    // Compression methods (skip)
    if pos >= payload.len() {
        return Some(build_tls_fields(
            record_type,
            client_major,
            client_minor,
            None,
            cipher_suites,
            session_id,
        ));
    }
    let comp_len = payload[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    let mut sni: Option<String> = None;
    let mut tls_version = tls_version_string(client_major, client_minor);

    if pos + 2 <= payload.len() {
        let ext_length = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_length).min(payload.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
            let ext_data_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
            pos += 4;

            if pos + ext_data_len > ext_end {
                break;
            }

            match ext_type {
                0x0000 => {
                    // SNI
                    sni = parse_sni_extension(&payload[pos..pos + ext_data_len]);
                }
                0x002B => {
                    // supported_versions
                    if let Some(ver) =
                        parse_supported_versions_client(&payload[pos..pos + ext_data_len])
                    {
                        tls_version = ver;
                    }
                }
                _ => {}
            }

            pos += ext_data_len;
        }
    }

    Some(TlsFields {
        record_type: record_type.to_string(),
        tls_version,
        sni,
        cipher_suites,
        session_id,
    })
}

fn parse_server_hello(
    payload: &[u8],
    record_type: &str,
    _record_major: u8,
    _record_minor: u8,
) -> Option<TlsFields> {
    if payload.len() < 44 {
        return None;
    }

    let server_major = payload[9];
    let server_minor = payload[10];
    // 32 bytes random (skip)

    let mut pos = 43usize;

    // Session ID
    if pos >= payload.len() {
        return None;
    }
    let session_id_len = payload[pos] as usize;
    pos += 1;
    let session_id = if session_id_len > 0 {
        if pos + session_id_len > payload.len() {
            return None;
        }
        let hex: String = payload[pos..pos + session_id_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        pos += session_id_len;
        Some(hex)
    } else {
        None
    };

    // Single selected cipher suite
    if pos + 2 > payload.len() {
        return None;
    }
    let suite_id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    let cipher_suites = vec![cipher_suites::cipher_suite_name(suite_id)];
    pos += 2;

    // Compression method (1 byte, skip)
    if pos >= payload.len() {
        return Some(build_tls_fields(
            record_type,
            server_major,
            server_minor,
            None,
            cipher_suites,
            session_id,
        ));
    }
    pos += 1;

    // Extensions
    let mut tls_version = tls_version_string(server_major, server_minor);

    if pos + 2 <= payload.len() {
        let ext_length = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_length).min(payload.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
            let ext_data_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
            pos += 4;

            if pos + ext_data_len > ext_end {
                break;
            }

            if ext_type == 0x002B {
                // supported_versions (server: direct 2-byte version, no length prefix)
                if ext_data_len == 2 {
                    tls_version = tls_version_string(payload[pos], payload[pos + 1]);
                }
            }

            pos += ext_data_len;
        }
    }

    Some(TlsFields {
        record_type: record_type.to_string(),
        tls_version,
        sni: None, // ServerHello doesn't have SNI
        cipher_suites,
        session_id,
    })
}

fn build_tls_fields(
    record_type: &str,
    major: u8,
    minor: u8,
    sni: Option<String>,
    cipher_suites: Vec<String>,
    session_id: Option<String>,
) -> TlsFields {
    TlsFields {
        record_type: record_type.to_string(),
        tls_version: tls_version_string(major, minor),
        sni,
        cipher_suites,
        session_id,
    }
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // server_name_list_length (2 bytes)
    if data.len() < 5 {
        return None;
    }
    // let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let name_type = data[2];
    if name_type != 0 {
        return None; // only host_name type
    }
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + name_len {
        return None;
    }
    String::from_utf8(data[5..5 + name_len].to_vec()).ok()
}

fn parse_supported_versions_client(data: &[u8]) -> Option<String> {
    // Client: 1 byte list length, then 2-byte version entries
    if data.is_empty() {
        return None;
    }
    let list_len = data[0] as usize;
    if data.len() < 1 + list_len || list_len < 2 {
        return None;
    }
    // Pick the highest version advertised
    let mut best: Option<(u8, u8)> = None;
    let mut pos = 1;
    let end = 1 + list_len;
    while pos + 1 < end {
        let major = data[pos];
        let minor = data[pos + 1];
        pos += 2;
        match best {
            None => best = Some((major, minor)),
            Some((bm, bn)) => {
                if (major, minor) > (bm, bn) {
                    best = Some((major, minor));
                }
            }
        }
    }
    best.map(|(m, n)| tls_version_string(m, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_request() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n";
        let result = try_parse_http(payload).expect("should parse HTTP request");
        assert!(result.is_request);
        assert_eq!(result.method.as_deref(), Some("GET"));
        assert_eq!(result.path.as_deref(), Some("/index.html"));
        assert_eq!(result.version, "HTTP/1.1");
        assert_eq!(result.headers.len(), 2);
        assert_eq!(
            result.headers[0],
            ("Host".to_string(), "example.com".to_string())
        );
    }

    #[test]
    fn test_parse_http_response() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>";
        let result = try_parse_http(payload).expect("should parse HTTP response");
        assert!(!result.is_request);
        assert_eq!(result.status_code, Some(200));
        assert_eq!(result.status_text.as_deref(), Some("OK"));
        assert_eq!(result.version, "HTTP/1.1");
    }

    #[test]
    fn test_parse_http_rejects_non_http() {
        assert!(try_parse_http(b"\x16\x03\x01").is_none());
        assert!(try_parse_http(b"random data here").is_none());
    }

    #[test]
    fn test_dns_name_simple() {
        // "example.com" = \x07example\x03com\x00
        let data = b"\x07example\x03com\x00";
        let (name, consumed) = read_dns_name(data, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_dns_name_with_pointer() {
        // At offset 0: \x07example\x03com\x00 (13 bytes)
        // At offset 13: pointer to offset 0 → \xC0\x00
        let mut data = b"\x07example\x03com\x00".to_vec();
        data.extend_from_slice(&[0xC0, 0x00]);
        let (name, consumed) = read_dns_name(&data, 13).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(consumed, 2); // just the pointer
    }

    #[test]
    fn test_dns_query_parse() {
        // Minimal DNS query for "example.com" type A
        let mut pkt = vec![
            0x12, 0x34, // transaction ID
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        // QNAME: example.com
        pkt.extend_from_slice(b"\x07example\x03com\x00");
        // QTYPE A = 1, QCLASS IN = 1
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let dns = try_parse_dns(&pkt).expect("should parse DNS query");
        assert!(!dns.is_response);
        assert_eq!(dns.transaction_id, 0x1234);
        assert_eq!(dns.questions.len(), 1);
        assert_eq!(dns.questions[0].name, "example.com");
        assert_eq!(dns.questions[0].qtype, "A");
        assert!(dns.answers.is_empty());
    }

    #[test]
    fn test_dns_response_with_answer() {
        let mut pkt = vec![
            0xAB, 0xCD, // transaction ID
            0x81, 0x80, // flags: response
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, 0x00, 0x00,
        ];
        // Question: example.com A
        pkt.extend_from_slice(b"\x07example\x03com\x00");
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Answer: pointer to offset 12 (the question name), A record, TTL 300, 4 bytes
        pkt.extend_from_slice(&[
            0xC0, 0x0C, // name pointer
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
            0x00, 0x00, 0x01, 0x2C, // TTL 300
            0x00, 0x04, // RDLENGTH 4
            93, 184, 216, 34, // 93.184.216.34
        ]);

        let dns = try_parse_dns(&pkt).expect("should parse DNS response");
        assert!(dns.is_response);
        assert_eq!(dns.answers.len(), 1);
        assert_eq!(dns.answers[0].data, "93.184.216.34");
        assert_eq!(dns.answers[0].ttl, 300);
        assert_eq!(dns.answers[0].rtype, "A");
    }
}
