pub fn cipher_suite_name(id: u16) -> String {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        0x1304 => "TLS_AES_128_CCM_SHA256".to_string(),
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".to_string(),
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".to_string(),
        0xC009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".to_string(),
        0xC00A => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA".to_string(),
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".to_string(),
        0x00FF => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV".to_string(),
        0x5600 => "TLS_FALLBACK_SCSV".to_string(),
        0x0A0A | 0x1A1A | 0x2A2A | 0x3A3A | 0x4A4A | 0x5A5A | 0x6A6A | 0x7A7A | 0x8A8A | 0x9A9A
        | 0xAAAA | 0xBABA | 0xCACA | 0xDADA | 0xEAEA | 0xFAFA => "GREASE".to_string(),
        _ => format!("0x{:04X}", id),
    }
}
