pub mod application;
pub mod cipher_suites;
pub mod ethernet;
pub mod ip;
pub mod transport;
pub mod types;

use types::*;

fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn compute_stream_id(ip_src: &str, port_src: u16, ip_dst: &str, port_dst: u16) -> u64 {
    let a = format!("{}:{}|{}:{}", ip_src, port_src, ip_dst, port_dst);
    let b = format!("{}:{}|{}:{}", ip_dst, port_dst, ip_src, port_src);
    let canonical = if a < b { a } else { b };
    fnv1a_hash(canonical.as_bytes())
}

fn format_tcp_flags(flags: &TcpFlags) -> String {
    let mut parts = Vec::new();
    if flags.syn {
        parts.push("SYN");
    }
    if flags.ack {
        parts.push("ACK");
    }
    if flags.fin {
        parts.push("FIN");
    }
    if flags.rst {
        parts.push("RST");
    }
    if flags.psh {
        parts.push("PSH");
    }
    if flags.urg {
        parts.push("URG");
    }
    if flags.ece {
        parts.push("ECE");
    }
    if flags.cwr {
        parts.push("CWR");
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" [{}]", parts.join(", "))
    }
}

pub fn parse_packet(
    id: u64,
    timestamp_us: i64,
    capture_len: u32,
    original_len: u32,
    interface: &str,
    data: &[u8],
) -> PacketRecord {
    let mut layers: Vec<LayerEntry> = Vec::new();
    let mut protocol = TopProtocol::Unknown;
    let mut src_addr: Option<String> = None;
    let mut dst_addr: Option<String> = None;
    let mut stream_id: Option<u64> = None;
    let mut info = String::new();
    let mut current_offset: usize = 0;

    // Layer 2: Ethernet
    let remaining = match ethernet::parse_ethernet(data) {
        Some((eth_fields, payload)) => {
            let ethertype = eth_fields.ethertype;
            let eth_len = 14;
            layers.push(LayerEntry {
                data: LayerData::Ethernet(eth_fields),
                byte_offset: 0,
                byte_len: eth_len,
            });
            current_offset = eth_len;
            protocol = TopProtocol::Ethernet;
            Some((ethertype, payload))
        }
        None => {
            layers.push(LayerEntry {
                data: LayerData::Raw(data.to_vec()),
                byte_offset: 0,
                byte_len: data.len(),
            });
            None
        }
    };

    // Layer 3: IP
    let transport_data = if let Some((ethertype, eth_payload)) = remaining {
        match ethertype {
            0x0800 => {
                // IPv4
                match ip::parse_ipv4(eth_payload) {
                    Some((ipv4_fields, payload)) => {
                        let ip_proto = ipv4_fields.protocol;
                        let ip_src = ipv4_fields.src.clone();
                        let ip_dst = ipv4_fields.dst.clone();
                        src_addr = Some(ip_src.clone());
                        dst_addr = Some(ip_dst.clone());

                        // Calculate actual IPv4 header length from the packet
                        let ipv4_header_len = if eth_payload.len() >= 1 {
                            ((eth_payload[0] & 0x0F) as usize) * 4
                        } else {
                            20
                        };

                        layers.push(LayerEntry {
                            data: LayerData::Ipv4(ipv4_fields),
                            byte_offset: current_offset,
                            byte_len: ipv4_header_len,
                        });
                        current_offset += ipv4_header_len;
                        protocol = TopProtocol::Ipv4;
                        Some((ip_proto, ip_src, ip_dst, payload.to_vec()))
                    }
                    None => {
                        let raw_len = eth_payload.len();
                        layers.push(LayerEntry {
                            data: LayerData::Raw(eth_payload.to_vec()),
                            byte_offset: current_offset,
                            byte_len: raw_len,
                        });
                        None
                    }
                }
            }
            0x0806 => {
                protocol = TopProtocol::Arp;
                info = "ARP".to_string();
                let raw_len = eth_payload.len();
                layers.push(LayerEntry {
                    data: LayerData::Raw(eth_payload.to_vec()),
                    byte_offset: current_offset,
                    byte_len: raw_len,
                });
                None
            }
            _ => {
                let raw_len = eth_payload.len();
                layers.push(LayerEntry {
                    data: LayerData::Raw(eth_payload.to_vec()),
                    byte_offset: current_offset,
                    byte_len: raw_len,
                });
                None
            }
        }
    } else {
        None
    };

    // Layer 4: Transport
    if let Some((ip_proto, ip_src, ip_dst, transport_payload)) = transport_data {
        match ip_proto {
            6 => {
                // TCP
                if let Some(tcp_fields) = transport::parse_tcp(&transport_payload) {
                    let sp = tcp_fields.src_port;
                    let dp = tcp_fields.dst_port;
                    src_addr = Some(format!("{}:{}", ip_src, sp));
                    dst_addr = Some(format!("{}:{}", ip_dst, dp));
                    stream_id = Some(compute_stream_id(&ip_src, sp, &ip_dst, dp));

                    let flag_str = format_tcp_flags(&tcp_fields.flags);
                    info = format!(
                        "TCP {}:{} \u{2192} {}:{}{}",
                        ip_src, sp, ip_dst, dp, flag_str
                    );

                    // TCP header length = data offset * 4
                    let tcp_header_len = if transport_payload.len() >= 13 {
                        ((transport_payload[12] >> 4) as usize) * 4
                    } else {
                        20
                    };

                    layers.push(LayerEntry {
                        data: LayerData::Tcp(tcp_fields),
                        byte_offset: current_offset,
                        byte_len: tcp_header_len,
                    });
                    current_offset += tcp_header_len;
                    protocol = TopProtocol::Tcp;

                    // Application layer parsing
                    let app_payload = &transport_payload[tcp_header_len..];
                    if !app_payload.is_empty() {
                        let app_len = app_payload.len();
                        if dp == 53 || sp == 53 {
                            if let Some(dns) = application::try_parse_dns(app_payload) {
                                let first_q = dns
                                    .questions
                                    .first()
                                    .map(|q| q.name.as_str())
                                    .unwrap_or("?");
                                let qtype = dns
                                    .questions
                                    .first()
                                    .map(|q| q.qtype.as_str())
                                    .unwrap_or("?");
                                if dns.is_response {
                                    let first_ans =
                                        dns.answers.first().map(|a| a.data.as_str()).unwrap_or("?");
                                    info =
                                        format!("DNS {} {} \u{2192} {}", qtype, first_q, first_ans);
                                } else {
                                    info = format!("DNS {} {}", qtype, first_q);
                                }
                                protocol = TopProtocol::Dns;
                                layers.push(LayerEntry {
                                    data: LayerData::Dns(dns),
                                    byte_offset: current_offset,
                                    byte_len: app_len,
                                });
                            }
                        } else if let Some(tls) = application::try_parse_tls(app_payload) {
                            let sni_part = tls
                                .sni
                                .as_deref()
                                .map(|s| format!(" \u{2192} {}", s))
                                .unwrap_or_default();
                            info = format!(
                                "TLS {}{} ({})",
                                tls.record_type, sni_part, tls.tls_version
                            );
                            protocol = TopProtocol::Tls;
                            layers.push(LayerEntry {
                                data: LayerData::Tls(tls),
                                byte_offset: current_offset,
                                byte_len: app_len,
                            });
                        } else if let Some(http) = application::try_parse_http(app_payload) {
                            if http.is_request {
                                info = format!(
                                    "{} {} {}",
                                    http.method.as_deref().unwrap_or("?"),
                                    http.path.as_deref().unwrap_or("/"),
                                    http.version
                                );
                            } else {
                                info = format!(
                                    "{} {} {}",
                                    http.version,
                                    http.status_code.map(|c| c.to_string()).unwrap_or_default(),
                                    http.status_text.as_deref().unwrap_or("")
                                );
                            }
                            protocol = TopProtocol::Http;
                            layers.push(LayerEntry {
                                data: LayerData::Http(http),
                                byte_offset: current_offset,
                                byte_len: app_len,
                            });
                        }
                    }
                } else {
                    let raw_len = transport_payload.len();
                    layers.push(LayerEntry {
                        data: LayerData::Raw(transport_payload),
                        byte_offset: current_offset,
                        byte_len: raw_len,
                    });
                }
            }
            17 => {
                // UDP
                if let Some(udp_fields) = transport::parse_udp(&transport_payload) {
                    let sp = udp_fields.src_port;
                    let dp = udp_fields.dst_port;
                    src_addr = Some(format!("{}:{}", ip_src, sp));
                    dst_addr = Some(format!("{}:{}", ip_dst, dp));
                    stream_id = Some(compute_stream_id(&ip_src, sp, &ip_dst, dp));

                    info = format!(
                        "UDP {}:{} \u{2192} {}:{} len={}",
                        ip_src, sp, ip_dst, dp, udp_fields.payload_len
                    );

                    layers.push(LayerEntry {
                        data: LayerData::Udp(udp_fields),
                        byte_offset: current_offset,
                        byte_len: 8,
                    });
                    current_offset += 8;
                    protocol = TopProtocol::Udp;

                    // Application layer: DNS over UDP
                    let app_payload = &transport_payload[8..];
                    if !app_payload.is_empty() && (dp == 53 || sp == 53) {
                        let app_len = app_payload.len();
                        if let Some(dns) = application::try_parse_dns(app_payload) {
                            let first_q = dns
                                .questions
                                .first()
                                .map(|q| q.name.as_str())
                                .unwrap_or("?");
                            let qtype = dns
                                .questions
                                .first()
                                .map(|q| q.qtype.as_str())
                                .unwrap_or("?");
                            if dns.is_response {
                                let first_ans =
                                    dns.answers.first().map(|a| a.data.as_str()).unwrap_or("?");
                                info = format!("DNS {} {} \u{2192} {}", qtype, first_q, first_ans);
                            } else {
                                info = format!("DNS {} {}", qtype, first_q);
                            }
                            protocol = TopProtocol::Dns;
                            layers.push(LayerEntry {
                                data: LayerData::Dns(dns),
                                byte_offset: current_offset,
                                byte_len: app_len,
                            });
                        }
                    }
                } else {
                    let raw_len = transport_payload.len();
                    layers.push(LayerEntry {
                        data: LayerData::Raw(transport_payload),
                        byte_offset: current_offset,
                        byte_len: raw_len,
                    });
                }
            }
            1 => {
                protocol = TopProtocol::Icmp;
                info = format!("ICMP {} \u{2192} {}", ip_src, ip_dst);
                let raw_len = transport_payload.len();
                layers.push(LayerEntry {
                    data: LayerData::Raw(transport_payload),
                    byte_offset: current_offset,
                    byte_len: raw_len,
                });
            }
            _ => {
                info = format!("IP Proto({}) {} \u{2192} {}", ip_proto, ip_src, ip_dst);
                let raw_len = transport_payload.len();
                layers.push(LayerEntry {
                    data: LayerData::Raw(transport_payload),
                    byte_offset: current_offset,
                    byte_len: raw_len,
                });
            }
        }
    }

    if info.is_empty() {
        info = format!("{:?}", protocol);
    }

    PacketRecord {
        id,
        timestamp_us,
        capture_len,
        original_len,
        interface: interface.to_string(),
        layers,
        protocol,
        src_addr,
        dst_addr,
        stream_id,
        info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_cap_first_5_packets() {
        let mut cap =
            pcap::Capture::from_file("tests/fixtures/http.cap").expect("Failed to open http.cap");

        let mut records = Vec::new();
        let mut count = 0;
        while let Ok(packet) = cap.next_packet() {
            if count >= 5 {
                break;
            }
            let timestamp_us =
                packet.header.ts.tv_sec as i64 * 1_000_000 + packet.header.ts.tv_usec as i64;
            let record = parse_packet(
                count as u64,
                timestamp_us,
                packet.header.caplen,
                packet.header.len,
                "test",
                packet.data,
            );
            println!(
                "Packet {}: src={:?} dst={:?} proto={:?} stream_id={:?} info={}",
                record.id,
                record.src_addr,
                record.dst_addr,
                record.protocol,
                record.stream_id,
                record.info
            );
            assert!(
                record.src_addr.is_some(),
                "Packet {} missing src_addr",
                count
            );
            assert!(
                record.dst_addr.is_some(),
                "Packet {} missing dst_addr",
                count
            );
            assert!(!record.layers.is_empty(), "Packet {} has no layers", count);
            // Verify LayerEntry structure: first layer should be Ethernet at offset 0
            let first = &record.layers[0];
            assert_eq!(first.byte_offset, 0);
            assert!(matches!(first.data, LayerData::Ethernet(_)));
            // TCP packets should have a stream_id
            if matches!(record.protocol, TopProtocol::Tcp) {
                assert!(
                    record.stream_id.is_some(),
                    "Packet {} is TCP but missing stream_id",
                    count
                );
            }
            records.push(record);
            count += 1;
        }
        assert_eq!(count, 5);

        // Packets 0 (SYN) and 1 (SYN-ACK) are part of the same TCP connection
        assert_eq!(
            records[0].stream_id, records[1].stream_id,
            "Packet 0 and 1 should share the same stream_id (same TCP connection)"
        );
    }

    #[test]
    fn test_stream_id_consistency() {
        let mut cap =
            pcap::Capture::from_file("tests/fixtures/http.cap").expect("Failed to open http.cap");

        let mut stream_ids = std::collections::HashSet::new();
        let mut count = 0u64;
        while let Ok(packet) = cap.next_packet() {
            let timestamp_us =
                packet.header.ts.tv_sec as i64 * 1_000_000 + packet.header.ts.tv_usec as i64;
            let record = parse_packet(
                count,
                timestamp_us,
                packet.header.caplen,
                packet.header.len,
                "test",
                packet.data,
            );
            if let Some(sid) = record.stream_id {
                stream_ids.insert(sid);
            }
            count += 1;
        }
        println!(
            "Parsed {} packets, found {} unique stream IDs",
            count,
            stream_ids.len()
        );
        assert!(
            stream_ids.len() <= 20,
            "Expected at most 20 unique stream IDs in http.cap, got {}",
            stream_ids.len()
        );
    }

    #[test]
    fn test_parse_http_application_layer() {
        let mut cap =
            pcap::Capture::from_file("tests/fixtures/http.cap").expect("Failed to open http.cap");

        let mut http_count = 0;
        let mut id = 0u64;
        while let Ok(packet) = cap.next_packet() {
            let timestamp_us =
                packet.header.ts.tv_sec as i64 * 1_000_000 + packet.header.ts.tv_usec as i64;
            let record = parse_packet(
                id,
                timestamp_us,
                packet.header.caplen,
                packet.header.len,
                "test",
                packet.data,
            );

            for layer in &record.layers {
                if matches!(layer.data, LayerData::Http(_)) {
                    http_count += 1;
                    if let LayerData::Http(ref http) = layer.data {
                        println!(
                            "HTTP: request={} method={:?} path={:?} status={:?}",
                            http.is_request, http.method, http.path, http.status_code
                        );
                    }
                }
            }
            id += 1;
        }
        assert!(
            http_count >= 1,
            "Expected at least 1 HTTP packet, got {}",
            http_count
        );
    }

    #[test]
    fn test_parse_dns_packets() {
        let mut cap =
            pcap::Capture::from_file("tests/fixtures/dns.cap").expect("Failed to open dns.cap");

        let mut dns_count = 0;
        let mut id = 0u64;
        while let Ok(packet) = cap.next_packet() {
            let timestamp_us =
                packet.header.ts.tv_sec as i64 * 1_000_000 + packet.header.ts.tv_usec as i64;
            let record = parse_packet(
                id,
                timestamp_us,
                packet.header.caplen,
                packet.header.len,
                "test",
                packet.data,
            );

            for layer in &record.layers {
                if let LayerData::Dns(ref dns) = layer.data {
                    dns_count += 1;
                    println!(
                        "DNS: response={} questions={:?} answers={:?}",
                        dns.is_response, dns.questions, dns.answers
                    );
                    assert!(
                        !dns.questions.is_empty(),
                        "DNS packet should have questions"
                    );
                }
            }
            id += 1;
        }
        assert!(
            dns_count >= 1,
            "Expected at least 1 DNS packet, got {}",
            dns_count
        );
    }

    #[test]
    fn test_parse_tls_client_hello() {
        // Raw TLS ClientHello with SNI "example.com"
        let client_hello: Vec<u8> = vec![
            // TLS record header
            0x16, // content_type: Handshake
            0x03, 0x01, // version: TLS 1.0 (record layer)
            0x00, 0xF1, // length: 241
            // Handshake header
            0x01, // type: ClientHello
            0x00, 0x00, 0xED, // length: 237
            // ClientHello body
            0x03, 0x03, // version: TLS 1.2
            // 32 bytes random
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, // session_id length
            0x00, // cipher suites length (6 = 3 suites)
            0x00, 0x06, 0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0x00, 0x9C, // TLS_RSA_WITH_AES_128_GCM_SHA256
            // compression methods
            0x01, 0x00, // extensions length
            0x00, 0x98, // SNI extension (type 0x0000)
            0x00, 0x00, // extension type: server_name
            0x00, 0x10, // extension length: 16
            0x00, 0x0E, // server_name_list length: 14
            0x00, // host_name type
            0x00, 0x0B, // hostname length: 11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        ];

        let result = application::try_parse_tls(&client_hello);
        assert!(result.is_some(), "Should parse TLS ClientHello");
        let tls = result.unwrap();
        assert_eq!(tls.record_type, "ClientHello");
        assert_eq!(tls.sni.as_deref(), Some("example.com"));
        assert!(
            tls.cipher_suites.len() >= 3,
            "Expected >= 3 cipher suites, got {}",
            tls.cipher_suites.len()
        );
        println!(
            "TLS: type={} sni={:?} version={} suites={:?}",
            tls.record_type, tls.sni, tls.tls_version, tls.cipher_suites
        );
    }
}
