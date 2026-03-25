use pnet::packet::ipv4::Ipv4Packet;

use super::types::{Ipv4Fields, Ipv4Flags};

fn ip_protocol_name(proto: u8) -> String {
    match proto {
        1 => "ICMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        41 => "IPv6-in-IPv4".to_string(),
        47 => "GRE".to_string(),
        58 => "ICMPv6".to_string(),
        other => format!("Proto({})", other),
    }
}

pub fn parse_ipv4(data: &[u8]) -> Option<(Ipv4Fields, &[u8])> {
    let packet = Ipv4Packet::new(data)?;

    let raw_flags = packet.get_flags();
    let flags = Ipv4Flags {
        dont_fragment: (raw_flags & 0b010) != 0,
        more_fragments: (raw_flags & 0b001) != 0,
    };

    let proto = packet.get_next_level_protocol().0;
    let header_len = (packet.get_header_length() as usize) * 4;
    let total_len = packet.get_total_length() as usize;

    let fields = Ipv4Fields {
        src: packet.get_source().to_string(),
        dst: packet.get_destination().to_string(),
        ttl: packet.get_ttl(),
        protocol: proto,
        protocol_name: ip_protocol_name(proto),
        total_len: packet.get_total_length(),
        flags,
        fragment_offset: packet.get_fragment_offset(),
        checksum: packet.get_checksum(),
    };

    // Slice from the original data to avoid lifetime issues with the packet borrow
    let payload_end = total_len.min(data.len());
    let payload = if header_len <= payload_end {
        &data[header_len..payload_end]
    } else {
        &data[data.len()..] // empty slice
    };

    Some((fields, payload))
}
