use pnet::packet::ethernet::EthernetPacket;

use super::types::EthernetFields;

const ETHERNET_HEADER_LEN: usize = 14;

fn format_mac(addr: pnet::util::MacAddr) -> String {
    let o = addr.octets();
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        o[0], o[1], o[2], o[3], o[4], o[5]
    )
}

fn ethertype_name(ethertype: u16) -> String {
    match ethertype {
        0x0800 => "IPv4".to_string(),
        0x0806 => "ARP".to_string(),
        0x86DD => "IPv6".to_string(),
        0x8100 => "802.1Q".to_string(),
        other => format!("0x{:04x}", other),
    }
}

pub fn parse_ethernet(data: &[u8]) -> Option<(EthernetFields, &[u8])> {
    let packet = EthernetPacket::new(data)?;

    let raw_ethertype = packet.get_ethertype().0;

    let fields = EthernetFields {
        src_mac: format_mac(packet.get_source()),
        dst_mac: format_mac(packet.get_destination()),
        ethertype: raw_ethertype,
        ethertype_name: ethertype_name(raw_ethertype),
    };

    // Slice from original data to avoid lifetime issues with packet borrow
    let payload = if data.len() > ETHERNET_HEADER_LEN {
        &data[ETHERNET_HEADER_LEN..]
    } else {
        &data[data.len()..]
    };

    Some((fields, payload))
}
