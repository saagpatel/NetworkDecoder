use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use super::types::{TcpFields, TcpFlags, UdpFields};

pub fn parse_tcp(data: &[u8]) -> Option<TcpFields> {
    let packet = TcpPacket::new(data)?;

    let raw_flags = packet.get_flags();

    let flags = TcpFlags {
        syn: (raw_flags & 0b0000_0010) != 0,
        ack: (raw_flags & 0b0001_0000) != 0,
        fin: (raw_flags & 0b0000_0001) != 0,
        rst: (raw_flags & 0b0000_0100) != 0,
        psh: (raw_flags & 0b0000_1000) != 0,
        urg: (raw_flags & 0b0010_0000) != 0,
        ece: (raw_flags & 0b0100_0000) != 0,
        cwr: (raw_flags & 0b1000_0000) != 0,
    };

    let payload = packet.payload();

    Some(TcpFields {
        src_port: packet.get_source(),
        dst_port: packet.get_destination(),
        seq: packet.get_sequence(),
        ack: packet.get_acknowledgement(),
        flags,
        window: packet.get_window(),
        checksum: packet.get_checksum(),
        urgent_ptr: packet.get_urgent_ptr(),
        payload_len: payload.len() as u32,
    })
}

pub fn parse_udp(data: &[u8]) -> Option<UdpFields> {
    let packet = UdpPacket::new(data)?;

    let payload = packet.payload();

    Some(UdpFields {
        src_port: packet.get_source(),
        dst_port: packet.get_destination(),
        length: packet.get_length(),
        checksum: packet.get_checksum(),
        payload_len: payload.len() as u32,
    })
}
