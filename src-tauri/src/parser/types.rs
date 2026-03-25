use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PacketRecord {
    pub id: u64,
    pub timestamp_us: i64,
    pub capture_len: u32,
    pub original_len: u32,
    pub interface: String,
    pub layers: Vec<LayerEntry>,
    pub protocol: TopProtocol,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub stream_id: Option<u64>,
    pub info: String,
}

impl PacketRecord {
    pub fn to_summary(&self) -> PacketSummary {
        PacketSummary {
            id: self.id,
            timestamp_us: self.timestamp_us,
            capture_len: self.capture_len,
            stream_id: self.stream_id,
            protocol: self.protocol.clone(),
            src_addr: self.src_addr.clone(),
            dst_addr: self.dst_addr.clone(),
            info: self.info.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketSummary {
    pub id: u64,
    pub timestamp_us: i64,
    pub capture_len: u32,
    pub stream_id: Option<u64>,
    pub protocol: TopProtocol,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub info: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LayerEntry {
    #[serde(flatten)]
    pub data: LayerData,
    pub byte_offset: usize,
    pub byte_len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureStats {
    pub received: u64,
    pub dropped: u64,
    pub rate_pps: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportProgress {
    pub parsed: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "layer", content = "fields")]
pub enum LayerData {
    Ethernet(EthernetFields),
    Ipv4(Ipv4Fields),
    Ipv6(Ipv6Fields),
    Tcp(TcpFields),
    Udp(UdpFields),
    Http(HttpFields),
    Dns(DnsFields),
    Tls(TlsFields),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
pub struct EthernetFields {
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: u16,
    pub ethertype_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv4Fields {
    pub src: String,
    pub dst: String,
    pub ttl: u8,
    pub protocol: u8,
    pub protocol_name: String,
    pub total_len: u16,
    pub flags: Ipv4Flags,
    pub fragment_offset: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv4Flags {
    pub dont_fragment: bool,
    pub more_fragments: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv6Fields {
    pub src: String,
    pub dst: String,
    pub next_header: u8,
    pub hop_limit: u8,
    pub payload_len: u16,
    pub traffic_class: u8,
    pub flow_label: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpFields {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub payload_len: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UdpFields {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload_len: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpFields {
    pub method: Option<String>,
    pub path: Option<String>,
    pub status_code: Option<u16>,
    pub status_text: Option<String>,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub is_request: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsFields {
    pub transaction_id: u16,
    pub is_response: bool,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: String,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsFields {
    pub record_type: String,
    pub tls_version: String,
    pub sni: Option<String>,
    pub cipher_suites: Vec<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub enum TopProtocol {
    Ethernet,
    Arp,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Http,
    Https,
    Dns,
    Tls,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    pub is_up: bool,
    pub is_loopback: bool,
}
