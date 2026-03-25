export interface PacketSummary {
	id: number;
	timestamp_us: number;
	capture_len: number;
	stream_id: number | null;
	protocol: TopProtocol;
	src_addr: string | null;
	dst_addr: string | null;
	info: string;
}

export interface LayerEntry {
	layer: string;
	fields: Record<string, unknown>;
	byte_offset: number;
	byte_len: number;
}

export interface CaptureStats {
	received: number;
	dropped: number;
	rate_pps: number;
}

export interface ImportProgress {
	parsed: number;
	total: number;
}

export interface PacketRecord {
	id: number;
	timestamp_us: number;
	capture_len: number;
	original_len: number;
	interface: string;
	layers: LayerEntry[];
	protocol: TopProtocol;
	src_addr: string | null;
	dst_addr: string | null;
	stream_id: number | null;
	info: string;
}

export type LayerData =
	| { layer: "Ethernet"; fields: EthernetFields }
	| { layer: "Ipv4"; fields: Ipv4Fields }
	| { layer: "Ipv6"; fields: Ipv6Fields }
	| { layer: "Tcp"; fields: TcpFields }
	| { layer: "Udp"; fields: UdpFields }
	| { layer: "Http"; fields: HttpFields }
	| { layer: "Dns"; fields: DnsFields }
	| { layer: "Tls"; fields: TlsFields }
	| { layer: "Raw"; fields: number[] };

export interface EthernetFields {
	src_mac: string;
	dst_mac: string;
	ethertype: number;
	ethertype_name: string;
}

export interface Ipv4Fields {
	src: string;
	dst: string;
	ttl: number;
	protocol: number;
	protocol_name: string;
	total_len: number;
	flags: { dont_fragment: boolean; more_fragments: boolean };
	fragment_offset: number;
	checksum: number;
}

export interface Ipv6Fields {
	src: string;
	dst: string;
	next_header: number;
	hop_limit: number;
	payload_len: number;
	traffic_class: number;
	flow_label: number;
}

export interface TcpFields {
	src_port: number;
	dst_port: number;
	seq: number;
	ack: number;
	flags: TcpFlags;
	window: number;
	checksum: number;
	urgent_ptr: number;
	payload_len: number;
}

export interface TcpFlags {
	syn: boolean;
	ack: boolean;
	fin: boolean;
	rst: boolean;
	psh: boolean;
	urg: boolean;
	ece: boolean;
	cwr: boolean;
}

export interface UdpFields {
	src_port: number;
	dst_port: number;
	length: number;
	checksum: number;
	payload_len: number;
}

export interface HttpFields {
	method: string | null;
	path: string | null;
	status_code: number | null;
	status_text: string | null;
	version: string;
	headers: [string, string][];
	is_request: boolean;
}

export interface DnsFields {
	transaction_id: number;
	is_response: boolean;
	questions: { name: string; qtype: string }[];
	answers: { name: string; rtype: string; ttl: number; data: string }[];
}

export interface TlsFields {
	record_type: string;
	tls_version: string;
	sni: string | null;
	cipher_suites: string[];
	session_id: string | null;
}

export type TopProtocol =
	| "Ethernet"
	| "Arp"
	| "Ipv4"
	| "Ipv6"
	| "Tcp"
	| "Udp"
	| "Icmp"
	| "Http"
	| "Https"
	| "Dns"
	| "Tls"
	| "Unknown";

export interface ConnectionRecord {
	stream_id: number;
	src_addr: string;
	dst_addr: string;
	protocol: "Tcp" | "Udp";
	packet_count: number;
	byte_count: number;
	syn_time: number | null;
	fin_time: number | null;
	first_seen: number;
	last_seen: number;
}

export interface InterfaceInfo {
	name: string;
	description: string;
	is_up: boolean;
	is_loopback: boolean;
}
