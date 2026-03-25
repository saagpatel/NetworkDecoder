import { type ReactNode, useRef, useState } from "react";

const EXPLANATIONS: Record<string, string> = {
	// Ethernet
	src_mac:
		"Hardware address of the device that sent this frame on the local network.",
	dst_mac:
		"Hardware address of the intended receiver on the local network. ff:ff:ff:ff:ff:ff means broadcast to all devices.",
	ethertype:
		"Identifies the protocol in the payload. 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP.",

	// IPv4
	src: "IP address of the device that sent this packet.",
	dst: "IP address of the intended receiver.",
	ttl: "How many router hops this packet can pass through before being discarded. Prevents infinite routing loops.",
	protocol_name: "The transport-layer protocol carried in this IP packet.",
	total_len:
		"Total size of this IP packet in bytes, including the header and payload.",
	fragment_offset:
		"Position of this fragment in the original packet, in 8-byte units. 0 means first or only fragment.",

	// TCP
	src_port:
		"Port number on the sender. Ephemeral ports (49152-65535) are temporary; well-known ports (0-1023) identify services.",
	dst_port:
		"Port number on the receiver. Common: 80=HTTP, 443=HTTPS, 53=DNS, 22=SSH.",
	seq: "Byte position of this segment's first data byte in the TCP stream. Used to reassemble data in order.",
	ack: "The next byte number the sender expects to receive, confirming all prior bytes were received.",
	window:
		"How much data (in bytes) the receiver can accept before the sender must pause and wait for acknowledgement.",
	checksum:
		"Error-detection value computed over the header and payload. Receivers discard packets with mismatched checksums.",
	urgent_ptr:
		"Offset to the end of urgent data. Only meaningful when the URG flag is set.",
	payload_len:
		"Number of bytes of application data carried in this segment, after the TCP header.",

	// UDP
	length:
		"Total size of this UDP datagram in bytes, including the 8-byte header and payload.",

	// TCP Flags
	flags: "Control bits that manage the TCP connection lifecycle and data flow.",

	// DNS
	transaction_id:
		"Identifier that pairs a DNS query with its response. Both share the same ID.",
	is_response: "Whether this is a response (true) or a query (false).",
	questions: "The domain names and record types being queried.",
	answers: "The resolved records returned by the DNS server.",
	qtype:
		"The type of DNS record requested. A=IPv4 address, AAAA=IPv6, CNAME=alias, MX=mail server.",
	name: "The domain name this record applies to.",
	rtype: "The type of DNS record in this answer.",
	data: "The resolved value \u2014 an IP address, hostname, or other record data.",

	// HTTP
	method:
		"The HTTP verb: GET=read, POST=create, PUT=update, DELETE=remove, HEAD=metadata only.",
	path: "The URL path being requested on the server.",
	status_code:
		"Three-digit result code. 2xx=success, 3xx=redirect, 4xx=client error, 5xx=server error.",
	status_text: "Human-readable phrase explaining the status code.",
	version: "HTTP protocol version. 1.1 is most common; 2.0 uses multiplexing.",
	headers: "Key-value metadata pairs sent with the request or response.",
	is_request: "Whether this is a request (true) or response (false).",

	// TLS
	record_type:
		"Type of TLS handshake message. ClientHello initiates; ServerHello responds.",
	tls_version:
		"The TLS protocol version negotiated. TLS 1.3 is the latest and most secure.",
	sni: "Server Name Indication \u2014 the hostname the client wants to connect to. Sent in cleartext, visible even though the connection is encrypted.",
	cipher_suites:
		"Encryption algorithms the client supports (ClientHello) or the server selected (ServerHello).",
	session_id:
		"Identifier for resuming a previous TLS session without a full handshake.",
};

interface FieldExplainerProps {
	fieldKey: string;
	children: ReactNode;
}

export function FieldExplainer({ fieldKey, children }: FieldExplainerProps) {
	const [show, setShow] = useState(false);
	const [position, setPosition] = useState<{ top: number; left: number }>({
		top: 0,
		left: 0,
	});
	const ref = useRef<HTMLSpanElement>(null);
	const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

	const explanation = EXPLANATIONS[fieldKey];
	if (!explanation) return <>{children}</>;

	const handleMouseEnter = () => {
		timerRef.current = setTimeout(() => {
			if (ref.current) {
				const rect = ref.current.getBoundingClientRect();
				setPosition({ top: rect.top - 8, left: rect.left });
				setShow(true);
			}
		}, 300);
	};

	const handleMouseLeave = () => {
		clearTimeout(timerRef.current);
		setShow(false);
	};

	return (
		<span
			ref={ref}
			onMouseEnter={handleMouseEnter}
			onMouseLeave={handleMouseLeave}
			className="cursor-help border-b border-dotted border-gray-600"
		>
			{children}
			{show && (
				<div
					className="fixed z-50 max-w-xs px-3 py-2 text-xs text-gray-200 bg-gray-800 border border-gray-600 rounded shadow-lg"
					style={{
						top: `${position.top}px`,
						left: `${position.left}px`,
						transform: "translateY(-100%)",
					}}
				>
					{explanation}
				</div>
			)}
		</span>
	);
}
