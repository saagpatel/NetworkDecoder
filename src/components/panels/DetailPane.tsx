import { useState } from "react";
import { usePacketStore } from "../../stores/packet-store";
import type { LayerEntry } from "../../types/packets";
import { FieldExplainer } from "./FieldExplainer";

const LAYER_LABELS: Record<string, string> = {
	Ethernet: "Ethernet II",
	Ipv4: "Internet Protocol v4",
	Ipv6: "Internet Protocol v6",
	Tcp: "Transmission Control Protocol",
	Udp: "User Datagram Protocol",
	Http: "HTTP",
	Dns: "Domain Name System",
	Tls: "Transport Layer Security",
	Raw: "Raw Data",
};

const FIELD_LABELS: Record<string, string> = {
	src_mac: "Source MAC",
	dst_mac: "Destination MAC",
	ethertype: "EtherType",
	ethertype_name: "Protocol",
	src: "Source",
	dst: "Destination",
	ttl: "Time to Live",
	protocol: "Protocol Number",
	protocol_name: "Protocol",
	total_len: "Total Length",
	flags: "Flags",
	fragment_offset: "Fragment Offset",
	checksum: "Checksum",
	src_port: "Source Port",
	dst_port: "Destination Port",
	seq: "Sequence Number",
	ack: "Acknowledgment Number",
	window: "Window Size",
	urgent_ptr: "Urgent Pointer",
	payload_len: "Payload Length",
	length: "Length",
	hop_limit: "Hop Limit",
	next_header: "Next Header",
	traffic_class: "Traffic Class",
	flow_label: "Flow Label",
};

function formatValue(key: string, value: unknown): string {
	if (value === null || value === undefined) return "\u2014";
	if (typeof value === "boolean") return value ? "Set" : "Not set";
	if (typeof value === "object" && !Array.isArray(value)) {
		return (
			Object.entries(value as Record<string, unknown>)
				.filter(([, v]) => v === true)
				.map(([k]) => k.toUpperCase())
				.join(", ") || "(none)"
		);
	}
	if (key === "checksum" || key === "ethertype") {
		return `0x${(value as number).toString(16).padStart(4, "0")}`;
	}
	return String(value);
}

function isFlagsObject(value: unknown): value is Record<string, boolean> {
	return (
		typeof value === "object" &&
		value !== null &&
		!Array.isArray(value) &&
		Object.values(value as Record<string, unknown>).length > 0 &&
		Object.values(value as Record<string, unknown>).every(
			(v) => typeof v === "boolean",
		)
	);
}

function FlagBadges({ flags }: { flags: Record<string, boolean> }) {
	return (
		<div className="flex flex-wrap gap-1">
			{Object.entries(flags).map(([name, set]) => (
				<span
					key={name}
					className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
						set ? "bg-green-800 text-green-200" : "bg-gray-800 text-gray-600"
					}`}
				>
					{name}
				</span>
			))}
		</div>
	);
}

function LayerSection({ entry }: { entry: LayerEntry }) {
	const [expanded, setExpanded] = useState(true);
	const setHoveredLayer = usePacketStore((s) => s.setHoveredLayer);
	const layerName = entry.layer ?? "Unknown";

	const fields = entry.fields as Record<string, unknown> | undefined;

	return (
		<div
			className="border-b border-gray-700"
			onMouseEnter={() =>
				setHoveredLayer({
					byte_offset: entry.byte_offset,
					byte_len: entry.byte_len,
				})
			}
			onMouseLeave={() => setHoveredLayer(null)}
		>
			<button
				onClick={() => setExpanded(!expanded)}
				className="w-full flex items-center gap-2 px-3 py-1.5 text-xs font-mono text-gray-200 hover:bg-gray-800 text-left"
			>
				<span className="text-gray-500">{expanded ? "\u25BC" : "\u25B6"}</span>
				<span className="font-bold">
					{LAYER_LABELS[layerName] ?? layerName}
				</span>
				<span className="ml-auto text-gray-500 text-[10px]">
					[{entry.byte_offset}..{entry.byte_offset + entry.byte_len}]
				</span>
			</button>
			{expanded && fields && (
				<div className="px-6 pb-2 text-xs font-mono">
					{Object.entries(fields).map(([key, value]) => (
						<div key={key} className="flex py-0.5">
							<span className="w-40 text-gray-400 shrink-0">
								<FieldExplainer fieldKey={key}>
									{FIELD_LABELS[key] ?? key}
								</FieldExplainer>
							</span>
							<span className="text-gray-200">
								{isFlagsObject(value) ? (
									<FlagBadges flags={value} />
								) : (
									formatValue(key, value)
								)}
							</span>
						</div>
					))}
				</div>
			)}
		</div>
	);
}

export function DetailPane() {
	const selectedDetail = usePacketStore((s) => s.selectedDetail);

	if (!selectedDetail) {
		return (
			<div className="flex items-center justify-center h-full text-gray-500 text-sm font-mono">
				Select a packet to view details
			</div>
		);
	}

	return (
		<div className="overflow-auto h-full">
			{selectedDetail.layers.map((entry, i) => (
				<LayerSection key={i} entry={entry} />
			))}
		</div>
	);
}
