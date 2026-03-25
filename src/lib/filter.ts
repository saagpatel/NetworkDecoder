import type { PacketSummary } from "../types/packets";

interface FilterTerm {
	type: "proto" | "ip" | "port" | "stream" | "text";
	value: string;
}

export function parseFilter(text: string): FilterTerm[] {
	if (!text.trim()) return [];
	return text
		.trim()
		.split(/\s+/)
		.map((term) => {
			const colonIndex = term.indexOf(":");
			if (colonIndex > 0) {
				const key = term.slice(0, colonIndex).toLowerCase();
				const value = term.slice(colonIndex + 1);
				if (["proto", "ip", "port", "stream"].includes(key)) {
					return { type: key as FilterTerm["type"], value };
				}
			}
			return { type: "text" as const, value: term };
		});
}

export function applyFilter(
	packet: PacketSummary,
	terms: FilterTerm[],
): boolean {
	return terms.every((term) => {
		switch (term.type) {
			case "proto":
				return packet.protocol.toLowerCase() === term.value.toLowerCase();
			case "ip":
				return (
					(packet.src_addr ?? "").includes(term.value) ||
					(packet.dst_addr ?? "").includes(term.value)
				);
			case "port": {
				const port = `:${term.value}`;
				return (
					(packet.src_addr ?? "").endsWith(port) ||
					(packet.dst_addr ?? "").endsWith(port)
				);
			}
			case "stream":
				return (
					packet.stream_id !== null && String(packet.stream_id) === term.value
				);
			case "text":
				return (
					packet.info.toLowerCase().includes(term.value.toLowerCase()) ||
					(packet.src_addr ?? "").includes(term.value) ||
					(packet.dst_addr ?? "").includes(term.value)
				);
			default:
				return true;
		}
	});
}
