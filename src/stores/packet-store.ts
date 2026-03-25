import { invoke } from "@tauri-apps/api/core";
import { create } from "zustand";
import type {
	CaptureStats,
	ConnectionRecord,
	ImportProgress,
	PacketRecord,
	PacketSummary,
} from "../types/packets";

const MAX_PACKETS = 50_000;

interface PacketState {
	packets: PacketSummary[];
	selectedId: number | null;
	selectedDetail: PacketRecord | null;
	selectedBytes: number[] | null;
	captureActive: boolean;
	stats: CaptureStats | null;
	importProgress: ImportProgress | null;
	hoveredLayer: { byte_offset: number; byte_len: number } | null;
	viewMode: "list" | "swimlane" | "cards";
	filterText: string;
	connections: Record<number, ConnectionRecord>;
}

interface PacketActions {
	appendBatch: (batch: PacketSummary[]) => void;
	selectPacket: (id: number) => void;
	clearSelection: () => void;
	clearPackets: () => void;
	setCaptureActive: (active: boolean) => void;
	setStats: (stats: CaptureStats) => void;
	setImportProgress: (progress: ImportProgress | null) => void;
	setHoveredLayer: (
		layer: { byte_offset: number; byte_len: number } | null,
	) => void;
	setViewMode: (mode: "list" | "swimlane" | "cards") => void;
	setFilterText: (text: string) => void;
}

export const usePacketStore = create<PacketState & PacketActions>((set) => ({
	packets: [],
	selectedId: null,
	selectedDetail: null,
	selectedBytes: null,
	captureActive: false,
	stats: null,
	importProgress: null,
	hoveredLayer: null,
	viewMode: "list",
	filterText: "",
	connections: {},

	appendBatch: (batch) =>
		set((state) => {
			const combined = [...state.packets, ...batch];
			const packets =
				combined.length > MAX_PACKETS
					? combined.slice(combined.length - MAX_PACKETS)
					: combined;

			const connections = { ...state.connections };
			for (const pkt of batch) {
				if (pkt.stream_id === null) continue;
				const sid = pkt.stream_id;
				const existing = connections[sid];
				if (existing) {
					connections[sid] = {
						...existing,
						packet_count: existing.packet_count + 1,
						byte_count: existing.byte_count + pkt.capture_len,
						last_seen: pkt.timestamp_us,
						syn_time:
							existing.syn_time === null &&
							pkt.info.includes("[SYN]") &&
							!pkt.info.includes("[SYN, ACK]")
								? pkt.timestamp_us
								: existing.syn_time,
						fin_time:
							existing.fin_time === null &&
							(pkt.info.includes("[FIN") || pkt.info.includes("[RST"))
								? pkt.timestamp_us
								: existing.fin_time,
					};
				} else {
					const isSyn =
						pkt.info.includes("[SYN]") && !pkt.info.includes("[SYN, ACK]");
					const isFin = pkt.info.includes("[FIN") || pkt.info.includes("[RST");
					connections[sid] = {
						stream_id: sid,
						src_addr: pkt.src_addr ?? "",
						dst_addr: pkt.dst_addr ?? "",
						protocol: pkt.protocol === "Udp" ? "Udp" : "Tcp",
						packet_count: 1,
						byte_count: pkt.capture_len,
						first_seen: pkt.timestamp_us,
						last_seen: pkt.timestamp_us,
						syn_time: isSyn ? pkt.timestamp_us : null,
						fin_time: isFin ? pkt.timestamp_us : null,
					};
				}
			}

			return { packets, connections };
		}),

	selectPacket: async (id) => {
		set({ selectedId: id, selectedDetail: null, selectedBytes: null });
		try {
			const [detail, bytes] = await Promise.all([
				invoke<PacketRecord | null>("get_packet_detail", { id }),
				invoke<number[] | null>("get_packet_bytes", { id }),
			]);
			set({ selectedDetail: detail, selectedBytes: bytes });
		} catch (e) {
			console.error("Failed to fetch packet detail:", e);
		}
	},

	clearSelection: () =>
		set({
			selectedId: null,
			selectedDetail: null,
			selectedBytes: null,
			hoveredLayer: null,
		}),

	clearPackets: () =>
		set({
			packets: [],
			selectedId: null,
			selectedDetail: null,
			selectedBytes: null,
			connections: {},
		}),

	setCaptureActive: (active) => set({ captureActive: active }),

	setStats: (stats) => set({ stats }),

	setImportProgress: (progress) => set({ importProgress: progress }),

	setHoveredLayer: (layer) => set({ hoveredLayer: layer }),

	setViewMode: (mode) => set({ viewMode: mode }),

	setFilterText: (text) => set({ filterText: text }),
}));
