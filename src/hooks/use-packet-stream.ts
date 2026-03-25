import { listen } from "@tauri-apps/api/event";
import { useEffect } from "react";
import { usePacketStore } from "../stores/packet-store";
import type {
	CaptureStats,
	ImportProgress,
	PacketSummary,
} from "../types/packets";

export function usePacketStream() {
	useEffect(() => {
		const unlisteners: (() => void)[] = [];

		const setup = async () => {
			const u1 = await listen<PacketSummary[]>("packets_batch", (event) => {
				usePacketStore.getState().appendBatch(event.payload);
			});
			unlisteners.push(u1);

			const u2 = await listen<CaptureStats>("capture_stats", (event) => {
				usePacketStore.getState().setStats(event.payload);
			});
			unlisteners.push(u2);

			const u3 = await listen<ImportProgress>("import_progress", (event) => {
				usePacketStore.getState().setImportProgress(event.payload);
			});
			unlisteners.push(u3);
		};

		setup();

		return () => {
			unlisteners.forEach((u) => u());
		};
	}, []);
}
