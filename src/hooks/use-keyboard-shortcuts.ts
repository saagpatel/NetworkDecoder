import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { useEffect } from "react";
import { usePacketStore } from "../stores/packet-store";

function isInputFocused(): boolean {
	const tag = document.activeElement?.tagName;
	return tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA";
}

export function useKeyboardShortcuts() {
	const store = usePacketStore;

	useEffect(() => {
		const handleKeydown = async (e: KeyboardEvent) => {
			const meta = e.metaKey || e.ctrlKey;

			// Cmd+F -> focus filter bar
			if (meta && e.key === "f") {
				e.preventDefault();
				const input = document.querySelector(
					"[data-filter-input]",
				) as HTMLInputElement | null;
				input?.focus();
				return;
			}

			// Cmd+O -> import file
			if (meta && e.key === "o") {
				e.preventDefault();
				const path = await open({
					filters: [{ name: "PCAP", extensions: ["pcap", "pcapng", "cap"] }],
				});
				if (path) {
					store.getState().clearPackets();
					const total = await invoke<number>("import_file", { path });
					console.log(`Imported ${total} packets`);
					store.getState().setImportProgress(null);
				}
				return;
			}

			// Cmd+E -> export PCAP
			if (meta && e.key === "e") {
				e.preventDefault();
				if (store.getState().packets.length === 0) return;
				const path = await save({
					filters: [{ name: "PCAP", extensions: ["pcap"] }],
					defaultPath: "capture.pcap",
				});
				if (path) {
					const written = await invoke<number>("export_pcap", {
						path,
					});
					console.log(`Exported ${written} packets`);
				}
				return;
			}

			// Esc -> clear filter + blur
			if (e.key === "Escape") {
				store.getState().setFilterText("");
				(document.activeElement as HTMLElement)?.blur();
				return;
			}

			// Skip remaining shortcuts if input is focused
			if (isInputFocused()) return;

			// Space -> stop active capture (starting requires the CaptureBar UI)
			if (e.key === " ") {
				e.preventDefault();
				const state = store.getState();
				if (state.captureActive) {
					await invoke("stop_capture");
					state.setCaptureActive(false);
				}
				return;
			}

			// 1/2/3 -> switch views
			if (e.key === "1") {
				store.getState().setViewMode("list");
				return;
			}
			if (e.key === "2") {
				store.getState().setViewMode("swimlane");
				return;
			}
			if (e.key === "3") {
				store.getState().setViewMode("cards");
				return;
			}
		};

		window.addEventListener("keydown", handleKeydown);
		return () => window.removeEventListener("keydown", handleKeydown);
	}, []);
}
