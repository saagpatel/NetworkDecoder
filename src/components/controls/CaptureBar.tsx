import { invoke } from "@tauri-apps/api/core";
import { confirm, open, save } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";
import { usePacketStore } from "../../stores/packet-store";
import type { InterfaceInfo } from "../../types/packets";
import { FilterBar } from "./FilterBar";
import { ViewSwitcher } from "./ViewSwitcher";

export function CaptureBar() {
	const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
	const [selectedInterface, setSelectedInterface] = useState<string>("");
	const {
		captureActive,
		setCaptureActive,
		stats,
		importProgress,
		clearPackets,
	} = usePacketStore();
	const packetCount = usePacketStore((s) => s.packets.length);

	useEffect(() => {
		invoke<InterfaceInfo[]>("get_interfaces").then((ifaces) => {
			setInterfaces(ifaces);
			const defaultIface =
				ifaces.find((i) => i.is_up && !i.is_loopback) ?? ifaces[0];
			if (defaultIface) setSelectedInterface(defaultIface.name);
		});
	}, []);

	const handleStartStop = async () => {
		if (captureActive) {
			await invoke("stop_capture");
			setCaptureActive(false);
		} else {
			// Show privilege warning on first capture attempt
			const dismissed = localStorage.getItem(
				"networkdecoder_privilege_warning_dismissed",
			);
			if (!dismissed) {
				const ok = await confirm(
					"Live packet capture requires root/admin access.\n\nThis app captures raw network traffic which may include passwords, tokens, and private data.\n\nOnly use on networks you own or have permission to monitor.",
					{ title: "Elevated Privileges Required", kind: "warning" },
				);
				if (!ok) return;
				localStorage.setItem(
					"networkdecoder_privilege_warning_dismissed",
					"true",
				);
			}

			clearPackets();
			await invoke("start_capture", { interface: selectedInterface });
			setCaptureActive(true);
		}
	};

	const handleExport = async () => {
		const path = await save({
			filters: [{ name: "PCAP", extensions: ["pcap"] }],
			defaultPath: "capture.pcap",
		});
		if (path) {
			const written = await invoke<number>("export_pcap", { path });
			console.log(`Exported ${written} packets`);
		}
	};

	const handleImport = async () => {
		const path = await open({
			filters: [{ name: "PCAP", extensions: ["pcap", "pcapng", "cap"] }],
		});
		if (path) {
			clearPackets();
			const total = await invoke<number>("import_file", { path });
			console.log(`Imported ${total} packets`);
			usePacketStore.getState().setImportProgress(null);
		}
	};

	return (
		<div className="flex items-center gap-3 px-4 py-2 bg-gray-900 border-b border-gray-700 text-sm font-mono">
			<select
				value={selectedInterface}
				onChange={(e) => setSelectedInterface(e.target.value)}
				disabled={captureActive}
				className="bg-gray-800 text-gray-200 border border-gray-600 rounded px-2 py-1 text-xs"
			>
				{interfaces.map((iface) => (
					<option key={iface.name} value={iface.name}>
						{iface.name}
						{iface.is_loopback ? " (lo)" : ""}
						{iface.is_up ? "" : " (down)"}
					</option>
				))}
			</select>

			<button
				onClick={handleStartStop}
				className={`px-3 py-1 rounded text-xs font-bold ${
					captureActive
						? "bg-red-700 hover:bg-red-600 text-white"
						: "bg-green-700 hover:bg-green-600 text-white"
				}`}
			>
				{captureActive ? "Stop" : "Start"}
			</button>

			<button
				onClick={handleImport}
				disabled={captureActive}
				className="px-3 py-1 rounded text-xs bg-gray-700 hover:bg-gray-600 text-gray-200 disabled:opacity-50"
			>
				Import File
			</button>

			<button
				onClick={handleExport}
				disabled={packetCount === 0}
				className="px-3 py-1 rounded text-xs bg-gray-700 hover:bg-gray-600 text-gray-200 disabled:opacity-50"
			>
				Export
			</button>

			<div className="w-px h-5 bg-gray-700" />

			<ViewSwitcher />

			<div className="w-px h-5 bg-gray-700" />

			<FilterBar />

			<div className="ml-auto flex items-center gap-4 text-xs text-gray-400">
				{importProgress && importProgress.total === 0 && (
					<span className="text-yellow-400">
						Importing... {importProgress.parsed} packets
					</span>
				)}
				{stats && (
					<>
						<span>{stats.rate_pps.toFixed(0)} pkt/s</span>
						<span>Recv: {stats.received}</span>
						{stats.dropped > 0 && (
							<span className="text-red-400">Drop: {stats.dropped}</span>
						)}
					</>
				)}
				<span className="text-gray-500">{packetCount} packets</span>
				<button
					onClick={() => {
						localStorage.removeItem("networkdecoder_onboarding_dismissed");
						window.dispatchEvent(new CustomEvent("show-onboarding"));
					}}
					className="text-gray-500 hover:text-gray-300 text-sm ml-1"
					title="Show Guide"
					type="button"
				>
					?
				</button>
			</div>
		</div>
	);
}
