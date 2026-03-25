import { useEffect, useMemo, useState } from "react";
import { CaptureBar } from "./components/controls/CaptureBar";
import { Onboarding } from "./components/Onboarding";
import { DetailPane } from "./components/panels/DetailPane";
import { HexDump } from "./components/panels/HexDump";
import { PacketListView } from "./components/views/PacketListView";
import { ProtocolCardView } from "./components/views/ProtocolCardView";
import { SwimLaneView } from "./components/views/SwimLaneView";
import { useKeyboardShortcuts } from "./hooks/use-keyboard-shortcuts";
import { usePacketStream } from "./hooks/use-packet-stream";
import { applyFilter, parseFilter } from "./lib/filter";
import { usePacketStore } from "./stores/packet-store";

function App() {
	usePacketStream();
	useKeyboardShortcuts();

	const [showOnboarding, setShowOnboarding] = useState(
		!localStorage.getItem("networkdecoder_onboarding_dismissed"),
	);

	useEffect(() => {
		const handler = () => setShowOnboarding(true);
		window.addEventListener("show-onboarding", handler);
		return () => window.removeEventListener("show-onboarding", handler);
	}, []);
	const selectedId = usePacketStore((s) => s.selectedId);
	const viewMode = usePacketStore((s) => s.viewMode);
	const allPackets = usePacketStore((s) => s.packets);
	const filterText = usePacketStore((s) => s.filterText);

	const filteredPackets = useMemo(() => {
		const terms = parseFilter(filterText);
		if (terms.length === 0) return allPackets;
		return allPackets.filter((p) => applyFilter(p, terms));
	}, [allPackets, filterText]);

	const isFiltered = filterText.trim().length > 0;

	return (
		<div className="flex flex-col h-screen bg-gray-950 text-gray-200">
			{showOnboarding && (
				<Onboarding onDismiss={() => setShowOnboarding(false)} />
			)}
			<CaptureBar />

			{isFiltered && (
				<div className="px-4 py-0.5 bg-gray-900 border-b border-gray-800 text-[10px] font-mono text-gray-500">
					Showing {filteredPackets.length} of {allPackets.length} packets
				</div>
			)}

			{/* Main content area */}
			<div className="flex flex-col flex-1 min-h-0">
				{/* Packet view -- takes more space when nothing selected */}
				<div
					className={`flex flex-col ${selectedId !== null ? "h-[55%]" : "flex-1"} min-h-0`}
				>
					{viewMode === "list" && <PacketListView packets={filteredPackets} />}
					{viewMode === "swimlane" && (
						<SwimLaneView packets={filteredPackets} />
					)}
					{viewMode === "cards" && (
						<ProtocolCardView packets={filteredPackets} />
					)}
				</div>

				{/* Detail area -- shown when a packet is selected */}
				{selectedId !== null && (
					<div className="flex h-[45%] border-t border-gray-700 min-h-0">
						<div className="w-[60%] border-r border-gray-700 overflow-hidden">
							<DetailPane />
						</div>
						<div className="w-[40%] overflow-hidden">
							<HexDump />
						</div>
					</div>
				)}
			</div>
		</div>
	);
}

export default App;
