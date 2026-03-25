import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useRef } from "react";
import { PROTOCOL_COLORS } from "../../lib/protocol-colors";
import { usePacketStore } from "../../stores/packet-store";
import type { PacketSummary } from "../../types/packets";

const ROW_HEIGHT = 28;

function formatTimestamp(us: number, firstUs: number): string {
	const delta = (us - firstUs) / 1_000_000;
	return delta.toFixed(6);
}

export function PacketListView({ packets }: { packets: PacketSummary[] }) {
	const selectedId = usePacketStore((s) => s.selectedId);
	const captureActive = usePacketStore((s) => s.captureActive);
	const selectPacket = usePacketStore((s) => s.selectPacket);

	const parentRef = useRef<HTMLDivElement>(null);
	const shouldAutoScroll = useRef(true);

	const virtualizer = useVirtualizer({
		count: packets.length,
		getScrollElement: () => parentRef.current,
		estimateSize: () => ROW_HEIGHT,
		overscan: 20,
	});

	// Auto-scroll to bottom during capture
	useEffect(() => {
		if (captureActive && shouldAutoScroll.current && parentRef.current) {
			virtualizer.scrollToIndex(packets.length - 1);
		}
	}, [packets.length, captureActive, virtualizer]);

	// Detect manual scroll to disable auto-scroll
	const handleScroll = () => {
		if (!parentRef.current) return;
		const { scrollTop, scrollHeight, clientHeight } = parentRef.current;
		shouldAutoScroll.current =
			scrollHeight - scrollTop - clientHeight < ROW_HEIGHT * 2;
	};

	const firstTimestamp = packets[0]?.timestamp_us ?? 0;

	return (
		<div className="flex flex-col flex-1 min-h-0">
			{/* Header */}
			<div className="flex bg-gray-800 border-b border-gray-700 text-xs text-gray-400 font-mono px-2">
				<div className="w-16 py-1 shrink-0">No.</div>
				<div className="w-24 py-1 shrink-0">Time</div>
				<div className="w-40 py-1 shrink-0">Source</div>
				<div className="w-40 py-1 shrink-0">Destination</div>
				<div className="w-16 py-1 shrink-0">Proto</div>
				<div className="w-14 py-1 shrink-0">Len</div>
				<div className="flex-1 py-1">Info</div>
			</div>

			{/* Virtualized rows */}
			<div
				ref={parentRef}
				onScroll={handleScroll}
				className="flex-1 overflow-auto"
			>
				<div
					style={{
						height: `${virtualizer.getTotalSize()}px`,
						position: "relative",
					}}
				>
					{virtualizer.getVirtualItems().map((virtualRow) => {
						const pkt = packets[virtualRow.index];
						const colors =
							PROTOCOL_COLORS[pkt.protocol] ?? PROTOCOL_COLORS.Unknown;
						const isSelected = pkt.id === selectedId;

						return (
							<div
								key={pkt.id}
								onClick={() => selectPacket(pkt.id)}
								className={`flex items-center text-xs font-mono px-2 cursor-pointer border-b border-gray-800/50 ${
									isSelected
										? "bg-blue-800/70 text-white"
										: `${colors.row} text-gray-300 hover:bg-gray-800`
								}`}
								style={{
									position: "absolute",
									top: 0,
									left: 0,
									width: "100%",
									height: `${ROW_HEIGHT}px`,
									transform: `translateY(${virtualRow.start}px)`,
								}}
							>
								<div className="w-16 shrink-0 text-gray-500">{pkt.id}</div>
								<div className="w-24 shrink-0">
									{formatTimestamp(pkt.timestamp_us, firstTimestamp)}
								</div>
								<div className="w-40 shrink-0 truncate">
									{pkt.src_addr ?? "\u2014"}
								</div>
								<div className="w-40 shrink-0 truncate">
									{pkt.dst_addr ?? "\u2014"}
								</div>
								<div className="w-16 shrink-0">
									<span
										className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${colors.bg} ${colors.text}`}
									>
										{pkt.protocol}
									</span>
								</div>
								<div className="w-14 shrink-0">{pkt.capture_len}</div>
								<div className="flex-1 truncate text-gray-400">{pkt.info}</div>
							</div>
						);
					})}
				</div>
			</div>
		</div>
	);
}
