import { useCallback, useEffect, useMemo, useRef } from "react";
import { usePacketStore } from "../../stores/packet-store";
import type { PacketSummary, TopProtocol } from "../../types/packets";

const LANE_HEIGHT = 32;
const TICK_WIDTH = 3;
const TICK_HEIGHT = 20;
const LABEL_WIDTH = 220;
const TIME_HEADER_HEIGHT = 24;
const PADDING_RIGHT = 40;

const CANVAS_COLORS: Record<TopProtocol, string> = {
	Http: "#3b82f6",
	Https: "#3b82f6",
	Dns: "#a855f7",
	Tls: "#14b8a6",
	Tcp: "#6b7280",
	Udp: "#f97316",
	Icmp: "#eab308",
	Ipv4: "#4b5563",
	Ipv6: "#4b5563",
	Arp: "#22c55e",
	Ethernet: "#4b5563",
	Unknown: "#374151",
};

interface LaneData {
	streamId: number;
	label: string;
	packets: { id: number; timeOffset: number; protocol: TopProtocol }[];
}

export function SwimLaneView({ packets }: { packets: PacketSummary[] }) {
	const canvasRef = useRef<HTMLCanvasElement>(null);
	const labelContainerRef = useRef<HTMLDivElement>(null);
	const canvasContainerRef = useRef<HTMLDivElement>(null);
	const selectPacket = usePacketStore((s) => s.selectPacket);
	const selectedId = usePacketStore((s) => s.selectedId);

	const { lanes, timeRange } = useMemo(() => {
		const streamMap = new Map<number, LaneData>();
		let minTime = Infinity;
		let maxTime = -Infinity;

		for (const pkt of packets) {
			if (pkt.stream_id === null) continue;
			if (pkt.timestamp_us < minTime) minTime = pkt.timestamp_us;
			if (pkt.timestamp_us > maxTime) maxTime = pkt.timestamp_us;

			let lane = streamMap.get(pkt.stream_id);
			if (!lane) {
				const label = `${pkt.src_addr ?? "?"} \u2192 ${pkt.dst_addr ?? "?"}`;
				lane = { streamId: pkt.stream_id, label, packets: [] };
				streamMap.set(pkt.stream_id, lane);
			}
			lane.packets.push({
				id: pkt.id,
				timeOffset: pkt.timestamp_us - minTime,
				protocol: pkt.protocol,
			});
		}

		const sortedLanes = Array.from(streamMap.values()).sort(
			(a, b) =>
				(a.packets[0]?.timeOffset ?? 0) - (b.packets[0]?.timeOffset ?? 0),
		);

		return {
			lanes: sortedLanes,
			timeRange: maxTime > minTime ? maxTime - minTime : 1_000_000,
		};
	}, [packets]);

	const canvasWidth =
		Math.max(800, Math.min((timeRange / 1000) * 2, 10000)) + PADDING_RIGHT;
	const canvasHeight = TIME_HEADER_HEIGHT + lanes.length * LANE_HEIGHT;

	const draw = useCallback(() => {
		const canvas = canvasRef.current;
		if (!canvas) return;
		const ctx = canvas.getContext("2d");
		if (!ctx) return;

		const dpr = window.devicePixelRatio || 1;
		canvas.width = canvasWidth * dpr;
		canvas.height = canvasHeight * dpr;
		canvas.style.width = `${canvasWidth}px`;
		canvas.style.height = `${canvasHeight}px`;
		ctx.scale(dpr, dpr);

		// Clear
		ctx.fillStyle = "#030712";
		ctx.fillRect(0, 0, canvasWidth, canvasHeight);

		// Time axis header
		ctx.fillStyle = "#1f2937";
		ctx.fillRect(0, 0, canvasWidth, TIME_HEADER_HEIGHT);

		// Time labels
		ctx.fillStyle = "#9ca3af";
		ctx.font = "10px monospace";
		const timeStepMs =
			Math.max(1, Math.ceil(timeRange / 1_000_000 / 10)) * 1000;
		for (let ms = 0; ms <= timeRange / 1000; ms += timeStepMs) {
			const x = (ms / (timeRange / 1000)) * (canvasWidth - PADDING_RIGHT);
			ctx.fillText(`${(ms / 1000).toFixed(1)}s`, x + 2, 16);
			ctx.strokeStyle = "#374151";
			ctx.beginPath();
			ctx.moveTo(x, TIME_HEADER_HEIGHT);
			ctx.lineTo(x, canvasHeight);
			ctx.stroke();
		}

		// Lane backgrounds
		for (let i = 0; i < lanes.length; i++) {
			const y = TIME_HEADER_HEIGHT + i * LANE_HEIGHT;
			ctx.fillStyle = i % 2 === 0 ? "#0a0f1a" : "#0d1117";
			ctx.fillRect(0, y, canvasWidth, LANE_HEIGHT);

			ctx.strokeStyle = "#1f2937";
			ctx.beginPath();
			ctx.moveTo(0, y + LANE_HEIGHT);
			ctx.lineTo(canvasWidth, y + LANE_HEIGHT);
			ctx.stroke();
		}

		// Draw ticks
		for (let laneIndex = 0; laneIndex < lanes.length; laneIndex++) {
			const lane = lanes[laneIndex];
			const y =
				TIME_HEADER_HEIGHT +
				laneIndex * LANE_HEIGHT +
				(LANE_HEIGHT - TICK_HEIGHT) / 2;
			for (const pkt of lane.packets) {
				const x = (pkt.timeOffset / timeRange) * (canvasWidth - PADDING_RIGHT);
				ctx.fillStyle =
					pkt.id === selectedId
						? "#60a5fa"
						: (CANVAS_COLORS[pkt.protocol] ?? CANVAS_COLORS.Unknown);
				ctx.fillRect(x, y, TICK_WIDTH, TICK_HEIGHT);
			}
		}
	}, [lanes, timeRange, canvasWidth, canvasHeight, selectedId]);

	useEffect(() => {
		draw();
	}, [draw]);

	const handleCanvasScroll = () => {
		if (canvasContainerRef.current && labelContainerRef.current) {
			labelContainerRef.current.scrollTop =
				canvasContainerRef.current.scrollTop;
		}
	};

	const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
		const canvas = canvasRef.current;
		if (!canvas) return;
		const rect = canvas.getBoundingClientRect();
		const x = e.clientX - rect.left;
		const y = e.clientY - rect.top;

		const laneIndex = Math.floor((y - TIME_HEADER_HEIGHT) / LANE_HEIGHT);
		if (laneIndex < 0 || laneIndex >= lanes.length) return;

		const lane = lanes[laneIndex];
		let closest: { id: number; dist: number } | null = null;

		for (const pkt of lane.packets) {
			const px = (pkt.timeOffset / timeRange) * (canvasWidth - PADDING_RIGHT);
			const dist = Math.abs(px - x);
			if (dist < 8 && (!closest || dist < closest.dist)) {
				closest = { id: pkt.id, dist };
			}
		}

		if (closest) {
			selectPacket(closest.id);
		}
	};

	if (lanes.length === 0) {
		return (
			<div className="flex items-center justify-center h-full text-gray-500 text-sm font-mono">
				No streams to display. Import a capture or start recording.
			</div>
		);
	}

	return (
		<div className="flex flex-1 min-h-0 overflow-hidden">
			{/* Labels */}
			<div
				ref={labelContainerRef}
				className="overflow-hidden shrink-0 border-r border-gray-700"
				style={{ width: LABEL_WIDTH }}
			>
				<div
					style={{ height: TIME_HEADER_HEIGHT }}
					className="bg-gray-800 border-b border-gray-700 px-2 flex items-center text-[10px] text-gray-500 font-mono"
				>
					Connection
				</div>
				{lanes.map((lane, i) => (
					<div
						key={lane.streamId}
						className={`flex items-center px-2 text-[10px] font-mono truncate border-b border-gray-800 ${
							i % 2 === 0 ? "bg-[#0a0f1a]" : "bg-[#0d1117]"
						} text-gray-400`}
						style={{ height: LANE_HEIGHT }}
						title={lane.label}
					>
						{lane.label}
					</div>
				))}
			</div>

			{/* Canvas */}
			<div
				ref={canvasContainerRef}
				className="flex-1 overflow-auto"
				onScroll={handleCanvasScroll}
			>
				<canvas
					ref={canvasRef}
					onClick={handleCanvasClick}
					className="cursor-crosshair"
					style={{ width: canvasWidth, height: canvasHeight }}
				/>
			</div>
		</div>
	);
}
