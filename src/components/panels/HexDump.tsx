import { usePacketStore } from "../../stores/packet-store";

function isPrintable(byte: number): boolean {
	return byte >= 0x20 && byte <= 0x7e;
}

export function HexDump() {
	const selectedBytes = usePacketStore((s) => s.selectedBytes);
	const hoveredLayer = usePacketStore((s) => s.hoveredLayer);

	if (!selectedBytes || selectedBytes.length === 0) {
		return (
			<div className="flex items-center justify-center h-full text-gray-500 text-sm font-mono">
				No packet data
			</div>
		);
	}

	const rows: { offset: number; bytes: number[] }[] = [];
	for (let i = 0; i < selectedBytes.length; i += 16) {
		rows.push({
			offset: i,
			bytes: selectedBytes.slice(i, i + 16),
		});
	}

	const isHighlighted = (byteIndex: number): boolean => {
		if (!hoveredLayer) return false;
		return (
			byteIndex >= hoveredLayer.byte_offset &&
			byteIndex < hoveredLayer.byte_offset + hoveredLayer.byte_len
		);
	};

	return (
		<div className="overflow-auto h-full p-2 font-mono text-xs leading-5">
			{rows.map((row) => (
				<div key={row.offset} className="flex whitespace-pre">
					{/* Offset */}
					<span className="text-gray-500 w-12 shrink-0">
						{row.offset.toString(16).padStart(4, "0")}
					</span>

					{/* Hex bytes */}
					<span className="w-[25rem] shrink-0">
						{row.bytes.map((byte, j) => {
							const globalIndex = row.offset + j;
							return (
								<span
									key={j}
									className={
										isHighlighted(globalIndex)
											? "bg-blue-800/60 text-blue-200"
											: "text-gray-300"
									}
								>
									{byte.toString(16).padStart(2, "0")}
									{j === 7 ? "  " : " "}
								</span>
							);
						})}
						{/* Pad if less than 16 bytes */}
						{row.bytes.length < 16 && (
							<span>{"   ".repeat(16 - row.bytes.length)}</span>
						)}
					</span>

					{/* ASCII */}
					<span className="text-gray-500">
						{row.bytes.map((byte, j) => {
							const globalIndex = row.offset + j;
							const char = isPrintable(byte) ? String.fromCharCode(byte) : ".";
							return (
								<span
									key={j}
									className={
										isHighlighted(globalIndex)
											? "bg-blue-800/60 text-blue-200"
											: ""
									}
								>
									{char}
								</span>
							);
						})}
					</span>
				</div>
			))}
		</div>
	);
}
