import { useEffect, useRef, useState } from "react";
import { usePacketStore } from "../../stores/packet-store";

export function FilterBar() {
	const setFilterText = usePacketStore((s) => s.setFilterText);
	const filterText = usePacketStore((s) => s.filterText);
	const [localValue, setLocalValue] = useState(filterText);
	const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

	useEffect(() => {
		setLocalValue(filterText);
	}, [filterText]);

	const handleChange = (value: string) => {
		setLocalValue(value);
		clearTimeout(timerRef.current);
		timerRef.current = setTimeout(() => {
			setFilterText(value);
		}, 200);
	};

	const handleClear = () => {
		setLocalValue("");
		setFilterText("");
	};

	return (
		<div className="flex items-center gap-1.5 flex-1 min-w-0">
			<div className="relative flex-1 min-w-0">
				<input
					data-filter-input
					type="text"
					value={localValue}
					onChange={(e) => handleChange(e.target.value)}
					placeholder="Filter: proto:tcp  ip:192.168.1.1  port:80  stream:5"
					className="w-full bg-gray-800 text-gray-200 border border-gray-600 rounded px-2 py-1 text-xs font-mono placeholder:text-gray-600 focus:outline-none focus:border-blue-500"
				/>
				{localValue && (
					<button
						onClick={handleClear}
						className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 text-xs"
					>
						×
					</button>
				)}
			</div>
		</div>
	);
}
