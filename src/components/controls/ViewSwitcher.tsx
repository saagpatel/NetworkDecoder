import { usePacketStore } from "../../stores/packet-store";

type ViewMode = "list" | "swimlane" | "cards";

const views: { mode: ViewMode; label: string; disabled?: boolean }[] = [
	{ mode: "list", label: "List" },
	{ mode: "swimlane", label: "Swimlane" },
	{ mode: "cards", label: "Cards" },
];

export function ViewSwitcher() {
	const viewMode = usePacketStore((s) => s.viewMode);
	const setViewMode = usePacketStore((s) => s.setViewMode);

	return (
		<div className="flex rounded overflow-hidden border border-gray-600">
			{views.map(({ mode, label, disabled }) => (
				<button
					key={mode}
					onClick={() => !disabled && setViewMode(mode)}
					disabled={disabled}
					className={`px-2.5 py-0.5 text-[11px] font-mono transition-colors ${
						viewMode === mode
							? "bg-blue-700 text-white"
							: disabled
								? "bg-gray-800 text-gray-600 cursor-not-allowed"
								: "bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-200"
					}`}
					title={disabled ? "Coming in Phase 3" : undefined}
				>
					{label}
				</button>
			))}
		</div>
	);
}
