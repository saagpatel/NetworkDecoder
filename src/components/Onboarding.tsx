import { useState } from "react";

const STEPS = [
	{
		icon: "\u2460",
		title: "Select an Interface",
		description:
			'Choose a network interface from the dropdown in the toolbar. For Wi-Fi traffic, select "en0".',
	},
	{
		icon: "\u2461",
		title: "Start Capturing",
		description:
			"Click the green Start button to begin capturing packets. You will need elevated privileges (sudo) for live capture.",
	},
	{
		icon: "\u2462",
		title: "Inspect Packets",
		description:
			"Click any packet in the list to see its decoded layers, field values, and raw hex bytes.",
	},
];

interface OnboardingProps {
	onDismiss: () => void;
}

export function Onboarding({ onDismiss }: OnboardingProps) {
	const [step, setStep] = useState(0);

	const handleDismiss = () => {
		localStorage.setItem("networkdecoder_onboarding_dismissed", "true");
		onDismiss();
	};

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
			<div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl max-w-md w-full mx-4">
				{/* Header */}
				<div className="px-6 pt-6 pb-2">
					<h2 className="text-lg font-bold text-gray-100">
						Welcome to Network Decoder
					</h2>
					<p className="text-xs text-gray-500 mt-1">
						A visual packet analyzer for macOS
					</p>
				</div>

				{/* Step content */}
				<div className="px-6 py-6">
					<div className="text-center">
						<div className="text-4xl mb-3 text-blue-400">
							{STEPS[step].icon}
						</div>
						<h3 className="text-sm font-bold text-gray-200 mb-2">
							{STEPS[step].title}
						</h3>
						<p className="text-xs text-gray-400 leading-relaxed">
							{STEPS[step].description}
						</p>
					</div>
				</div>

				{/* Step indicators */}
				<div className="flex justify-center gap-1.5 pb-4">
					{STEPS.map((_, i) => (
						<div
							key={`step-${i}`}
							className={`w-2 h-2 rounded-full ${i === step ? "bg-blue-500" : "bg-gray-700"}`}
						/>
					))}
				</div>

				{/* Actions */}
				<div className="flex items-center justify-between px-6 pb-6">
					<button
						onClick={handleDismiss}
						className="text-xs text-gray-500 hover:text-gray-300"
						type="button"
					>
						Skip
					</button>
					<div className="flex gap-2">
						{step > 0 && (
							<button
								onClick={() => setStep(step - 1)}
								className="px-4 py-1.5 text-xs rounded bg-gray-800 text-gray-300 hover:bg-gray-700"
								type="button"
							>
								Back
							</button>
						)}
						{step < STEPS.length - 1 ? (
							<button
								onClick={() => setStep(step + 1)}
								className="px-4 py-1.5 text-xs rounded bg-blue-700 text-white hover:bg-blue-600"
								type="button"
							>
								Next
							</button>
						) : (
							<button
								onClick={handleDismiss}
								className="px-4 py-1.5 text-xs rounded bg-blue-700 text-white hover:bg-blue-600"
								type="button"
							>
								Get Started
							</button>
						)}
					</div>
				</div>
			</div>
		</div>
	);
}
