import type { TopProtocol } from "../types/packets";

export const PROTOCOL_COLORS: Record<
	TopProtocol,
	{ bg: string; text: string; row: string }
> = {
	Http: { bg: "bg-blue-900", text: "text-blue-300", row: "bg-blue-950/50" },
	Https: { bg: "bg-blue-900", text: "text-blue-300", row: "bg-blue-950/50" },
	Dns: {
		bg: "bg-purple-900",
		text: "text-purple-300",
		row: "bg-purple-950/50",
	},
	Tls: { bg: "bg-teal-900", text: "text-teal-300", row: "bg-teal-950/50" },
	Tcp: { bg: "bg-gray-800", text: "text-gray-300", row: "bg-gray-900/50" },
	Udp: {
		bg: "bg-orange-900",
		text: "text-orange-300",
		row: "bg-orange-950/50",
	},
	Icmp: {
		bg: "bg-yellow-900",
		text: "text-yellow-300",
		row: "bg-yellow-950/50",
	},
	Ipv4: { bg: "bg-gray-800", text: "text-gray-400", row: "bg-gray-900/30" },
	Ipv6: { bg: "bg-gray-800", text: "text-gray-400", row: "bg-gray-900/30" },
	Arp: {
		bg: "bg-green-900",
		text: "text-green-300",
		row: "bg-green-950/50",
	},
	Ethernet: {
		bg: "bg-gray-800",
		text: "text-gray-400",
		row: "bg-gray-900/30",
	},
	Unknown: {
		bg: "bg-gray-900",
		text: "text-gray-500",
		row: "bg-gray-900/20",
	},
};
