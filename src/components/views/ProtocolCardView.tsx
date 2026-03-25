import { invoke } from "@tauri-apps/api/core";
import { useEffect, useMemo, useState } from "react";
import { PROTOCOL_COLORS } from "../../lib/protocol-colors";
import { usePacketStore } from "../../stores/packet-store";
import type {
	DnsFields,
	HttpFields,
	PacketRecord,
	PacketSummary,
	TlsFields,
	TopProtocol,
} from "../../types/packets";

interface CardData {
	id: string;
	protocol: TopProtocol;
	title: string;
	subtitle: string;
	packetId: number;
	packetCount: number;
}

const APP_PROTOCOLS: TopProtocol[] = ["Http", "Dns", "Tls"];

export function ProtocolCardView({ packets }: { packets: PacketSummary[] }) {
	const cards = useMemo(() => {
		const cardMap = new Map<string, CardData>();

		for (const pkt of packets) {
			if (!APP_PROTOCOLS.includes(pkt.protocol)) continue;

			const key =
				pkt.stream_id !== null
					? `${pkt.protocol}-${pkt.stream_id}`
					: `${pkt.protocol}-${pkt.src_addr}-${pkt.dst_addr}`;

			const existing = cardMap.get(key);
			if (existing) {
				existing.packetCount++;
			} else {
				cardMap.set(key, {
					id: key,
					protocol: pkt.protocol,
					title: pkt.info,
					subtitle: `${pkt.src_addr ?? "?"} \u2192 ${pkt.dst_addr ?? "?"}`,
					packetId: pkt.id,
					packetCount: 1,
				});
			}
		}

		return Array.from(cardMap.values());
	}, [packets]);

	if (cards.length === 0) {
		return (
			<div className="flex items-center justify-center h-full text-gray-500 text-sm font-mono">
				No application-layer protocols detected. Import a capture with HTTP,
				DNS, or TLS traffic.
			</div>
		);
	}

	return (
		<div className="flex-1 overflow-auto p-4">
			<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
				{cards.map((card) => (
					<ProtocolCard key={card.id} card={card} />
				))}
			</div>
		</div>
	);
}

function ProtocolCard({ card }: { card: CardData }) {
	const [detail, setDetail] = useState<PacketRecord | null>(null);
	const selectPacket = usePacketStore((s) => s.selectPacket);
	const colors = PROTOCOL_COLORS[card.protocol] ?? PROTOCOL_COLORS.Unknown;

	useEffect(() => {
		invoke<PacketRecord | null>("get_packet_detail", { id: card.packetId })
			.then(setDetail)
			.catch((err: unknown) => {
				console.error("Failed to fetch card detail:", err);
			});
	}, [card.packetId]);

	const appLayer = detail?.layers.find((l) =>
		APP_PROTOCOLS.includes(l.layer as TopProtocol),
	);
	const fields = appLayer?.fields as Record<string, unknown> | undefined;

	return (
		<div
			className="rounded-lg border border-gray-700 bg-gray-900 overflow-hidden cursor-pointer hover:border-gray-500 transition-colors"
			onClick={() => selectPacket(card.packetId)}
		>
			<div className={`px-4 py-2 flex items-center gap-2 ${colors.bg}`}>
				<span className={`text-xs font-bold ${colors.text}`}>
					{card.protocol}
				</span>
				<span className="text-xs text-gray-400 ml-auto">
					{card.packetCount} pkts
				</span>
			</div>

			<div className="px-4 py-3 text-xs font-mono space-y-2">
				{card.protocol === "Http" && fields && (
					<HttpCardBody fields={fields as unknown as HttpFields} />
				)}
				{card.protocol === "Dns" && fields && (
					<DnsCardBody fields={fields as unknown as DnsFields} />
				)}
				{card.protocol === "Tls" && fields && (
					<TlsCardBody fields={fields as unknown as TlsFields} />
				)}
				{!fields && (
					<div className="text-gray-500">
						<p className="truncate">{card.title}</p>
						<p className="text-gray-600 truncate">{card.subtitle}</p>
					</div>
				)}
			</div>
		</div>
	);
}

/* ---------- HTTP ---------- */

const METHOD_COLORS: Record<string, string> = {
	GET: "bg-green-800 text-green-200",
	POST: "bg-blue-800 text-blue-200",
	PUT: "bg-yellow-800 text-yellow-200",
	DELETE: "bg-red-800 text-red-200",
	PATCH: "bg-orange-800 text-orange-200",
	HEAD: "bg-gray-700 text-gray-300",
	OPTIONS: "bg-gray-700 text-gray-300",
};

function HttpCardBody({ fields }: { fields: HttpFields }) {
	const [showAllHeaders, setShowAllHeaders] = useState(false);
	const headers = fields.headers ?? [];
	const visibleHeaders = showAllHeaders ? headers : headers.slice(0, 3);

	return (
		<div className="space-y-1.5">
			<div className="flex items-center gap-2">
				{fields.method && (
					<span
						className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${METHOD_COLORS[fields.method] ?? "bg-gray-700 text-gray-300"}`}
					>
						{fields.method}
					</span>
				)}
				{fields.status_code != null && (
					<span
						className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
							fields.status_code < 300
								? "bg-green-800 text-green-200"
								: fields.status_code < 400
									? "bg-yellow-800 text-yellow-200"
									: "bg-red-800 text-red-200"
						}`}
					>
						{fields.status_code} {fields.status_text ?? ""}
					</span>
				)}
				<span className="text-gray-500 text-[10px]">{fields.version}</span>
			</div>

			{fields.path && <p className="text-gray-200 truncate">{fields.path}</p>}

			{visibleHeaders.length > 0 && (
				<div className="space-y-0.5 text-[10px]">
					{visibleHeaders.map(([k, v], i) => (
						<div key={`${k}-${i}`} className="flex gap-1">
							<span className="text-gray-500 shrink-0">{k}:</span>
							<span className="text-gray-400 truncate">{v}</span>
						</div>
					))}
					{headers.length > 3 && (
						<button
							type="button"
							onClick={(e) => {
								e.stopPropagation();
								setShowAllHeaders(!showAllHeaders);
							}}
							className="text-blue-400 hover:text-blue-300"
						>
							{showAllHeaders
								? "Show less"
								: `Show all ${headers.length} headers`}
						</button>
					)}
				</div>
			)}
		</div>
	);
}

/* ---------- DNS ---------- */

function DnsCardBody({ fields }: { fields: DnsFields }) {
	return (
		<div className="space-y-1.5">
			<div className="flex items-center gap-2">
				<span
					className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
						fields.is_response
							? "bg-green-800 text-green-200"
							: "bg-purple-800 text-purple-200"
					}`}
				>
					{fields.is_response ? "Response" : "Query"}
				</span>
				{fields.questions.length > 0 && (
					<span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-gray-700 text-gray-300">
						{fields.questions[0].qtype}
					</span>
				)}
			</div>

			{fields.questions.map((q, i) => (
				<p key={`q-${i}`} className="text-gray-200 font-bold truncate">
					{q.name}
				</p>
			))}

			{fields.answers.length > 0 && (
				<div className="space-y-0.5 text-[10px]">
					{fields.answers.map((a, i) => (
						<div key={`a-${i}`} className="flex gap-1">
							<span className="text-gray-500 shrink-0">{a.rtype}</span>
							<span className="text-gray-300 truncate">{a.data}</span>
							<span className="text-gray-600 shrink-0 ml-auto">
								TTL {a.ttl}
							</span>
						</div>
					))}
				</div>
			)}
		</div>
	);
}

/* ---------- TLS ---------- */

function TlsCardBody({ fields }: { fields: TlsFields }) {
	const [showAllCiphers, setShowAllCiphers] = useState(false);
	const ciphers = fields.cipher_suites ?? [];
	const visibleCiphers = showAllCiphers ? ciphers : ciphers.slice(0, 3);

	return (
		<div className="space-y-1.5">
			<div className="flex items-center gap-2 flex-wrap">
				<span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-teal-800 text-teal-200">
					{fields.record_type}
				</span>
				<span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-gray-700 text-gray-300">
					{fields.tls_version}
				</span>
			</div>

			{fields.sni && (
				<p className="text-gray-200 font-bold truncate">{fields.sni}</p>
			)}

			{visibleCiphers.length > 0 && (
				<div className="space-y-0.5 text-[10px]">
					{visibleCiphers.map((c, i) => (
						<p key={`c-${i}`} className="text-gray-400 truncate">
							{c}
						</p>
					))}
					{ciphers.length > 3 && (
						<button
							type="button"
							onClick={(e) => {
								e.stopPropagation();
								setShowAllCiphers(!showAllCiphers);
							}}
							className="text-blue-400 hover:text-blue-300"
						>
							{showAllCiphers
								? "Show less"
								: `Show all ${ciphers.length} cipher suites`}
						</button>
					)}
				</div>
			)}
		</div>
	);
}
