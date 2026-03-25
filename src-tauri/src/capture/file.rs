use tauri::{AppHandle, Emitter};

use crate::parser;
use crate::parser::types::{ImportProgress, PacketSummary};
use crate::state::AppState;

pub fn import_pcap_file(app: &AppHandle, state: &AppState, path: &str) -> Result<u64, String> {
    let mut cap = pcap::Capture::from_file(path).map_err(|e| e.to_string())?;

    let mut batch: Vec<PacketSummary> = Vec::with_capacity(200);
    let mut total_parsed: u64 = 0;

    while let Ok(packet) = cap.next_packet() {
        let id = state
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let timestamp_us =
            packet.header.ts.tv_sec as i64 * 1_000_000 + packet.header.ts.tv_usec as i64;

        let record = parser::parse_packet(
            id,
            timestamp_us,
            packet.header.caplen,
            packet.header.len,
            "file",
            packet.data,
        );

        let summary = record.to_summary();

        // Store raw bytes and full record
        {
            let mut raw = state.raw_bytes.lock().unwrap();
            raw.push((id, packet.data.to_vec()));
        }
        {
            let mut packets = state.packets.lock().unwrap();
            packets.push(record);
        }

        batch.push(summary);
        total_parsed += 1;

        // Emit batch every 200 packets
        if batch.len() >= 200 {
            let _ = app.emit("packets_batch", &batch);
            batch.clear();

            let _ = app.emit(
                "import_progress",
                &ImportProgress {
                    parsed: total_parsed,
                    total: 0, // unknown total
                },
            );
        }
    }

    // Flush remaining
    if !batch.is_empty() {
        let _ = app.emit("packets_batch", &batch);
    }

    // Final progress
    let _ = app.emit(
        "import_progress",
        &ImportProgress {
            parsed: total_parsed,
            total: total_parsed,
        },
    );

    Ok(total_parsed)
}
