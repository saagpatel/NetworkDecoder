use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tauri::{AppHandle, Emitter, Manager};

use crate::parser;
use crate::parser::types::PacketSummary;
use crate::state::{AppState, CaptureHandle};

pub fn start_live_capture(app: AppHandle, state: &AppState, interface: &str) -> Result<(), String> {
    // Check if already capturing
    {
        let handle = state.capture_handle.lock().unwrap();
        if handle.is_some() {
            return Err("Capture already in progress".to_string());
        }
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_clone = stop_flag.clone();
    let interface = interface.to_string();

    let app_clone = app.clone();

    let thread = std::thread::spawn(move || {
        let mut cap = match pcap::Capture::from_device(interface.as_str())
            .map_err(|e| e.to_string())
            .and_then(|c| {
                c.promisc(true)
                    .snaplen(65535)
                    .timeout(100)
                    .open()
                    .map_err(|e| e.to_string())
            }) {
            Ok(cap) => cap,
            Err(e) => {
                eprintln!("Failed to open capture: {}", e);
                return;
            }
        };

        let mut batch: Vec<PacketSummary> = Vec::with_capacity(200);
        let mut last_stats_time = Instant::now();
        let mut packets_since_last_stats: u64 = 0;

        let state = app_clone.state::<AppState>();

        loop {
            if stop_flag_clone.load(Ordering::Relaxed) {
                break;
            }

            match cap.next_packet() {
                Ok(packet) => {
                    let id = state.next_id.fetch_add(1, Ordering::Relaxed);
                    let timestamp_us = packet.header.ts.tv_sec as i64 * 1_000_000
                        + packet.header.ts.tv_usec as i64;

                    let record = parser::parse_packet(
                        id,
                        timestamp_us,
                        packet.header.caplen,
                        packet.header.len,
                        &interface,
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
                    packets_since_last_stats += 1;

                    // Emit batch when full (max 200)
                    if batch.len() >= 200 {
                        let _ = app_clone.emit("packets_batch", &batch);
                        batch.clear();
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Natural 100ms tick — emit accumulated batch
                    if !batch.is_empty() {
                        let _ = app_clone.emit("packets_batch", &batch);
                        batch.clear();
                    }
                }
                Err(e) => {
                    eprintln!("Capture error: {}", e);
                    break;
                }
            }

            // Emit stats every ~1 second
            if last_stats_time.elapsed().as_secs() >= 1 {
                let elapsed = last_stats_time.elapsed().as_secs_f64();
                let stats = match cap.stats() {
                    Ok(s) => crate::parser::types::CaptureStats {
                        received: s.received as u64,
                        dropped: s.dropped as u64,
                        rate_pps: packets_since_last_stats as f64 / elapsed,
                    },
                    Err(_) => crate::parser::types::CaptureStats {
                        received: 0,
                        dropped: 0,
                        rate_pps: packets_since_last_stats as f64 / elapsed,
                    },
                };
                let _ = app_clone.emit("capture_stats", &stats);
                packets_since_last_stats = 0;
                last_stats_time = Instant::now();
            }
        }

        // Flush remaining batch
        if !batch.is_empty() {
            let _ = app_clone.emit("packets_batch", &batch);
        }
    });

    // Store the capture handle
    let mut handle = state.capture_handle.lock().unwrap();
    *handle = Some(CaptureHandle {
        stop_flag,
        thread: Some(thread),
    });

    Ok(())
}
