use std::fs::File;
use std::io::Write;
use std::sync::atomic::Ordering;

use tauri::{AppHandle, State};

use crate::capture;
use crate::parser::types::{InterfaceInfo, PacketRecord};
use crate::state::AppState;

#[tauri::command]
pub fn get_interfaces() -> Vec<InterfaceInfo> {
    pnet_datalink::interfaces()
        .into_iter()
        .map(|iface| InterfaceInfo {
            name: iface.name.clone(),
            description: iface.description.clone(),
            is_up: iface.is_up(),
            is_loopback: iface.is_loopback(),
        })
        .collect()
}

#[tauri::command]
pub fn start_capture(
    interface: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    capture::live::start_live_capture(app, &state, &interface)
}

#[tauri::command]
pub fn stop_capture(state: State<'_, AppState>) -> Result<(), String> {
    let mut handle = state.capture_handle.lock().unwrap();
    if let Some(capture_handle) = handle.take() {
        capture_handle.stop_flag.store(true, Ordering::Relaxed);
        if let Some(thread) = capture_handle.thread {
            thread
                .join()
                .map_err(|_| "Failed to join capture thread".to_string())?;
        }
    }
    Ok(())
}

#[tauri::command]
pub fn import_file(
    path: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<u64, String> {
    capture::file::import_pcap_file(&app, &state, &path)
}

#[tauri::command]
pub fn get_packet_detail(id: u64, state: State<'_, AppState>) -> Option<PacketRecord> {
    let packets = state.packets.lock().unwrap();
    packets.find(|p| p.id == id).cloned()
}

#[tauri::command]
pub fn get_packet_bytes(id: u64, state: State<'_, AppState>) -> Option<Vec<u8>> {
    let raw = state.raw_bytes.lock().unwrap();
    raw.find(|entry| entry.0 == id)
        .map(|(_, bytes)| bytes.clone())
}

#[tauri::command]
pub fn clear_buffer(state: State<'_, AppState>) {
    state.packets.lock().unwrap().clear();
    state.raw_bytes.lock().unwrap().clear();
    state.next_id.store(0, Ordering::Relaxed);
}

#[tauri::command]
pub fn export_pcap(path: String, state: State<'_, AppState>) -> Result<u64, String> {
    let raw = state.raw_bytes.lock().unwrap();
    let packets_buf = state.packets.lock().unwrap();

    let mut packet_data: Vec<(i64, u32, u32, Vec<u8>)> = Vec::new();
    for (id, bytes) in raw.iter() {
        if let Some(record) = packets_buf.find(|p| p.id == *id) {
            packet_data.push((
                record.timestamp_us,
                bytes.len() as u32,
                record.original_len,
                bytes.clone(),
            ));
        }
    }

    drop(raw);
    drop(packets_buf);

    let written = write_pcap_file(&path, &packet_data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(written)
}

fn write_pcap_file(path: &str, packets: &[(i64, u32, u32, Vec<u8>)]) -> Result<u64, String> {
    let mut file = File::create(path).map_err(|e| e.to_string())?;

    // PCAP global header (24 bytes)
    let header: [u8; 24] = [
        0xd4, 0xc3, 0xb2, 0xa1, // magic number (little-endian)
        0x02, 0x00, 0x04, 0x00, // version 2.4
        0x00, 0x00, 0x00, 0x00, // thiszone
        0x00, 0x00, 0x00, 0x00, // sigfigs
        0xff, 0xff, 0x00, 0x00, // snaplen (65535)
        0x01, 0x00, 0x00, 0x00, // Ethernet link type
    ];
    file.write_all(&header).map_err(|e| e.to_string())?;

    let mut written = 0u64;
    for (timestamp_us, caplen, origlen, data) in packets {
        let ts_sec = (*timestamp_us / 1_000_000) as u32;
        let ts_usec = (*timestamp_us % 1_000_000) as u32;

        // Packet record header (16 bytes)
        file.write_all(&ts_sec.to_le_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(&ts_usec.to_le_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(&caplen.to_le_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(&origlen.to_le_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(data).map_err(|e| e.to_string())?;
        written += 1;
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;

    #[test]
    fn test_export_pcap_round_trip() {
        let state = AppState::new();

        let mut cap =
            pcap::Capture::from_file("tests/fixtures/http.cap").expect("Failed to open http.cap");

        let mut count = 0u64;
        while let Ok(packet) = cap.next_packet() {
            let id = state.next_id.fetch_add(1, Ordering::Relaxed);
            let timestamp_us =
                packet.header.ts.tv_sec as i64 * 1_000_000 + packet.header.ts.tv_usec as i64;

            let record = crate::parser::parse_packet(
                id,
                timestamp_us,
                packet.header.caplen,
                packet.header.len,
                "test",
                packet.data,
            );

            state
                .raw_bytes
                .lock()
                .unwrap()
                .push((id, packet.data.to_vec()));
            state.packets.lock().unwrap().push(record);
            count += 1;
        }

        assert!(count > 0, "Should have imported at least one packet");

        let tmp_path = "/tmp/test_export_round_trip.pcap";

        // Collect packet data (mimicking the command logic)
        let raw = state.raw_bytes.lock().unwrap();
        let packets_buf = state.packets.lock().unwrap();

        let mut packet_data: Vec<(i64, u32, u32, Vec<u8>)> = Vec::new();
        for (id, bytes) in raw.iter() {
            if let Some(record) = packets_buf.find(|p| p.id == *id) {
                packet_data.push((
                    record.timestamp_us,
                    bytes.len() as u32,
                    record.original_len,
                    bytes.clone(),
                ));
            }
        }
        drop(raw);
        drop(packets_buf);

        let written = write_pcap_file(tmp_path, &packet_data).expect("Failed to write PCAP");
        assert_eq!(written, count, "Written count should match imported count");

        // Re-import and verify
        let mut reimport =
            pcap::Capture::from_file(tmp_path).expect("Failed to re-open exported PCAP");
        let mut reimport_count = 0u64;
        while reimport.next_packet().is_ok() {
            reimport_count += 1;
        }
        assert_eq!(
            reimport_count, count,
            "Re-imported count should match original"
        );

        let _ = std::fs::remove_file(tmp_path);
    }
}
