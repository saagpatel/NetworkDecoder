use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::buffer::ring::RingBuffer;
use crate::parser::types::PacketRecord;

const BUFFER_CAPACITY: usize = 50_000;

pub struct CaptureHandle {
    pub stop_flag: Arc<AtomicBool>,
    pub thread: Option<JoinHandle<()>>,
}

pub struct AppState {
    pub packets: Mutex<RingBuffer<PacketRecord>>,
    pub raw_bytes: Mutex<RingBuffer<(u64, Vec<u8>)>>,
    pub capture_handle: Mutex<Option<CaptureHandle>>,
    pub next_id: AtomicU64,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            packets: Mutex::new(RingBuffer::new(BUFFER_CAPACITY)),
            raw_bytes: Mutex::new(RingBuffer::new(BUFFER_CAPACITY)),
            capture_handle: Mutex::new(None),
            next_id: AtomicU64::new(0),
        }
    }
}
