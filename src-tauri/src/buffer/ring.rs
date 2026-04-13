use std::collections::VecDeque;

pub struct RingBuffer<T> {
    capacity: usize,
    inner: VecDeque<T>,
}

impl<T> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: VecDeque::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, item: T) {
        if self.inner.len() == self.capacity {
            self.inner.pop_front();
        }
        self.inner.push_back(item);
    }

    pub fn drain(&mut self) -> Vec<T> {
        self.inner.drain(..).collect()
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
    }

    pub fn find<F: Fn(&T) -> bool>(&self, predicate: F) -> Option<&T> {
        self.inner.iter().find(|item| predicate(item))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_eviction() {
        let mut buf = RingBuffer::new(50_000);
        for i in 0..50_001u64 {
            buf.push(i);
        }
        assert_eq!(buf.len(), 50_000);
        let items = buf.drain();
        assert_eq!(items[0], 1); // oldest (0) was evicted
        assert_eq!(*items.last().unwrap(), 50_000);
    }

    #[test]
    fn test_ring_buffer_drain() {
        let mut buf = RingBuffer::new(10);
        for i in 0..5u64 {
            buf.push(i);
        }
        let drained = buf.drain();
        assert_eq!(drained.len(), 5);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_ring_buffer_clear() {
        let mut buf = RingBuffer::new(10);
        for i in 0..5u64 {
            buf.push(i);
        }
        buf.clear();
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_ring_buffer_get_valid_index() {
        let mut buf = RingBuffer::new(10);
        buf.push(42u32);
        buf.push(99u32);
        assert_eq!(buf.get(0), Some(&42));
        assert_eq!(buf.get(1), Some(&99));
    }

    #[test]
    fn test_ring_buffer_get_out_of_bounds() {
        let buf: RingBuffer<u32> = RingBuffer::new(10);
        assert_eq!(buf.get(0), None);
    }

    #[test]
    fn test_ring_buffer_find_present() {
        let mut buf = RingBuffer::new(10);
        for i in 0u32..5 {
            buf.push(i);
        }
        let found = buf.find(|&x| x == 3);
        assert_eq!(found, Some(&3));
    }

    #[test]
    fn test_ring_buffer_find_absent() {
        let mut buf = RingBuffer::new(10);
        for i in 0u32..5 {
            buf.push(i);
        }
        assert!(buf.find(|&x| x == 99).is_none());
    }

    #[test]
    fn test_ring_buffer_capacity_one_overflow() {
        // Capacity of 1: each push replaces the only element
        let mut buf = RingBuffer::new(1);
        buf.push(10u32);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.get(0), Some(&10));
        buf.push(20u32);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.get(0), Some(&20));
    }

    #[test]
    fn test_ring_buffer_iter_order() {
        let mut buf = RingBuffer::new(5);
        for i in 0u32..5 {
            buf.push(i);
        }
        let collected: Vec<u32> = buf.iter().copied().collect();
        assert_eq!(collected, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_ring_buffer_iter_after_overflow_preserves_insertion_order() {
        // Push 7 items into capacity-5 buffer; first 2 are evicted
        let mut buf = RingBuffer::new(5);
        for i in 0u32..7 {
            buf.push(i);
        }
        let collected: Vec<u32> = buf.iter().copied().collect();
        assert_eq!(collected, vec![2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_ring_buffer_empty_drain() {
        let mut buf: RingBuffer<u32> = RingBuffer::new(10);
        let drained = buf.drain();
        assert!(drained.is_empty());
    }
}
