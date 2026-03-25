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
}
