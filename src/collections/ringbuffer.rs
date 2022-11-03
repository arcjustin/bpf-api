use crate::error::{Error, Result};
use crate::platform::{Map, MapType};

use byteorder::{ByteOrder, NativeEndian};

#[derive(Copy, Clone, Default)]
struct Void {}

/// A helper class used as a single place to deal with modular arithmetic.
struct RingMeta {
    cons_pos: usize,
    prod_pos: usize,
    capacity: usize,
}

impl RingMeta {
    /// Returns the amount of data left to consume.
    fn len(&self) -> usize {
        if self.cons_pos <= self.prod_pos {
            self.prod_pos - self.cons_pos
        } else {
            self.capacity - self.cons_pos + self.prod_pos + 1
        }
    }

    /// Returns whether there is data available to consume.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Safely gets the consumer position.
    fn get_cons_pos(&self) -> usize {
        self.cons_pos % self.capacity
    }

    /// Advances the consumer position by size, up to the producer position.
    fn consume(&mut self, mut size: usize) -> usize {
        if size > self.len() {
            size = self.len();
        }

        self.cons_pos = (self.cons_pos + size) % self.capacity;
        self.cons_pos
    }
}

/// An interface for using BPF ringbuffer maps.
pub struct RingBuffer {
    capacity: usize,
    map: Map<Void, Void>,
}

impl RingBuffer {
    const PAGE_SIZE: usize = 4096; // this could be different on different platforms.
    const CONSUMER_OFFSET: usize = 0;
    const PRODUCER_OFFSET: usize = Self::PAGE_SIZE;
    const BUFFER_OFFSET: usize = Self::PAGE_SIZE * 2;

    /// Creates a new ring buffer with the given number of pages. The capacity of
    /// a BPF ring buffer has to be a power of 2 pages. The min value given is
    /// rounded up to this capacity; `get_capacity` will return the actual allocated
    /// capacity of the ring buffer.
    ///
    /// # Arguments
    ///
    /// * `min_capacity` - The minimum capacity of the ringbuffer.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::RingBuffer;
    ///
    /// for capacity in [ 1, 4095, 4096, 8191, 8192, 16535, 16536, 40000 ] {
    ///     let ringbuffer = RingBuffer::with_capacity(capacity).expect("Failed to create ringbuffer");
    ///     assert!(ringbuffer.get_capacity() >= capacity as usize);
    /// }
    ///
    /// let ringbuffer = RingBuffer::with_capacity(4096).expect("Failed to create ringbuffer");
    /// assert_eq!(ringbuffer.get_capacity(), 4096);
    /// ```
    pub fn with_capacity(min_capacity: u32) -> Result<Self> {
        let min_capacity: usize = min_capacity.try_into()?;
        if min_capacity == 0 {
            return Err(Error::InvalidArgument);
        }

        // round up to the next power of 2 pages.
        let pages = (min_capacity + (Self::PAGE_SIZE - 1)) / Self::PAGE_SIZE;
        let mut capacity = pages - 1;
        capacity |= capacity >> 1;
        capacity |= capacity >> 2;
        capacity |= capacity >> 4;
        capacity |= capacity >> 8;
        capacity |= capacity >> 16;
        capacity += 1;
        capacity *= Self::PAGE_SIZE;

        let mut map = Map::with_capacity(MapType::RingBuf, capacity.try_into()?)?;

        // These calls premap the underlying ring buffer areas. Map caches the requested
        // mappings and returns them immediately on subsequent calls. This ensures that 1)
        // the mappings are successful and 2) calls like len(), get_buf(), etc don't fail.
        //
        // The consumer page is mapped twice: once as readable and once as writable so that
        // calls to functions that don't mutate the constants don't need to take a mutable
        // reference on self.
        //
        // The actual buffer itself is mapped 2x its size; this is an old trick to make dealing
        // with the boundary area of a ringbuffer easier. ie: you can map the full capacity size
        // from the start of the buffer til the last byte and get a contiguous VA mapping that
        // loops back onto itself.
        map.get_map::<u8>(Self::CONSUMER_OFFSET, Self::PAGE_SIZE)?;
        map.get_map_mut::<u8>(Self::CONSUMER_OFFSET, Self::PAGE_SIZE)?;
        map.get_map::<u8>(Self::PRODUCER_OFFSET, Self::PAGE_SIZE)?;
        map.get_map::<u8>(Self::BUFFER_OFFSET, capacity * 2)?;

        Ok(Self { capacity, map })
    }

    /// Returns the capacity of the ring buffer.
    pub fn get_capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the amount of data available for reading.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::RingBuffer;
    ///
    /// let ringbuffer = RingBuffer::with_capacity(4096).expect("Failed to create ringbuffer");
    /// assert_eq!(ringbuffer.len(), 0);
    /// ```
    pub fn len(&self) -> usize {
        self.get_meta().len()
    }

    /// Returns whether the ring buffer is empty or not.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::RingBuffer;
    ///
    /// let ringbuffer = RingBuffer::with_capacity(4096).expect("Failed to create ringbuffer");
    /// assert!(ringbuffer.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.get_meta().is_empty()
    }

    /// Returns a slice that represents the readable range.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::RingBuffer;
    ///
    /// let ringbuffer = RingBuffer::with_capacity(4096).expect("Failed to create ringbuffer");
    /// assert_eq!(ringbuffer.get_buf().len(), 0);
    /// ```
    pub fn get_buf(&self) -> &[u8] {
        // Ring buffers are single producer, single consumer. There's a race here between
        // reading the metadata and accessing the buffer. However, since there's only 1
        // reader and 1 writer, the buffer can only get larger between calls.
        let meta = self.get_meta();
        let cons_pos = meta.get_cons_pos();
        let len = meta.len();
        let buf = self
            .map
            .get_map::<u8>(Self::BUFFER_OFFSET, self.capacity * 2)
            .expect("Failed to map buffer");
        &buf[cons_pos..cons_pos + len]
    }

    /// Advances the read position by the given size. If the size is more than the number
    /// of bytes available, the read position is advanced to the write position, clearing
    /// the buffer.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::RingBuffer;
    ///
    /// let mut ringbuffer = RingBuffer::with_capacity(4096).expect("Failed to create ringbuffer");
    /// ringbuffer.consume(100);
    /// ```
    pub fn consume(&mut self, size: usize) {
        let mut meta = self.get_meta();
        let new_pos = meta.consume(size);
        let cons_buf = self
            .map
            .get_map_mut::<u8>(Self::CONSUMER_OFFSET, Self::PAGE_SIZE)
            .expect("Failed to map buffer");
        NativeEndian::write_u32(&mut cons_buf[0..4], new_pos as u32);
    }

    /// Retrieve the BPF identifier for this map. This is the underlying file
    /// descriptor that's used in eBPF programs.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::RingBuffer;
    ///
    /// let ringbuffer = RingBuffer::with_capacity(8).expect("Failed to create ringbuffer");
    /// ringbuffer.get_identifier();
    /// ```
    pub fn get_identifier(&self) -> u32 {
        self.map.get_identifier()
    }

    /// Returns meta info about the ring buffer like read/write pos and capacity.
    fn get_meta(&self) -> RingMeta {
        let cons_buf = self
            .map
            .get_map(Self::CONSUMER_OFFSET, Self::PAGE_SIZE)
            .expect("Failed to get consumer mapping");
        let prod_buf = self
            .map
            .get_map(Self::PRODUCER_OFFSET, Self::PAGE_SIZE)
            .expect("Failed to get producer mapping");
        let cons_pos = NativeEndian::read_u32(&cons_buf[0..4]) as usize;
        let prod_pos = NativeEndian::read_u32(&prod_buf[0..4]) as usize;

        RingMeta {
            cons_pos,
            prod_pos,
            capacity: self.capacity,
        }
    }
}
