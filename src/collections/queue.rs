use crate::error::Error;
use crate::platform::{Map, MapType};

#[derive(Copy, Clone, Default)]
struct Void {}

/// A queue that exposes an idiomatic Rust interface to an underlying BPF queue.
pub struct Queue<V: Copy + Default> {
    map: Map<Void, V>,
}

impl<V: Copy + Default> Queue<V> {
    /// Creates a new BPF queue with `entries` elements. A queue works as
    /// a FIFO container: `push()` inserts an element to the back and `pop()`
    /// consumes an element from the front.
    ///
    /// # Arguments
    ///
    /// * `entries` - The maximum number of elements in the queue.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::Queue;
    ///
    /// let queue = Queue::<u32>::with_capacity(10).expect("Failed to create queue");
    /// ```
    pub fn with_capacity(entries: u32) -> Result<Self, Error> {
        Ok(Self {
            map: Map::with_capacity(MapType::Queue, entries)?,
        })
    }

    /// Retrieves and removes the next element in the queue, if it exists.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::Queue;
    ///
    /// let queue = Queue::<u32>::with_capacity(10).expect("Failed to create queue");
    /// assert!(matches!(queue.pop(), Err(_)));
    /// ```
    pub fn pop(&self) -> Result<V, Error> {
        self.map.get_and_del(&Void::default())
    }

    /// Retrieves next element in the queue, if it exists. This does _not_ remove
    /// the element.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::Queue;
    ///
    /// let queue = Queue::<u32>::with_capacity(10).expect("Failed to create queue");
    /// assert!(matches!(queue.front(), Err(_)));
    /// ```
    pub fn front(&self) -> Result<V, Error> {
        self.map.get(&Void::default())
    }

    /// Push a new element to the back of the queue.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::Queue;
    ///
    /// let queue = Queue::<u32>::with_capacity(10).expect("Failed to create queue");
    /// assert!(matches!(queue.push(100), Ok(_)));
    /// assert!(matches!(queue.front(), Ok(100)));
    /// assert!(matches!(queue.pop(), Ok(100)));
    /// assert!(matches!(queue.pop(), Err(_)));
    /// ```
    pub fn push(&self, val: V) -> Result<(), Error> {
        self.map.set(&Void::default(), &val)
    }

    /// Retrieve the BPF identifier for this map. This is the underlying file
    /// descriptor that's used in eBPF programs.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::Queue;
    ///
    /// let queue = Queue::<u32>::with_capacity(10).expect("Failed to create queue");
    /// queue.get_identifier();
    /// ```
    pub fn get_identifier(&self) -> u32 {
        self.map.get_identifier()
    }
}
