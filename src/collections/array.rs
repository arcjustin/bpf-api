use crate::error::Error;
use crate::platform::{Map, MapType};

pub struct Array<V: Copy + Default> {
    map: Map<u32, V>,
}

impl<V: Copy + Default> Array<V> {
    /// Creates a new BPF array with `entries` elements. The kernel
    /// zero-initializes all elements on creation.
    ///
    /// # Arguments
    ///
    /// * `entries` - The number of elements in the array.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::Array;
    ///
    /// let array = Array::<u32>::with_capacity(10).expect("Failed to create array");
    /// ```
    pub fn with_capacity(entries: u32) -> Result<Self, Error> {
        Ok(Self {
            map: Map::with_capacity(MapType::Array, entries)?,
        })
    }

    /// Retrieves the value for a given element.
    ///
    /// # Arguments
    ///
    /// * `index` - The element index to retrieve.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::Array;
    ///
    /// let array = Array::<u32>::with_capacity(10).expect("Failed to create array");
    /// assert_eq!(array.get(5).expect("Failed to get element 5"), 0);
    /// ```
    pub fn get(&self, index: u32) -> Result<V, Error> {
        self.map.get(&index)
    }

    /// Sets the value at a given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The element index to retrieve.
    /// * `value` - The new value.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::Array;
    ///
    /// let array = Array::<u32>::with_capacity(10).expect("Failed to create array");
    /// assert_eq!(array.get(5).expect("Failed to get element 5"), 0);
    /// assert!(matches!(array.set(5, 10), Ok(_)));
    /// assert_eq!(array.get(5).expect("Failed to get element 5"), 10);
    /// ```
    pub fn set(&self, index: u32, value: V) -> Result<(), Error> {
        self.map.set(&index, &value)
    }

    /// Retrieve the BPF identifier for this map. This is the underlying file
    /// descriptor that's used in eBPF programs.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::Array;
    ///
    /// let array = Array::<u32>::with_capacity(10).expect("Failed to create array");
    /// array.get_identifier();
    /// ```
    pub fn get_identifier(&self) -> u32 {
        self.map.get_identifier()
    }
}
