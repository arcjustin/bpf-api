use crate::error::Error;
use crate::platform::{Map, MapType};

/// A hashmap that exposes an idiomatic Rust interface to an underlying BPF hashmap.
pub struct HashMap<K: Copy + Default, V: Copy + Default> {
    map: Map<K, V>,
}

impl<K: Copy + Default, V: Copy + Default> HashMap<K, V> {
    /// Creates a new BPF hashmap with `entries` elements.
    ///
    /// # Arguments
    ///
    /// * `entries` - The number of elements in the hashmap.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::HashMap;
    ///
    /// let hashmap = HashMap::<u32, u32>::with_capacity(10).expect("Failed to create hashmap");
    /// ```
    pub fn with_capacity(entries: u32) -> Result<Self, Error> {
        Ok(Self {
            map: Map::with_capacity(MapType::Hash, entries)?,
        })
    }

    /// Retrieves the value for a given key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key associated with the value to be retrieved.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::HashMap;
    ///
    /// let hashmap = HashMap::<u32, u32>::with_capacity(10).expect("Failed to create hashmap");
    /// assert!(matches!(hashmap.get(1000), Err(_)));
    /// ```
    pub fn get(&self, key: K) -> Result<V, Error> {
        self.map.get(&key)
    }

    /// Sets the value for a given key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key associated with the value to be set.
    /// * `value` - The new value.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::HashMap;
    ///
    /// let hashmap = HashMap::<u32, u32>::with_capacity(10).expect("Failed to create hashmap");
    /// assert!(matches!(hashmap.get(1000), Err(_)));
    /// assert!(matches!(hashmap.insert(1000, 0xdeadbeef), Ok(_)));
    /// assert!(matches!(hashmap.get(1000), Ok(0xdeadbeef)));
    /// ```
    pub fn insert(&self, key: K, val: V) -> Result<(), Error> {
        self.map.set(&key, &val)
    }

    /// Deletes an entry from the hash map given a key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key of the entry to be deleted.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::HashMap;
    ///
    /// let hashmap = HashMap::<u32, u32>::with_capacity(10).expect("Failed to create hashmap");
    /// assert!(matches!(hashmap.get(1000), Err(_)));
    /// assert!(matches!(hashmap.insert(1000, 0xdeadbeef), Ok(_)));
    /// assert!(matches!(hashmap.get(1000), Ok(0xdeadbeef)));
    /// assert!(matches!(hashmap.remove(1000), Ok(_)));
    /// assert!(matches!(hashmap.remove(1000), Err(_)));
    /// ```
    pub fn remove(&self, key: K) -> Result<(), Error> {
        self.map.del(&key)
    }

    /// Retrieve the BPF identifier for this map. This is the underlying file
    /// descriptor that's used in eBPF programs.
    ///
    /// # Example
    /// ```
    /// use bpf_api::collections::HashMap;
    ///
    /// let hashmap = HashMap::<u32, u32>::with_capacity(10).expect("Failed to create hashmap");
    /// hashmap.get_identifier();
    /// ```
    pub fn get_identifier(&self) -> u32 {
        self.map.get_identifier()
    }
}
