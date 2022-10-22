use crate::error::Error;
use crate::platform::{Map, MapType};

pub struct HashMap<K: Copy + Default + Sized, V: Copy + Default + Sized> {
    map: Map<K, V>,
}

impl<K: Copy + Default + Sized, V: Copy + Default + Sized> HashMap<K, V> {
    pub fn create(entries: u32) -> Result<Self, Error> {
        Ok(Self {
            map: Map::create(MapType::Hash, entries)?,
        })
    }

    pub fn get(&self, key: K) -> Result<V, Error> {
        self.map.get(&key)
    }

    pub fn set(&self, key: K, val: V) -> Result<(), Error> {
        self.map.set(&key, &val)
    }

    pub fn del(&self, key: K) -> Result<(), Error> {
        self.map.del(&key)
    }

    pub fn get_identifier(&self) -> u32 {
        self.map.get_identifier()
    }
}
