use crate::error::Error;
use crate::platform::{Map, MapType};

#[derive(Copy, Clone, Default)]
struct Void {}

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

pub struct Queue<V: Copy + Default + Sized> {
    map: Map<Void, V>,
}

impl<V: Copy + Default + Sized> Queue<V> {
    pub fn create(entries: u32) -> Result<Self, Error> {
        Ok(Self {
            map: Map::create(MapType::Queue, entries)?,
        })
    }

    pub fn pop(&self) -> Result<V, Error> {
        self.map.get_and_del(&Void::default())
    }

    pub fn front(&self) -> Result<V, Error> {
        self.map.get(&Void::default())
    }

    pub fn push(&self, val: V) -> Result<(), Error> {
        self.map.set(&Void::default(), &val)
    }

    pub fn get_identifier(&self) -> u32 {
        self.map.get_identifier()
    }
}
