use crate::error::Error;
use crate::platform::{Map, MapType};

pub struct Array<V: Copy + Default + Sized> {
    map: Map<u32, V>,
}

impl<V: Copy + Default + Sized> Array<V> {
    pub fn create(entries: u32) -> Result<Self, Error> {
        Ok(Self {
            map: Map::create(MapType::Array, entries)?,
        })
    }

    pub fn get(&self, el: u32) -> Result<V, Error> {
        self.map.get(&el)
    }

    pub fn set(&self, el: u32, val: V) -> Result<(), Error> {
        self.map.set(&el, &val)
    }

    pub fn get_identifier(&self) -> u32 {
        self.map.get_identifier()
    }
}
