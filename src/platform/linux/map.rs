use crate::error::Error;
use crate::platform::linux::bpf::{CallBpf, Command};
use crate::platform::linux::syscalls::close;

use std::marker::PhantomData;
use std::mem::size_of;

#[allow(dead_code)]
enum MapLookupFlags {
    Any = 0,     /* create new element or update existing */
    NoExist = 1, /* create new element if it didn't exist */
    Exist = 2,   /* update existing element */
    Locked = 4,  /* spin_lock-ed map_lookup/map_update */
}

#[derive(Default)]
#[repr(C, align(8))]
struct MapOperationAttr {
    pub map_fd: u32,
    pub key: u64,
    pub val: u64,
    pub flags: u64,
}

#[derive(Default)]
#[repr(C, align(8))]
struct MapAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

#[allow(dead_code)]
pub enum MapType {
    Unspec = 0,
    Hash,
    Array,
    ProgArray,
    PerfEventArray,
    PerCpuHash,
    PerCpuArray,
    StackTrace,
    CgroupArray,
    LruHash,
    LruPerCpuHash,
    LpmTrie,
    ArrayOfMaps,
    HashOfMaps,
    DevMap,
    SockMap,
    CpuMap,
    XSkMap,
    SockHash,
    CgroupStorage,
    ReusePortSockArray,
    PerCpuCgroupStorage,
    Queue,
    Stack,
    SkStorage,
    DevMapHash,
}

pub struct Map<K: Copy + Default + Sized, V: Copy + Default + Sized> {
    fd: u32,
    phantom1: PhantomData<K>,
    phantom2: PhantomData<V>,
}

impl<K: Copy + Default + Sized, V: Copy + Default + Sized> Map<K, V> {
    pub fn create(map_type: MapType, max_entries: u32) -> Result<Self, Error> {
        let attr = MapAttr {
            map_type: map_type as u32,
            key_size: size_of::<K>() as u32,
            value_size: size_of::<V>() as u32,
            max_entries,
        };

        match attr.call_bpf(Command::MapCreate) {
            Err(e) => Err(e),
            Ok(fd) => Ok(Self {
                fd,
                phantom1: PhantomData::<K>::default(),
                phantom2: PhantomData::<V>::default(),
            }),
        }
    }

    pub fn get(&self, key: &K) -> Result<V, Error> {
        let mut val = V::default();

        let attr = MapOperationAttr {
            map_fd: self.fd,
            key: key as *const K as u64,
            val: &mut val as *mut V as u64,
            flags: 0,
        };

        if let Err(e) = attr.call_bpf(Command::MapLookupElem) {
            Err(e)
        } else {
            Ok(val)
        }
    }

    pub fn set(&self, key: &K, val: &V) -> Result<(), Error> {
        let attr = MapOperationAttr {
            map_fd: self.fd,
            key: key as *const K as u64,
            val: val as *const V as u64,
            flags: MapLookupFlags::Any as u64,
        };

        if let Err(e) = attr.call_bpf(Command::MapUpdateElem) {
            Err(e)
        } else {
            Ok(())
        }
    }

    pub fn del(&self, key: &K) -> Result<(), Error> {
        let attr = MapOperationAttr {
            map_fd: self.fd,
            key: key as *const K as u64,
            val: 0,
            flags: 0,
        };

        if let Err(e) = attr.call_bpf(Command::MapDeleteElem) {
            Err(e)
        } else {
            Ok(())
        }
    }

    pub fn get_identifier(&self) -> u32 {
        self.fd
    }
}

impl<K: Copy + Default + Sized, V: Copy + Default + Sized> Drop for Map<K, V> {
    fn drop(&mut self) {
        close(self.fd);
    }
}
