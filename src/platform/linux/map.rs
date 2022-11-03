use crate::error::Error;
use crate::platform::linux::bpf::{CallBpf, Command};
use crate::platform::linux::syscalls::{
    close, mmap, munmap, MmapFlags, MmapProtection, MAP_FAILED,
};

use std::collections::HashMap;
use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::Mutex;

#[allow(dead_code)]
enum MapLookupFlags {
    Any = 0,     /* create new element or update existing */
    NoExist = 1, /* create new element if it didn't exist */
    Exist = 2,   /* update existing element */
    Locked = 4,  /* spin_lock-ed map_lookup/map_update */
}

#[derive(Copy, Clone, Default, Debug)]
#[repr(C, align(8))]
struct MapOperationAttr {
    pub map_fd: u32,
    pub key: u64,
    pub val: u64,
    pub flags: u64,
}

impl CallBpf for MapOperationAttr {}

#[derive(Default, Debug)]
#[repr(C, align(8))]
struct MapAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

impl CallBpf for MapAttr {}

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
    StructOps,
    RingBuf,
    InodeStorage,
    TaskStorage,
    BloomFilter,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MappedArea {
    offset: usize,
    length: usize,
    prot: MmapProtection,
    flags: MmapFlags,
}

pub struct Map<K: Copy + Default, V: Copy + Default> {
    fd: u32,
    mapped_areas: Mutex<HashMap<MappedArea, usize>>,
    phantom1: PhantomData<K>,
    phantom2: PhantomData<V>,
}

impl<K: Copy + Default, V: Copy + Default> Map<K, V> {
    pub fn with_capacity(map_type: MapType, max_entries: u32) -> Result<Self, Error> {
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
                mapped_areas: Default::default(),
                phantom1: PhantomData::<K>::default(),
                phantom2: PhantomData::<V>::default(),
            }),
        }
    }

    pub fn get(&self, key: &K) -> Result<V, Error> {
        let key_ptr = if size_of::<K>() == 0 {
            0
        } else {
            key as *const K as u64
        };
        let mut val = V::default();

        let attr = MapOperationAttr {
            map_fd: self.fd,
            key: key_ptr,
            val: &mut val as *mut V as u64,
            flags: 0,
        };

        attr.call_bpf(Command::MapLookupElem)?;
        Ok(val)
    }

    pub fn set(&self, key: &K, val: &V) -> Result<(), Error> {
        let key_ptr = if size_of::<K>() == 0 {
            0
        } else {
            key as *const K as u64
        };

        let attr = MapOperationAttr {
            map_fd: self.fd,
            key: key_ptr,
            val: val as *const V as u64,
            flags: MapLookupFlags::Any as u64,
        };

        attr.call_bpf(Command::MapUpdateElem)?;
        Ok(())
    }

    pub fn del(&self, key: &K) -> Result<(), Error> {
        let key_ptr = if size_of::<K>() == 0 {
            0
        } else {
            key as *const K as u64
        };

        let attr = MapOperationAttr {
            map_fd: self.fd,
            key: key_ptr,
            val: 0,
            flags: 0,
        };

        attr.call_bpf(Command::MapDeleteElem)?;
        Ok(())
    }

    pub fn get_and_del(&self, key: &K) -> Result<V, Error> {
        let key_ptr = if size_of::<K>() == 0 {
            0
        } else {
            key as *const K as u64
        };
        let mut val = V::default();

        let attr = MapOperationAttr {
            map_fd: self.fd,
            key: key_ptr,
            val: &mut val as *mut V as u64,
            flags: 0,
        };

        attr.call_bpf(Command::MapLookupAndDeleteElem)?;
        Ok(val)
    }

    pub fn get_identifier(&self) -> u32 {
        self.fd
    }

    pub fn get_map<T>(&self, offset: usize, count: usize) -> Result<&[T], Error> {
        let length = std::mem::size_of::<T>() * count;
        let prot = MmapProtection::Read;
        let flags = MmapFlags::Shared;
        let mapped_area = MappedArea {
            offset,
            length,
            prot,
            flags,
        };

        let mut mapped_areas = self.mapped_areas.lock().or(Err(Error::MutexPoisoned))?;
        if let Some(buf) = mapped_areas.get(&mapped_area) {
            return Ok(unsafe { std::slice::from_raw_parts(*buf as *const T, count) });
        }

        let buf = mmap(
            0,
            length,
            prot as usize,
            flags as usize,
            self.fd.try_into()?,
            offset,
        );

        if buf == MAP_FAILED {
            return Err(Error::SystemError(buf));
        }

        mapped_areas.insert(mapped_area, buf as usize);
        Ok(unsafe { std::slice::from_raw_parts(buf as *const T, count) })
    }

    pub fn get_map_mut<T>(&mut self, offset: usize, count: usize) -> Result<&mut [T], Error> {
        let length = std::mem::size_of::<T>() * count;
        let prot = MmapProtection::Write;
        let flags = MmapFlags::Shared;
        let mapped_area = MappedArea {
            offset,
            length,
            prot,
            flags,
        };

        let mut mapped_areas = self.mapped_areas.lock().or(Err(Error::MutexPoisoned))?;
        if let Some(buf) = mapped_areas.get(&mapped_area) {
            return Ok(unsafe { std::slice::from_raw_parts_mut(*buf as *mut T, count) });
        }

        let buf = mmap(
            0,
            length,
            prot as usize,
            flags as usize,
            self.fd.try_into()?,
            offset,
        );

        if buf == MAP_FAILED {
            return Err(Error::SystemError(buf));
        }

        mapped_areas.insert(mapped_area, buf as usize);
        Ok(unsafe { std::slice::from_raw_parts_mut(buf as *mut T, count) })
    }
}

impl<K: Copy + Default, V: Copy + Default> Drop for Map<K, V> {
    fn drop(&mut self) {
        close(self.fd);
        let mapped_areas = self
            .mapped_areas
            .lock()
            .expect("failed to drop mapped areas");
        for (area, buf) in mapped_areas.iter() {
            munmap(*buf, area.length);
        }
    }
}
