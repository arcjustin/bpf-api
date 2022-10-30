use crate::error::Error;
use crate::platform::linux::bpf::{CallBpf, Command};
use crate::platform::linux::syscalls::close;

use std::marker::PhantomData;
use std::mem::size_of;

#[allow(dead_code)]
// Add a repr(uX)
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

#[derive(Default, Debug)]
#[repr(C, align(8))]
struct MapAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

// It may not matter, but a type like this might as well be `Copy` and
// presumably should have a `repr(_)` attribute based on the data type used by
// bpf.
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

// I think you probably want to add `'static` bound to both `K` and `V`. Can't
// imagine there's any concept of this working with lifetimes. Currently `&u8`
// meets the bound requirements here for example.
//
// Also, it's common to not actually put the trait bounds on the struct and only
// put them on the `impl`. In this case, I think it's probably fine, since this
// type is meaningless without the bounds, but since the type can't be created
// directly, the trait bounds on `impl` would prevent incorrect usage.
//
// Final comment related to this is whether the bounds need to be stricter. I
// know I ran into issues with structs with padding. If that's guaranteed to be
// an issue, I would consider adding the trait bound `bytemuck::NoUninit`. At
// least, that's my preferred crate for these kind of requirements.
//
// Final comment, I think the `Sized` bound is implicit in this case. You need
// to explicitly specify `?Sized` if you don't want a `Sized` bound.
pub struct Map<K: Copy + Default, V: Copy + Default> {
    fd: u32,
    phantom1: PhantomData<K>,
    phantom2: PhantomData<V>,
}

impl<K: Copy + Default, V: Copy + Default> Map<K, V> {
    pub fn with_capacity(map_type: MapType, max_entries: u32) -> Result<Self, Error> {
        let attr = MapAttr {
            map_type: map_type as u32,
            // The safer approach here is `.try_into()?` to handle overflows.
            // Can't imagine it's possible to have key or value 2^32 size, but
            // `try_into` should get optimized away at compile time anyway.
            key_size: size_of::<K>() as u32,
            value_size: size_of::<V>() as u32,
            max_entries,
        };

        match attr.call_bpf(Command::MapCreate) {
            Err(e) => Err(e),
            Ok(fd) => Ok(Self {
                fd,
                // This can actually just be `PhantomData` no need for type or
                // function call, since its a unit struct and the type will be
                // inferred.
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
}

impl<K: Copy + Default, V: Copy + Default> Drop for Map<K, V> {
    fn drop(&mut self) {
        close(self.fd);
    }
}
