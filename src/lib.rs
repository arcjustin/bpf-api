//! [![Build Status](https://github.com/arcjustin/bpf-api/workflows/build/badge.svg)](https://github.com/arcjustin/bpf-api/actions?query=workflow%3Abuild)
//! [![crates.io](https://img.shields.io/crates/v/bpf-api.svg)](https://crates.io/crates/bpf-api)
//! [![mio](https://docs.rs/bpf-api/badge.svg)](https://docs.rs/bpf-api/)
//! [![Lines of Code](https://tokei.rs/b1/github/arcjustin/bpf-api?category=code)](https://tokei.rs/b1/github/arcjustin/bpf-api?category=code)
//!
//! Idomatic Rust bindings for eBPF programs, probes, and maps. Want write in-line eBPF without relying on external dependencies, like shelling out to bcc/llvm? Check out this crate's sister crates:
//!
//! * [btf](https://crates.io/crates/btf)
//! * [bpf-script](https://crates.io/crates/bpf-script)
//!
//! ## Usage
//! ```
//! use bpf_api::collections::Array;
//!
//! const ARRAY_SIZE: u32 = 10;
//! let array = Array::<u32>::with_capacity(ARRAY_SIZE).unwrap();
//!
//! for i in 0..ARRAY_SIZE {
//!     let val = i + 100;
//!     assert!(matches!(array.get(i), Ok(0)));
//!     assert!(array.set(i, val).is_ok());
//!     match array.get(i) {
//!         Ok(v) => assert_eq!(v, val),
//!         Err(e) => panic!("array.get() failed: {}", e),
//!     }
//! }
//! ```
//!
//! ## License
//!
//! * [MIT license](http://opensource.org/licenses/MIT)

pub mod collections;
pub mod error;
pub mod probes;
pub mod prog;

mod platform;

#[cfg(test)]
mod tests {
    use crate::collections::{Array, HashMap, Queue};

    #[test]
    fn hashmap_insert_get() {
        let list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let map = HashMap::<u32, [u8; 16]>::with_capacity(10).unwrap();
        assert!(map.insert(300, list).is_ok());
        assert!(map.get(300).is_ok());
        assert_eq!(map.get(300).unwrap(), list);
    }

    #[test]
    fn queue_push_pop() {
        const QUEUE_SIZE: u32 = 10;
        let queue = Queue::<u32>::with_capacity(QUEUE_SIZE).unwrap();

        /* Fill the queue to the max */
        for i in 0..10 {
            assert!(queue.push(i + 100).is_ok());
        }

        /* make sure the next push fails */
        assert!(queue.push(1000).is_err());

        /* test front and make sure it doesn't consume */
        assert!(matches!(queue.front(), Ok(100)));
        assert!(matches!(queue.front(), Ok(100)));

        /* pop all items and check values */
        for i in 0..10 {
            match queue.pop() {
                Ok(val) => assert_eq!(val, i + 100),
                Err(e) => panic!("queue.pop() failed: {}", e),
            }
        }

        /* make sure queue is now empty */
        assert!(queue.pop().is_err());
    }

    #[test]
    fn array_set_get() {
        const ARRAY_SIZE: u32 = 10;
        let array = Array::<u32>::with_capacity(ARRAY_SIZE).unwrap();

        for i in 0..ARRAY_SIZE {
            let val = i + 100;
            assert!(matches!(array.get(i), Ok(0)));
            assert!(array.set(i, val).is_ok());
            match array.get(i) {
                Ok(v) => assert_eq!(v, val),
                Err(e) => panic!("array.get() failed: {}", e),
            }
        }
    }
}
