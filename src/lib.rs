pub mod bpf;
pub mod error;
pub mod map;
pub mod probes;
pub mod prog;

mod platform;

#[cfg(test)]
mod tests {
    use crate::map::HashMap as BpfHashMap;

    #[test]
    fn hashmap_set_get() {
        let list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let map = BpfHashMap::<u32, [u8; 16]>::create(10).unwrap();
        assert!(matches!(map.set(300, list), Ok(_)));
        assert!(matches!(map.get(300), Ok(_)));
        assert_eq!(map.get(300).unwrap(), list);
    }
}
