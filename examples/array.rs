use bpf_api::collections::Array;

fn main() {
    const ARRAY_SIZE: u32 = 10;
    let array = Array::<u32>::create(ARRAY_SIZE).unwrap();

    for i in 0..ARRAY_SIZE {
        let val = i + 100;
        assert!(matches!(array.get(i), Ok(0)));
        assert!(matches!(array.set(i, val), Ok(_)));
        match array.get(i) {
            Ok(v) => assert_eq!(v, val),
            Err(e) => panic!("array.get() failed: {}", e),
        }
    }
}
