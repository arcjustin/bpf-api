use bpf_api::collections::Array;

fn main() {
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
