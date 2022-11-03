use bpf_api::collections::RingBuffer;

fn main() {
    const RING_SIZE: u32 = 10 << 20;
    let ring = RingBuffer::with_capacity(RING_SIZE).unwrap();
    ring.len();
    ring.is_empty();
    ring.get_buf();
}
