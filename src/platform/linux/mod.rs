pub mod bpf;
pub mod map;
pub mod perf;
pub mod probes;
pub mod prog;

#[cfg(target_arch = "x86_64")]
mod x86_64;
use x86_64::syscalls;
