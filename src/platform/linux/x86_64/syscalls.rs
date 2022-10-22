use std::arch::asm;
use std::ptr;

enum SyscallNumber {
    Close = 3,
    Ioctl = 16,
    PerfEventOpen = 298,
    Bpf = 321,
}

pub fn cbzero<T>(s: &mut T) {
    unsafe { std::ptr::write_bytes(s as *mut T, 0, 1) };
}

#[inline]
unsafe fn syscall1(n: u64, arg1: u64) -> i64 {
    let mut ret: i64;
    let mut _ret_addr: u64;
    let mut _rflags: u64;
    asm!(
        "syscall",
        inlateout("rax") n as i64 => ret,
        in("rdi") arg1,
        out("rcx") _ret_addr,
        out("r11") _rflags,
        options(nostack, preserves_flags)
    );
    ret
}

#[inline]
unsafe fn syscall3(n: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let mut ret: i64;
    let mut _ret_addr: u64;
    let mut _rflags: u64;
    asm!(
        "syscall",
        inlateout("rax") n as i64 => ret,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        out("rcx") _ret_addr,
        out("r11") _rflags,
        options(nostack, preserves_flags)
    );
    ret
}

#[inline]
unsafe fn syscall5(n: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
    let mut ret: i64;
    let mut _ret_addr: u64;
    let mut _rflags: u64;
    asm!(
        "syscall",
        inlateout("rax") n as i64 => ret,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        in("r8") arg5,
        out("rcx") _ret_addr,
        out("r11") _rflags,
        options(nostack, preserves_flags)
    );
    ret
}

/*
 * bpf()
 */
pub fn bpf(cmd: u32, attr: *const u8, size: usize) -> i64 {
    unsafe {
        /*
         * regardless of the size you pass in to bpf(), the kernel assumes the memory
         * pointed to by attr spans to at least sizeof(bpf_attr). Furthermore, it makes
         * sure the structure data outside of the union arm being used is all zero.
         * The structure is currently only 120 bytes, 1024 bytes is safe for the foreseeable
         * future.
         */
        const BPF_ATTR_SIZE: usize = 120;
        if size > BPF_ATTR_SIZE {
            panic!("Structure passed to bpf() has size > BPF_ATTR_SIZE");
        }

        let mut buf: [u8; BPF_ATTR_SIZE] = [0; BPF_ATTR_SIZE];
        ptr::copy(attr, buf.as_mut_ptr() as *mut _, size);

        syscall3(
            SyscallNumber::Bpf as u64,
            cmd as u64,
            &buf as *const u8 as u64,
            BPF_ATTR_SIZE as u64,
        )
    }
}

/*
 * perf_event_open()
 */
pub fn perf_event_open(attr: *const u8, pid: u32, cpu: u32, gid: u32, flags: u32) -> i64 {
    unsafe {
        syscall5(
            SyscallNumber::PerfEventOpen as u64,
            attr as u64,
            pid as u64,
            cpu as u64,
            gid as u64,
            flags as u64,
        )
    }
}

/*
 * ioctl(probe_fd, PERF_EVENT_IOC_SET_BPF, prog_fd)
 */
pub fn perf_event_attach(probe_fd: u32, prog_fd: u32) -> i64 {
    unsafe {
        syscall3(
            SyscallNumber::Ioctl as u64,
            probe_fd as u64,
            0x40042408,
            prog_fd as u64,
        )
    }
}

/*
 * ioctl(probe_fd, PERF_EVENT_IOC_ENABLE, 0)
 */
pub fn perf_event_enable(probe_fd: u32) -> i64 {
    unsafe { syscall3(SyscallNumber::Ioctl as u64, probe_fd as u64, 0x2400, 0) }
}

/*
 * close()
 */
pub fn close(fd: u32) -> i64 {
    unsafe { syscall1(SyscallNumber::Close as u64, fd as u64) }
}
