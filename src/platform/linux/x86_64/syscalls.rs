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
unsafe fn syscall1(n: usize, arg1: usize) -> isize {
    let mut ret: isize;
    let mut _ret_addr: usize;
    let mut _rflags: usize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") arg1,
        out("rcx") _ret_addr,
        out("r11") _rflags,
        options(nostack, preserves_flags)
    );
    ret
}

#[inline]
unsafe fn syscall3(n: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    let mut ret: isize;
    let mut _ret_addr: usize;
    let mut _rflags: usize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
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
unsafe fn syscall5(
    n: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> isize {
    let mut ret: isize;
    let mut _ret_addr: usize;
    let mut _rflags: usize;
    asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
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
pub fn bpf(cmd: u32, attr: *const u8, size: usize) -> isize {
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
            SyscallNumber::Bpf as usize,
            cmd as usize,
            &buf as *const u8 as usize,
            BPF_ATTR_SIZE as usize,
        )
    }
}

/*
 * perf_event_open()
 */
pub fn perf_event_open(attr: *const u8, pid: u32, cpu: u32, gid: u32, flags: u32) -> isize {
    unsafe {
        syscall5(
            SyscallNumber::PerfEventOpen as usize,
            attr as usize,
            pid as usize,
            cpu as usize,
            gid as usize,
            flags as usize,
        )
    }
}

/*
 * ioctl(probe_fd, PERF_EVENT_IOC_SET_BPF, prog_fd)
 */
pub fn perf_event_attach(probe_fd: u32, prog_fd: u32) -> isize {
    unsafe {
        syscall3(
            SyscallNumber::Ioctl as usize,
            probe_fd as usize,
            0x40042408,
            prog_fd as usize,
        )
    }
}

/*
 * ioctl(probe_fd, PERF_EVENT_IOC_ENABLE, 0)
 */
pub fn perf_event_enable(probe_fd: u32) -> isize {
    unsafe { syscall3(SyscallNumber::Ioctl as usize, probe_fd as usize, 0x2400, 0) }
}

/*
 * close()
 */
pub fn close(fd: u32) -> isize {
    unsafe { syscall1(SyscallNumber::Close as usize, fd as usize) }
}
