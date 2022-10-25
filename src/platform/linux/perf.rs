use super::syscalls::{
    cbzero, perf_event_attach as arch_perf_event_attach,
    perf_event_enable as arch_perf_event_enable, perf_event_open,
};

use crate::error::Error;

use num_cpus;

use std::fs::read_to_string;
use std::mem::size_of;

const DYNAMIC_PMU_PATH_KPROBE: &str = "/sys/bus/event_source/devices/";

pub fn get_pmu_typeid(name: &str) -> Result<u32, Error> {
    if name.contains('/') {
        return Err(Error::InvalidArgument);
    }

    let mut path = String::from(DYNAMIC_PMU_PATH_KPROBE);
    path.push_str(name);
    path.push_str("/type");

    let s = read_to_string(path)?;
    Ok(s.trim_end().parse::<u32>()?)
}

#[derive(Default)]
#[repr(C, align(8))]
struct PerfEventAttr {
    pub event_type: u32,
    pub size: u32,
    pub config: u64,
    pub sampling: u64,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: u64,
    pub wakeup: u32,
    pub bp_type: u32,
    pub probe_name: u64,
    pub probe_addr: u64,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clock_id: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub reserved: u16,
}

pub fn perf_event_open_by_name(kind: &str, name: &str) -> Result<Vec<u32>, Error> {
    let mut attr = PerfEventAttr::default();
    cbzero(&mut attr);

    let mut probe_name = name.to_owned();
    probe_name.push('\0');

    attr.event_type = get_pmu_typeid(kind)?;
    attr.size = size_of::<PerfEventAttr>() as u32;
    attr.probe_name = probe_name.as_ptr() as u64;

    let mut fds = vec![];
    for i in 0..num_cpus::get() {
        let r = perf_event_open(
            &attr as *const _ as *const u8,
            u32::MAX,
            i as u32,
            u32::MAX,
            0,
        );
        if r < 0 {
            return Err(Error::SystemError(r));
        } else {
            fds.push(r as u32);
        }
    }

    Ok(fds)
}

/*
 * ioctl(probe_fd, PERF_EVENT_IOC_SET_BPF, prog_fd)
 */
pub fn perf_event_attach(probe_fd: u32, prog_fd: u32) -> Result<(), Error> {
    match arch_perf_event_attach(probe_fd, prog_fd) {
        n if n == 0 => Ok(()),
        n => Err(Error::SystemError(n)),
    }
}

/*
 * ioctl(probe_fd, PERF_EVENT_IOC_ENABLE, 0)
 */
pub fn perf_event_enable(probe_fd: u32) -> Result<(), Error> {
    match arch_perf_event_enable(probe_fd) {
        n if n == 0 => Ok(()),
        n => Err(Error::SystemError(n)),
    }
}
