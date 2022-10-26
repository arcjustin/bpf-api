use crate::error::Error;
use crate::platform::linux::bpf::{CallBpf, Command};
use crate::platform::linux::perf::{perf_event_attach, perf_event_enable, perf_event_open_by_name};
use crate::platform::linux::prog::Program;
use crate::platform::linux::syscalls::{cbzero, close};

use std::collections::HashMap;

#[derive(Default)]
#[repr(C, align(8))]
struct BpfRawTracepointOpenAttr {
    pub name: u64,
    pub prog_fd: u32,
}

#[derive(Default)]
#[repr(C, align(8))]
struct BpfLinkCreateAttr {
    pub prog_fd: u32,
    pub target_fd: u32,
    pub attach_type: u32,
    pub flags: u32,
    pub target_btf_id: u32,
}

#[derive(Clone)]
pub enum AttachInfo {
    RawTracepoint(String),
    KProbe((String, u64)),
    UProbe((String, u64)),
}

pub struct Probe {
    attach_info: AttachInfo,
    attach_fds: HashMap<u32, Vec<u32>>,
}

impl Probe {
    /// Create a probe object from a given program.
    ///
    /// # Arguments
    ///
    /// * `attach_info` - Describes the type of probe and attributes.
    pub fn create(attach_info: AttachInfo) -> Self {
        Self {
            attach_info,
            attach_fds: HashMap::new(),
        }
    }

    /// Attaches the given program to the probe.
    pub fn attach(&mut self, program: &Program) -> Result<(), Error> {
        let attach_info = self.attach_info.clone();
        match &attach_info {
            AttachInfo::RawTracepoint(name) => self.attach_raw_tracepoint(program, name),
            AttachInfo::KProbe((name, addr)) => self.attach_probe(program, "kprobe", name, *addr),
            AttachInfo::UProbe((name, addr)) => self.attach_probe(program, "uprobe", name, *addr),
        }
    }

    fn attach_probe(
        &mut self,
        program: &Program,
        probe_name: &str,
        name: &str,
        addr: u64,
    ) -> Result<(), Error> {
        let perf_event_fds = perf_event_open_by_name(probe_name, name, addr)?;

        let mut fds = vec![];
        for fd in perf_event_fds {
            perf_event_attach(fd, program.get_fd())?;
            perf_event_enable(fd)?;
            fds.push(fd);
        }
        self.attach_fds.insert(program.get_fd(), fds);

        Ok(())
    }

    fn attach_raw_tracepoint(&mut self, program: &Program, name: &str) -> Result<(), Error> {
        let mut bpf_attr = BpfRawTracepointOpenAttr::default();

        /*
         * this unsafe zeroing is required to have the padding in the
         * attr structure zeroed. this padding is checked by the kernel
         * and has to be zero. std::mem:zeroed and Default don't work.
         */
        cbzero(&mut bpf_attr);

        /*
         * Assumes that String's internal representation of a string is
         * ascii.
         */
        let mut attach_name = String::from("");
        attach_name.push_str(name);
        attach_name.push('\0');

        bpf_attr.prog_fd = program.get_fd();
        bpf_attr.name = attach_name.as_ptr() as u64;

        let fds = vec![bpf_attr.call_bpf(Command::RawTracepointOpen)?];
        self.attach_fds.insert(program.get_fd(), fds);

        Ok(())
    }

    /// Attaches the program from the probe.
    pub fn detach(&mut self, program: &Program) -> Result<(), Error> {
        if let Some(fds) = self.attach_fds.get(&program.get_fd()) {
            for fd in fds {
                close(*fd);
            }
        }
        self.attach_fds.remove(&program.get_fd());

        Ok(())
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        for fds in self.attach_fds.values() {
            for fd in fds {
                close(*fd);
            }
        }
    }
}
