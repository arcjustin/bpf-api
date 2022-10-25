use crate::error::Error;
use crate::platform::linux::bpf::{CallBpf, Command};
use crate::platform::linux::perf::{perf_event_attach, perf_event_enable, perf_event_open_by_name};
use crate::platform::linux::prog::{Program, ProgramType};
use crate::platform::linux::syscalls::{cbzero, close};

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

pub struct Probe {
    program: Program,
    attach_fds: Option<Vec<u32>>,
}

impl Probe {
    /// Create a probe object from a given program.
    ///
    /// # Arguments
    ///
    /// * `program` - The program to use as a probe.
    pub fn create(program: Program) -> Self {
        Self {
            program,
            attach_fds: None,
        }
    }

    /// Attaches/enables the probe.
    pub fn attach(&mut self) -> Result<(), Error> {
        let attr = self.program.get_attr();
        match attr.prog_type {
            ProgramType::Kprobe => self.attach_kprobe(),
            _ => self.attach_raw_tracepoint(),
        }
    }

    fn attach_kprobe(&mut self) -> Result<(), Error> {
        let attr = self.program.get_attr();

        let perf_event_fds = match &attr.attach_name {
            Some(name) => perf_event_open_by_name("kprobe", name)?,
            None => return Err(Error::InvalidArgument),
        };

        let mut fds = vec![];
        for fd in perf_event_fds {
            perf_event_attach(fd, self.program.get_fd())?;
            perf_event_enable(fd)?;
            fds.push(fd);
        }

        self.attach_fds = Some(fds);
        Ok(())
    }

    fn attach_raw_tracepoint(&mut self) -> Result<(), Error> {
        let mut bpf_attr = BpfRawTracepointOpenAttr::default();

        /*
         * this unsafe zeroing is required to have the padding in the
         * attr structure zeroed. this padding is checked by the kernel
         * and has to be zero. std::mem:zeroed and Default don't work.
         */
        cbzero(&mut bpf_attr);

        let attr = self.program.get_attr();

        /*
         * Assumes that String's internal representation of a string is
         * ascii.
         */
        let mut attach_name = String::from("");
        let name = if let Some(n) = &attr.attach_name {
            attach_name.push_str(n);
            attach_name.push('\0');
            attach_name.as_ptr() as u64
        } else {
            0
        };

        bpf_attr.prog_fd = self.program.get_fd();
        bpf_attr.name = name;

        self.attach_fds = Some(vec![bpf_attr.call_bpf(Command::RawTracepointOpen)?]);

        Ok(())
    }

    /// Detaches/disables the probe.
    pub fn detach(&mut self) -> Result<(), Error> {
        if let Some(fds) = &self.attach_fds {
            for fd in fds {
                close(*fd);
            }
        }

        self.attach_fds = None;
        Ok(())
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}
