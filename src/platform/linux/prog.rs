use crate::error::Error;
use crate::platform::linux::bpf::{AttachType, CallBpf, Command};
use crate::platform::linux::syscalls::close;

use std::io::Write;

#[derive(Default)]
#[repr(C, align(8))]
#[derive(Copy, Clone)]
struct BpfProgramAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: u64,
    pub kern_version: u32,
    pub prog_flags: u32,
    pub prog_name: [u8; 16],
    pub prog_ifindex: u32,
    pub expected_attach_type: u32,
    pub prog_btf_fd: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub func_info_count: u32,
    pub line_info_rec_size: u32,
    pub line_info: u64,
    pub line_info_count: u32,
    pub attach_btf_id: u32,
}

#[derive(Copy, Clone)]
pub enum ProgramType {
    Unspec = 0,
    SocketFilter,
    Kprobe,
    SchedCls,
    SchedAct,
    Tracepoint,
    Xdp,
    PerfEvent,
    CgroupSkb,
    CgroupSock,
    LwtIn,
    LwtOut,
    LwtXmit,
    SockOps,
    SkSkb,
    CgroupDevice,
    SkMsg,
    RawTracepoint,
    CgroupSockAddr,
    LwtSeg6local,
    LircMode2,
    SkReuseport,
    FlowDissector,
    CgroupSysctl,
    RawTracepointWritable,
    CgroupSockopt,
    Tracing,
    StructOps,
    Ext,
    Lsm,
    SkLookup,
    Syscall,
}

#[derive(Clone)]
pub struct ProgramAttr {
    pub attach_btf_id: Option<u32>,
    pub attach_name: Option<String>,
    pub expected_attach_type: Option<AttachType>,
    pub prog_name: [u8; 16],
    pub prog_type: ProgramType,
}

pub struct Program {
    attr: ProgramAttr,
    fd: u32,
}

impl Program {
    const LICENSE: &'static str = "GPL\0";

    pub fn create<W: Write>(
        attr: &ProgramAttr,
        instructions: &[u64],
        log_out: &mut W,
    ) -> Result<Self, Error> {
        let mut buf = vec![0; 1 << 20];

        let expected_attach_type = if let Some(t) = attr.expected_attach_type {
            t as u32
        } else {
            0
        };

        let attach_btf_id = if let Some(id) = attr.attach_btf_id {
            id as u32
        } else {
            0
        };

        let bpf_attr = BpfProgramAttr {
            prog_type: attr.prog_type as u32,
            insns: instructions.as_ptr() as u64,
            insn_cnt: instructions.len() as u32,
            license: Self::LICENSE.as_ptr() as u64,
            log_level: 1,
            log_size: 1 << 20,
            log_buf: buf.as_mut_ptr() as u64,
            kern_version: 0,
            prog_flags: 0,
            prog_name: attr.prog_name,
            prog_ifindex: 0,
            expected_attach_type,
            prog_btf_fd: 0,
            func_info_rec_size: 0,
            func_info: 0,
            func_info_count: 0,
            line_info_rec_size: 0,
            line_info: 0,
            line_info_count: 0,
            attach_btf_id,
        };

        let r = bpf_attr.call_bpf(Command::ProgLoad);

        if let Ok(s) = std::str::from_utf8(&buf) {
            let _ = write!(log_out, "{}", s);
        }

        match r {
            Err(e) => Err(e),
            Ok(r) => Ok(Self {
                fd: r as u32,
                attr: attr.clone(),
            }),
        }
    }

    pub fn get_attr(&self) -> &ProgramAttr {
        &self.attr
    }

    pub fn get_fd(&self) -> u32 {
        self.fd
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        close(self.fd);
    }
}
