use super::syscalls::bpf;
use crate::error::Error;

use std::mem::size_of;

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum AttachType {
    CgroupInetIngress,
    CgroupInetEgress,
    CgroupInetSockCreate,
    CgroupSockOps,
    SkSkbStreamParser,
    SkSkbStreamVerdict,
    CgroupDevice,
    SkMsgVerdict,
    CgroupInet4Bind,
    CgroupInet6Bind,
    CgroupInet4Connect,
    CgroupInet6Connect,
    CgroupInet4PostBind,
    CgroupInet6PostBind,
    CgroupUdp4Sendmsg,
    CgroupUdp6Sendmsg,
    LircMode2,
    FlowDissector,
    CgroupSysctl,
    CgroupUdp4Recvmsg,
    CgroupUdp6Recvmsg,
    CgroupGetsockopt,
    CgroupSetsockopt,
    TraceRawTp,
    TraceFentry,
    TraceFexit,
    ModifyReturn,
    LsmMac,
    TraceIter,
    CgroupInet4Getpeername,
    CgroupInet6Getpeername,
    CgroupInet4Getsockname,
    CgroupInet6Getsockname,
    XdpDevmap,
    CgroupInetSockRelease,
    XdpCpumap,
    SkLookup,
    Xdp,
    SkSkbVerdict,
    SkReuseportSelect,
    SkReuseportSelectOrMigrate,
    PerfEvent,
    TraceKprobeMulti,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub enum Command {
    MapCreate = 0,
    MapLookupElem,
    MapUpdateElem,
    MapDeleteElem,
    MapGetNextKey,
    ProgLoad,
    ObjPin,
    ObjGet,
    ProgAttach,
    ProgDetach,
    ProgTestRun,
    ProgGetNextId,
    MapGetNextId,
    ProgGetFdById,
    MapGetFdById,
    ObjGetInfoByFd,
    ProgQuery,
    RawTracepointOpen,
    BtfLoad,
    BtfGetFdById,
    TaskFdQuery,
    MapLookupAndDeleteElem,
    MapFreeze,
    GetNextId,
    MapLookupBatch,
    MapLookupAndDeleteBatch,
    MapUpdateBatch,
    MapDeleteBatch,
    LinkCreate,
    LinkUpdate,
    LinkGetFdById,
    LinkGetNextId,
    EnableStats,
    IterCreate,
    LinkDetach,
    ProgBindMap,
}

pub trait CallBpf {
    fn call_bpf(&self, cmd: Command) -> Result<u32, Error>
    where
        Self: Sized,
    {
        let r = bpf(
            cmd as u32,
            self as *const Self as *const u8,
            size_of::<Self>(),
        );
        if r < 0 {
            Err(Error::SystemError(r))
        } else {
            Ok(r as u32)
        }
    }
}
