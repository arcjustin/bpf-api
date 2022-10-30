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
    fn call_bpf(&self, cmd: Command) -> Result<u32, Error>;
}

// This seems to broad. I'm not sure the benefit impl implementing this for all
// types, since there presumably is only a narrow number of types that this
// would even work. Since there's a single definition for this method, you can
// move the definition into the `trait` definition. And then you just need to do
// `impl CallBpf for MyBpfType {}` to use `call_bpf`.
impl<T> CallBpf for T {
    fn call_bpf(&self, cmd: Command) -> Result<u32, Error> {
        let r = bpf(cmd as u32, self as *const Self as *const u8, size_of::<T>());
        if r < 0 {
            Err(Error::SystemError(r))
        } else {
            Ok(r as u32)
        }
    }
}
