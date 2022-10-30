// See comment in `platform::mod`. If we get rid of wildcard there, this becomes
// a bit more clear where they're coming from by doing
// `crate::platform::probes::{AttachInfo, ...};`
pub use crate::platform::{AttachInfo, AttachType, Probe};
