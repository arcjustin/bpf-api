// See comment in `platform::mod`. If we get rid of wildcard there, this becomes
// a bit more clear where they're coming from by doing
// `crate::platform::prog::{Program, ...};`
pub use crate::platform::{Program, ProgramAttr, ProgramType};
