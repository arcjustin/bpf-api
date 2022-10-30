// I think you have some explicit expectations of `x86_64` based on pointer
// sizes. You should consider just restricting to `x86_64` for now.
//
// Another related point is that is not important now, but often with these
// types of crates that are platform explicit, I see the crate basically compile
// to an empty crate on other platforms or at least return a descriptive compile
// error stating that an incorrect platform is not supported. I forget the
// specific benefit to compiling to an empty crate though.
#[cfg(target_os = "linux")]
mod linux;
// I generally am not a fan of wildcard imports. In this case I would probably
// just import the modules such as `pub use linux::bpf;`
pub use linux::bpf::*;
pub use linux::map::*;
pub use linux::probes::*;
pub use linux::prog::*;
