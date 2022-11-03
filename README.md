# bpf-api
[![Build Status](https://github.com/arcjustin/bpf-api/workflows/build/badge.svg)](https://github.com/arcjustin/bpf-api/actions?query=workflow%3Abuild)
[![crates.io](https://img.shields.io/crates/v/bpf-api.svg)](https://crates.io/crates/bpf-api)
[![mio](https://docs.rs/bpf-api/badge.svg)](https://docs.rs/bpf-api/)
[![Lines of Code](https://tokei.rs/b1/github/arcjustin/bpf-api?category=code)](https://tokei.rs/b1/github/arcjustin/bpf-api?category=code)

Idomatic Rust bindings for eBPF programs, probes, and maps.

The motive behind this crate and sister crates: `btf`, `btf-derive`, `bpf-ins`, and `bpf-script`, aside from learning more about eBPF, was to be able to have a fully Rust eBPF solution. That is, the ability to easily write, compile, and attach BPF programs and use maps without any dependencies on bcc, libbpf or any other non-Rust BPF dependencies.

## Usage

For usage examples, see code located in [examples/](examples/) :

  | Examples | Description |
  |----------|-------------|
  |[array](examples/array.rs)| A short example using a BPF array|
  |[print-programs](examples/print-programs.rs)| A short example that attachs a probe to `sched_process_exec` and prints program executions|
  |[user-tracer](examples/user-tracer.rs)| Probes a given image path and symbol name using uprobes|

## TODO

* Add ARM support.
* Make probe attachment easier / write convenience macros.

## License

* [MIT license](http://opensource.org/licenses/MIT)
