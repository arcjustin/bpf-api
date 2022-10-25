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
  |[print-programs](examples/print-programs.rs)| Attaches to the `sched_process_exec` tracepoint, waits 5 seconds, and prints the programs that ran in that time|

## TODO
- Add ARM support.
- Make probe attachment easier / write convenience macros.
