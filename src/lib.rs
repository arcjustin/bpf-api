pub mod bpf;
pub mod error;
pub mod map;
pub mod probes;
pub mod prog;

mod platform;

#[cfg(test)]
mod tests {
    use crate::map::HashMap as BpfHashMap;
    use crate::probes::Probe;
    use crate::prog::{Program, ProgramAttr, ProgramType};

    use bpf_script::Compiler;
    use btf::BtfTypes;

    use std::io::stdout;

    fn from_cstr(buf: &[u8]) -> String {
        String::from_utf8_lossy(match buf.iter().position(|c| *c == 0) {
            Some(p) => &buf[0..p],
            None => buf,
        })
        .to_string()
    }

    #[test]
    fn call_bpf() {
        let map = BpfHashMap::<u32, [u8; 16]>::create(10).unwrap();
        let btf = BtfTypes::from_file("/sys/kernel/btf/vmlinux").unwrap();

        let prog = r#"
            fn(ctx: &bpf_raw_tracepoint_args)
                key = 300
                task: &task_struct = ctx.args[0]
                comm = task.comm
                map_update_elem(map, &key, &comm, 0)
        "#;

        let mut compiler = Compiler::create(&btf);
        compiler.capture("map", map.get_identifier().into());
        compiler.compile(prog).expect("compilation failed");

        let attr = ProgramAttr {
            prog_type: ProgramType::RawTracepoint,
            attach_name: Some("sched_process_exec".into()),
            prog_name: [0; 16],
            attach_btf_id: None,
            expected_attach_type: None,
        };

        let bytecode = compiler.get_bytecode();
        let program = Program::create(&attr, &bytecode, &mut stdout()).unwrap();
        let mut probe = Probe::create(program);
        probe.attach().unwrap();

        std::thread::sleep(std::time::Duration::from_secs(5));

        let raw_comm = map.get(300).unwrap();
        println!("RAN: \"{}\"", from_cstr(&raw_comm));
    }
}
