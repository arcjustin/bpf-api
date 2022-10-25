use bpf_api::collections::Queue;
use bpf_api::probes::Probe;
use bpf_api::prog::{Program, ProgramAttr, ProgramType};
use bpf_script::Compiler;
use btf::traits::AddToBtf;
use btf::BtfTypes;
use btf_derive::AddToBtf;

use std::io::stdout;

#[repr(C, align(1))]
#[derive(Copy, Clone, Default, Debug, AddToBtf)]
struct ExecEntry {
    pub pid: u32,
    pub tgid: u32,
    pub uid_gid: u64,
    pub utime: u64,
    pub comm: [u8; 16],
}

fn main() {
    /*
     * Load types from the vmlinux BTF file and add the custom Rust type
     * to the database.
     */
    let mut btf = BtfTypes::from_file("/sys/kernel/btf/vmlinux").unwrap();
    ExecEntry::add_to_btf(&mut btf).unwrap();

    /*
     * Create a BPF script compiler.
     */
    let mut compiler = Compiler::create(&btf);

    /*
     * Create a shared queue and "capture" it in the compiler context.
     */
    let queue = Queue::<ExecEntry>::create(10).unwrap();
    compiler.capture("queue", queue.get_identifier().into());

    /*
     * Compile a program.
     */
    compiler
        .compile(
            r#"
            fn(tp: &bpf_raw_tracepoint_args)
                task: &task_struct = tp.args[0]
                entry: ExecEntry = 0
                entry.pid = task.pid
                entry.tgid = task.tgid
                entry.uid_gid = get_current_uid_gid()
                entry.utime = task.utime
                entry.comm = task.comm
                map_push_elem(queue, &entry, 0)
        "#,
        )
        .expect("compilation failed");

    /*
     * Insert the program into the kernel with the intended attachment point.
     */
    let attr = ProgramAttr {
        prog_type: ProgramType::RawTracepoint,
        attach_name: Some("sched_process_exec".into()),
        prog_name: [0; 16],
        attach_btf_id: None,
        expected_attach_type: None,
    };

    let bytecode = compiler.get_bytecode();
    let program = Program::create(&attr, &bytecode, &mut stdout()).unwrap();

    /*
     * Create a probe and attach it.
     */
    let mut probe = Probe::create(program);
    probe.attach().unwrap();

    fn from_cstr(buf: &[u8]) -> String {
        String::from_utf8_lossy(match buf.iter().position(|c| *c == 0) {
            Some(p) => &buf[0..p],
            None => buf,
        })
        .to_string()
    }

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));

        while let Ok(entry) = queue.pop() {
            println!(
                "comm={}, pid={}, tgid={}, gid={}, uid={}, utime={}",
                from_cstr(&entry.comm),
                entry.pid,
                entry.tgid,
                entry.uid_gid >> 32,
                entry.uid_gid as u32,
                entry.utime,
            );
        }
    }
}
