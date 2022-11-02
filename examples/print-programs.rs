use bpf_api::collections::Queue;
use bpf_api::probes::{AttachInfo, Probe};
use bpf_api::prog::{Program, ProgramAttr, ProgramType};
use bpf_script::compiler::Compiler;
use bpf_script::types::{AddToTypeDatabase, TypeDatabase};
use bpf_script_derive::AddToTypeDatabase;
use btf::Btf;

#[repr(C, align(1))]
#[derive(Copy, Clone, Default, Debug, AddToTypeDatabase)]
struct ExecEntry {
    pub pid: u32,
    pub tgid: u32,
    pub uid_gid: u64,
    pub utime: u64,
    pub comm: [u8; 16],
}

fn main() {
    println!("Initializing...");

    /*
     * Load types from the vmlinux BTF file.
     */
    let btf = Btf::from_file("/sys/kernel/btf/vmlinux").expect("Failed to parse vmlinux BTF file.");

    /*
     * Put custom type and BTF types into database.
     */
    let mut database = TypeDatabase::default();
    ExecEntry::add_to_database(&mut database).expect("Failed to add ExecEntry.");
    database
        .add_btf_types(&btf)
        .expect("Failed to add BTF types.");

    /*
     * Create a BPF script compiler.
     */
    let mut compiler = Compiler::create(&database);

    /*
     * Create a shared queue and "capture" it in the compiler context.
     */
    let queue = Queue::<ExecEntry>::with_capacity(10).unwrap();
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
                entry.comm = task.comm
                entry.utime = task.utime
                map_push_elem(queue, &entry, 0)
        "#,
        )
        .expect("compilation failed");

    /*
     * Insert the program into the kernel with the intended attachment point.
     */
    let attr = ProgramAttr {
        prog_name: None,
        prog_type: ProgramType::RawTracepoint,
        expected_attach_type: None,
        attach_btf_id: None,
    };

    let bytecode = compiler.get_bytecode();
    let program = Program::create(&attr, &bytecode, None).unwrap();

    /*
     * Create a probe and attach it.
     */
    let attach_info = AttachInfo::RawTracepoint("sched_process_exec".into());
    let mut probe = Probe::create(attach_info);
    probe.attach(&program).unwrap();

    fn from_cstr(buf: &[u8]) -> String {
        String::from_utf8_lossy(match buf.iter().position(|c| *c == 0) {
            Some(p) => &buf[0..p],
            None => buf,
        })
        .to_string()
    }

    println!("Reading executed programs from BPF queue...");
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
