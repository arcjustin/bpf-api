use bpf_api::collections::Queue;
use bpf_api::probes::{AttachInfo, Probe};
use bpf_api::prog::{Program, ProgramAttr, ProgramType};
use bpf_script::Compiler;
use btf::traits::AddToBtf;
use btf::BtfTypes;
use btf_derive::AddToBtf;

#[repr(C, align(1))]
#[derive(Copy, Clone, Default, Debug, AddToBtf)]
struct ExecEntry {
    pub uid_gid: u64,
    pub comm: [u8; 16],
}

fn main() {
    println!("Initializing...");

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
            fn()
                entry: ExecEntry = 0
                entry.uid_gid = get_current_uid_gid()
                get_current_comm(&entry.comm, 16)
                map_push_elem(queue, &entry, 0)
        "#,
        )
        .expect("compilation failed");

    /*
     * Insert the program into the kernel with the intended attachment point.
     */
    let attr = ProgramAttr {
        prog_name: None,
        prog_type: ProgramType::KProbe,
        expected_attach_type: None,
        attach_btf_id: None,
    };

    let bytecode = compiler.get_bytecode();
    let program = Program::create(&attr, &bytecode, None).unwrap();

    /*
     * Create a probe and attach the program to it.
     */
    let attach_info = AttachInfo::UProbe(("/usr/bin/cat".into(), 0x3200));
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
                "comm={}, gid={}, uid={}",
                from_cstr(&entry.comm),
                entry.uid_gid >> 32,
                entry.uid_gid as u32,
            );
        }
    }
}