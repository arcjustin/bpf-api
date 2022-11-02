use anyhow::{bail, Context, Result};
use bpf_api::collections::Queue;
use bpf_api::probes::{AttachInfo, AttachType, Probe};
use bpf_api::prog::{Program, ProgramAttr, ProgramType};
use bpf_script::compiler::Compiler;
use bpf_script_derive::AddToTypeDatabase;
use bpf_script::types::{AddToTypeDatabase, TypeDatabase};
use btf::Btf;
use clap::Parser;

fn get_function_address(image_path: &str, function: Option<&String>, dynamic: bool) -> Result<u64> {
    let file = std::fs::read(image_path).context("Could not read file.")?;
    let file_data = file.as_slice();

    let mut file = elf::File::open_stream(file_data).expect("Could not parse ELF Header");

    let (symtab, strtab) = if dynamic {
        file.dynamic_symbol_table()
            .context("Failed to read symbol table")?
            .context("File contained no symbol table")?
    } else {
        file.symbol_table()
            .context("Failed to read symbol table")?
            .context("File contained no symbol table")?
    };

    let function = if let Some(function) = function {
        function
    } else {
        return Ok(file.ehdr.e_entry);
    };

    Ok(symtab
        .iter()
        .find(|s| {
            let name = strtab
                .get(s.st_name as usize)
                .expect("Malformed symbol table");
            name == function
        })
        .context("Failed to find function address")?
        .st_value)
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to a program or library to trace
    image_path: String,

    /// The function to trace; entry is used, if omitted
    function: Option<String>,

    /// Argument types (in order); used to format output
    #[arg(short, long)]
    arg: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    /*
     * Before anything, try to find the function address for (image_path, function)
     */
    let address = if let Ok(address) =
        get_function_address(&args.image_path, args.function.as_ref(), false)
    {
        address
    } else if let Ok(address) = get_function_address(&args.image_path, args.function.as_ref(), true)
    {
        address
    } else {
        bail!("Failed to find function address")
    };

    /*
     * Create a custom type database and add the `ExecEntry` structure to it.
     */
    let mut database = TypeDatabase::default();

    #[repr(C, align(1))]
    #[derive(Copy, Clone, Debug, Default, AddToTypeDatabase)]
    struct ExecEntry {
        pub uid_gid: u64,
        pub args: [u64; 4],
        pub strs: [[u8; 32]; 4],
        pub comm: [u8; 16],
    }

    ExecEntry::add_to_database(&mut database)
        .context("Failed to add ExecEntry to type database.")?;

    let btf = Btf::from_file("/sys/kernel/btf/vmlinux").context("Failed to parse BTF")?;
    database
        .add_btf_types(&btf)
        .context("Failed to add BTF types to database.")?;

    /*
     * Create a BPF script compiler.
     */
    let mut compiler = Compiler::create(&database);

    /*
     * Create a shared queue and "capture" it in the compiler context.
     */
    let queue = Queue::<ExecEntry>::with_capacity(10).expect("Failed to create BPF queue");
    compiler.capture("queue", queue.get_identifier().into());

    /*
     * Compile a program from a script, at run-time, and without bcc/llvm.
     */
    compiler
        .compile(
            r#"
            fn(regs: &bpf_user_pt_regs_t)
                entry: ExecEntry = 0
                entry.uid_gid = get_current_uid_gid()
                entry.args[0] = regs.di
                entry.args[1] = regs.si
                entry.args[2] = regs.dx
                entry.args[3] = regs.cx
                probe_read_str(&entry.strs[0], 32, regs.di)
                probe_read_str(&entry.strs[1], 32, regs.si)
                probe_read_str(&entry.strs[2], 32, regs.dx)
                probe_read_str(&entry.strs[3], 32, regs.cx)
                get_current_comm(&entry.comm, 16)
                map_push_elem(queue, &entry, 0)
        "#,
        )
        .context("Failed to compile script")?;

    /*
     * Insert the program into the kernel with the intended attachment point.
     */
    let attr = ProgramAttr {
        prog_name: None,
        prog_type: ProgramType::KProbe,
        expected_attach_type: Some(AttachType::PerfEvent),
        attach_btf_id: None,
    };

    let bytecode = compiler.get_bytecode();
    let program = Program::create(&attr, &bytecode, None).expect("Failed to create program");

    /*
     * Create a probe and attach the program to it.
     */
    let attach_info = AttachInfo::UProbe((args.image_path, address));
    let mut probe = Probe::create(attach_info);
    probe.attach(&program).expect("Failed to attach program");

    fn from_cstr(buf: &[u8]) -> String {
        String::from_utf8_lossy(match buf.iter().position(|c| *c == 0) {
            Some(p) => &buf[0..p],
            None => buf,
        })
        .to_string()
    }

    fn format_arguments(args: &[String], entry: &ExecEntry) -> String {
        let mut formatted = vec![];
        for (i, arg_type) in args.iter().enumerate() {
            match arg_type.as_str() {
                "cstr" => formatted.push(format!("\"{}\"", from_cstr(&entry.strs[i]))),
                "num" => formatted.push(entry.args[i].to_string()),
                "hex" => formatted.push(format!("{:#0x}", entry.args[i])),
                "ptr" => formatted.push(format!("{:#016x}", entry.args[i])),
                fmt => panic!("Unknown formatter: {}", fmt),
            }
        }

        formatted.join(", ")
    }

    println!("Reading from queue...");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));

        while let Ok(entry) = queue.pop() {
            let comm = from_cstr(&entry.comm);
            if comm == "user-tracer" {
                continue;
            }

            let args = format_arguments(&args.arg, &entry);
            println!(
                "comm={}, gid/uid={}/{}, args=[{}]",
                comm,
                entry.uid_gid >> 32,
                entry.uid_gid as u32,
                args,
            );
        }
    }
}
