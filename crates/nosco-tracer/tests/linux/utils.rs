use std::path::Path;
use std::process::Command;

pub fn compile_tracee(
    asm_path: &Path,
    is_64bit: bool,
    is_pie: bool,
    is_static: bool,
) -> tempfile::TempPath {
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_file = tempfile::NamedTempFile::new().expect("tempfile");

    let mut nasm = nasm_rs::Build::new();

    if is_64bit {
        nasm.target("x86_64-unknown-linux-gnu");
    } else {
        nasm.target("i686-unknown-linux-gnu");
    }

    let o = nasm
        .debug(true)
        .file(asm_path)
        .out_dir(&out_dir)
        .compile_objects()
        .expect("nasm")
        .pop()
        .unwrap();

    let mut gcc = Command::new("gcc");
    gcc.arg(o).arg("-o").arg(out_file.path());

    if !is_64bit {
        gcc.arg("-m32");
    }

    if is_pie && is_static {
        gcc.arg("-static-pie");
    } else if is_pie {
        gcc.arg("-pie");
    } else {
        gcc.arg("-no-pie");
        if is_static {
            gcc.arg("-static");
        }
    }

    println!("running: {gcc:?}");

    let gcc = gcc.output().expect("gcc");

    if !gcc.status.success() {
        let msg = String::from_utf8_lossy(&gcc.stderr);
        panic!("{msg}");
    }

    out_file.into_temp_path()
}
