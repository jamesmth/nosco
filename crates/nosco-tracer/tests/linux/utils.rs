use std::path::{Path, PathBuf};
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

    let mut ld = Command::new("ld");
    ld.arg("-o").arg(out_file.path());

    if !is_64bit {
        ld.args(["-m", "elf_i386"]);
    }

    if is_pie {
        ld.arg("-pie");
    }

    ld.arg(o);

    if is_static {
        ld.arg("-static");

        if is_pie {
            ld.arg("--no-dynamic-linker")
                .arg(gcc_path("rcrt1.o", is_64bit));
        } else {
            ld.arg(gcc_path("crt1.o", is_64bit));
        }

        ld.arg(gcc_path("crti.o", is_64bit))
            .arg("--start-group")
            .arg(gcc_path("libgcc.a", is_64bit))
            .arg(gcc_path("libgcc_eh.a", is_64bit))
            .arg("-lc")
            .arg("--end-group")
            .arg(gcc_path("crtn.o", is_64bit));
    } else {
        if is_64bit {
            ld.args(["-dynamic-linker", "/lib64/ld-linux-x86-64.so.2"]);
        } else {
            ld.args(["-dynamic-linker", "/lib/ld-linux.so.2"]);
        }

        ld.arg(gcc_path("Scrt1.o", is_64bit))
            .arg(gcc_path("crti.o", is_64bit))
            .arg("-lc")
            .arg(gcc_path("crtn.o", is_64bit));
    }

    println!("running: {ld:?}");

    let ld = ld.output().expect("ld");

    if !ld.status.success() {
        let msg = String::from_utf8_lossy(&ld.stderr);
        panic!("{msg}");
    }

    out_file.into_temp_path()
}

fn gcc_path(filename: &str, is_64bit: bool) -> PathBuf {
    let mut gcc = Command::new("gcc");

    if !is_64bit {
        gcc.arg("-m32");
    }

    let output = gcc
        .arg("--print-file-name")
        .arg(filename)
        .output()
        .expect("gcc");

    std::str::from_utf8(&output.stdout)
        .expect("utf8")
        .trim()
        .to_owned()
        .into()
}
