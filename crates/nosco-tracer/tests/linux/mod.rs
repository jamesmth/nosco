mod utils;

use std::path::PathBuf;

use test_log::test;

use tokio::io::AsyncReadExt;

use crate::common::TestTraceHandler;

#[test(tokio::test)]
async fn hello_32bit_nopie_nostatic() {
    test_trace_hello(false, false, false).await;
}

#[test(tokio::test)]
async fn hello_32bit_nopie_static() {
    test_trace_hello(false, false, true).await;
}

#[test(tokio::test)]
async fn hello_32bit_pie_nostatic() {
    test_trace_hello(false, true, false).await;
}

#[test(tokio::test)]
async fn hello_32bit_pie_static() {
    test_trace_hello(false, true, true).await;
}

#[test(tokio::test)]
async fn hello_64bit_nopie_nostatic() {
    test_trace_hello(true, false, false).await;
}

#[test(tokio::test)]
async fn hello_64bit_nopie_static() {
    test_trace_hello(true, false, true).await;
}

#[test(tokio::test)]
async fn hello_64bit_pie_nostatic() {
    test_trace_hello(true, true, false).await;
}

#[test(tokio::test)]
async fn hello_64bit_pie_static() {
    test_trace_hello(true, true, true).await;
}

pub async fn test_trace_hello(is_64bit: bool, is_pie: bool, is_static: bool) {
    let base_dir: PathBuf = "tests/linux".to_owned().into();

    let asm_file = format!("hello.{}.asm", if is_64bit { "64" } else { "32" });
    let trace_file = format!(
        "hello.{}{}.yml",
        if is_64bit { "64" } else { "32" },
        if is_static { ".static" } else { "" }
    );

    let tracee_path =
        self::utils::compile_tracee(&base_dir.join(asm_file), is_64bit, is_pie, is_static);
    let tracee_name = tracee_path.file_name().unwrap().to_string_lossy();

    let trace_handler = TestTraceHandler::new(&base_dir.join(trace_file), tracee_name.to_string());

    let tracer = nosco_tracer::tracer::Tracer::builder()
        .with_debugger(nosco_debugger::Debugger)
        .with_event_handler(trace_handler)
        .trace_scopes()
        .scope(tracee_name, "main", 1)
        .build();

    let mut tracee = tracer
        .spawn(std::process::Command::new(&tracee_path))
        .await
        .expect("spawn");

    let mut stdout = tracee.stdout().expect("stdout");

    let exit_code = tracee.resume_and_trace().await.expect("run");
    assert_eq!(exit_code, 0);

    let mut output = String::new();
    stdout
        .read_to_string(&mut output)
        .await
        .expect("read_to_string");

    assert_eq!(output, "Hello, world!\n");

    drop(tracee_path);
}
