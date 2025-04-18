mod error;
mod parser;
mod stream;

use std::io::Cursor;

use indoc::indoc;

use self::error::Result;
pub use self::stream::YamlStream;

#[derive(Debug)]
pub enum TraceEvent {
    FnCall { name: String },
    FnReturn,
    Exec { offset: u64, asm: String },
    StateInitBinaryLoaded { name: String },
    StateUpdateBinaryLoaded { name: String },
    StateUpdateBinaryUnloaded { name: String },
}

#[test]
fn init_binary_loaded_empty() {
    let input = indoc! {"
        init:
            loaded_binaries: []

        trace: []
    "};

    let mut stream = YamlStream::from_reader(Cursor::new(input));
    assert!(stream.next().is_none());
}

#[test]
fn init_binary_loaded() {
    let input = indoc! {"
        init:
          loaded_binaries:
            - foo.so
            - bar.so

        trace: []
    "};

    let mut stream = YamlStream::from_reader(Cursor::new(input));
    assert!(is_init_binary_loaded(stream.next(), "foo.so"));
    assert!(is_init_binary_loaded(stream.next(), "bar.so"));
    assert!(stream.next().is_none());
}

#[test]
fn update_binary_loaded_unloaded() {
    let input = indoc! {"
        init:
          loaded_binaries: []

        trace:
          - loaded: foo.so
          - unloaded: foo.so
    "};

    let mut stream = YamlStream::from_reader(Cursor::new(input));
    assert!(is_update_binary_loaded(stream.next(), "foo.so"));
    assert!(is_update_binary_unloaded(stream.next(), "foo.so"));
    assert!(stream.next().is_none());
}

#[test]
fn mixed_nested_calls_and_execs() {
    let input = indoc! {"
        init:
          loaded_binaries: []

        trace:
          - 0x0000: asm 1
          - Function1:
            - 0x0000: asm 2
            - Function2:
              - 0x0000: asm 3
              - 0x0001: asm 4
              - Function3:
                - 0x0000: asm 5
                - 0x0001: asm 6
          - 0x0001: asm 7
          - 0x0002: asm 8
          - Function4: []
    "};

    let mut stream = YamlStream::from_reader(Cursor::new(input));

    assert!(is_exec(stream.next(), 0, "asm 1"));
    assert!(is_fn_call(stream.next(), "Function1"));
    assert!(is_exec(stream.next(), 0, "asm 2"));
    assert!(is_fn_call(stream.next(), "Function2"));
    assert!(is_exec(stream.next(), 0, "asm 3"));
    assert!(is_exec(stream.next(), 1, "asm 4"));
    assert!(is_fn_call(stream.next(), "Function3"));
    assert!(is_exec(stream.next(), 0, "asm 5"));
    assert!(is_exec(stream.next(), 1, "asm 6"));
    assert!(is_fn_ret(stream.next()));
    assert!(is_fn_ret(stream.next()));
    assert!(is_fn_ret(stream.next()));
    assert!(is_exec(stream.next(), 1, "asm 7"));
    assert!(is_exec(stream.next(), 2, "asm 8"));
    assert!(is_fn_call(stream.next(), "Function4"));
    assert!(is_fn_ret(stream.next()));
    assert!(stream.next().is_none());
}

fn is_exec(event: Option<self::Result<TraceEvent>>, off: u64, instr: &str) -> bool {
    matches!(
        event.expect("opt").expect("res"),
        TraceEvent::Exec { offset, asm } if offset == off && asm == instr
    )
}

fn is_fn_call(event: Option<self::Result<TraceEvent>>, fn_name: &str) -> bool {
    matches!(
        event.expect("opt").expect("res"),
        TraceEvent::FnCall { name } if name == fn_name
    )
}

fn is_fn_ret(event: Option<self::Result<TraceEvent>>) -> bool {
    matches!(event.expect("opt").expect("res"), TraceEvent::FnReturn)
}

fn is_init_binary_loaded(event: Option<self::Result<TraceEvent>>, bin_name: &str) -> bool {
    matches!(
        event.expect("opt").expect("res"),
        TraceEvent::StateInitBinaryLoaded { name } if bin_name == name
    )
}

fn is_update_binary_loaded(event: Option<self::Result<TraceEvent>>, bin_name: &str) -> bool {
    matches!(
        event.expect("opt").expect("res"),
        TraceEvent::StateUpdateBinaryLoaded { name } if bin_name == name
    )
}

fn is_update_binary_unloaded(event: Option<self::Result<TraceEvent>>, bin_name: &str) -> bool {
    matches!(
        event.expect("opt").expect("res"),
        TraceEvent::StateUpdateBinaryUnloaded { name } if bin_name == name
    )
}
