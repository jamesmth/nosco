use std::collections::HashMap;
use std::path::Path;

use nosco_tracer::debugger::BinaryView;

type MappedBinary = <nosco_debugger::Session as nosco_tracer::debugger::DebugSession>::MappedBinary;
type MappedView = <MappedBinary as nosco_tracer::debugger::BinaryInformation>::View;

use super::yaml::{TraceEvent, YamlStream};

#[derive(Debug, thiserror::Error)]
pub enum Error {}

pub struct TestTraceHandler {
    expected: YamlStream<std::fs::File>,
    mapped_exe: Option<MappedView>,
    disass: capstone::Capstone,
    exe_name: String,
    last_fn_addr: Vec<u64>,
    mapped_images: HashMap<u64, String>,
}

impl TestTraceHandler {
    pub fn new(trace_file: &Path, exe_name: String, is_64bits: bool) -> Self {
        use capstone::arch::BuildsCapstone;

        let expected = YamlStream::from_path(trace_file).expect("from_path");

        let mode = if is_64bits {
            capstone::arch::x86::ArchMode::Mode64
        } else {
            capstone::arch::x86::ArchMode::Mode32
        };

        Self {
            expected,
            mapped_exe: None,
            disass: capstone::Capstone::new().x86().mode(mode).build().unwrap(),
            exe_name,
            last_fn_addr: Vec::new(),
            mapped_images: HashMap::new(),
        }
    }
}

impl nosco_tracer::handler::EventHandler for TestTraceHandler {
    type Session = nosco_debugger::Session;
    type Error = Error;

    async fn binary_loaded(
        &mut self,
        _session: &mut Self::Session,
        thread_id: Option<u64>,
        binary: &<Self::Session as nosco_tracer::debugger::DebugSession>::MappedBinary,
    ) -> Result<(), Self::Error> {
        use nosco_tracer::debugger::BinaryInformation;

        if binary.file_name() == self.exe_name {
            let view = binary.to_view().await.expect("view");
            self.mapped_exe = Some(view);
        }

        let trace_event = self.expected.next().expect("next").expect("event");

        if thread_id.is_some() {
            assert!(
                matches!(trace_event, TraceEvent::StateUpdateBinaryLoaded { name } if name == binary.file_name())
            );
        } else {
            match trace_event {
                TraceEvent::StateInitBinaryLoaded { name } if name == "<exe>" => {
                    assert_eq!(self.exe_name, binary.file_name())
                }
                TraceEvent::StateInitBinaryLoaded { name } => assert_eq!(name, binary.file_name()),
                _ => panic!("bad trace event"),
            }
        }

        self.mapped_images
            .insert(binary.base_addr(), binary.file_name().to_owned());

        Ok(())
    }

    async fn binary_unloaded(
        &mut self,
        _session: &mut Self::Session,
        _thread_id: u64,
        unload_addr: u64,
    ) -> Result<(), Self::Error> {
        let TraceEvent::StateUpdateBinaryUnloaded { name } =
            self.expected.next().expect("next").expect("event")
        else {
            panic!("bad trace event");
        };

        let Some(s) = self.mapped_images.remove(&unload_addr) else {
            panic!("bad unload addr")
        };

        assert_eq!(name, s);

        Ok(())
    }

    async fn function_entered(
        &mut self,
        _session: &mut Self::Session,
        thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
    ) -> Result<(), Self::Error> {
        use nosco_tracer::debugger::Thread;

        let trace_event = self.expected.next().expect("next").expect("event");

        let TraceEvent::FnCall { name } = trace_event else {
            panic!("expected fn call");
        };

        self.last_fn_addr.push(thread.instr_addr());

        if name != "?" {
            if let Some((symbol, offset)) = self
                .mapped_exe
                .as_ref()
                .unwrap()
                .symbol_of_addr(thread.instr_addr())
                .await
                .expect("symbol_of_addr")
            {
                assert_eq!(offset, 0);
                assert_eq!(name, symbol);
            } else {
                panic!("fn symbol not found at {:#x}", thread.instr_addr());
            }
        }

        Ok(())
    }

    async fn function_returned(
        &mut self,
        _session: &mut Self::Session,
        _thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
    ) -> Result<(), Self::Error> {
        let trace_event = self.expected.next().expect("next").expect("event");

        assert!(matches!(trace_event, TraceEvent::FnReturn));

        self.last_fn_addr.pop();

        Ok(())
    }

    async fn instruction_executed(
        &mut self,
        _session: &mut Self::Session,
        _thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
        opcodes_addr: u64,
        opcodes: Vec<u8>,
    ) -> Result<(), Self::Error> {
        let trace_event = self.expected.next().expect("next").expect("event");

        let TraceEvent::Exec { offset, asm } = trace_event else {
            panic!("expected instr exec");
        };

        let regex = regex::Regex::new(&asm).unwrap();

        let disass = {
            let insns = self
                .disass
                .disasm_count(&opcodes, opcodes_addr, 1)
                .expect("disasm_all");

            let disass_ins = insns.iter().next().unwrap();

            let mut ins_pretty = String::new();

            if let Some(m) = disass_ins.mnemonic() {
                ins_pretty.push_str(m);
            }

            if let Some(o) = disass_ins.op_str() {
                if !ins_pretty.is_empty() {
                    ins_pretty.push(' ');
                }
                ins_pretty.push_str(o);
            }

            ins_pretty
        };

        assert!(regex.is_match(&disass), "regex not matched by: {disass}");

        assert_eq!(opcodes_addr, self.last_fn_addr.last().unwrap() + offset);

        Ok(())
    }

    async fn thread_exited(
        &mut self,
        _session: &mut Self::Session,
        _thread_id: u64,
        _exit_code: i32,
    ) -> Result<(), Self::Error> {
        assert!(self.expected.next().is_none());

        Ok(())
    }
}
