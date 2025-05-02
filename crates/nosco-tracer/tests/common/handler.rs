use std::collections::HashMap;

use kdl::{KdlDocument, KdlNode};

use nosco_tracer::debugger::BinaryView;

use regex::Regex;

type MappedBinary = <nosco_debugger::Session as nosco_tracer::debugger::DebugSession>::MappedBinary;
type MappedView = <MappedBinary as nosco_tracer::debugger::BinaryInformation>::View;

#[derive(Debug, thiserror::Error)]
pub enum Error {}

pub struct TestTraceHandler {
    mapped_exe: Option<MappedView>,
    disass: capstone::Capstone,
    exe_name: String,
    last_fn_addr: Vec<u64>,
    mapped_images: HashMap<u64, String>,
    backtrace_depth: Option<usize>,

    regex_imm: Regex,

    kdl_node_binaries: KdlNode,
    kdl_node_calls: Vec<KdlNode>,
}

impl TestTraceHandler {
    pub fn new(exe_name: String, is_64bits: bool, backtrace_depth: Option<usize>) -> Self {
        use capstone::arch::BuildsCapstone;

        let mode = if is_64bits {
            capstone::arch::x86::ArchMode::Mode64
        } else {
            capstone::arch::x86::ArchMode::Mode32
        };

        Self {
            mapped_exe: None,
            disass: capstone::Capstone::new().x86().mode(mode).build().unwrap(),
            exe_name,
            last_fn_addr: Vec::new(),
            mapped_images: HashMap::new(),
            backtrace_depth,
            regex_imm: Regex::new("0x[0-9a-fA-F]+").unwrap(),
            kdl_node_binaries: KdlNode::new("binaries"),
            kdl_node_calls: vec![KdlNode::new("trace")],
        }
    }

    pub fn into_kdl(mut self) -> KdlDocument {
        let mut kdl = KdlDocument::new();

        let mut node = KdlNode::new("start");
        node.ensure_children()
            .nodes_mut()
            .push(self.kdl_node_binaries);
        kdl.nodes_mut().push(node);

        kdl.nodes_mut().push(self.kdl_node_calls.pop().unwrap());

        kdl
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

        let binary_name = if binary.file_name() == self.exe_name {
            let view = binary.to_view().await.expect("view");
            self.mapped_exe = Some(view);
            "<exe>"
        } else {
            binary.file_name()
        };

        if thread_id.is_some() {
            let mut node = KdlNode::new("load_binary");
            node.entries_mut().push(binary_name.into());

            self.kdl_node_calls
                .last_mut()
                .unwrap()
                .ensure_children()
                .nodes_mut()
                .push(node);
        } else {
            let mut node = KdlNode::new("-");
            node.entries_mut().push(binary_name.into());

            self.kdl_node_binaries
                .ensure_children()
                .nodes_mut()
                .push(node);
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
        let Some(binary_name) = self.mapped_images.remove(&unload_addr) else {
            panic!("bad unload addr")
        };

        let mut node = KdlNode::new("unload_binary");
        node.entries_mut().push(binary_name.into());

        self.kdl_node_calls
            .last_mut()
            .unwrap()
            .ensure_children()
            .nodes_mut()
            .push(node);

        Ok(())
    }

    async fn function_entered(
        &mut self,
        session: &mut Self::Session,
        thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
    ) -> Result<(), Self::Error> {
        use nosco_tracer::debugger::DebugSession;
        use nosco_tracer::debugger::Thread;

        self.last_fn_addr.push(thread.instr_addr());

        let symbol = self
            .mapped_exe
            .as_ref()
            .unwrap()
            .symbol_of_addr(thread.instr_addr())
            .await
            .expect("symbol_of_addr")
            .and_then(|(s, offset)| (offset == 0).then_some(s))
            .unwrap_or_else(|| "<unknown>".to_owned());

        let mut node = KdlNode::new("call");
        node.entries_mut().push(symbol.into());

        if let Some(backtrace_depth) = self.backtrace_depth {
            let backtrace = session
                .compute_backtrace(thread, backtrace_depth)
                .expect("backtrace");

            let mut bt_node = KdlNode::new("backtrace");

            for addr in backtrace.into_iter().rev() {
                let symbol = self
                    .mapped_exe
                    .as_ref()
                    .unwrap()
                    .symbol_of_addr(addr)
                    .await
                    .expect("symbol_of_addr")
                    .map_or_else(
                        || "<unknown>".to_owned(),
                        |(s, o)| if o == 0 { s } else { format!("{s}+{o:#x}") },
                    );

                bt_node
                    .ensure_children()
                    .nodes_mut()
                    .push(KdlNode::new(symbol));
            }

            node.ensure_children().nodes_mut().push(bt_node);
        }

        self.kdl_node_calls.push(node);

        Ok(())
    }

    async fn function_returned(
        &mut self,
        _session: &mut Self::Session,
        _thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
    ) -> Result<(), Self::Error> {
        let node = self.kdl_node_calls.pop().unwrap();
        self.kdl_node_calls
            .last_mut()
            .unwrap()
            .ensure_children()
            .nodes_mut()
            .push(node);

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

        let offset = opcodes_addr - self.last_fn_addr.last().unwrap();
        let disass = self.regex_imm.replace_all(disass.trim(), "<imm>");

        let mut node = KdlNode::new(format!("<{offset:#x}>"));
        node.entries_mut().push(disass.as_ref().into());

        self.kdl_node_calls
            .last_mut()
            .unwrap()
            .ensure_children()
            .nodes_mut()
            .push(node);

        Ok(())
    }

    async fn thread_exited(
        &mut self,
        _session: &mut Self::Session,
        _thread_id: u64,
        _exit_code: i32,
    ) -> Result<(), Self::Error> {
        while self.kdl_node_calls.len() > 1 {
            let node = self.kdl_node_calls.pop().unwrap();
            self.kdl_node_calls
                .last_mut()
                .unwrap()
                .ensure_children()
                .nodes_mut()
                .push(node);
        }

        Ok(())
    }
}
