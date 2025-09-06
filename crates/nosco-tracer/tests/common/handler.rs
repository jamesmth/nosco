use std::collections::HashMap;

use kdl::{KdlDocument, KdlNode};
use nosco_tracer::debugger::{MappedBinary, Thread};
use regex::Regex;

type MappedBin = <nosco_debugger::Session as nosco_tracer::debugger::DebugSession>::MappedBinary;

#[derive(Debug, thiserror::Error)]
pub enum Error {}

pub struct TestTraceHandler {
    mapped_exe: Option<MappedBin>,
    disass: capstone::Capstone,
    exe_name: String,
    last_fn_addrs: HashMap<u64, Vec<u64>>,
    mapped_images: HashMap<u64, String>,
    backtrace_depth: Option<usize>,

    regex_imm: Regex,

    kdl_node_binaries: KdlNode,
    kdl_node_calls: HashMap<u64, Vec<KdlNode>>,

    next_thread_idx: u64,
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
            last_fn_addrs: HashMap::new(),
            mapped_images: HashMap::new(),
            backtrace_depth,
            regex_imm: Regex::new("0x[0-9a-fA-F]{2}[0-9a-fA-F]*").unwrap(),
            kdl_node_binaries: KdlNode::new("binaries"),
            kdl_node_calls: HashMap::new(),
            next_thread_idx: 1,
        }
    }

    pub fn into_kdl(self) -> KdlDocument {
        let mut kdl = KdlDocument::new();

        let mut node = KdlNode::new("start");
        node.ensure_children()
            .nodes_mut()
            .push(self.kdl_node_binaries);
        kdl.nodes_mut().push(node);

        let mut threads_nodes = self
            .kdl_node_calls
            .into_values()
            .map(|mut nodes| nodes.pop().unwrap())
            .collect::<Vec<_>>();

        threads_nodes.sort_by(|node1, node2| {
            let thread_1_id = node1.entry(0).unwrap().value().as_integer().unwrap();
            let thread_2_id = node2.entry(0).unwrap().value().as_integer().unwrap();
            thread_1_id.cmp(&thread_2_id)
        });

        kdl.nodes_mut().extend(threads_nodes);

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
        binary: &mut MappedBin,
    ) -> Result<(), Self::Error> {
        let binary_name = if binary.file_name() == self.exe_name {
            self.mapped_exe = Some(binary.clone());
            "<exe>"
        } else {
            binary.file_name()
        };

        if let Some(thread_id) = thread_id {
            let mut node = KdlNode::new("load_binary");
            node.entries_mut().push(binary_name.into());

            self.kdl_node_calls
                .get_mut(&thread_id)
                .unwrap()
                .last_mut()
                .unwrap()
                .ensure_children()
                .nodes_mut()
                .push(node);
        } else {
            let node = KdlNode::new(binary_name);

            self.kdl_node_binaries
                .ensure_children()
                .nodes_mut()
                .push(node);
        }

        self.mapped_images
            .insert(binary.addr_range().start, binary.file_name().to_owned());

        Ok(())
    }

    async fn binary_unloaded(
        &mut self,
        _session: &mut Self::Session,
        thread_id: u64,
        unload_addr: u64,
    ) -> Result<(), Self::Error> {
        let Some(binary_name) = self.mapped_images.remove(&unload_addr) else {
            panic!("bad unload addr")
        };

        let mut node = KdlNode::new("unload_binary");
        node.entries_mut().push(binary_name.into());

        self.kdl_node_calls
            .get_mut(&thread_id)
            .unwrap()
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

        self.last_fn_addrs
            .get_mut(&thread.id())
            .unwrap()
            .push(thread.instr_addr());

        let symbol = self
            .mapped_exe
            .as_mut()
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
                    .as_mut()
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

        self.kdl_node_calls
            .get_mut(&thread.id())
            .unwrap()
            .push(node);

        Ok(())
    }

    async fn function_returned(
        &mut self,
        _session: &mut Self::Session,
        thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
    ) -> Result<(), Self::Error> {
        let kdl_node_calls = self.kdl_node_calls.get_mut(&thread.id()).unwrap();

        let node = kdl_node_calls.pop().unwrap();
        kdl_node_calls
            .last_mut()
            .unwrap()
            .ensure_children()
            .nodes_mut()
            .push(node);

        self.last_fn_addrs.get_mut(&thread.id()).unwrap().pop();

        Ok(())
    }

    async fn instruction_executed(
        &mut self,
        _session: &mut Self::Session,
        thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
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

        let offset = opcodes_addr
            - self
                .last_fn_addrs
                .get(&thread.id())
                .unwrap()
                .last()
                .unwrap();

        let disass = self.regex_imm.replace_all(disass.trim(), "<imm>");

        let mut node = KdlNode::new(format!("<{offset:#x}>"));
        node.entries_mut().push(disass.as_ref().into());

        self.kdl_node_calls
            .get_mut(&thread.id())
            .unwrap()
            .last_mut()
            .unwrap()
            .ensure_children()
            .nodes_mut()
            .push(node);

        Ok(())
    }

    async fn thread_created(
        &mut self,
        _session: &mut Self::Session,
        parent_thread_id: Option<u64>,
        new_thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
    ) -> Result<(), Self::Error> {
        let thread_idx = self.next_thread_idx;
        self.next_thread_idx += 1;

        if let Some(parent_thread_id) = parent_thread_id {
            let mut node = KdlNode::new("create_thread");
            node.entries_mut().push(i128::from(thread_idx).into());

            self.kdl_node_calls
                .get_mut(&parent_thread_id)
                .unwrap()
                .last_mut()
                .unwrap()
                .ensure_children()
                .nodes_mut()
                .push(node);
        }

        assert!(
            self.kdl_node_calls
                .insert(new_thread.id(), Vec::new())
                .is_none()
        );

        let mut node = KdlNode::new("thread");
        node.entries_mut().push(i128::from(thread_idx).into());

        self.kdl_node_calls
            .get_mut(&new_thread.id())
            .unwrap()
            .push(node);

        assert!(
            self.last_fn_addrs
                .insert(new_thread.id(), Vec::new())
                .is_none()
        );

        Ok(())
    }

    async fn thread_exited(
        &mut self,
        _session: &mut Self::Session,
        thread_id: u64,
        _exit_code: i32,
    ) -> Result<(), Self::Error> {
        let kdl_node_calls = self.kdl_node_calls.get_mut(&thread_id).unwrap();

        while kdl_node_calls.len() > 1 {
            let node = kdl_node_calls.pop().unwrap();

            kdl_node_calls
                .last_mut()
                .unwrap()
                .ensure_children()
                .nodes_mut()
                .push(node);
        }

        Ok(())
    }
}
