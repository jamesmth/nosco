use std::collections::HashMap;
use std::io::{Read, Seek};
use std::vec::IntoIter;

use capstone::Capstone;
use capstone::arch::BuildsCapstone;
use kdl::{KdlDocument, KdlEntry, KdlNode};
use miette::IntoDiagnostic;
use nosco_storage::MlaStorageReader;
use nosco_storage::content::CallData;

use super::call_info::{CallInformation, CallInformationFetcher};

pub fn dump_to_kdl(
    mut reader: MlaStorageReader<impl Read + Seek>,
    mut call_info_fetcher: CallInformationFetcher,
    max_depth: Option<usize>,
    asm: bool,
    call_id: String,
) -> miette::Result<KdlDocument> {
    // TODO: encode arch in trace session storage
    let disass = if cfg!(target_arch = "x86_64") && asm {
        Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .build()
            .map(Some)
            .into_diagnostic()?
    } else if cfg!(target_arch = "aarch64") && asm {
        Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .build()
            .map(Some)
            .into_diagnostic()?
    } else {
        None
    };

    //
    // Read all the call traces (children calls included) from the storage.
    //

    let mut call_trace_info = HashMap::new();
    let mut call_ids = vec![(0, call_id.clone())];
    let mut state_update_ids = Vec::new();

    while let Some((depth, call_id)) = call_ids.pop() {
        let entry = call_trace_info
            .entry(call_id.clone())
            .insert_entry(CallTraceInformation {
                call_info: call_info_fetcher.fetch(call_id, &mut reader)?,
                call_data_info: Vec::new(),
            });

        // no need to fetch a backtrace for children calls
        call_info_fetcher = call_info_fetcher.with_backtrace(false);

        if max_depth.is_some_and(|max| depth >= max) {
            continue;
        }

        let call_id = entry.key().clone();
        let CallTraceInformation { call_data_info, .. } = entry.into_mut();

        for call_data in reader.call_stream_reader(call_id).into_diagnostic()? {
            match call_data.into_diagnostic()? {
                CallData::ExecutedInstruction {
                    opcodes_addr,
                    opcodes,
                } => {
                    if let Some(disass) = disass.as_ref() {
                        let exec = ExecutedInstructionInformation::from_opcodes(
                            opcodes_addr,
                            &opcodes,
                            disass,
                            call_info_fetcher.fetch_address,
                        )?;

                        call_data_info.push(CallDataInformation::Exec(Some(exec), None));
                    }
                }
                CallData::CalledFunction { call_id } => {
                    if let Some(CallDataInformation::Exec(Some(_), call @ None)) =
                        call_data_info.last_mut()
                    {
                        *call = Some(call_id.clone());
                    } else {
                        call_data_info.push(CallDataInformation::Exec(None, Some(call_id.clone())));
                    }

                    call_ids.push((depth + 1, call_id));
                }
                CallData::UpdatedState { update_id } => {
                    state_update_ids.push(update_id);

                    call_data_info.push(CallDataInformation::StateUpdate(update_id));
                }
            }
        }
    }

    let state_updates = reader
        .state_updates_reader()
        .into_diagnostic()?
        .map(|res| res.into_diagnostic())
        .enumerate()
        .filter_map(|(id, res)| match res {
            Ok((_, data)) => state_update_ids
                .contains(&(id as u64))
                .then_some(Ok((id as u64, data))),
            Err(e) => Some(Err(e)),
        })
        .collect::<miette::Result<HashMap<_, _>>>()?;

    //
    // Recursively dump the call traces to KDL.
    //

    let Some(mut action) = call_trace_info
        .remove(&call_id)
        .map(|info| DumpStep::EnterCall(None, info))
    else {
        unreachable!()
    };

    let mut kdl = KdlDocument::new();

    let mut call_data_iters = Vec::new();

    loop {
        action = match action {
            DumpStep::EnterCall(node, call_trace) => {
                let node = call_trace.call_info.dump_to_kdl_node(node);

                DumpStep::IterExec(node, call_trace.call_data_info.into_iter())
            }
            DumpStep::IterExec(mut node, mut all_call_data) => loop {
                let Some(call_data) = all_call_data.next() else {
                    break DumpStep::LeaveCall(node);
                };

                match call_data {
                    CallDataInformation::Exec(exec, call) => {
                        let exec_node = exec.map(|exec| exec.to_kdl_node());

                        if let Some(call_id) = call {
                            let Some(call_info) = call_trace_info.remove(&call_id) else {
                                unreachable!()
                            };

                            call_data_iters.push((node, all_call_data));

                            break DumpStep::EnterCall(exec_node, call_info);
                        } else if let Some(exec_node) = exec_node {
                            node.ensure_children().nodes_mut().push(exec_node);
                        }
                    }
                    CallDataInformation::StateUpdate(update_id) => {
                        let Some(update_node) = state_updates
                            .get(&update_id)
                            .map(super::call_info::kdl_node_from_state_change_data)
                        else {
                            unreachable!()
                        };

                        node.ensure_children().nodes_mut().push(update_node);
                    }
                }
            },
            DumpStep::LeaveCall(node) => {
                if let Some((mut parent_node, all_call_data)) = call_data_iters.pop() {
                    parent_node.ensure_children().nodes_mut().push(node);
                    DumpStep::IterExec(parent_node, all_call_data)
                } else {
                    kdl.nodes_mut().push(node);
                    break;
                }
            }
        };
    }

    Ok(kdl)
}

enum DumpStep {
    EnterCall(Option<KdlNode>, CallTraceInformation),
    LeaveCall(KdlNode),
    IterExec(KdlNode, IntoIter<CallDataInformation>),
}

struct CallTraceInformation {
    call_info: CallInformation,
    call_data_info: Vec<CallDataInformation>,
}

enum CallDataInformation {
    Exec(Option<ExecutedInstructionInformation>, Option<String>),
    StateUpdate(u64),
}

struct ExecutedInstructionInformation {
    addr: Option<u64>,
    asm: String,
}

impl ExecutedInstructionInformation {
    fn from_opcodes(
        opcodes_addr: u64,
        opcodes: &[u8],
        disass: &Capstone,
        fetch_addresses: bool,
    ) -> miette::Result<Self> {
        let code = disass
            .disasm_count(opcodes, opcodes_addr, 1)
            .into_diagnostic()?;

        let asm = code.first().map_or_else(String::default, |insn| {
            let mut asm = String::new();

            if let Some(m) = insn.mnemonic() {
                asm.push_str(m);
            }

            if let Some(op) = insn.op_str() {
                asm.push(' ');
                asm.push_str(op);
            }

            asm.trim().to_owned()
        });

        Ok(Self {
            addr: fetch_addresses.then_some(opcodes_addr),
            asm,
        })
    }

    fn to_kdl_node(&self) -> KdlNode {
        let mut kdl_node = KdlNode::new("exec");

        if let Some(addr) = self.addr {
            kdl_node
                .entries_mut()
                .push(KdlEntry::new(format!("<{addr:#x}>")));
        }

        kdl_node
            .entries_mut()
            .push(KdlEntry::new(self.asm.as_str()));

        kdl_node
    }
}
