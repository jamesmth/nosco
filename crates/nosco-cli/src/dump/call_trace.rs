use std::collections::HashMap;
use std::io::{Read, Seek};
use std::vec::IntoIter;

use kdl::{KdlDocument, KdlNode};
use miette::IntoDiagnostic;
use nosco_storage::MlaStorageReader;
use nosco_storage::content::CallData;

use super::SymbolResolver;
use super::call_info::{CallInformation, CallInformationFetcher};

pub fn dump_to_kdl(
    mut reader: MlaStorageReader<impl Read + Seek>,
    mut call_info_fetcher: CallInformationFetcher,
    mut resolver: Option<&mut SymbolResolver>,
    max_depth: Option<usize>,
    call_id: String,
) -> miette::Result<KdlDocument> {
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
                call_info: call_info_fetcher.fetch(
                    call_id,
                    &mut reader,
                    resolver.as_deref_mut(),
                )?,
                call_data_info: Vec::new(),
            });

        // no need to fetch a backtrace for children calls
        call_info_fetcher = call_info_fetcher.with_backtrace(false);

        if max_depth.is_some_and(|max| depth >= max) {
            continue;
        }

        let call_id = entry.key().clone();
        let CallTraceInformation { call_data_info, .. } = entry.into_mut();

        let (_, call_data_iter) = reader.call_stream_reader(call_id).into_diagnostic()?;
        for call_data in call_data_iter {
            match call_data.into_diagnostic()? {
                CallData::CalledFunction { call_id } => {
                    call_data_info.push(CallDataInformation::Call(call_id.clone()));

                    call_ids.push((depth + 1, call_id));
                }
                CallData::UpdatedState { update_id } => {
                    state_update_ids.push(update_id);

                    call_data_info.push(CallDataInformation::StateUpdate(update_id));
                }
                CallData::ExecutedInstruction { .. } => (),
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

    let Some(mut action) = call_trace_info.remove(&call_id).map(DumpStep::EnterCall) else {
        unreachable!()
    };

    let mut kdl = KdlDocument::new();

    let mut call_data_iters = Vec::new();

    loop {
        action = match action {
            DumpStep::EnterCall(call_trace) => {
                let node = call_trace.call_info.dump_to_kdl_node(None);

                DumpStep::IterExec(node, call_trace.call_data_info.into_iter())
            }
            DumpStep::IterExec(mut node, mut all_call_data) => loop {
                let Some(call_data) = all_call_data.next() else {
                    break DumpStep::LeaveCall(node);
                };

                match call_data {
                    CallDataInformation::Call(call_id) => {
                        let Some(call_info) = call_trace_info.remove(&call_id) else {
                            unreachable!()
                        };

                        call_data_iters.push((node, all_call_data));

                        break DumpStep::EnterCall(call_info);
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
    EnterCall(CallTraceInformation),
    LeaveCall(KdlNode),
    IterExec(KdlNode, IntoIter<CallDataInformation>),
}

struct CallTraceInformation {
    call_info: CallInformation,
    call_data_info: Vec<CallDataInformation>,
}

enum CallDataInformation {
    Call(String),
    StateUpdate(u64),
}
