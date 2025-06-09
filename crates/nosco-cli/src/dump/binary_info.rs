use std::io::{Read, Seek};
use std::path::PathBuf;

use kdl::{KdlDocument, KdlEntry, KdlNode};
use miette::IntoDiagnostic;
use nosco_storage::MlaStorageReader;
use nosco_storage::content::{StateChangeData, StateUpdateOrigin};

use super::call_info::{CallInformation, CallInformationFetcher};

pub fn dump_to_kdl(
    mut reader: MlaStorageReader<impl Read + Seek>,
    call_info_fetcher: CallInformationFetcher,
    single_binary: Option<String>,
) -> miette::Result<KdlDocument> {
    let binaries_info = fetch_partial_binaries_info(&mut reader, single_binary.as_deref())?
        .into_iter()
        .map(|info| info.fetch_calls_info(&mut reader, call_info_fetcher))
        .collect::<miette::Result<Vec<_>>>()?;

    let mut kdl = KdlDocument::new();

    for binary_info in binaries_info {
        kdl.nodes_mut().push({
            let mut node = KdlNode::new("binary");
            binary_info.dump_to_kdl_node(&mut node);
            node
        });
    }

    Ok(kdl)
}

fn fetch_partial_binaries_info(
    reader: &mut MlaStorageReader<impl Read + Seek>,
    single_binary: Option<&str>,
) -> miette::Result<Vec<PartialBinaryInformation>> {
    // fetch binaries information from initial state
    let mut binaries_info = reader
        .state_init_reader()
        .into_diagnostic()?
        .filter_map(|res| match res {
            Ok(StateChangeData::LoadedBinary { path, load_addr })
                if single_binary.is_none_or(|binary| path.ends_with(binary)) =>
            {
                Some(Ok(PartialBinaryInformation {
                    path,
                    load_addr,
                    loaded: None,
                    unloaded: None,
                }))
            }
            Err(e) => Some(Err(e).into_diagnostic()),
            _ => None,
        })
        .collect::<miette::Result<Vec<_>>>()?;

    let mut unloaded_binaries = Vec::new();

    // fetch binaries information from state updates
    binaries_info.extend(
        reader
            .state_updates_reader()
            .into_diagnostic()?
            .filter_map(|res| match res {
                Ok((update_origin, StateChangeData::LoadedBinary { path, load_addr }))
                    if single_binary.is_none_or(|binary| path.ends_with(binary)) =>
                {
                    Some(Ok(PartialBinaryInformation {
                        path,
                        load_addr,
                        loaded: Some(update_origin),
                        unloaded: None,
                    }))
                }
                Ok((update_origin, StateChangeData::UnloadedBinary { unload_addr })) => {
                    unloaded_binaries.push((update_origin, unload_addr));
                    None
                }
                Err(e) => Some(Err(e).into_diagnostic()),
                _ => None,
            })
            .collect::<miette::Result<Vec<_>>>()?,
    );

    if let Some(binary_suffix) = single_binary {
        miette::ensure!(
            !binaries_info.is_empty(),
            "Binary with suffix '{binary_suffix}' not found"
        );
    }

    for (unload_update_origin, unload_addr) in unloaded_binaries {
        let mut unloaded_binary_info = None;

        for info in binaries_info
            .iter_mut()
            .filter(|info| info.load_addr == unload_addr)
        {
            let timestamp_diff = info.loaded.as_ref().and_then(|load_update_origin| {
                unload_update_origin
                    .timestamp
                    .duration_since(load_update_origin.timestamp)
                    .ok()
            });

            let Some((unloaded_binary_info, prev_timestamp_diff)) = unloaded_binary_info.as_mut()
            else {
                unloaded_binary_info = Some((info, timestamp_diff));
                continue;
            };

            if timestamp_diff.is_some_and(|new_dur| {
                prev_timestamp_diff.is_none_or(|prev_dur| new_dur < prev_dur)
            }) {
                *unloaded_binary_info = info;
                *prev_timestamp_diff = timestamp_diff;
            }
        }

        if let Some((binary_info, _)) = unloaded_binary_info {
            binary_info.unloaded = Some(unload_update_origin);
        }
    }

    Ok(binaries_info)
}

struct PartialBinaryInformation {
    path: PathBuf,
    load_addr: u64,
    loaded: Option<StateUpdateOrigin>,
    unloaded: Option<StateUpdateOrigin>,
}

impl PartialBinaryInformation {
    fn fetch_calls_info(
        self,
        reader: &mut MlaStorageReader<'_, impl Read + Seek>,
        call_info_fetcher: CallInformationFetcher,
    ) -> miette::Result<BinaryInformation> {
        let loaded = self
            .loaded
            .map(
                |StateUpdateOrigin {
                     thread_id,
                     call_id,
                     timestamp: _,
                 }| {
                    call_id
                        .map(|(call_id, addr)| {
                            call_info_fetcher
                                .fetch(call_id, reader)
                                .map(|mut call_info| {
                                    if let Some(address) = call_info.address.as_mut() {
                                        *address = addr;
                                    };
                                    call_info
                                })
                        })
                        .transpose()
                        .map(|call_info| (thread_id, call_info))
                },
            )
            .transpose()?;

        let unloaded = self
            .unloaded
            .map(
                |StateUpdateOrigin {
                     thread_id,
                     call_id,
                     timestamp: _,
                 }| {
                    call_id
                        .map(|(call_id, addr)| {
                            call_info_fetcher
                                .fetch(call_id, reader)
                                .map(|mut call_info| {
                                    if let Some(address) = call_info.address.as_mut() {
                                        *address = addr;
                                    };
                                    call_info
                                })
                        })
                        .transpose()
                        .map(|call_info| (thread_id, call_info))
                },
            )
            .transpose()?;

        Ok(BinaryInformation {
            path: self.path,
            load_addr: self.load_addr,
            loaded,
            unloaded,
        })
    }
}

struct BinaryInformation {
    path: PathBuf,
    load_addr: u64,
    loaded: Option<(u64, Option<CallInformation>)>,
    unloaded: Option<(u64, Option<CallInformation>)>,
}

impl BinaryInformation {
    pub fn dump_to_kdl_node(&self, kdl_node: &mut KdlNode) {
        kdl_node
            .entries_mut()
            .push(self.path.display().to_string().into());

        kdl_node
            .entries_mut()
            .push(KdlEntry::new_prop("addr", format!("{:#x}", self.load_addr)));

        if let Some((thread_id, ref call_info)) = self.loaded {
            kdl_node.ensure_children().nodes_mut().push({
                let mut node = KdlNode::new("loaded_by");

                if let Some(call_info) = call_info {
                    node = call_info.dump_to_kdl_node(Some(node));
                }

                node.entries_mut()
                    .push(KdlEntry::new_prop("thread", i128::from(thread_id)));

                node
            });
        }

        if let Some((thread_id, ref call_info)) = self.unloaded {
            kdl_node.ensure_children().nodes_mut().push({
                let mut node = KdlNode::new("unloaded_by");

                if let Some(call_info) = call_info {
                    node = call_info.dump_to_kdl_node(Some(node));
                }

                node.entries_mut()
                    .push(KdlEntry::new_prop("thread", i128::from(thread_id)));

                node
            });
        }
    }
}
