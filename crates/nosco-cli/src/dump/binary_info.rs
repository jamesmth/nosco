use std::io::{Read, Seek};
use std::ops::Range;
use std::path::PathBuf;

use kdl::{KdlDocument, KdlEntry, KdlIdentifier, KdlNode};
use miette::IntoDiagnostic;
use nosco_storage::content::{StateChangeData, StateUpdateOrigin};
use nosco_storage::{BacktraceElement, MlaStorageReader};

use super::SymbolResolver;
use super::call_info::{BacktraceElementInformation, CallInformation, CallInformationFetcher};
use super::call_info::{dump_backtrace_info_to_kdl, fetch_backtrace_info};

pub fn dump_to_kdl(
    mut reader: MlaStorageReader<impl Read + Seek>,
    call_info_fetcher: CallInformationFetcher,
    single_binary: Option<String>,
    mut resolver: Option<&mut SymbolResolver>,
) -> miette::Result<KdlDocument> {
    let binaries_info = fetch_partial_binaries_info(&mut reader, single_binary.as_deref())?
        .into_iter()
        .map(|info| info.fetch_calls_info(&mut reader, call_info_fetcher, resolver.as_deref_mut()))
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

pub fn fetch_partial_binaries_info(
    reader: &mut MlaStorageReader<impl Read + Seek>,
    single_binary: Option<&str>,
) -> miette::Result<Vec<PartialBinaryInformation>> {
    // fetch binaries information from initial state
    let mut binaries_info = reader
        .state_init_reader()
        .into_diagnostic()?
        .filter_map(|res| match res {
            Ok(StateChangeData::LoadedBinary { path, addr_range })
                if single_binary.is_none_or(|binary| path.ends_with(binary)) =>
            {
                Some(Ok(PartialBinaryInformation {
                    path,
                    addr_range,
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
                Ok((update_origin, StateChangeData::LoadedBinary { path, addr_range }))
                    if single_binary.is_none_or(|binary| path.ends_with(binary)) =>
                {
                    Some(Ok(PartialBinaryInformation {
                        path,
                        addr_range,
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
            .filter(|info| info.addr_range.start == unload_addr)
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

pub struct PartialBinaryInformation {
    pub path: PathBuf,
    pub addr_range: Range<u64>,
    pub loaded: Option<StateUpdateOrigin>,
    pub unloaded: Option<StateUpdateOrigin>,
}

impl PartialBinaryInformation {
    fn fetch_calls_info(
        self,
        reader: &mut MlaStorageReader<'_, impl Read + Seek>,
        call_info_fetcher: CallInformationFetcher,
        mut resolver: Option<&mut SymbolResolver>,
    ) -> miette::Result<BinaryInformation> {
        let loaded = self
            .loaded
            .map(|origin| {
                BinaryLoadInfo::fetch_load_info(
                    origin,
                    reader,
                    call_info_fetcher,
                    resolver.as_deref_mut(),
                )
            })
            .transpose()?;

        let unloaded = self
            .unloaded
            .map(|origin| {
                BinaryLoadInfo::fetch_load_info(origin, reader, call_info_fetcher, resolver)
            })
            .transpose()?;

        Ok(BinaryInformation {
            path: self.path,
            addr_range: self.addr_range,
            loaded,
            unloaded,
        })
    }
}

struct BinaryInformation {
    path: PathBuf,
    addr_range: Range<u64>,
    loaded: Option<BinaryLoadInfo>,
    unloaded: Option<BinaryLoadInfo>,
}

impl BinaryInformation {
    pub fn dump_to_kdl_node(&self, kdl_node: &mut KdlNode) {
        kdl_node
            .entries_mut()
            .push(self.path.display().to_string().into());

        kdl_node.entries_mut().push(KdlEntry::new_prop(
            "addr_range",
            format!("{:#x?}", self.addr_range),
        ));

        if let Some(ref loaded) = self.loaded {
            kdl_node
                .ensure_children()
                .nodes_mut()
                .push(loaded.dump_to_kdl_node("loaded_by".into()));
        }

        if let Some(ref unloaded) = self.unloaded {
            kdl_node
                .ensure_children()
                .nodes_mut()
                .push(unloaded.dump_to_kdl_node("unloaded_by".into()));
        }
    }
}

struct BinaryLoadInfo {
    thread_id: u64,
    backtrace: Option<Vec<BacktraceElementInformation>>,
    call_info: Option<CallInformation>,
    dump_addresses: bool,
}

impl BinaryLoadInfo {
    fn fetch_load_info(
        update_origin: StateUpdateOrigin,
        reader: &mut MlaStorageReader<'_, impl Read + Seek>,
        call_info_fetcher: CallInformationFetcher,
        mut resolver: Option<&mut SymbolResolver>,
    ) -> miette::Result<Self> {
        let StateUpdateOrigin {
            thread_id,
            timestamp,
            call_id,
            backtrace,
        } = update_origin;

        let call_info = if let Some((call_id, addr)) = call_id {
            let mut call_info =
                call_info_fetcher.fetch(call_id, reader, resolver.as_deref_mut())?;
            if let Some(address) = call_info.address.as_mut() {
                *address = addr;
            };
            Some(call_info)
        } else {
            None
        };

        let backtrace = if call_info.is_none() && call_info_fetcher.fetch_backtrace {
            fetch_backtrace_info(
                backtrace
                    .into_iter()
                    .map(BacktraceElement::CallAddr)
                    .collect(),
                reader,
                resolver,
                timestamp,
                call_info_fetcher.fetch_address,
            )
            .map(Some)?
        } else {
            None
        };

        Ok(Self {
            thread_id,
            backtrace,
            call_info,
            dump_addresses: call_info_fetcher.fetch_address,
        })
    }

    fn dump_to_kdl_node(&self, node_id: KdlIdentifier) -> KdlNode {
        let mut node = KdlNode::new(node_id);

        if let Some(ref call_info) = self.call_info {
            node = call_info.dump_to_kdl_node(Some(node));
        } else if let Some(ref backtrace) = self.backtrace {
            node.ensure_children()
                .nodes_mut()
                .push(dump_backtrace_info_to_kdl(backtrace, self.dump_addresses));
        }

        node.entries_mut()
            .push(KdlEntry::new_prop("thread", i128::from(self.thread_id)));

        node
    }
}
