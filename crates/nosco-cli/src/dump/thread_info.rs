use std::io::{Read, Seek};

use kdl::{KdlDocument, KdlEntry, KdlNode};
use miette::IntoDiagnostic;
use nosco_storage::content::{StateChangeData, StateUpdateOrigin};
use nosco_storage::{BacktraceElement, MlaStorageReader};

use super::SymbolResolver;
use super::call_info::{BacktraceElementInformation, CallInformation, CallInformationFetcher};
use super::call_info::{dump_backtrace_info_to_kdl, fetch_backtrace_info};

pub fn dump_to_kdl(
    mut reader: MlaStorageReader<impl Read + Seek>,
    call_info_fetcher: CallInformationFetcher,
    mut resolver: Option<&mut SymbolResolver>,
    single_thread: Option<u64>,
) -> miette::Result<KdlDocument> {
    let threads_info = fetch_partial_threads_info(&mut reader, single_thread)?
        .into_iter()
        .map(|info| info.fetch_calls_info(&mut reader, call_info_fetcher, resolver.as_deref_mut()))
        .collect::<miette::Result<Vec<_>>>()?;

    let mut kdl = KdlDocument::new();

    for thread_info in threads_info {
        kdl.nodes_mut().push({
            let mut node = KdlNode::new("thread");
            thread_info.dump_to_kdl_node(&mut node);
            node
        });
    }

    Ok(kdl)
}

fn fetch_partial_threads_info(
    reader: &mut MlaStorageReader<impl Read + Seek>,
    single_thread: Option<u64>,
) -> miette::Result<Vec<PartialThreadInformation>> {
    // fetch threads information from initial state
    let mut threads_info = reader
        .state_init_reader()
        .into_diagnostic()?
        .filter_map(|res| match res {
            Ok(StateChangeData::CreatedThread {
                thread_id,
                root_call_ids,
            }) if single_thread.is_none_or(|tid| tid == thread_id) => {
                Some(Ok(PartialThreadInformation {
                    thread_id,
                    root_call_ids,
                    origin: None,
                    exit: None,
                }))
            }
            Err(e) => Some(Err(e).into_diagnostic()),
            _ => None,
        })
        .collect::<miette::Result<Vec<_>>>()?;

    let mut exited_threads = Vec::new();

    // fetch threads information from state updates
    threads_info.extend(
        reader
            .state_updates_reader()
            .into_diagnostic()?
            .filter_map(|res| match res {
                Ok((
                    update_origin,
                    StateChangeData::CreatedThread {
                        thread_id,
                        root_call_ids,
                    },
                )) if single_thread.is_none_or(|tid| tid == thread_id) => {
                    Some(Ok(PartialThreadInformation {
                        thread_id,
                        root_call_ids,
                        origin: Some(update_origin),
                        exit: None,
                    }))
                }
                Ok((
                    update_origin,
                    StateChangeData::ExitedThread {
                        thread_id,
                        exit_code,
                    },
                )) => {
                    exited_threads.push((update_origin, thread_id, exit_code));
                    None
                }
                Err(e) => Some(Err(e).into_diagnostic()),
                _ => None,
            })
            .collect::<miette::Result<Vec<_>>>()?,
    );

    if let Some(thread_id) = single_thread {
        miette::ensure!(!threads_info.is_empty(), "Thread {thread_id} not found");
    }

    for (update_origin, thread_id, exit_code) in exited_threads {
        let Some(thread_info) = threads_info
            .iter_mut()
            .find(|info| info.thread_id == thread_id)
        else {
            continue;
        };

        thread_info.exit = Some((update_origin, exit_code));
    }

    Ok(threads_info)
}

struct PartialThreadInformation {
    thread_id: u64,
    origin: Option<StateUpdateOrigin>,
    exit: Option<(StateUpdateOrigin, i32)>,
    root_call_ids: Vec<String>,
}

impl PartialThreadInformation {
    fn fetch_calls_info(
        self,
        reader: &mut MlaStorageReader<'_, impl Read + Seek>,
        call_info_fetcher: CallInformationFetcher,
        mut resolver: Option<&mut SymbolResolver>,
    ) -> miette::Result<ThreadInformation> {
        let origin = self
            .origin
            .map(|origin| {
                ThreadOriginInfo::fetch_origin_info(
                    origin,
                    reader,
                    call_info_fetcher,
                    resolver.as_deref_mut(),
                )
            })
            .transpose()?;

        let exit = self
            .exit
            .map(|(origin, exit_code)| {
                ThreadExitInfo::fetch_exit_info(
                    origin,
                    exit_code,
                    reader,
                    call_info_fetcher,
                    resolver.as_deref_mut(),
                )
            })
            .transpose()?;

        let root_calls_info = self
            .root_call_ids
            .into_iter()
            .map(|call_id| call_info_fetcher.fetch(call_id, reader, resolver.as_deref_mut()))
            .collect::<miette::Result<_>>()?;

        Ok(ThreadInformation {
            thread_id: self.thread_id,
            origin,
            exit,
            root_calls_info,
        })
    }
}

struct ThreadInformation {
    thread_id: u64,
    origin: Option<ThreadOriginInfo>,
    exit: Option<ThreadExitInfo>,
    root_calls_info: Vec<CallInformation>,
}

impl ThreadInformation {
    pub fn dump_to_kdl_node(&self, kdl_node: &mut KdlNode) {
        kdl_node
            .entries_mut()
            .push(i128::from(self.thread_id).into());

        if let Some(ref origin) = self.origin {
            kdl_node
                .ensure_children()
                .nodes_mut()
                .push(origin.dump_to_kdl_node());
        }

        for call_info in self.root_calls_info.iter() {
            kdl_node
                .ensure_children()
                .nodes_mut()
                .push(call_info.dump_to_kdl_node(Some(KdlNode::new("traced"))));
        }

        if let Some(ref exit) = self.exit {
            kdl_node
                .ensure_children()
                .nodes_mut()
                .push(exit.dump_to_kdl_node());
        }
    }
}

struct ThreadOriginInfo {
    thread_id: u64,
    backtrace: Option<Vec<BacktraceElementInformation>>,
    call_info: Option<CallInformation>,
    dump_addresses: bool,
}

impl ThreadOriginInfo {
    fn fetch_origin_info(
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

    fn dump_to_kdl_node(&self) -> KdlNode {
        let mut node = KdlNode::new("created");

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

struct ThreadExitInfo {
    backtrace: Option<Vec<BacktraceElementInformation>>,
    call_info: Option<CallInformation>,
    exit_code: i32,
    dump_addresses: bool,
}

impl ThreadExitInfo {
    fn fetch_exit_info(
        update_origin: StateUpdateOrigin,
        exit_code: i32,
        reader: &mut MlaStorageReader<'_, impl Read + Seek>,
        call_info_fetcher: CallInformationFetcher,
        mut resolver: Option<&mut SymbolResolver>,
    ) -> miette::Result<Self> {
        let StateUpdateOrigin {
            thread_id: _,
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
            backtrace,
            call_info,
            exit_code,
            dump_addresses: call_info_fetcher.fetch_address,
        })
    }

    fn dump_to_kdl_node(&self) -> KdlNode {
        let mut node = KdlNode::new("exited");

        node.entries_mut()
            .push(KdlEntry::new_prop("code", i128::from(self.exit_code)));

        if let Some(ref call_info) = self.call_info {
            node = call_info.dump_to_kdl_node(Some(node));
        } else if let Some(ref backtrace) = self.backtrace {
            node.ensure_children()
                .nodes_mut()
                .push(dump_backtrace_info_to_kdl(backtrace, self.dump_addresses));
        }

        node
    }
}
