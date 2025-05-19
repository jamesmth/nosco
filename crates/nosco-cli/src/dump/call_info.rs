use std::io::{Read, Seek};

use kdl::{KdlDocument, KdlEntry, KdlNode};
use miette::IntoDiagnostic;
use nosco_storage::content::StateChangeData;
use nosco_storage::{BacktraceElement, MlaStorageReader};

pub fn dump_to_kdl(
    mut reader: MlaStorageReader<impl Read + Seek>,
    call_info_fetcher: CallInformationFetcher,
    call_id: String,
) -> miette::Result<KdlDocument> {
    let call_info = call_info_fetcher.fetch(call_id, &mut reader)?;

    let mut kdl = KdlDocument::new();

    kdl.nodes_mut().push(call_info.dump_to_kdl_node(None));

    Ok(kdl)
}

pub(super) struct CallInformation {
    pub call_id: String,
    pub symbol: Option<String>,
    pub backtrace: Option<Vec<BacktraceElementInformation>>,
    pub thread_id: Option<u64>,
    pub address: Option<u64>,
    pub state_updates: Option<Vec<StateChangeData>>,
}

impl CallInformation {
    pub fn fetcher() -> CallInformationFetcher {
        CallInformationFetcher::default()
    }

    pub fn dump_to_kdl_node(&self, kdl_node: Option<KdlNode>) -> KdlNode {
        let symbol = self.symbol.as_deref().unwrap_or("<unknown>");

        let mut kdl_node = if let Some(mut node) = kdl_node {
            node.entries_mut().push(KdlEntry::new(symbol));
            node
        } else {
            KdlNode::new(symbol)
        };

        kdl_node
            .entries_mut()
            .push(KdlEntry::new_prop("call_id", self.call_id.as_str()));

        if let Some(addr) = self.address {
            kdl_node
                .entries_mut()
                .push(KdlEntry::new_prop("addr", format!("{addr:#x}")));
        }

        if let Some(thread_id) = self.thread_id {
            kdl_node
                .entries_mut()
                .push(KdlEntry::new_prop("thread", i128::from(thread_id)));
        }

        if let Some(backtrace) = &self.backtrace {
            let mut bt_node = KdlNode::new("backtrace");

            if backtrace.is_empty() {
                bt_node.entries_mut().push(KdlEntry::new("<none>"));
            } else {
                bt_node
                    .ensure_children()
                    .nodes_mut()
                    .extend(backtrace.iter().rev().map(|bt| bt.dump_to_kdl_node()));
            }

            kdl_node.ensure_children().nodes_mut().push(bt_node);
        }

        if let Some(state_updates) = &self.state_updates {
            if !state_updates.is_empty() {
                kdl_node
                    .ensure_children()
                    .nodes_mut()
                    .extend(state_updates.iter().map(kdl_node_from_state_change_data));
            }
        }

        kdl_node
    }
}

#[derive(Default, Clone, Copy)]
pub(super) struct CallInformationFetcher {
    pub fetch_thread_id: bool,
    pub fetch_address: bool,
    pub fetch_backtrace: bool,
    pub fetch_state_updates: bool,
}

impl CallInformationFetcher {
    pub fn with_backtrace(mut self, enable: bool) -> Self {
        self.fetch_backtrace = enable;
        self
    }

    pub fn with_thread_id(mut self, enable: bool) -> Self {
        self.fetch_thread_id = enable;
        self
    }

    pub fn with_call_address(mut self, enable: bool) -> Self {
        self.fetch_address = enable;
        self
    }

    pub fn with_state_updates(mut self, enable: bool) -> Self {
        self.fetch_state_updates = enable;
        self
    }

    pub fn fetch(
        self,
        call_id: String,
        reader: &mut MlaStorageReader<'_, impl Read + Seek>,
    ) -> miette::Result<CallInformation> {
        let (thread_id, address) = if self.fetch_thread_id || self.fetch_address {
            let (metadata, _) = reader.call_stream_reader(&call_id).into_diagnostic()?;
            (
                self.fetch_thread_id.then_some(metadata.thread_id),
                self.fetch_address.then_some(metadata.addr),
            )
        } else {
            (None, None)
        };

        let backtrace = if self.fetch_backtrace {
            let backtrace = reader
                .backtrace_reader(&call_id)
                .into_diagnostic()?
                .map(|res| res.into_diagnostic())
                .collect::<miette::Result<Vec<_>>>()?;

            backtrace
                .into_iter()
                .map(|bt| match bt {
                    BacktraceElement::CallAddr(addr) => {
                        Ok(BacktraceElementInformation::CallAddr(addr))
                    }
                    BacktraceElement::CallId(call_id) => CallInformation::fetcher()
                        .with_call_address(self.fetch_address)
                        .fetch(call_id, reader)
                        .map(BacktraceElementInformation::CallInfo),
                })
                .collect::<miette::Result<Vec<_>>>()
                .map(Some)?
        } else {
            None
        };

        let state_updates = if self.fetch_state_updates {
            reader
                .state_updates_reader()
                .into_diagnostic()?
                .map(|res| res.into_diagnostic())
                .filter_map(|res| match res {
                    Ok((origin, data)) => origin
                        .call_id
                        .and_then(|(id, _)| (id == call_id).then_some(Ok(data))),
                    Err(e) => Some(Err(e)),
                })
                .collect::<miette::Result<Vec<_>>>()
                .map(Some)?
        } else {
            None
        };

        Ok(CallInformation {
            call_id,
            symbol: None,
            backtrace,
            address,
            thread_id,
            state_updates,
        })
    }
}

pub(super) enum BacktraceElementInformation {
    CallAddr(u64),
    CallInfo(CallInformation),
}

impl BacktraceElementInformation {
    pub fn dump_to_kdl_node(&self) -> KdlNode {
        match self {
            BacktraceElementInformation::CallAddr(addr) => KdlNode::new(format!("<{addr:#x}>")),
            BacktraceElementInformation::CallInfo(call_info) => call_info.dump_to_kdl_node(None),
        }
    }
}

pub(super) fn kdl_node_from_state_change_data(state_change_data: &StateChangeData) -> KdlNode {
    match state_change_data {
        StateChangeData::CreatedThread { thread_id, .. } => {
            let mut node = KdlNode::new("create_thread");
            node.entries_mut()
                .push(KdlEntry::new(i128::from(*thread_id)));
            node
        }
        StateChangeData::ExitedThread { thread_id, .. } => {
            let mut node = KdlNode::new("exit_thread");
            node.entries_mut()
                .push(KdlEntry::new(i128::from(*thread_id)));
            node
        }
        StateChangeData::LoadedBinary { path, load_addr } => {
            let mut node = KdlNode::new("load_binary");
            node.entries_mut()
                .push(KdlEntry::new(path.display().to_string()));
            node.entries_mut()
                .push(KdlEntry::new_prop("addr", format!("{load_addr:#x}")));
            node
        }
        StateChangeData::UnloadedBinary { unload_addr } => {
            let mut node = KdlNode::new("unload_binary");
            node.entries_mut()
                .push(KdlEntry::new_prop("addr", format!("{unload_addr:#x}")));
            node
        }
    }
}
