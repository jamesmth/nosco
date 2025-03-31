use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const STATE_INIT_STREAM_LABEL: &str = "state_init";
pub const STATE_UPDATE_STREAM_LABEL: &str = "state_update";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallMetadata {
    Root { backtrace: Vec<u64> },
    Sub { caller_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallData {
    ExecutedInstruction { opcodes_addr: u64, opcodes: Vec<u8> },
    CalledFunction { call_id: String },
    UpdatedState { update_id: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateInitData(pub StateChangeData);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateUpdateData {
    pub header: StateUpdateDataHeader,
    pub content: StateChangeData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateUpdateDataHeader {
    pub update_id: u64,
    pub update_origin: Option<StateUpdateOrigin>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateUpdateOrigin {
    pub call_id: String,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StateChangeData {
    LoadedBinary {
        path: PathBuf,
        load_addr: u64,
    },
    UnloadedBinary {
        unload_addr: u64,
    },
    CreatedThread {
        thread_id: u64,
        root_call_ids: Vec<String>,
    },
    ExitedThread {
        thread_id: u64,
        exit_code: i32,
    },
}
