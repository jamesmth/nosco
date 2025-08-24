use std::time::SystemTime;
use std::{ops::Range, path::PathBuf};

use serde::{Deserialize, Serialize};

pub(super) const STATE_INIT_STREAM_LABEL: &str = "state_init";
pub(super) const STATE_UPDATE_STREAM_LABEL: &str = "state_update";

/// Metadata of a function call trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallMetadata {
    /// Thread ID of the function call.
    pub thread_id: u64,

    /// Address of the function call.
    pub addr: u64,

    /// Level information of the function call.
    pub level: CallLevel,

    /// Time at which this metadata was written.
    pub timestamp: SystemTime,
}

/// Level information of a function call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallLevel {
    /// Metadata related to a root function call.
    Root {
        /// Backtrace of this call, containing the addresses of all parent
        /// function calls.
        backtrace: Vec<u64>,
    },

    /// Metadata related to a nested function call.
    Sub {
        /// Call ID of the parent function call.
        caller_id: String,

        /// Address of the call instruction in the parent.
        caller_addr: u64,
    },
}

/// Event data of a function call trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallData {
    /// Data related to an executed instruction
    ExecutedInstruction {
        /// Address of the executed instruction.
        opcodes_addr: u64,

        /// Opcodes of the executed instruction.
        opcodes: Vec<u8>,
    },

    /// Data related to a called function.
    CalledFunction {
        /// Call ID of the called function.
        call_id: String,
    },

    /// Data related to an update of the tracee's state (e.g., loaded binary, created thread).
    UpdatedState {
        /// Internal ID of the update.
        update_id: u64,
    },
}

/// Data related to an initial tracee's state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateInitData(pub StateChangeData);

/// Data related to an update of the tracee's state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateUpdateData {
    /// Header of the update data.
    pub header: StateUpdateDataHeader,

    /// Body of the update data.
    pub content: StateChangeData,
}

/// Header of an update of the tracee's state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateUpdateDataHeader {
    /// Internal ID of the update.
    pub update_id: u64,

    /// Origin of the update.
    pub update_origin: StateUpdateOrigin,
}

/// Origin of an update of the tracee's state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateUpdateOrigin {
    /// ID of the thread responsible for the update.
    pub thread_id: u64,

    /// Time at which this update was written.
    pub timestamp: SystemTime,

    /// ID (and instruction address) of the call responsible for the update.
    pub call_id: Option<(String, u64)>,
}

/// Data related to a change occurring on the tracee's state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StateChangeData {
    /// Data related to a loaded binary.
    LoadedBinary {
        /// Absolute path of the binary.
        path: PathBuf,

        /// Address range of the loaded binary.
        addr_range: Range<u64>,
    },

    /// Data related to an unloaded binary.
    UnloadedBinary {
        /// Address of the unloaded binary.
        unload_addr: u64,
    },

    /// Data related to a created thread.
    CreatedThread {
        /// ID of the created thread.
        thread_id: u64,

        /// IDs of the traced calls of this thread.
        root_call_ids: Vec<String>,
    },

    /// Data related to an exited thread.
    ExitedThread {
        /// ID of the exited thread.
        thread_id: u64,

        /// Exit code of the thread.
        exit_code: i32,
    },
}
