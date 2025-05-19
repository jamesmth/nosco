use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use mla::config::ArchiveWriterConfig;
use mla::{ArchiveWriter, Layers};
use serde::Serialize;

use super::content::{CallData, CallLevel, CallMetadata, StateChangeData, StateInitData};
use super::content::{STATE_INIT_STREAM_LABEL, STATE_UPDATE_STREAM_LABEL};
use super::content::{StateUpdateData, StateUpdateDataHeader, StateUpdateOrigin};
use crate::TraceSessionStorageWriter;

/// Storage writer for the MLA backend.
pub struct MlaStorageWriter<W> {
    tx: mpsc::Sender<StorageAction>,
    core_task: CoreTaskState<W>,
}

enum CoreTaskState<W> {
    Running(tokio::task::JoinHandle<crate::Result<W>>),
    Finalized(W),
    Failed,
}

impl<W: Write + Send + 'static> MlaStorageWriter<W> {
    /// Initializes a new MLA storage writer from an inner writer.
    ///
    /// # Warning
    ///
    /// This function is currently limited to be called within the Tokio
    /// runtime, because a background blocking task is spawned under the hood.
    /// This limitation may be lifted in the future.
    pub fn from_writer(writer: W) -> crate::Result<Self> {
        let (tx, rx) = mpsc::channel();

        let core_task = MlaStorageWriterCore::from_writer(writer, rx)
            .map(|core| tokio::task::spawn_blocking(move || core.run()))
            .map(CoreTaskState::Running)?;

        Ok(Self { tx, core_task })
    }
}

impl<W> MlaStorageWriter<W> {
    /// Finalizes the writing operation and returns the inner writer.
    pub async fn finalize_and_unwrap(mut self) -> crate::Result<W> {
        self.finalize().await?;

        match self.core_task {
            CoreTaskState::Running(task) => task.await?,
            CoreTaskState::Finalized(w) => Ok(w),
            CoreTaskState::Failed => Err(crate::Error::WriterPreviouslyFailed),
        }
    }

    async fn send_storage_action(&mut self, action: StorageAction) -> crate::Result<()> {
        if self.tx.send(action).is_ok() {
            return Ok(());
        }

        match mem::replace(&mut self.core_task, CoreTaskState::Failed) {
            CoreTaskState::Running(task) => match task.await {
                Ok(_) => unreachable!(),
                Err(e) => Err(e.into()),
            },
            CoreTaskState::Finalized(_) => Err(crate::Error::WriterFinalized),
            CoreTaskState::Failed => Err(crate::Error::WriterPreviouslyFailed),
        }
    }
}

impl<W> TraceSessionStorageWriter for MlaStorageWriter<W> {
    type Error = crate::Error;

    async fn write_call_start(
        &mut self,
        thread_id: u64,
        call_addr: u64,
        backtrace: Option<Vec<u64>>,
    ) -> Result<(), Self::Error> {
        self.send_storage_action(StorageAction::WriteCallStart {
            thread_id,
            call_addr,
            backtrace,
        })
        .await
    }

    async fn write_call_end(&mut self, thread_id: u64) -> Result<(), Self::Error> {
        self.send_storage_action(StorageAction::WriteCallEnd { thread_id })
            .await
    }

    async fn write_executed_instruction(
        &mut self,
        thread_id: u64,
        opcodes_addr: u64,
        opcodes: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.send_storage_action(StorageAction::WriteExecutedInstruction {
            thread_id,
            opcodes_addr,
            opcodes,
        })
        .await
    }

    async fn write_loaded_binary(
        &mut self,
        thread_id: Option<u64>,
        binary_path: &Path,
        load_addr: u64,
    ) -> Result<(), Self::Error> {
        self.send_storage_action(StorageAction::WriteLoadedBinary {
            thread_id,
            path: binary_path.to_path_buf(),
            load_addr,
        })
        .await
    }

    async fn write_unloaded_binary(
        &mut self,
        thread_id: u64,
        unload_addr: u64,
    ) -> Result<(), Self::Error> {
        self.send_storage_action(StorageAction::WriteUnloadedBinary {
            thread_id,
            unload_addr,
        })
        .await
    }

    async fn write_created_thread(
        &mut self,
        parent_thread_id: Option<u64>,
        new_thread_id: u64,
    ) -> Result<(), Self::Error> {
        self.send_storage_action(StorageAction::WriteCreatedThread {
            thread_id: parent_thread_id,
            new_thread_id,
        })
        .await
    }

    async fn write_exited_thread(
        &mut self,
        thread_id: u64,
        exit_code: i32,
    ) -> Result<(), Self::Error> {
        self.send_storage_action(StorageAction::WriteExitedThread {
            thread_id,
            exit_code,
        })
        .await
    }

    async fn finalize(&mut self) -> Result<(), Self::Error> {
        let _ = self.tx.send(StorageAction::Finalize);

        match mem::replace(&mut self.core_task, CoreTaskState::Failed) {
            CoreTaskState::Running(task) => {
                self.core_task = task.await?.map(CoreTaskState::Finalized)?;
                Ok(())
            }
            CoreTaskState::Finalized(_) => Err(crate::Error::WriterFinalized),
            CoreTaskState::Failed => Err(crate::Error::WriterPreviouslyFailed),
        }
    }
}

struct MlaStorageWriterCore<'a, W: Write + Send> {
    mla: ArchiveWriter<'a, W>,
    rx: mpsc::Receiver<StorageAction>,

    state_init_stream_id: Option<u64>,
    state_update_stream_id: Option<u64>,

    call_streams: HashMap<u64, Vec<CallStream>>,
    created_threads: HashMap<u64, CreatedThread>,

    update_id_generator: IdSequence,
    call_id_generator: IdSequence,
}

impl<W: Write + Send> MlaStorageWriterCore<'_, W> {
    fn from_writer(writer: W, rx: mpsc::Receiver<StorageAction>) -> crate::Result<Self> {
        let mut config = ArchiveWriterConfig::default();
        config.enable_layer(Layers::COMPRESS);
        config.disable_layer(Layers::ENCRYPT);

        let mla = ArchiveWriter::from_config(writer, config)?;

        Ok(Self {
            mla,
            rx,
            state_init_stream_id: None,
            state_update_stream_id: None,
            call_streams: HashMap::new(),
            created_threads: HashMap::new(),
            update_id_generator: IdSequence::new(),
            call_id_generator: IdSequence::new(),
        })
    }

    fn run(mut self) -> crate::Result<W> {
        loop {
            let action = self.rx.recv()?;

            match action {
                StorageAction::WriteCallStart {
                    thread_id,
                    call_addr,
                    backtrace,
                } => {
                    self.write_call_start(thread_id, call_addr, backtrace)?;
                }
                StorageAction::WriteCallEnd { thread_id } => {
                    self.write_call_end(thread_id)?;
                }
                StorageAction::WriteExecutedInstruction {
                    thread_id,
                    opcodes_addr,
                    opcodes,
                } => {
                    self.write_executed_instruction(thread_id, opcodes_addr, opcodes)?;
                }
                StorageAction::WriteLoadedBinary {
                    thread_id,
                    path,
                    load_addr,
                } => {
                    self.write_loaded_binary(thread_id, path, load_addr)?;
                }
                StorageAction::WriteUnloadedBinary {
                    thread_id,
                    unload_addr,
                } => {
                    self.write_unloaded_binary(thread_id, unload_addr)?;
                }
                StorageAction::WriteCreatedThread {
                    thread_id,
                    new_thread_id,
                } => {
                    self.write_created_thread(thread_id, new_thread_id)?;
                }
                StorageAction::WriteExitedThread {
                    thread_id,
                    exit_code,
                } => {
                    self.write_exited_thread(thread_id, exit_code)?;
                }
                StorageAction::Finalize => break self.finalize(),
            }
        }
    }

    fn finalize(mut self) -> crate::Result<W> {
        for (_, created_thread) in self.created_threads.drain().collect::<Vec<_>>() {
            self.finalize_write_created_thread(created_thread)?;
        }

        if let Some(stream_id) = self.state_init_stream_id {
            self.mla.end_file(stream_id)?;
        }

        if let Some(stream_id) = self.state_update_stream_id {
            self.mla.end_file(stream_id)?;
        }

        for CallStream { id, .. } in self.call_streams.into_values().flatten() {
            self.mla.end_file(id)?;
        }

        self.mla.finalize()?;

        Ok(self.mla.into_raw())
    }

    fn write_call_start(
        &mut self,
        thread_id: u64,
        call_addr: u64,
        backtrace: Option<Vec<u64>>,
    ) -> crate::Result<()> {
        let (new_stream_id, new_stream_label) = self.create_call_stream()?;

        let call_streams = self
            .call_streams
            .get_mut(&thread_id)
            .ok_or(crate::Error::UnexpectedThreadId(thread_id))?;

        let level = if let Some(CallStream { id, label, .. }) = call_streams.last() {
            // this is a nested call

            let stream_id = *id;
            let stream_label = label.clone();

            call_streams.push(CallStream {
                id: new_stream_id,
                label: new_stream_label.clone(),
                latest_addr: call_addr,
            });

            self.write_to_stream(
                stream_id,
                CallData::CalledFunction {
                    call_id: new_stream_label,
                },
            )?;

            CallLevel::Sub {
                caller_id: stream_label,
            }
        } else {
            // this is a root call

            let created_thread = self
                .created_threads
                .get_mut(&thread_id)
                .ok_or(crate::Error::UnexpectedThreadId(thread_id))?;

            created_thread.root_call_ids.push(new_stream_label.clone());

            call_streams.push(CallStream {
                id: new_stream_id,
                label: new_stream_label,
                latest_addr: call_addr,
            });

            CallLevel::Root {
                backtrace: backtrace.unwrap_or_default(),
            }
        };

        self.write_to_stream(
            new_stream_id,
            CallMetadata {
                thread_id,
                addr: call_addr,
                level,
            },
        )?;

        Ok(())
    }

    fn write_call_end(&mut self, thread_id: u64) -> crate::Result<()> {
        let CallStream { id, .. } = self
            .call_streams
            .get_mut(&thread_id)
            .ok_or(crate::Error::UnexpectedThreadId(thread_id))?
            .pop()
            .ok_or(crate::Error::MissingCallStream)?;

        self.mla.end_file(id)?;

        Ok(())
    }

    fn write_executed_instruction(
        &mut self,
        thread_id: u64,
        opcodes_addr: u64,
        opcodes: Vec<u8>,
    ) -> crate::Result<()> {
        let call_stream = match self
            .call_streams
            .get_mut(&thread_id)
            .and_then(|call_streams| call_streams.last_mut())
        {
            Some(call_stream) => call_stream,
            None => {
                self.write_call_start(thread_id, opcodes_addr, None)?;

                self.call_streams
                    .get_mut(&thread_id)
                    .ok_or(crate::Error::UnexpectedThreadId(thread_id))?
                    .last_mut()
                    .ok_or(crate::Error::MissingCallStream)?
            }
        };

        call_stream.latest_addr = opcodes_addr;

        let stream_id = call_stream.id;

        self.write_to_stream(
            stream_id,
            CallData::ExecutedInstruction {
                opcodes_addr,
                opcodes,
            },
        )?;

        Ok(())
    }

    fn write_loaded_binary(
        &mut self,
        thread_id: Option<u64>,
        path: PathBuf,
        load_addr: u64,
    ) -> crate::Result<()> {
        let state_change = StateChangeData::LoadedBinary { path, load_addr };

        if let Some(thread_id) = thread_id {
            self.write_state_update(thread_id, state_change)?;
        } else {
            self.write_state_init(state_change)?;
        }

        Ok(())
    }

    fn write_created_thread(
        &mut self,
        thread_id: Option<u64>,
        new_thread_id: u64,
    ) -> crate::Result<()> {
        let state_update_header = if let Some(thread_id) = thread_id {
            Some(self.write_state_update_origin(thread_id)?)
        } else {
            None
        };

        let created_thread = CreatedThread {
            state_update_header,
            id: new_thread_id,
            root_call_ids: Vec::new(),
        };

        if self
            .call_streams
            .insert(new_thread_id, Vec::new())
            .is_some()
        {
            return Err(crate::Error::UnexpectedThreadId(new_thread_id));
        }

        if self
            .created_threads
            .insert(new_thread_id, created_thread)
            .is_some()
        {
            return Err(crate::Error::UnexpectedThreadId(new_thread_id));
        }

        Ok(())
    }

    fn finalize_write_created_thread(&mut self, thread: CreatedThread) -> crate::Result<()> {
        let state_change = StateChangeData::CreatedThread {
            thread_id: thread.id,
            root_call_ids: thread.root_call_ids,
        };

        if let Some(update_header) = thread.state_update_header {
            let state_update_stream_id = self.get_or_create_state_update_stream()?;

            self.write_to_stream(
                state_update_stream_id,
                StateUpdateData {
                    header: update_header,
                    content: state_change,
                },
            )?;
        } else {
            self.write_state_init(state_change)?;
        };

        Ok(())
    }

    fn write_unloaded_binary(&mut self, thread_id: u64, unload_addr: u64) -> crate::Result<()> {
        self.write_state_update(thread_id, StateChangeData::UnloadedBinary { unload_addr })?;

        Ok(())
    }

    fn write_exited_thread(&mut self, thread_id: u64, exit_code: i32) -> crate::Result<()> {
        let Some(thread) = self.created_threads.remove(&thread_id) else {
            return Err(crate::Error::UnexpectedThreadId(thread_id));
        };

        self.finalize_write_created_thread(thread)?;

        self.write_state_update(
            thread_id,
            StateChangeData::ExitedThread {
                thread_id,
                exit_code,
            },
        )?;

        Ok(())
    }

    fn create_call_stream(&mut self) -> crate::Result<(u64, String)> {
        let stream_label = format!("{}", self.call_id_generator.next_id());

        let stream_id = self.mla.start_file(&stream_label)?;

        Ok((stream_id, stream_label))
    }

    fn write_to_stream(&mut self, stream_id: u64, data: impl Serialize) -> crate::Result<()> {
        let data = bincode::serialize(&data).map(Cursor::new)?;

        self.mla
            .append_file_content(stream_id, data.get_ref().len() as u64, data)?;

        Ok(())
    }

    fn get_or_create_state_init_stream(&mut self) -> crate::Result<u64> {
        if let Some(stream_id) = self.state_init_stream_id {
            Ok(stream_id)
        } else {
            let stream_id = self.mla.start_file(STATE_INIT_STREAM_LABEL)?;
            self.state_init_stream_id = Some(stream_id);
            Ok(stream_id)
        }
    }

    fn get_or_create_state_update_stream(&mut self) -> crate::Result<u64> {
        if let Some(stream_id) = self.state_update_stream_id {
            Ok(stream_id)
        } else {
            let stream_id = self.mla.start_file(STATE_UPDATE_STREAM_LABEL)?;
            self.state_update_stream_id = Some(stream_id);
            Ok(stream_id)
        }
    }

    fn write_state_update_origin(
        &mut self,
        thread_id: u64,
    ) -> crate::Result<StateUpdateDataHeader> {
        let update_id = self.update_id_generator.next_id();

        let call_id = if let Some(call_stream) = self
            .call_streams
            .get(&thread_id)
            .ok_or(crate::Error::UnexpectedThreadId(thread_id))?
            .last()
        {
            let stream_id = call_stream.id;
            let stream_label = call_stream.label.clone();
            let stream_latest_addr = call_stream.latest_addr;

            self.write_to_stream(stream_id, CallData::UpdatedState { update_id })?;

            Some((stream_label, stream_latest_addr))
        } else {
            None
        };

        Ok(StateUpdateDataHeader {
            update_id,
            update_origin: StateUpdateOrigin { thread_id, call_id },
        })
    }

    fn write_state_update(&mut self, thread_id: u64, change: StateChangeData) -> crate::Result<()> {
        let update_header = self.write_state_update_origin(thread_id)?;

        let state_update_stream_id = self.get_or_create_state_update_stream()?;

        self.write_to_stream(
            state_update_stream_id,
            StateUpdateData {
                header: update_header,
                content: change,
            },
        )?;

        Ok(())
    }

    fn write_state_init(&mut self, change: StateChangeData) -> crate::Result<()> {
        let state_init_stream_id = self.get_or_create_state_init_stream()?;

        self.write_to_stream(state_init_stream_id, StateInitData(change))?;

        Ok(())
    }
}

enum StorageAction {
    WriteCallStart {
        thread_id: u64,
        call_addr: u64,
        backtrace: Option<Vec<u64>>,
    },

    WriteCallEnd {
        thread_id: u64,
    },

    WriteExecutedInstruction {
        thread_id: u64,
        opcodes_addr: u64,
        opcodes: Vec<u8>,
    },

    WriteLoadedBinary {
        thread_id: Option<u64>,
        path: PathBuf,
        load_addr: u64,
    },

    WriteUnloadedBinary {
        thread_id: u64,
        unload_addr: u64,
    },

    WriteCreatedThread {
        thread_id: Option<u64>,
        new_thread_id: u64,
    },

    WriteExitedThread {
        thread_id: u64,
        exit_code: i32,
    },

    Finalize,
}

struct CallStream {
    id: u64,
    label: String,
    latest_addr: u64,
}

struct CreatedThread {
    state_update_header: Option<StateUpdateDataHeader>,
    id: u64,
    root_call_ids: Vec<String>,
}

struct IdSequence {
    next_id: u64,
}

impl IdSequence {
    const fn new() -> Self {
        Self { next_id: 0 }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }
}
