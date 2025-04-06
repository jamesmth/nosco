/// Module exposing the data structures used within the storage.
pub mod content;

mod reader;
mod writer;

pub use self::reader::{BacktraceElement, MlaStorageReader};
pub use self::writer::MlaStorageWriter;

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::Path;

    use super::content::{StateChangeData, StateUpdateOrigin};
    use super::{MlaStorageReader, MlaStorageWriter};
    use crate::TraceSessionStorageWriter;
    use crate::mla::content::CallData;
    use crate::mla::reader::BacktraceElement;

    #[test]
    fn writer_task_reports_error() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                // provoke an error
                writer
                    .write_executed_instruction(1, 0x0, vec![])
                    .await
                    .unwrap();

                let err = writer.finalize().await.unwrap_err();

                assert!(matches!(err, crate::Error::UnexpectedThreadId(1)));
            });
    }

    #[test]
    fn writer_task_reports_finalized() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.finalize().await.unwrap();

                let err = writer.finalize().await.unwrap_err();

                assert!(matches!(err, crate::Error::WriterFinalized));
            });
    }

    #[test]
    fn write_instr_without_thread_fail() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer
                    .write_executed_instruction(1, 0x0, vec![])
                    .await
                    .unwrap();

                let err = writer.finalize().await.unwrap_err();

                assert!(matches!(err, crate::Error::UnexpectedThreadId(1)));
            });
    }

    #[test]
    fn write_created_thread_same_id_fail() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.write_created_thread(None, 1).await.unwrap();
                writer.write_created_thread(None, 1).await.unwrap();

                let err = writer.finalize().await.unwrap_err();

                assert!(matches!(err, crate::Error::UnexpectedThreadId(1)));
            });
    }

    #[test]
    fn write_exited_thread_bad_id_fail() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.write_exited_thread(1, 0).await.unwrap();

                let err = writer.finalize().await.unwrap_err();

                assert!(matches!(err, crate::Error::UnexpectedThreadId(1)));
            });
    }

    #[test]
    fn write_call_end_without_thread_fail() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.write_call_end(1).await.unwrap();

                let err = writer.finalize().await.unwrap_err();

                assert!(matches!(err, crate::Error::UnexpectedThreadId(1)));
            });
    }

    #[test]
    fn write_call_end_without_start_fail() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.write_created_thread(None, 1).await.unwrap();
                writer.write_call_end(1).await.unwrap();

                let err = writer.finalize().await.unwrap_err();

                assert!(matches!(err, crate::Error::MissingCallStream));
            });
    }

    #[test]
    fn write_loaded_binaries() {
        let storage = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer
                    .write_loaded_binary(None, Path::new("bin1"), 0x0)
                    .await
                    .unwrap();
                writer
                    .write_loaded_binary(None, Path::new("bin2"), 0x1)
                    .await
                    .unwrap();

                writer.finalize_and_unwrap().await.unwrap()
            });

        let mut reader = MlaStorageReader::from_reader(Cursor::new(storage)).unwrap();

        let binaries_init = reader
            .state_init_reader()
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(binaries_init.len(), 2);

        assert_eq!(
            binaries_init[0],
            StateChangeData::LoadedBinary {
                path: "bin1".into(),
                load_addr: 0x0,
            }
        );

        assert_eq!(
            binaries_init[1],
            StateChangeData::LoadedBinary {
                path: "bin2".into(),
                load_addr: 0x1,
            }
        );
    }

    #[test]
    fn write_unloaded_binaries() {
        let storage = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer
                    .write_loaded_binary(None, Path::new("bin1"), 0x0)
                    .await
                    .unwrap();
                writer
                    .write_loaded_binary(None, Path::new("bin2"), 0x1)
                    .await
                    .unwrap();

                writer.write_created_thread(None, 1).await.unwrap();

                writer.write_unloaded_binary(1, 0x0).await.unwrap();
                writer.write_unloaded_binary(1, 0x1).await.unwrap();

                writer.finalize_and_unwrap().await.unwrap()
            });

        let mut reader = MlaStorageReader::from_reader(Cursor::new(storage)).unwrap();

        let binary_updates = reader
            .state_updates_reader()
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(binary_updates.len(), 2);

        assert_eq!(
            binary_updates[0],
            (
                StateUpdateOrigin {
                    thread_id: 1,
                    call_id: None
                },
                StateChangeData::UnloadedBinary { unload_addr: 0x0 }
            )
        );

        assert_eq!(
            binary_updates[1],
            (
                StateUpdateOrigin {
                    thread_id: 1,
                    call_id: None
                },
                StateChangeData::UnloadedBinary { unload_addr: 0x1 }
            )
        );
    }

    #[test]
    fn write_created_threads() {
        let storage = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.write_created_thread(None, 1).await.unwrap();
                writer.write_created_thread(Some(1), 2).await.unwrap();

                writer.finalize_and_unwrap().await.unwrap()
            });

        let mut reader = MlaStorageReader::from_reader(Cursor::new(storage)).unwrap();

        let threads_init = reader
            .state_init_reader()
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(threads_init.len(), 1);

        assert_eq!(
            threads_init[0],
            StateChangeData::CreatedThread {
                thread_id: 1,
                root_call_ids: vec![],
            }
        );

        let threads_updates = reader
            .state_updates_reader()
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(threads_updates.len(), 1);

        assert_eq!(
            threads_updates[0],
            (
                StateUpdateOrigin {
                    thread_id: 1,
                    call_id: None
                },
                StateChangeData::CreatedThread {
                    thread_id: 2,
                    root_call_ids: vec![],
                }
            )
        );
    }

    #[test]
    fn write_exited_threads() {
        let storage = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.write_created_thread(None, 1).await.unwrap();
                writer.write_created_thread(Some(1), 2).await.unwrap();

                writer.write_exited_thread(2, 0).await.unwrap();
                writer.write_exited_thread(1, 0).await.unwrap();

                writer.finalize_and_unwrap().await.unwrap()
            });

        let mut reader = MlaStorageReader::from_reader(Cursor::new(storage)).unwrap();

        let thread_updates = reader
            .state_updates_reader()
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(thread_updates.len(), 3);

        assert_eq!(
            thread_updates[1],
            (
                StateUpdateOrigin {
                    thread_id: 2,
                    call_id: None
                },
                StateChangeData::ExitedThread {
                    thread_id: 2,
                    exit_code: 0
                }
            )
        );

        assert_eq!(
            thread_updates[2],
            (
                StateUpdateOrigin {
                    thread_id: 1,
                    call_id: None
                },
                StateChangeData::ExitedThread {
                    thread_id: 1,
                    exit_code: 0
                }
            )
        );
    }

    #[test]
    fn write_instr_without_call_start() {
        let storage = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.write_created_thread(None, 1).await.unwrap();
                writer
                    .write_executed_instruction(1, 0x0, vec![1, 2, 3])
                    .await
                    .unwrap();

                writer.finalize_and_unwrap().await.unwrap()
            });

        let mut reader = MlaStorageReader::from_reader(Cursor::new(storage)).unwrap();

        let StateChangeData::CreatedThread { root_call_ids, .. } =
            reader.state_init_reader().unwrap().next().unwrap().unwrap()
        else {
            panic!();
        };

        let call_data = reader
            .call_stream_reader(&root_call_ids[0])
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(call_data.len(), 1);

        assert_eq!(
            call_data[0],
            CallData::ExecutedInstruction {
                opcodes_addr: 0x0,
                opcodes: vec![1, 2, 3],
            }
        );
    }

    #[test]
    fn write_simple_call() {
        let storage = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.write_created_thread(None, 1).await.unwrap();

                writer
                    .write_call_start(1, 0x0, Some(vec![0x1, 0x2]))
                    .await
                    .unwrap();
                writer
                    .write_executed_instruction(1, 0x0, vec![1])
                    .await
                    .unwrap();
                writer.write_call_end(1).await.unwrap();

                writer.finalize_and_unwrap().await.unwrap()
            });

        let mut reader = MlaStorageReader::from_reader(Cursor::new(storage)).unwrap();

        let StateChangeData::CreatedThread { root_call_ids, .. } =
            reader.state_init_reader().unwrap().next().unwrap().unwrap()
        else {
            panic!();
        };

        assert_eq!(root_call_ids.len(), 1);

        let backtrace = reader
            .backtrace_reader(&root_call_ids[0])
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(
            backtrace,
            vec![
                BacktraceElement::CallAddr(0x1),
                BacktraceElement::CallAddr(0x2),
            ]
        );

        let call_data = reader
            .call_stream_reader(&root_call_ids[0])
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(call_data.len(), 1);

        assert_eq!(
            call_data[0],
            CallData::ExecutedInstruction {
                opcodes_addr: 0x0,
                opcodes: vec![1],
            }
        );
    }

    #[test]
    fn write_double_call() {
        let storage = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.write_created_thread(None, 1).await.unwrap();

                writer.write_call_start(1, 0x0, None).await.unwrap();
                writer.write_call_end(1).await.unwrap();

                writer.write_call_start(1, 0x1, None).await.unwrap();
                writer.write_call_end(1).await.unwrap();

                writer.finalize_and_unwrap().await.unwrap()
            });

        let mut reader = MlaStorageReader::from_reader(Cursor::new(storage)).unwrap();

        let StateChangeData::CreatedThread { root_call_ids, .. } =
            reader.state_init_reader().unwrap().next().unwrap().unwrap()
        else {
            panic!();
        };

        assert_eq!(root_call_ids.len(), 2);

        let backtrace = reader
            .backtrace_reader(&root_call_ids[0])
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert!(backtrace.is_empty());

        let call_data = reader
            .call_stream_reader(&root_call_ids[0])
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert!(call_data.is_empty());

        let backtrace = reader
            .backtrace_reader(&root_call_ids[1])
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert!(backtrace.is_empty());

        let call_data = reader
            .call_stream_reader(&root_call_ids[1])
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert!(call_data.is_empty());
    }

    #[test]
    fn write_recursive_call() {
        let storage = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async move {
                let mut writer = MlaStorageWriter::from_writer(vec![]).unwrap();

                writer.write_created_thread(None, 1).await.unwrap();

                writer
                    .write_call_start(1, 0x0, Some(vec![0xa]))
                    .await
                    .unwrap();
                writer.write_call_start(1, 0x1, None).await.unwrap();
                writer.write_call_start(1, 0x2, None).await.unwrap();

                writer.write_call_end(1).await.unwrap();
                writer.write_call_end(1).await.unwrap();
                writer.write_call_end(1).await.unwrap();

                writer.finalize_and_unwrap().await.unwrap()
            });

        let mut reader = MlaStorageReader::from_reader(Cursor::new(storage)).unwrap();

        let StateChangeData::CreatedThread { root_call_ids, .. } =
            reader.state_init_reader().unwrap().next().unwrap().unwrap()
        else {
            panic!();
        };

        assert_eq!(root_call_ids.len(), 1);

        let backtrace = reader
            .backtrace_reader(&root_call_ids[0])
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(backtrace, vec![BacktraceElement::CallAddr(0xa)]);

        let child_call_id_1 = reader
            .call_stream_reader(&root_call_ids[0])
            .unwrap()
            .find_map(|call_data| match call_data {
                Ok(CallData::CalledFunction { call_id }) => Some(call_id),
                _ => None,
            })
            .unwrap();

        let backtrace = reader
            .backtrace_reader(&child_call_id_1)
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(
            backtrace,
            vec![
                BacktraceElement::CallId(root_call_ids[0].clone()),
                BacktraceElement::CallAddr(0xa)
            ]
        );

        let child_call_id_2 = reader
            .call_stream_reader(&child_call_id_1)
            .unwrap()
            .find_map(|call_data| match call_data {
                Ok(CallData::CalledFunction { call_id }) => Some(call_id),
                _ => None,
            })
            .unwrap();

        let backtrace = reader
            .backtrace_reader(child_call_id_2)
            .unwrap()
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(
            backtrace,
            vec![
                BacktraceElement::CallId(child_call_id_1),
                BacktraceElement::CallId(root_call_ids[0].clone()),
                BacktraceElement::CallAddr(0xa)
            ]
        );
    }
}
