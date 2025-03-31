use std::io::{Read, Seek};
use std::marker::PhantomData;
use std::vec::IntoIter;

use either::Either;

use mla::config::ArchiveReaderConfig;
use mla::layers::traits::LayerReader;
use mla::{ArchiveFile, ArchiveReader, BlocksToFileReader};

use serde::de::DeserializeOwned;

use super::content::{CallData, CallMetadata, StateChangeData, StateInitData};
use super::content::{StateUpdateData, StateUpdateOrigin};
use super::content::{STATE_INIT_STREAM_LABEL, STATE_UPDATE_STREAM_LABEL};

/// Storage reader for the MLA backend.
pub struct MlaStorageReader<'a, R: 'a + Read + Seek> {
    mla: ArchiveReader<'a, R>,
}

impl<'rd, R: 'rd + Read + Seek> MlaStorageReader<'rd, R> {
    /// Initializes a new MLA storage reader from an inner reader.
    pub fn from_reader(reader: R) -> crate::Result<Self> {
        // `ArchiveReader::from_config` loads the persistent configuration from
        // the archive's header, so there is no need to tweak `ArchiveReaderConfig`
        // settings here.
        let config = ArchiveReaderConfig::new();

        let mla = ArchiveReader::from_config(reader, config)?;

        Ok(Self { mla })
    }

    /// Returns a reader for retrieving backtrace information of a function
    /// call.
    pub fn backtrace_reader<S: Into<String>>(
        &mut self,
        call_id: S,
    ) -> crate::Result<impl Iterator<Item = crate::Result<BacktraceElement>> + use<'_, 'rd, R, S>>
    {
        let (metadata, _) = self
            .read_call_stream(call_id)
            .and_then(|stream| stream.read_metadata())?;

        Ok(BacktraceReader {
            next_element: Either::Left(Some(metadata)),
            reader: self,
        })
    }

    /// Returns a reader for retrieving tracing state updates information (e.g.,
    /// loaded binaries, created threads).
    pub fn state_updates_reader(
        &mut self,
    ) -> crate::Result<
        impl Iterator<Item = crate::Result<(Option<StateUpdateOrigin>, StateChangeData)>>
            + use<'_, 'rd, R>,
    > {
        let stream = self.read_state_update_stream()?;

        Ok(stream.map(|res| match res {
            Ok(StateUpdateData { header, content }) => Ok((header.update_origin, content)),
            Err(e) => Err(e),
        }))
    }

    /// Returns a reader for retrieving tracing state initialization information
    /// (e.g., loaded binaries, created threads).
    pub fn state_init_reader(
        &mut self,
    ) -> crate::Result<impl Iterator<Item = crate::Result<StateChangeData>> + use<'_, 'rd, R>> {
        let stream = self.read_state_init_stream()?;

        Ok(stream.map(|res| match res {
            Ok(StateInitData(content)) => Ok(content),
            Err(e) => Err(e),
        }))
    }

    /// Returns a reader for retrieving function call tracing information (e.g.,
    /// executed instructions, called functions).
    pub fn call_stream_reader<S: Into<String>>(
        &mut self,
        call_id: S,
    ) -> crate::Result<impl Iterator<Item = crate::Result<CallData>> + use<'_, 'rd, R, S>> {
        let (_, stream) = self.read_call_stream(call_id)?.read_metadata()?;
        Ok(stream)
    }

    fn read_call_stream<'a>(
        &'a mut self,
        call_id: impl Into<String>,
    ) -> crate::Result<StreamMetadataReader<'a, 'rd, R, CallMetadata, CallData>> {
        let call_label = call_id.into();

        let file = self
            .mla
            .get_file(call_label.clone())?
            .ok_or_else(|| crate::Error::InvalidCallId(call_label))?;

        Ok(StreamMetadataReader {
            file,
            _phantom1: PhantomData,
            _phantom2: PhantomData,
        })
    }

    fn read_state_init_stream<'a>(
        &'a mut self,
    ) -> crate::Result<StreamDataReader<'a, 'rd, R, StateInitData>> {
        let file = self
            .mla
            .get_file(STATE_INIT_STREAM_LABEL.to_owned())?
            .ok_or(crate::Error::MissingInitState)?;

        Ok(StreamDataReader {
            file,
            _phantom: PhantomData,
        })
    }

    fn read_state_update_stream<'a>(
        &'a mut self,
    ) -> crate::Result<StreamDataReader<'a, 'rd, R, StateUpdateData>> {
        let file = self
            .mla
            .get_file(STATE_UPDATE_STREAM_LABEL.to_owned())?
            .ok_or(crate::Error::MissingUpdateState)?;

        Ok(StreamDataReader {
            file,
            _phantom: PhantomData,
        })
    }
}

struct StreamMetadataReader<'a, 'rd, R, M, D> {
    file: ArchiveFile<BlocksToFileReader<'a, Box<dyn 'rd + LayerReader<'rd, R>>>>,
    _phantom1: PhantomData<M>,
    _phantom2: PhantomData<D>,
}

impl<'a, 'rd, R, M: DeserializeOwned, D> StreamMetadataReader<'a, 'rd, R, M, D> {
    fn read_metadata(mut self) -> crate::Result<(M, StreamDataReader<'a, 'rd, R, D>)> {
        let metadata = bincode::deserialize_from(&mut self.file.data)?;

        Ok((
            metadata,
            StreamDataReader {
                file: self.file,
                _phantom: PhantomData,
            },
        ))
    }
}

struct StreamDataReader<'a, 'rd, R, T> {
    file: ArchiveFile<BlocksToFileReader<'a, Box<dyn 'rd + LayerReader<'rd, R>>>>,
    _phantom: PhantomData<T>,
}

impl<R, D: DeserializeOwned> StreamDataReader<'_, '_, R, D> {
    fn read_data(&mut self) -> crate::Result<Option<D>> {
        match bincode::deserialize_from(&mut self.file.data) {
            Ok(d) => Ok(Some(d)),
            Err(e) if matches!(*e, bincode::ErrorKind::Io(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

impl<R, D: DeserializeOwned> Iterator for StreamDataReader<'_, '_, R, D> {
    type Item = crate::Result<D>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read_data().transpose()
    }
}

struct BacktraceReader<'a, 'rd, R: Read + Seek> {
    next_element: Either<Option<CallMetadata>, IntoIter<u64>>,
    reader: &'a mut MlaStorageReader<'rd, R>,
}

impl<R: Read + Seek> BacktraceReader<'_, '_, R> {
    fn read_next_backtrace_element(&mut self) -> crate::Result<Option<BacktraceElement>> {
        loop {
            let next_call_metadata = match self.next_element {
                Either::Left(ref mut m) => match m.take() {
                    Some(m) => m,
                    None => break Ok(None),
                },
                Either::Right(ref mut root_backtrace) => {
                    break Ok(root_backtrace.next().map(BacktraceElement::CallAddr))
                }
            };

            let next_call_id = match next_call_metadata {
                CallMetadata::Sub { caller_id } => caller_id,
                CallMetadata::Root { backtrace } => {
                    self.next_element = Either::Right(backtrace.into_iter());
                    continue;
                }
            };

            let (metadata, _) = self
                .reader
                .read_call_stream(&next_call_id)
                .and_then(|stream| stream.read_metadata())?;

            self.next_element = Either::Left(Some(metadata));

            break Ok(Some(BacktraceElement::CallId(next_call_id)));
        }
    }
}

impl<R: Read + Seek> Iterator for BacktraceReader<'_, '_, R> {
    type Item = crate::Result<BacktraceElement>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read_next_backtrace_element().transpose()
    }
}

/// Backtrace element of a function call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BacktraceElement {
    /// Function call address of the backtrace element.
    CallAddr(u64),

    /// Function call ID of the backtrace element.
    CallId(String),
}
