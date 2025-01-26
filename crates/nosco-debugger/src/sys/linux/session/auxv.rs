use std::path::PathBuf;

use futures_util::Stream;

use nix::unistd::Pid;

use scroll::Pread;

use tokio::fs::File;
use tokio::io::BufReader;
use tokio_util::bytes::Buf;
use tokio_util::codec::{Decoder, FramedRead};

pub async fn auxv_entries(
    pid: Pid,
    elf_ctx: goblin::container::Ctx,
) -> crate::sys::Result<impl Stream<Item = crate::sys::Result<(u64, u64)>>> {
    let path: PathBuf = format!("/proc/{pid}/auxv").into();

    let reader = File::open(&path)
        .await
        .map(BufReader::new)
        .map_err(|e| crate::sys::Error::File(path, e))?;

    let framed = FramedRead::new(reader, AuxvDecoder { elf_ctx });

    Ok(framed)
}

struct AuxvDecoder {
    elf_ctx: goblin::container::Ctx,
}

impl Decoder for AuxvDecoder {
    type Item = (u64, u64);
    type Error = crate::sys::Error;

    fn decode(
        &mut self,
        src: &mut tokio_util::bytes::BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < self.elf_ctx.size() * 2 {
            return Ok(None);
        }

        let mut offset = 0;

        let (auxv_ty, aux_val) = if self.elf_ctx.is_big() {
            let ty = src
                .gread_with(&mut offset, self.elf_ctx.le)
                .map_err(goblin::error::Error::from)?;
            let val = src
                .gread_with(&mut offset, self.elf_ctx.le)
                .map_err(goblin::error::Error::from)?;

            (ty, val)
        } else {
            let ty: u32 = src
                .gread_with(&mut offset, self.elf_ctx.le)
                .map_err(goblin::error::Error::from)?;
            let val: u32 = src
                .gread_with(&mut offset, self.elf_ctx.le)
                .map_err(goblin::error::Error::from)?;

            (ty as u64, val as u64)
        };

        src.advance(self.elf_ctx.size() * 2);

        Ok(Some((auxv_ty, aux_val)))
    }
}
