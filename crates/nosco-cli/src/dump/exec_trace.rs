use std::collections::HashMap;
use std::io::{Read, Seek, Write};

use capstone::Capstone;
use capstone::arch::BuildsCapstone;
use miette::IntoDiagnostic;
use nosco_storage::MlaStorageReader;
use nosco_storage::content::{CallData, StateChangeData};

use super::SymbolResolver;
use super::call_info::CallInformationFetcher;

pub fn dump_to_gas(
    mut reader: MlaStorageReader<impl Read + Seek>,
    output: &mut dyn Write,
    call_info_fetcher: CallInformationFetcher,
    mut resolver: Option<&mut SymbolResolver>,
    call_id: String,
) -> miette::Result<()> {
    // TODO: encode arch in trace session storage
    let disass = if cfg!(target_arch = "x86_64") {
        Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .build()
            .into_diagnostic()?
    } else if cfg!(target_arch = "aarch64") {
        Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .build()
            .into_diagnostic()?
    } else {
        miette::bail!("unsupported CPU architecture")
    };

    writeln!(output, ".intel_syntax noprefix\n").into_diagnostic()?;

    let call_info = call_info_fetcher.fetch(call_id, &mut reader, resolver.as_deref_mut())?;

    write!(
        output,
        "{}: # call_id={}",
        call_info.symbol.as_deref().unwrap_or("<unknown>"),
        call_info.call_id
    )
    .into_diagnostic()?;

    if let Some(addr) = call_info.address {
        write!(output, " addr={addr:#x}").into_diagnostic()?;
    }

    writeln!(output).into_diagnostic()?;

    let mut state_update_ids = Vec::new();
    let mut exec_infos = Vec::new();

    let (_, call_data_iter) = reader
        .call_stream_reader(call_info.call_id)
        .into_diagnostic()?;

    for call_data in call_data_iter {
        match call_data.into_diagnostic()? {
            CallData::ExecutedInstruction {
                opcodes_addr,
                opcodes,
            } => {
                exec_infos.push(ExecInfo::from_opcodes(
                    opcodes_addr,
                    &opcodes,
                    &disass,
                    call_info_fetcher.fetch_address,
                )?);
            }
            CallData::CalledFunction { call_id } => {
                if let Some(exec_info) = exec_infos.last_mut() {
                    exec_info.extra_info.push(CallDataInfo::Call(call_id));
                }
            }
            CallData::UpdatedState { update_id } => {
                if let Some(exec_info) = exec_infos.last_mut() {
                    exec_info
                        .extra_info
                        .push(CallDataInfo::StateUpdate(update_id));
                }
                state_update_ids.push(update_id);
            }
        }
    }

    if exec_infos.is_empty() {
        return Ok(());
    }

    let state_updates = reader
        .state_updates_reader()
        .into_diagnostic()?
        .map(|res| res.into_diagnostic())
        .enumerate()
        .filter_map(|(id, res)| match res {
            Ok((_, data)) => state_update_ids
                .contains(&(id as u64))
                .then_some(Ok((id as u64, data))),
            Err(e) => Some(Err(e)),
        })
        .collect::<miette::Result<HashMap<_, _>>>()?;

    for exec_info in exec_infos {
        if let Some(addr) = exec_info.addr {
            write!(output, " /* {addr:#x} */").into_diagnostic()?;
        }
        write!(output, "    {}", exec_info.asm).into_diagnostic()?;

        let mut call_data_infos = exec_info.extra_info.into_iter().peekable();

        if call_data_infos.peek().is_some() {
            write!(output, "   #").into_diagnostic()?;
        }

        for call_data_info in call_data_infos {
            match call_data_info {
                CallDataInfo::Call(call_id) => {
                    let call_info =
                        call_info_fetcher.fetch(call_id, &mut reader, resolver.as_deref_mut())?;

                    write!(
                        output,
                        " {} call_id={}",
                        call_info.symbol.as_deref().unwrap_or("<unknown>"),
                        call_info.call_id
                    )
                    .into_diagnostic()?;

                    if let Some(addr) = call_info.address {
                        write!(output, " addr={addr:#x}").into_diagnostic()?;
                    }
                }
                CallDataInfo::StateUpdate(update_id) => {
                    if let Some(state_change_data) = state_updates.get(&update_id) {
                        print_state_change_data(state_change_data, output)?;
                    }
                }
            }
        }

        writeln!(output).into_diagnostic()?;
    }

    Ok(())
}

struct ExecInfo {
    addr: Option<u64>,
    asm: String,
    extra_info: Vec<CallDataInfo>,
}

impl ExecInfo {
    fn from_opcodes(
        opcodes_addr: u64,
        opcodes: &[u8],
        disass: &Capstone,
        fetch_addresses: bool,
    ) -> miette::Result<Self> {
        let code = disass
            .disasm_count(opcodes, opcodes_addr, 1)
            .into_diagnostic()?;

        let asm = code.first().map_or_else(String::default, |insn| {
            let mut asm = String::new();

            if let Some(m) = insn.mnemonic() {
                asm.push_str(m);
            }

            if let Some(op) = insn.op_str() {
                asm.push(' ');
                asm.push_str(op);
            }

            asm.trim().to_owned()
        });

        Ok(Self {
            addr: fetch_addresses.then_some(opcodes_addr),
            asm,
            extra_info: Vec::new(),
        })
    }
}

fn print_state_change_data(
    state_change_data: &StateChangeData,
    output: &mut dyn Write,
) -> miette::Result<()> {
    match state_change_data {
        StateChangeData::CreatedThread { thread_id, .. } => {
            write!(output, " create_thread={thread_id}").into_diagnostic()
        }
        StateChangeData::ExitedThread { thread_id, .. } => {
            write!(output, " exit_thread={thread_id}").into_diagnostic()
        }
        StateChangeData::LoadedBinary { path, .. } => {
            write!(output, " load_binary={}", path.display()).into_diagnostic()
        }
        StateChangeData::UnloadedBinary { unload_addr } => {
            write!(output, " unload_binary={unload_addr:#x}").into_diagnostic()
        }
    }
}

enum CallDataInfo {
    Call(String),
    StateUpdate(u64),
}
