mod binary_info;
mod call_info;
mod call_trace;
mod exec_trace;
mod thread_info;

use std::io::{Read, Seek, Write};
use std::sync::Arc;
use std::time::SystemTime;

use miette::IntoDiagnostic;
use nosco_storage::MlaStorageReader;
use nosco_symbol::elf::MappedElf;
use nosco_tracer::debugger::MappedBinary;
use wholesym::{SymbolManager, SymbolManagerConfig};

use self::binary_info::PartialBinaryInformation;
use self::call_info::CallInformation;
use super::cli::{CliDumpAction, CliSymbolicate};

/// Runs the subcommand for dumping trace session information.
pub fn evaluate_dump(
    input: impl Read + Seek,
    output: &mut dyn Write,
    symbolicate_args: CliSymbolicate,
    dump_action: CliDumpAction,
) -> miette::Result<()> {
    let mut reader = MlaStorageReader::from_reader(input).into_diagnostic()?;

    let mut resolver = if symbolicate_args.symbolicate {
        Some(SymbolResolver::init(&mut reader, symbolicate_args)?)
    } else {
        None
    };

    match dump_action {
        CliDumpAction::CallInfo {
            call_info_args,
            call_id,
        } => {
            let call_info_fetcher = CallInformation::fetcher()
                .with_backtrace(call_info_args.backtrace)
                .with_call_address(call_info_args.addresses)
                .with_thread_id(true)
                .with_state_updates(true);

            let mut kdl = self::call_info::dump_to_kdl(
                reader,
                call_info_fetcher,
                call_id,
                resolver.as_mut(),
            )?;

            kdl.autoformat();

            output
                .write_all(kdl.to_string().as_bytes())
                .into_diagnostic()?;
        }
        CliDumpAction::BinaryInfo {
            call_info_args,
            binary_name,
        } => {
            let call_info_fetcher = CallInformation::fetcher()
                .with_backtrace(call_info_args.backtrace)
                .with_call_address(call_info_args.addresses);

            let mut kdl = self::binary_info::dump_to_kdl(
                reader,
                call_info_fetcher,
                binary_name,
                resolver.as_mut(),
            )?;

            kdl.autoformat();

            output
                .write_all(kdl.to_string().as_bytes())
                .into_diagnostic()?;
        }
        CliDumpAction::CallTrace {
            depth,
            call_info_args,
            call_id,
        } => {
            let call_info_fetcher = CallInformation::fetcher()
                .with_backtrace(call_info_args.backtrace)
                .with_call_address(call_info_args.addresses);

            let mut kdl = self::call_trace::dump_to_kdl(
                reader,
                call_info_fetcher,
                resolver.as_mut(),
                depth,
                call_id,
            )?;

            kdl.autoformat();

            output
                .write_all(kdl.to_string().as_bytes())
                .into_diagnostic()?;
        }
        CliDumpAction::ThreadInfo {
            call_info_args,
            thread_id,
        } => {
            let call_info_fetcher = CallInformation::fetcher()
                .with_backtrace(call_info_args.backtrace)
                .with_call_address(call_info_args.addresses);

            let mut kdl = self::thread_info::dump_to_kdl(
                reader,
                call_info_fetcher,
                resolver.as_mut(),
                thread_id,
            )?;

            kdl.autoformat();

            output
                .write_all(kdl.to_string().as_bytes())
                .into_diagnostic()?;
        }
        CliDumpAction::ExecTrace { addresses, call_id } => {
            let call_info_fetcher = CallInformation::fetcher().with_call_address(addresses);

            self::exec_trace::dump_to_gas(
                reader,
                output,
                call_info_fetcher,
                resolver.as_mut(),
                call_id,
            )?;
        }
    }

    Ok(())
}

struct SymbolResolver {
    binaries: Vec<(PartialBinaryInformation, MappedElf)>,
    runtime: tokio::runtime::Runtime,
}

impl SymbolResolver {
    fn init(
        reader: &mut MlaStorageReader<impl Read + Seek>,
        symbolicate_args: CliSymbolicate,
    ) -> miette::Result<Self> {
        let symbol_manager = SymbolManager::with_config(SymbolManagerConfig::default());
        let symbol_manager = Arc::new(symbol_manager);

        let binaries = self::binary_info::fetch_partial_binaries_info(reader, None)?
            .into_iter()
            .map(|info| {
                let path = if let Some(sysroot) = symbolicate_args.sysroot.as_ref() {
                    sysroot.join(info.path.strip_prefix("/").unwrap_or(&info.path))
                } else {
                    info.path.clone()
                };

                let binary = MappedElf::new(info.addr_range.clone(), path, symbol_manager.clone());

                (info, binary)
            })
            .collect();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .into_diagnostic()?;

        Ok(Self { binaries, runtime })
    }

    fn resolve_symbol_at_addr(
        &mut self,
        addr: u64,
        timestamp: SystemTime,
    ) -> miette::Result<Option<(String, u64)>> {
        let Some(binary) = self.binaries.iter_mut().find_map(|(info, binary)| {
            let found = info.addr_range.contains(&addr)
                && info
                    .loaded
                    .as_ref()
                    .is_none_or(|loaded| loaded.timestamp <= timestamp)
                && info
                    .unloaded
                    .as_ref()
                    .is_none_or(|unloaded| timestamp <= unloaded.timestamp);
            found.then_some(binary)
        }) else {
            return Ok(None);
        };

        self.runtime
            .block_on(binary.symbol_of_addr(addr))
            .into_diagnostic()
    }
}
