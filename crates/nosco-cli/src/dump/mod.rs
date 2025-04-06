mod binary_info;
mod call_info;
mod call_trace;
mod thread_info;

use std::io::{Read, Seek, Write};

use miette::IntoDiagnostic;

use nosco_storage::MlaStorageReader;

use self::call_info::CallInformation;
use super::cli::CliDumpAction;

/// Runs the subcommand for dumping trace session information.
pub fn evaluate_dump(
    input: impl Read + Seek,
    mut output: impl Write,
    dump_action: CliDumpAction,
) -> miette::Result<()> {
    let reader = MlaStorageReader::from_reader(input).into_diagnostic()?;

    let mut kdl = match dump_action {
        CliDumpAction::CallInfo {
            call_info_args,
            call_id,
        } => {
            let call_info_fetcher = CallInformation::fetcher()
                .with_backtrace(call_info_args.backtrace)
                .with_call_address(call_info_args.addresses)
                .with_thread_id(true)
                .with_state_updates(true);

            self::call_info::dump_to_kdl(reader, call_info_fetcher, call_id)?
        }
        CliDumpAction::BinaryInfo {
            call_info_args,
            binary_name,
        } => {
            let call_info_fetcher = CallInformation::fetcher()
                .with_backtrace(call_info_args.backtrace)
                .with_call_address(call_info_args.addresses);

            self::binary_info::dump_to_kdl(reader, call_info_fetcher, binary_name)?
        }
        CliDumpAction::CallTrace {
            depth,
            asm,
            call_info_args,
            call_id,
        } => {
            let call_info_fetcher = CallInformation::fetcher()
                .with_backtrace(call_info_args.backtrace)
                .with_call_address(call_info_args.addresses);

            self::call_trace::dump_to_kdl(reader, call_info_fetcher, depth, asm, call_id)?
        }
        CliDumpAction::ThreadInfo {
            call_info_args,
            thread_id,
        } => {
            let call_info_fetcher = CallInformation::fetcher()
                .with_backtrace(call_info_args.backtrace)
                .with_call_address(call_info_args.addresses);

            self::thread_info::dump_to_kdl(reader, call_info_fetcher, thread_id)?
        }
    };

    kdl.autoformat();

    output
        .write_all(kdl.to_string().as_bytes())
        .into_diagnostic()?;

    Ok(())
}
