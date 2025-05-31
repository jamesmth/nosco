#![allow(missing_docs)]
#![allow(clippy::print_stderr)]

use std::fs::File;
use std::path::PathBuf;

use miette::IntoDiagnostic;
use nosco_cli::{CliAction, CliDumpAction, CliOpts};
use tracing_subscriber::EnvFilter;

fn main() {
    let cli = CliOpts::parse_from_cmdline();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_env_var("NOSCO_LOG")
                .from_env_lossy(),
        )
        .init();

    let res = match cli.action {
        CliAction::Run {
            config,
            output,
            program,
            args,
        } => nosco_cli::evaluate_run(config, output, program, args).map(Some),
        CliAction::Dump {
            input,
            output,
            dump_action,
        } => evaluate_dump(input, output, dump_action).map(|_| None),
    };

    match res {
        Ok(Some(exit_code)) => std::process::exit(exit_code),
        Ok(None) => (),
        Err(e) => {
            eprintln!("{e:?}");
            std::process::exit(1);
        }
    }
}

fn evaluate_dump(
    input: PathBuf,
    output: Option<PathBuf>,
    dump_action: CliDumpAction,
) -> miette::Result<()> {
    let storage = File::open(input).into_diagnostic()?;

    if let Some(output) = output {
        let mut file = File::create(output).into_diagnostic()?;
        nosco_cli::evaluate_dump(storage, &mut file, dump_action)
    } else {
        nosco_cli::evaluate_dump(storage, &mut std::io::stdout(), dump_action)
    }
}
