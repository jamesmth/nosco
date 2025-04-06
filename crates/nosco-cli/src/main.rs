#![allow(missing_docs)]
#![allow(clippy::print_stderr)]

use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};

use miette::IntoDiagnostic;

use nosco_cli::{CliAction, CliDumpAction, CliOpts, TraceConfig, TraceEventHandler};

use nosco_debugger::Debugger;

use nosco_storage::MlaStorageWriter;

use nosco_tracer::Command;
use nosco_tracer::tracer::Tracer;

use tokio::process::{ChildStderr, ChildStdout};

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
        } => evaluate_run(config, output, program, args).map(Some),
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
        let file = File::create(output).into_diagnostic()?;
        nosco_cli::evaluate_dump(storage, file, dump_action)
    } else {
        nosco_cli::evaluate_dump(storage, std::io::stdout(), dump_action)
    }
}

fn evaluate_run(
    config: String,
    output: PathBuf,
    program: PathBuf,
    args: Vec<String>,
) -> miette::Result<i32> {
    let config = parse_run_config(config)?;

    let output = File::create(output).into_diagnostic()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .into_diagnostic()?;

    runtime.block_on(async move {
        let output = MlaStorageWriter::from_writer(output).into_diagnostic()?;

        let tracer = Tracer::builder()
            .with_debugger(Debugger)
            .with_event_handler(TraceEventHandler::new(output, config.backtrace_depth));

        let tracer = if config.tracing_scopes.is_empty() {
            tracer.trace_all(config.call_depth).build()
        } else {
            config
                .tracing_scopes
                .into_iter()
                .fold(tracer.trace_scopes(), |tracer, scope| {
                    tracer.scope(
                        scope.binary,
                        scope.symbol,
                        scope.call_depth.unwrap_or(config.call_depth),
                    )
                })
                .build()
        };

        let command = Command::new(program).args(args);

        let (process, stdio) = tracer.spawn(command).await.into_diagnostic()?;

        let stdout = ChildStdout::from_std(stdio.stdout)
            .map(|mut stdout| {
                tokio::spawn(
                    async move { tokio::io::copy(&mut stdout, &mut tokio::io::stdout()).await },
                )
            })
            .into_diagnostic()?;

        let stderr = ChildStderr::from_std(stdio.stderr)
            .map(|mut stderr| {
                tokio::spawn(
                    async move { tokio::io::copy(&mut stderr, &mut tokio::io::stderr()).await },
                )
            })
            .into_diagnostic()?;

        let (exit_code, event_handler) = process.resume_and_trace().await.into_diagnostic()?;

        let _ = stdout.await;
        let _ = stderr.await;

        event_handler.finalize_storage().await.into_diagnostic()?;

        Ok(exit_code)
    })
}

fn parse_run_config(config: String) -> miette::Result<TraceConfig> {
    let path = Path::new(&config);

    let config = if let Some((filename, "kdl")) = path
        .file_name()
        .and_then(OsStr::to_str)
        .zip(path.extension().and_then(OsStr::to_str))
    {
        let content = std::fs::read_to_string(path).into_diagnostic()?;
        knus::parse(filename, &content)?
    } else {
        knus::parse("<content>", &config)?
    };

    Ok(config)
}
