use std::path::PathBuf;

/// The Nosco tracer.
#[derive(clap::Parser)]
pub struct CliOpts {
    /// The command to run.
    #[clap(subcommand)]
    pub action: CliAction,
}

/// The command to run.
#[derive(clap::Subcommand)]
pub enum CliAction {
    /// Command to spawn a new process and trace it.
    Run {
        /// Tracing configuration (KDL format).
        ///
        /// If it ends with `.kdl`, it is treated as a path to a configuration
        /// file for the tracing operation. Otherwise it is directly parsed as
        /// inline KDL-formatted configuration.
        #[clap(short, long, value_name = "CONTENT/PATH")]
        config: String,

        /// Path where to store the output of the tracing session.
        #[clap(short, long, value_name = "PATH")]
        output: PathBuf,

        /// Name of program to run.
        program: PathBuf,

        /// Program's arguments.
        args: Vec<String>,
    },

    /// Command to dump information from a tracing session file.
    Dump {
        /// Path to the tracing session file to dump.
        #[clap(short, long, value_name = "PATH")]
        input: PathBuf,

        /// Path to the optional destination of the dump.
        #[clap(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// The type of dump to perform.
        #[clap(subcommand)]
        dump_action: CliDumpAction,
    },
}

/// The dump command to run.
#[derive(clap::Subcommand)]
pub enum CliDumpAction {
    /// Dump call information of a specified call.
    CallInfo {
        /// Configuration for dumping call information.
        #[clap(flatten)]
        call_info_args: CliCallInfo,

        /// ID of the call.
        call_id: String,
    },

    /// Dump call trace starting from the specified call.
    CallTrace {
        /// Maximum call trace depth to dump.
        #[clap(long)]
        depth: Option<usize>,

        /// Whether to dump executed assembler instructions.
        #[clap(long)]
        asm: bool,

        /// Configuration for dumping call information.
        #[clap(flatten)]
        call_info_args: CliCallInfo,

        /// ID of the call.
        call_id: String,
    },

    /// Dump binary information.
    BinaryInfo {
        /// Configuration for dumping call information.
        #[clap(flatten)]
        call_info_args: CliCallInfo,

        /// Dump information for a single binary matching the given suffix.
        binary_name: Option<String>,
    },

    /// Dump thread information.
    ThreadInfo {
        /// Configuration for dumping call information.
        #[clap(flatten)]
        call_info_args: CliCallInfo,

        /// Dump information for a single thread with the given ID.
        thread_id: Option<u64>,
    },
}

/// Configuration for dumping call information.
#[derive(clap::Parser)]
pub struct CliCallInfo {
    /// Dump backtrace information.
    #[clap(long)]
    pub backtrace: bool,

    /// Dump addresses information.
    #[clap(long)]
    pub addresses: bool,

    /// Dump symbols information, using the given trace symbols file.
    #[clap(short, long, value_name = "PATH")]
    pub symbols: Option<PathBuf>,
}

impl CliOpts {
    /// Parses the CLI from the command-line.
    ///
    /// # Warning
    ///
    /// Exits on error.
    pub fn parse_from_cmdline() -> Self {
        <Self as clap::Parser>::parse()
    }
}
