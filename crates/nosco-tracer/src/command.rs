use std::collections::BTreeMap;
use std::path::PathBuf;

/// A process builder, providing fine-grained control over how a new process
/// should be spawned.
#[derive(Debug)]
pub struct Command {
    /// Program to spawn.
    pub program: PathBuf,

    /// Program arguments for the process to spawn.
    pub args: Vec<String>,

    /// Environment variables for the process to spawn.
    pub env: CommandEnv,

    /// Working directory for the process to spawn
    pub current_dir: Option<PathBuf>,
}

impl Command {
    /// Constructs a new `Command` for launching the program at
    /// path `program`, with the following default configuration:
    ///
    /// * No arguments to the program
    /// * Inherit the current process's environment
    /// * Inherit the current process's working directory
    ///
    /// Builder methods are provided to change these defaults and
    /// otherwise configure the process.
    ///
    /// If `program` is not an absolute path, the `PATH` will be searched in
    /// an OS-defined way.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: CommandEnv::Inherit(BTreeMap::new()),
            current_dir: None,
        }
    }

    /// Adds an argument to pass to the program.
    ///
    /// Only one argument can be passed per use. So instead of:
    ///
    /// ```no_run
    /// # std::process::Command::new("sh")
    /// .arg("-C /path/to/repo")
    /// # ;
    /// ```
    ///
    /// usage would be:
    ///
    /// ```no_run
    /// # std::process::Command::new("sh")
    /// .arg("-C")
    /// .arg("/path/to/repo")
    /// # ;
    /// ```
    ///
    /// To pass multiple arguments see [`args`](Self::args).
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Adds multiple arguments to pass to the program.
    ///
    /// To pass a single argument see [`arg`](Self::arg).
    pub fn args<I, S>(self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        args.into_iter().fold(self, |cmd, arg| cmd.arg(arg))
    }

    /// Inserts or updates an explicit environment variable mapping.
    ///
    /// This method allows you to add an environment variable mapping to the
    /// process to spawn or overwrite a previously set value. You can use
    /// [`envs`](Self::envs) to set multiple environment variables simultaneously.
    ///
    /// Child processes will inherit environment variables from their parent
    /// process by default. Environment variables explicitly set using
    /// [`env`](Self::env) take precedence over inherited variables. You can
    /// disable environment variable inheritance entirely using
    /// [`env_clear`](Self::env_clear) or for a single key using
    /// [`env_remove`](Self::env_remove).
    ///
    /// Note that environment variable names are case-insensitive (but
    /// case-preserving) on Windows and case-sensitive on all other platforms.
    pub fn env<K, V>(mut self, key: K, val: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        match self.env {
            CommandEnv::Inherit(ref mut env) => {
                env.insert(key.into(), Some(val.into()));
            }
            CommandEnv::NoInherit(ref mut env) => {
                env.insert(key.into(), val.into());
            }
        }

        self
    }

    /// Inserts or updates multiple explicit environment variable mappings.
    ///
    /// This method allows you to add multiple environment variable mappings to
    /// the process to spawn or overwrite previously set values. You can use
    /// [`env`](Self::env) to set a single environment variable.
    ///
    /// Child processes will inherit environment variables from their parent
    /// process by default. Environment variables explicitly set using
    /// [`envs`](Self::envs) take precedence over inherited variables. You can
    /// disable environment variable inheritance entirely using
    /// [`env_clear`](Self::env_clear) or for a single key using
    /// [`env_remove`](Self::env_remove).
    ///
    /// Note that environment variable names are case-insensitive (but
    /// case-preserving) on Windows and case-sensitive on all other platforms.
    pub fn envs<I, K, V>(self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        vars.into_iter().fold(self, |cmd, (k, v)| cmd.env(k, v))
    }

    /// Removes an explicitly set environment variable and prevents inheriting
    /// it from a parent process.
    ///
    /// This method will remove the explicit value of an environment variable
    /// set via [`env`](Self::env) or [`envs`](Self::envs). In addition, it
    /// will prevent the process to spawn from inheriting that environment
    /// variable from its parent process.
    ///
    /// After calling [`env_remove`](Self::env_remove), the value associated
    /// with its key in [`env`](Self#structfield.env) will be `None`.
    ///
    /// To clear all explicitly set environment variables and disable all
    /// environment variable inheritance, you can use
    /// [`env_clear`](Self::env_clear).
    pub fn env_remove(mut self, key: impl Into<String>) -> Self {
        match self.env {
            CommandEnv::Inherit(ref mut env) => {
                env.insert(key.into(), None);
            }
            CommandEnv::NoInherit(ref mut env) => {
                env.remove(&key.into());
            }
        }

        self
    }

    /// Clears all explicitly set environment variables and prevents inheriting
    /// any parent process environment variables.
    ///
    /// This method will remove all explicitly added environment variables set
    /// via [`env`](Self::env) or [`envs`](Self::envs). In addition, it will
    /// prevent the spawned child process from inheriting any environment
    /// variable from its parent process.
    ///
    /// After calling [`env_clear`](Self::env_clear), [`env`](Self#structfield.env)
    /// will be empty.
    ///
    /// You can use [`env_remove`](Self::env_remove) to clear a single mapping.
    pub fn env_clear(mut self) -> Self {
        self.env = CommandEnv::NoInherit(BTreeMap::new());
        self
    }

    /// Sets the working directory for the process to spawn.
    pub fn current_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(dir.into());
        self
    }
}

/// Environment variables attached to a [Command].
#[derive(Debug)]
pub enum CommandEnv {
    /// Environment variables the process to spawn will have, in addition to
    /// the ones inherited from the parent process.
    ///
    /// A `None` value indicates that the environment variable will be removed
    /// from the process to spawn, even if it was inherited.
    Inherit(BTreeMap<String, Option<String>>),

    /// Environment variables the process to spawn will have, without
    /// inheriting any from the parent process.
    NoInherit(BTreeMap<String, String>),
}

impl CommandEnv {
    /// Captures the current environment with the specified changes applied
    pub fn captured(&self) -> Option<BTreeMap<String, String>> {
        let mut captured_env = BTreeMap::new();

        match self {
            Self::Inherit(env) if env.is_empty() => return None,
            Self::Inherit(env) => {
                captured_env.extend(std::env::vars());
                for (k, v) in env {
                    if let Some(v) = v {
                        captured_env.insert(k.clone(), v.clone());
                    } else {
                        captured_env.remove(k);
                    }
                }
            }
            Self::NoInherit(env) => {
                captured_env.extend(env.iter().map(|(k, v)| (k.clone(), v.clone())));
            }
        }

        Some(captured_env)
    }
}
