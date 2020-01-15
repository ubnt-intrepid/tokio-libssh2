use std::{ffi::OsString, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
enum Arg {
    /// Run a script.
    Script {
        /// The script name
        #[structopt(name = "command", parse(from_os_str))]
        command: OsString,

        /// The arguments passed to script
        #[structopt(name = "args", parse(from_os_str))]
        args: Vec<OsString>,
    },
}

fn main() -> anyhow::Result<()> {
    match Arg::from_args() {
        Arg::Script { command, args } => do_script(command, args),
    }
}

fn do_script(command: OsString, args: Vec<OsString>) -> anyhow::Result<()> {
    let bin_dir = project_root()?.join("bin").canonicalize()?;
    anyhow::ensure!(bin_dir.is_dir(), "bin/ is not a directory");

    use std::process::{Command, Stdio};

    let mut script = Command::new(command);
    script.args(args);
    script.stdin(Stdio::null());
    script.stdout(Stdio::inherit());
    script.stderr(Stdio::inherit());
    if let Some(orig_path) = std::env::var_os("PATH") {
        let paths: Vec<_> = Some(bin_dir)
            .into_iter()
            .chain(std::env::split_paths(&orig_path))
            .collect();
        let new_path = std::env::join_paths(paths)?;
        script.env("PATH", new_path);
    }

    let status = script.status()?;
    anyhow::ensure!(status.success(), format!("Script failed: {}", status));

    Ok(())
}

fn project_root() -> anyhow::Result<PathBuf> {
    Ok(std::path::Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("missing ancestor"))?
        .to_owned())
}
