//! Generic binary shell for a protocol spec.
//!
//! The project root `main.rs` picks a protocol and delegates here. Core then
//! handles global CLI shape, adds the generic daemon `start` command, appends
//! protocol-provided commands, and runs the selected command against the
//! protocol context.

use std::path::{Path, PathBuf};

use crate::core::cli::{self, CliCommand};
use crate::core::daemon::{self, DaemonProtocol};

pub trait ProtocolSpec: DaemonProtocol {
    const NAME: &'static str;

    fn open_context(db_path: impl AsRef<Path>) -> Result<Self::Context, String>;
    fn commands() -> Vec<CliCommand<Self::Context>>;
}

pub fn run<P>(args: Vec<String>) -> Result<(), String>
where
    P: ProtocolSpec,
{
    let (db_path, command_args) = parse_global_args(args)?;
    let mut context = P::open_context(db_path)?;
    let mut commands = vec![daemon::command::<P>()];
    commands.extend(P::commands());
    let output = cli::run(&commands, &mut context, &command_args)?;
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

fn parse_global_args(args: Vec<String>) -> Result<(PathBuf, Vec<String>), String> {
    let mut iter = args.into_iter();
    let mut db_path = None;
    let mut command_args = Vec::new();

    while let Some(arg) = iter.next() {
        if arg == "--db" {
            db_path = iter.next().map(PathBuf::from);
        } else {
            command_args.push(arg);
            command_args.extend(iter);
            break;
        }
    }

    let db_path = db_path.ok_or_else(|| "missing --db PATH".to_string())?;
    Ok((db_path, command_args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_global_args_keeps_protocol_command_tail() {
        let (db, tail) = parse_global_args(vec![
            "--db".to_string(),
            "store.db".to_string(),
            "count".to_string(),
            "--json".to_string(),
        ])
        .expect("parse args");

        assert_eq!(db, PathBuf::from("store.db"));
        assert_eq!(tail, ["count", "--json"]);
    }
}
