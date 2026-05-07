//! Protocol-neutral daemon runner and `start` command.
//!
//! Core owns the reusable mechanics of long-lived operation: parse generic
//! daemon options, acquire the per-store lock, bind a TCP listener, run a set
//! of caller-supplied worker steps, and print generic counters. Protocols
//! supply the worker objects; core only sees names and function pointers.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::{runtime, tcp};

const START_USAGE: &str = "start --listen IP PORT [--tick-ms N] [--quiet-ms N]";
const DEFAULT_TICK_MS: u64 = 250;
const DEFAULT_WORK_LIMIT: usize = 4096;

/// A protocol-supplied daemon worker step.
#[derive(Clone, Copy)]
pub struct Worker<C> {
    pub name: &'static str,
    pub run: for<'a> fn(&mut StepContext<'a, C>) -> Result<(), String>,
}

/// Context handed to one daemon worker step.
pub struct StepContext<'a, C> {
    pub app: &'a mut C,
    pub listener: &'a tcp::Listener,
    pub options: DaemonOptions,
    pub report: &'a mut DaemonReport,
}

/// Protocol hooks needed by the generic daemon command.
pub trait DaemonProtocol {
    type Context;

    fn daemon_db_path(context: &Self::Context) -> &Path;
    fn daemon_workers() -> Vec<Worker<Self::Context>>;
    /// Called once after the listener is bound but before any worker step
    /// runs. The protocol may use this hook to advertise the bound address as
    /// memory-only state. The default implementation does nothing so most
    /// protocols can ignore the hook.
    fn after_listener_bound(_context: &mut Self::Context, _local_addr: SocketAddr) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonOptions {
    pub listen: SocketAddr,
    pub duration: Option<Duration>,
    pub idle: Duration,
    pub work_limit: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DaemonReport {
    pub local_addr: Option<SocketAddr>,
    pub ticks: usize,
    pub steps: usize,
    counters: BTreeMap<&'static str, usize>,
}

impl DaemonReport {
    pub fn add(&mut self, name: &'static str, value: usize) {
        *self.counters.entry(name).or_default() += value;
    }

    pub fn get(&self, name: &'static str) -> usize {
        self.counters.get(name).copied().unwrap_or(0)
    }

    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(local_addr) = self.local_addr {
            lines.push(format!("listening: {local_addr}"));
        }
        lines.push(format!("ticks: {}", self.ticks));
        lines.push(format!("steps: {}", self.steps));
        for (name, value) in &self.counters {
            lines.push(format!("{name}: {value}"));
        }
        lines
    }
}

pub fn command<P>() -> CliCommand<P::Context>
where
    P: DaemonProtocol,
{
    CliCommand {
        name: "start",
        usage: START_USAGE,
        help: "Run a long-lived daemon for this protocol.",
        run: run_start_command::<P>,
    }
}

fn run_start_command<P>(context: &mut P::Context, args: CliArgs<'_>) -> Result<CliOutput, String>
where
    P: DaemonProtocol,
{
    let options = StartOptions::parse(args)?;
    let _lock = DaemonLock::acquire(P::daemon_db_path(context))?;
    let listener = tcp::listen(options.listen)?;
    let local_addr = listener.local_addr();
    // Advertise the bound address before printing the visibility line so a
    // sibling CLI process that synchronizes on `listening: <addr>` can rely
    // on the advertised row being already committed.
    P::after_listener_bound(context, local_addr)?;
    print_line_now(&format!("listening: {local_addr}"))?;
    let report = run_with_listener(
        context,
        listener,
        &P::daemon_workers(),
        DaemonOptions {
            listen: options.listen,
            duration: None,
            idle: Duration::from_millis(options.tick_ms),
            work_limit: DEFAULT_WORK_LIMIT,
        },
    )?;
    Ok(CliOutput::lines(report.lines()))
}

pub fn run<C>(
    context: &mut C,
    workers: &[Worker<C>],
    options: DaemonOptions,
) -> Result<DaemonReport, String> {
    run_after_bind(context, workers, options, |_| Ok(()))
}

pub fn run_after_bind<C>(
    context: &mut C,
    workers: &[Worker<C>],
    options: DaemonOptions,
    after_bind: impl FnOnce(SocketAddr) -> Result<(), String>,
) -> Result<DaemonReport, String> {
    let listener = tcp::listen(options.listen)?;
    after_bind(listener.local_addr())?;
    run_with_listener(context, listener, workers, options)
}

fn run_with_listener<C>(
    context: &mut C,
    listener: tcp::Listener,
    workers: &[Worker<C>],
    options: DaemonOptions,
) -> Result<DaemonReport, String> {
    let started = Instant::now();
    let mut report = DaemonReport {
        local_addr: Some(listener.local_addr()),
        ..DaemonReport::default()
    };

    let runtime_report = runtime::run_round_robin(
        workers,
        options.idle,
        || {
            options
                .duration
                .is_some_and(|duration| started.elapsed() >= duration)
        },
        |worker| {
            let mut step = StepContext {
                app: context,
                listener: &listener,
                options,
                report: &mut report,
            };
            match (worker.run)(&mut step) {
                Ok(()) => {
                    report.add(worker.name, 1);
                    Ok(())
                }
                Err(err) if is_retryable_store_busy(&err) => Ok(()),
                Err(err) => Err(format!("{}: {err}", worker.name)),
            }
        },
    )?;
    report.ticks = runtime_report.ticks;
    report.steps = runtime_report.steps;
    Ok(report)
}

pub fn is_retryable_store_busy(err: &str) -> bool {
    err.contains("database is locked") || err.contains("database is busy")
}

#[derive(Clone, Copy)]
struct StartOptions {
    listen: SocketAddr,
    tick_ms: u64,
}

impl StartOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let mut listen = None;
        let mut tick_ms = DEFAULT_TICK_MS;
        let mut idx = 0;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
                "--listen" => {
                    let ip = args.get(idx + 1).ok_or_else(|| START_USAGE.to_string())?;
                    let port = args.get(idx + 2).ok_or_else(|| START_USAGE.to_string())?;
                    listen = Some(
                        format!("{ip}:{port}")
                            .parse::<SocketAddr>()
                            .map_err(|_| START_USAGE.to_string())?,
                    );
                    idx += 3;
                }
                "--sync-ms" | "--tick-ms" => {
                    tick_ms = parse_positive_u64(args.get(idx + 1), START_USAGE)?;
                    idx += 2;
                }
                "--quiet-ms" => {
                    let _quiet_ms = parse_positive_u64(args.get(idx + 1), START_USAGE)?;
                    idx += 2;
                }
                other => return Err(format!("unknown start option `{other}`\n{START_USAGE}")),
            }
        }
        let listen = listen.ok_or_else(|| START_USAGE.to_string())?;
        Ok(Self { listen, tick_ms })
    }
}

fn parse_positive_u64(value: Option<&str>, usage: &str) -> Result<u64, String> {
    let parsed = value
        .ok_or_else(|| usage.to_string())?
        .parse::<u64>()
        .map_err(|_| usage.to_string())?;
    if parsed == 0 {
        return Err(usage.to_string());
    }
    Ok(parsed)
}

struct DaemonLock {
    path: PathBuf,
    _file: File,
}

impl DaemonLock {
    fn acquire(db_path: &Path) -> Result<Self, String> {
        let path = lock_path(db_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("create lock dir: {err}"))?;
        }
        match create_lock_file(&path) {
            Ok(file) => Ok(Self { path, _file: file }),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if stale_lock_can_be_removed(&path)? {
                    let _ = fs::remove_file(&path);
                    let file = create_lock_file(&path)
                        .map_err(|err| format!("create daemon lock: {err}"))?;
                    Ok(Self { path, _file: file })
                } else {
                    Err(format!(
                        "daemon already running for {}",
                        db_path.to_string_lossy()
                    ))
                }
            }
            Err(err) => Err(format!("create daemon lock: {err}")),
        }
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_path(db_path: &Path) -> PathBuf {
    let mut path = db_path.to_path_buf();
    let lock_name = db_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.daemon.lock"))
        .unwrap_or_else(|| "daemon.lock".to_string());
    path.set_file_name(lock_name);
    path
}

fn create_lock_file(path: &Path) -> std::io::Result<File> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    writeln!(file, "{}", std::process::id())?;
    file.flush()?;
    Ok(file)
}

fn stale_lock_can_be_removed(path: &Path) -> Result<bool, String> {
    let pid_text = fs::read_to_string(path).map_err(|err| format!("read daemon lock: {err}"))?;
    let Ok(pid) = pid_text.trim().parse::<u32>() else {
        return Ok(false);
    };
    Ok(!Path::new(&format!("/proc/{pid}")).exists())
}

fn print_line_now(line: &str) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{line}").map_err(|err| format!("write daemon status: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("flush daemon status: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestContext;

    fn test_worker(ctx: &mut StepContext<'_, TestContext>) -> Result<(), String> {
        ctx.report.add("test_runs", 1);
        Ok(())
    }

    #[test]
    fn daemon_runs_named_workers_with_generic_counters() {
        let mut context = TestContext;
        let workers = [Worker {
            name: "test.worker",
            run: test_worker,
        }];
        let report = run(
            &mut context,
            &workers,
            DaemonOptions {
                listen: "127.0.0.1:0".parse().expect("listen"),
                duration: Some(Duration::from_millis(1)),
                idle: Duration::from_millis(1),
                work_limit: 1,
            },
        )
        .expect("run daemon");

        assert!(report.local_addr.is_some());
        assert!(report.ticks > 0);
        assert_eq!(report.get("test_runs"), report.get("test.worker"));
    }

    #[test]
    fn daemon_treats_store_busy_as_retryable() {
        assert!(is_retryable_store_busy("drain: database is locked"));
        assert!(is_retryable_store_busy("write: database is busy"));
        assert!(!is_retryable_store_busy("projection rejected event"));
    }
}
