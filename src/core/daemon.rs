//! Protocol-neutral daemon runner and lifecycle commands.
//!
//! Core owns the reusable mechanics of long-lived operation: parse generic
//! daemon options, acquire the per-store lock, bind a TCP listener, run a set
//! of caller-supplied worker steps, and print generic counters. Protocols
//! supply the worker objects; core only sees names and function pointers.
//!
//! In addition to `start`, this file owns the matching `stop` and `reset`
//! lifecycle commands. They operate on the same `<db>.daemon.lock` file the
//! runner writes at startup, so all three commands stay in one place rather
//! than scattering daemon-lifecycle plumbing across the codebase.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::{runtime, tcp};

const START_USAGE: &str = "start --listen IP PORT [--tick-ms N] [--quiet-ms N]";
const STOP_USAGE: &str = "stop";
const RESET_USAGE: &str = "reset";
const DEFAULT_TICK_MS: u64 = 250;
const DEFAULT_WORK_LIMIT: usize = 4096;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared shutdown flag set by SIGTERM/SIGINT. The runtime checks this each
/// tick so the daemon can finish a round of work and release its lock cleanly.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_termination_signal(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

fn install_termination_handlers() {
    // Idempotent: only install once per process. Callers may invoke `run`
    // multiple times in tests, but the handler simply flips a flag so a stale
    // installation is harmless. Still, avoid replacing per-call to keep tests
    // that toggle the flag manually predictable.
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    // SAFETY: `sigaction` is async-signal-safe to install, and our handler only
    // touches an `AtomicBool` (also async-signal-safe). `sigaction` is preferred
    // over `signal` because the BSD/SysV semantics of the latter vary across
    // platforms; `sigaction` gives explicit control over the flags and mask.
    let handler = handle_termination_signal as *const () as libc::sighandler_t;
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        // SA_RESTART so blocking IO calls (e.g. `accept`, `nanosleep`) restart
        // automatically once the handler returns, instead of failing with EINTR
        // for callers that do not handle that case.
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
}

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
    fn after_listener_bound(
        _context: &mut Self::Context,
        _local_addr: SocketAddr,
    ) -> Result<(), String> {
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

/// All daemon-lifecycle commands the generic app shell wires up: `start`,
/// `stop`, and `reset`. They all key off the same `<db>.daemon.lock` file the
/// runner writes at startup.
pub fn commands<P>() -> Vec<CliCommand<P::Context>>
where
    P: DaemonProtocol,
{
    vec![
        command::<P>(),
        CliCommand {
            name: "stop",
            usage: STOP_USAGE,
            help: "Stop a running daemon for this store.",
            run: run_stop_command::<P>,
        },
        CliCommand {
            name: "reset",
            usage: RESET_USAGE,
            help: "Stop the daemon (if any) and delete this store's local files.",
            run: run_reset_command::<P>,
        },
    ]
}

fn run_start_command<P>(context: &mut P::Context, args: CliArgs<'_>) -> Result<CliOutput, String>
where
    P: DaemonProtocol,
{
    let options = StartOptions::parse(args)?;
    install_termination_handlers();
    let lock = DaemonLock::acquire(P::daemon_db_path(context))?;
    let listener = tcp::listen(options.listen)?;
    let local_addr = listener.local_addr();
    // Record the bound address in the lock file before printing the visibility
    // line so a sibling CLI process that synchronizes on `listening: <addr>`
    // can read it back via `current_listen_addr` immediately.
    lock.record_listen_addr(local_addr)?;
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
            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                return true;
            }
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

fn run_stop_command<P>(context: &mut P::Context, args: CliArgs<'_>) -> Result<CliOutput, String>
where
    P: DaemonProtocol,
{
    args.require_len(0, STOP_USAGE)?;
    let db_path = P::daemon_db_path(context).to_path_buf();
    Ok(CliOutput::lines(stop_daemon(&db_path)?))
}

fn run_reset_command<P>(context: &mut P::Context, args: CliArgs<'_>) -> Result<CliOutput, String>
where
    P: DaemonProtocol,
{
    args.require_len(0, RESET_USAGE)?;
    let db_path = P::daemon_db_path(context).to_path_buf();
    let mut lines = stop_daemon(&db_path)?;
    lines.extend(reset_db_files(&db_path)?);
    Ok(CliOutput::lines(lines))
}

/// Best-effort stop of any daemon currently holding `<db>.daemon.lock`.
///
/// Returns the lines a CLI should print: either "no daemon running" or
/// "stopped daemon" plus a stale-lock note when applicable.
fn stop_daemon(db_path: &Path) -> Result<Vec<String>, String> {
    let lock = lock_path(db_path);
    let pid = match read_lock_pid(&lock)? {
        LockState::Missing => {
            return Ok(vec!["no daemon running".to_string()]);
        }
        LockState::Unreadable => {
            // Treat an unparseable lock file as a stale artifact rather than a
            // running daemon: if a current daemon owned it, the file would
            // contain a fresh PID. Removing the file unblocks future starts.
            let _ = fs::remove_file(&lock);
            return Ok(vec![
                "no daemon running (cleared unreadable lock)".to_string()
            ]);
        }
        LockState::Pid(pid) => pid,
    };

    if !process_exists(pid) {
        let _ = fs::remove_file(&lock);
        return Ok(vec![format!(
            "no daemon running (cleared stale lock for pid {pid})"
        )]);
    }

    send_termination_signal(pid)?;
    // The lock file is removed by `DaemonLock::drop` immediately before the
    // daemon process exits, so its disappearance is the signal that the
    // daemon shut down cleanly. We also check the process for cases where the
    // lock was removed manually but the process is still alive.
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    while Instant::now() < deadline {
        if !lock.exists() {
            return Ok(vec![format!("stopped daemon (pid {pid})")]);
        }
        if !process_exists(pid) {
            // Process gone but lock still present means an unclean exit.
            let _ = fs::remove_file(&lock);
            return Ok(vec![format!(
                "daemon process exited (pid {pid}); cleared remaining lock"
            )]);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "daemon (pid {pid}) did not exit within {}s",
        SHUTDOWN_TIMEOUT.as_secs()
    ))
}

/// Delete the local-only files this store owns: the SQLite db and its WAL/SHM
/// side files, plus the daemon lock if a stale one is still on disk.
///
/// Reset never recurses or globs: it unlinks an exact list and refuses paths
/// that look like they would escape the db's parent directory.
fn reset_db_files(db_path: &Path) -> Result<Vec<String>, String> {
    let safe_db_path = validate_reset_path(db_path)?;
    let lock = lock_path(&safe_db_path);
    let shm = sibling_path(&safe_db_path, "-shm");
    let wal = sibling_path(&safe_db_path, "-wal");
    let mut deleted = Vec::new();
    for candidate in [&safe_db_path, &shm, &wal, &lock] {
        match fs::remove_file(candidate) {
            Ok(()) => deleted.push(format!("deleted: {}", candidate.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!("delete {}: {err}", candidate.display()));
            }
        }
    }
    if deleted.is_empty() {
        deleted.push("nothing to reset".to_string());
    } else {
        deleted.push("reset complete".to_string());
    }
    Ok(deleted)
}

/// Refuse paths that look unsafe to reset. The intent is "this is a regular
/// file in a normal directory the user owns" — root, mountpoints, and special
/// files are not appropriate targets for `reset`.
fn validate_reset_path(db_path: &Path) -> Result<PathBuf, String> {
    if db_path.as_os_str().is_empty() {
        return Err("reset: empty db path".to_string());
    }
    let parent = db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            format!(
                "reset: refusing to operate on db path with no parent directory ({})",
                db_path.display()
            )
        })?;
    if db_path
        .file_name()
        .and_then(|name| name.to_str())
        .is_none_or(|name| name.is_empty() || name == "." || name == "..")
    {
        return Err(format!(
            "reset: refusing to operate on db path without a file name ({})",
            db_path.display()
        ));
    }
    let parent_abs = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf());
    if parent_abs.as_os_str().is_empty() || parent_abs == Path::new("/") {
        return Err(format!(
            "reset: refusing to operate inside `{}`",
            parent_abs.display()
        ));
    }
    Ok(db_path.to_path_buf())
}

fn sibling_path(db_path: &Path, suffix: &str) -> PathBuf {
    let mut sibling = db_path.as_os_str().to_owned();
    sibling.push(suffix);
    PathBuf::from(sibling)
}

enum LockState {
    Missing,
    Unreadable,
    Pid(u32),
}

fn read_lock_pid(lock: &Path) -> Result<LockState, String> {
    match fs::read_to_string(lock) {
        Ok(text) => {
            let pid_line = text.lines().next().unwrap_or("");
            match pid_line.trim().parse::<u32>() {
                Ok(pid) if pid > 0 => Ok(LockState::Pid(pid)),
                _ => Ok(LockState::Unreadable),
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(LockState::Missing),
        Err(err) => Err(format!("read daemon lock: {err}")),
    }
}

fn process_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn send_termination_signal(pid: u32) -> Result<(), String> {
    // SAFETY: `kill` is safe to call with any pid; `errno` is read through libc
    // before any other syscall could overwrite it.
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() == Some(libc::ESRCH) {
            // The process already exited between the lock-file read and the
            // signal call; treat that as success and let the poll loop notice.
            Ok(())
        } else {
            Err(format!("send SIGTERM to {pid}: {errno}"))
        }
    }
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

    /// Append the bound listen address to this daemon's lock file. Sibling CLI
    /// processes call `current_listen_addr` to read it back without going
    /// through any protocol-owned table — the lock file's lifetime is the
    /// daemon's lifetime, so a stale row cannot survive a restart.
    fn record_listen_addr(&self, addr: SocketAddr) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|err| format!("rewrite daemon lock: {err}"))?;
        writeln!(file, "{}", std::process::id())
            .map_err(|err| format!("write daemon lock pid: {err}"))?;
        writeln!(file, "{addr}").map_err(|err| format!("write daemon lock addr: {err}"))?;
        file.flush()
            .map_err(|err| format!("flush daemon lock: {err}"))
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Return the bound listen address of a running daemon for `db_path`, or
/// `None` if no live daemon is recorded.
///
/// This is the core-owned affordance protocol code uses to ask "is a daemon
/// running locally, and where is it listening?" without persisting the answer
/// in any protocol-owned table. The lock file is removed when the daemon
/// exits cleanly; for a hard crash, the PID liveness check filters out the
/// stale entry. Sibling CLI processes that share the database file read the
/// same lock file the daemon writes.
pub fn current_listen_addr(db_path: &Path) -> Result<Option<SocketAddr>, String> {
    let path = lock_path(db_path);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("read daemon lock: {err}")),
    };
    let mut lines = text.lines();
    let Some(pid_line) = lines.next() else {
        return Ok(None);
    };
    let Ok(pid) = pid_line.trim().parse::<u32>() else {
        return Ok(None);
    };
    if !Path::new(&format!("/proc/{pid}")).exists() {
        return Ok(None);
    }
    let Some(addr_line) = lines.next() else {
        return Ok(None);
    };
    addr_line
        .trim()
        .parse::<SocketAddr>()
        .map(Some)
        .map_err(|err| format!("daemon lock listen addr is invalid: {err}"))
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
    let text = fs::read_to_string(path).map_err(|err| format!("read daemon lock: {err}"))?;
    let pid_line = text.lines().next().unwrap_or("");
    let Ok(pid) = pid_line.trim().parse::<u32>() else {
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
