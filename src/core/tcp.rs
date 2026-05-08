//! TCP frame pump over opaque network queue rows.
//!
//! This file is deliberately a byte mover. It opens sockets, reads and writes
//! `[u32 length][bytes]` frames, records inbound bytes in the core queue, and
//! drains outbound bytes for the connected route.
//!
//! The protocol boundary is the stored queue rows in `core/network_queues.rs`.
//! On receive, TCP wraps each frame in an `InboundNetworkRow` keyed by the
//! observed `NetworkSource` and inserts it into the inbound queue. An
//! upper-layer worker later claims that row and writes any accepted protocol
//! bytes to its own input queues. On send, callers provide `OutboundNetworkRow`s
//! keyed by one `NetworkTarget`; TCP inserts them into the outbound queue,
//! claims rows for that same target, writes their opaque bytes as frames,
//! deletes the sent core rows, and then reports the sent rows back through
//! `on_sent` so protocol-owned bookkeeping can advance. Core never interprets
//! or constructs protocol bytes.
//!
//! The invariant is routing correctness: each outbound row is sent only on the
//! stream for its `NetworkTarget`, and each inbound row is recorded with the
//! `NetworkSource` observed from the socket before any worker sees the bytes. A
//! frame is first written to a core queue row and then left for admission. The
//! same shape is used on send: callers provide opaque rows, this pump writes
//! those rows in caller order, and then calls back so the caller can update its
//! own send bookkeeping. Keep this file boring; cleverness here usually means a
//! domain worker is missing.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::core::network_queues::{
    self, InboundNetworkRow, NetworkSource, NetworkTarget, OutboundNetworkRow,
};
use crate::core::store::Store;

const MAX_FRAME_BYTES: usize = 128 * 1024 * 1024;
const WRITE_FRAME_BUDGET: Duration = Duration::from_millis(100);

/// Counts observed while pumping one TCP stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamReport {
    pub sent_frames: usize,
    pub received_frames: usize,
}

/// Result of polling a reusable listener once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptReport<T> {
    pub accepted_connections: usize,
    pub value: T,
}

/// Result of serving a fixed number of inbound streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeReport<T> {
    pub local_addr: SocketAddr,
    pub accepted_connections: usize,
    pub value: T,
}

/// Bound TCP listener that can be polled by a caller-owned loop.
pub struct Listener {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl Listener {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept and pump at most one available inbound stream.
    ///
    /// If no stream is ready, the returned report has zero accepted
    /// connections. This gives higher-level schedulers a nonblocking accept
    /// step without moving any byte interpretation into core.
    pub fn accept_available(&self, store: &Store) -> Result<AcceptReport<StreamReport>, String> {
        let (mut stream, source_addr) = match self.listener.accept() {
            Ok(accepted) => accepted,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(AcceptReport {
                    accepted_connections: 0,
                    value: StreamReport::default(),
                })
            }
            Err(err) => return Err(format!("accept tcp stream: {err}")),
        };
        stream
            .set_nonblocking(false)
            .map_err(|err| format!("set stream blocking: {err}"))?;
        stream
            .set_nodelay(true)
            .map_err(|err| format!("set stream nodelay: {err}"))?;
        let value = read_inbound_frames(store, &mut stream, NetworkSource::new(source_addr))?;
        Ok(AcceptReport {
            accepted_connections: 1,
            value,
        })
    }

    /// Accept and pump at most one available inbound stream with caller replies.
    ///
    /// This is still an opaque byte pump. The caller receives queued inbound
    /// rows and may return queued outbound rows for the same route; core only
    /// moves bytes and invokes the send hook after rows are written.
    pub fn accept_exchange_available<T>(
        &self,
        store: &Store,
        value: T,
        on_inbound: impl FnMut(InboundNetworkRow, &mut T) -> Result<Vec<OutboundNetworkRow>, String>,
        on_sent: impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
    ) -> Result<AcceptReport<T>, String> {
        let (mut stream, source_addr) = match self.listener.accept() {
            Ok(accepted) => accepted,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(AcceptReport {
                    accepted_connections: 0,
                    value,
                })
            }
            Err(err) => return Err(format!("accept tcp stream: {err}")),
        };
        stream
            .set_nonblocking(false)
            .map_err(|err| format!("set stream blocking: {err}"))?;
        stream
            .set_nodelay(true)
            .map_err(|err| format!("set stream nodelay: {err}"))?;
        let target = NetworkTarget::new(source_addr);
        let (_, value) = pump_stream(
            store,
            &mut stream,
            target,
            Vec::new(),
            value,
            on_inbound,
            on_sent,
        )?;
        Ok(AcceptReport {
            accepted_connections: 1,
            value,
        })
    }
}

/// Bind a reusable TCP listener for caller-owned scheduling loops.
pub fn listen(listen: SocketAddr) -> Result<Listener, String> {
    let listener = TcpListener::bind(listen).map_err(|err| format!("listen: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("set listener nonblocking: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("listener local addr: {err}"))?;
    Ok(Listener {
        listener,
        local_addr,
    })
}

/// Open a TCP stream, send outbound rows for that target, and return.
///
/// This is the daemon-friendly shape for queued outbound work whose responses
/// will arrive later as ordinary inbound streams. It still stages bytes in the
/// core outbound queue and calls `on_sent` only after bounded socket writes and
/// queue deletion complete. If the remote side stops draining its socket, the write
/// times out and the protocol send rows remain queued for a later pass.
pub fn send_once<T>(
    store: &Store,
    target: NetworkTarget,
    rows: Vec<OutboundNetworkRow>,
    mut value: T,
    mut on_sent: impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
) -> Result<T, String> {
    let mut stream = connect(target.addr()).map_err(|err| format!("open tcp stream: {err}"))?;
    let mut report = StreamReport::default();
    write_outbound(
        store,
        &mut stream,
        target,
        rows,
        &mut value,
        &mut on_sent,
        &mut report,
    )?;
    stream
        .shutdown(Shutdown::Both)
        .map_err(|err| format!("shutdown sent stream: {err}"))?;
    Ok(value)
}

/// Open a stream, send initial opaque rows, then let the caller answer rows.
pub fn connect_exchange<T>(
    store: &Store,
    target: NetworkTarget,
    initial_outbound: Vec<OutboundNetworkRow>,
    value: T,
    on_inbound: impl FnMut(InboundNetworkRow, &mut T) -> Result<Vec<OutboundNetworkRow>, String>,
    on_sent: impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
) -> Result<T, String> {
    let mut stream = connect(target.addr()).map_err(|err| format!("open tcp stream: {err}"))?;
    pump_stream(
        store,
        &mut stream,
        target,
        initial_outbound,
        value,
        on_inbound,
        on_sent,
    )
    .map(|(_, value)| value)
}

/// Serve a fixed number of incoming streams with caller-produced replies.
pub fn serve<T>(
    store: &Store,
    listen: SocketAddr,
    accept_count: usize,
    mut value: T,
    mut on_inbound: impl FnMut(InboundNetworkRow, &mut T) -> Result<Vec<OutboundNetworkRow>, String>,
    mut on_sent: impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
) -> Result<ServeReport<T>, String> {
    let listener = TcpListener::bind(listen).map_err(|err| format!("listen: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("listener local addr: {err}"))?;

    let mut accepted_connections = 0;
    for _ in 0..accept_count {
        let (mut stream, source_addr) = listener
            .accept()
            .map_err(|err| format!("accept tcp stream: {err}"))?;
        stream
            .set_nodelay(true)
            .map_err(|err| format!("set stream nodelay: {err}"))?;
        let target = NetworkTarget::new(source_addr);
        let (_, next_value) = pump_stream(
            store,
            &mut stream,
            target,
            Vec::new(),
            value,
            &mut on_inbound,
            &mut on_sent,
        )?;
        value = next_value;
        accepted_connections += 1;
    }

    Ok(ServeReport {
        local_addr,
        accepted_connections,
        value,
    })
}

fn pump_stream<T>(
    store: &Store,
    stream: &mut TcpStream,
    target: NetworkTarget,
    initial_outbound: Vec<OutboundNetworkRow>,
    mut value: T,
    mut on_inbound: impl FnMut(InboundNetworkRow, &mut T) -> Result<Vec<OutboundNetworkRow>, String>,
    mut on_sent: impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
) -> Result<(StreamReport, T), String> {
    let mut report = StreamReport::default();
    let mut write_open = true;
    write_outbound(
        store,
        stream,
        target,
        initial_outbound,
        &mut value,
        &mut on_sent,
        &mut report,
    )?;

    loop {
        let bytes = match read_frame(stream) {
            Ok(bytes) => bytes,
            Err(err) if is_stream_closed(&err) => break,
            Err(err) => return Err(format!("read frame: {err}")),
        };
        report.received_frames += 1;

        let inbound = InboundNetworkRow::new(NetworkSource::new(target.addr()), bytes);
        network_queues::enqueue_inbound(store, std::slice::from_ref(&inbound))?;
        let outbound = on_inbound(inbound.clone(), &mut value)?;
        network_queues::delete_inbound(store, std::slice::from_ref(&inbound))?;

        if outbound.is_empty() {
            if write_open {
                stream
                    .shutdown(Shutdown::Write)
                    .map_err(|err| format!("shutdown stream write: {err}"))?;
                write_open = false;
            }
        } else {
            write_outbound(
                store,
                stream,
                target,
                outbound,
                &mut value,
                &mut on_sent,
                &mut report,
            )?;
        }
    }

    Ok((report, value))
}

// Drive one inbound stream until the remote side closes it. Every frame is
// queued before the admission worker sees it, which keeps the core/protocol
// handoff visible and retryable.
fn read_inbound_frames(
    store: &Store,
    stream: &mut TcpStream,
    source: NetworkSource,
) -> Result<StreamReport, String> {
    let mut report = StreamReport::default();
    loop {
        let bytes = match read_frame(stream) {
            Ok(bytes) => bytes,
            Err(err) if is_stream_closed(&err) => break,
            Err(err) => return Err(format!("read frame: {err}")),
        };
        report.received_frames += 1;

        let inbound = InboundNetworkRow::new(source, bytes);
        network_queues::enqueue_inbound(store, std::slice::from_ref(&inbound))?;
    }

    Ok(report)
}

// Commit rows to the outbound queue before writing them. The caller's `on_sent`
// hook runs only after the rows were written and removed from the core queue.
// The provided order is the stream order. Some protocol handshakes need an
// authorization frame before later frames on the same stream; the generic queue
// key is deterministic for idempotence, not an ordering primitive.
fn write_outbound<T>(
    store: &Store,
    stream: &mut TcpStream,
    target: NetworkTarget,
    rows: Vec<OutboundNetworkRow>,
    value: &mut T,
    on_sent: &mut impl FnMut(&[OutboundNetworkRow], &mut T) -> Result<(), String>,
    report: &mut StreamReport,
) -> Result<(), String> {
    if rows.is_empty() {
        return Ok(());
    }
    ensure_target(target, &rows)?;
    network_queues::enqueue_outbound(store, &rows)?;
    let claimed = network_queues::claim_outbound_for_target(store, target, rows.len())?;
    if rows
        .iter()
        .any(|row| !claimed.iter().any(|claimed| claimed.key == row.key))
    {
        return Err("queued outbound network row was not claimable for stream target".to_string());
    }
    for row in &rows {
        write_frame(stream, &row.bytes).map_err(|err| format!("write frame: {err}"))?;
    }
    network_queues::delete_outbound(store, &rows)?;
    on_sent(&rows, value)?;
    report.sent_frames += rows.len();
    Ok(())
}

fn ensure_target(target: NetworkTarget, rows: &[OutboundNetworkRow]) -> Result<(), String> {
    if rows.iter().all(|row| row.target == target) {
        return Ok(());
    }
    Err("outbound network row target does not match stream target".to_string())
}

fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    write_frame_with_budget(stream, bytes, WRITE_FRAME_BUDGET)
}

fn write_frame_with_budget(
    stream: &mut TcpStream,
    bytes: &[u8],
    budget: Duration,
) -> std::io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + budget;
    let result = (|| {
        write_all_until(stream, &len.to_be_bytes(), deadline)?;
        write_all_until(stream, bytes, deadline)?;
        stream.flush()
    })();
    let reset = stream.set_nonblocking(false);
    match (result, reset) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
    }
}

fn write_all_until(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tcp frame write budget exhausted",
            ));
        }
        match stream.write(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "tcp stream accepted zero bytes",
                ))
            }
            Ok(n) => bytes = &bytes[n..],
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

// The frame format is fixed and intentionally not self-describing. Type tags,
// encryption, and validation are all properties of the bytes carried inside the
// frame and are owned above this layer.
fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn is_stream_closed(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn write_frame_sends_length_prefixed_bytes_within_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let reader = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut len = [0; 4];
            stream.read_exact(&mut len).expect("read len");
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).expect("read body");
            body
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        write_frame_with_budget(&mut stream, b"abc", Duration::from_secs(1)).expect("write frame");

        assert_eq!(reader.join().expect("reader thread"), b"abc");
    }

    #[test]
    fn write_frame_zero_budget_times_out_before_blocking() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let reader = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept");
            thread::sleep(Duration::from_millis(20));
        });

        let mut stream = TcpStream::connect(addr).expect("connect");
        let err = write_frame_with_budget(&mut stream, b"abc", Duration::ZERO)
            .expect_err("zero budget should time out");

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        reader.join().expect("reader thread");
    }
}
