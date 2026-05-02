mod event_modules;
mod network;
mod store;
mod wire;

use std::env;
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;

use event_modules::{connection, content, sync};
use store::Store;

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let (db_path, command) = parse_args(args)?;
    let store = Store::open(db_path).map_err(|err| format!("open store: {err}"))?;

    match command {
        Command::Connect { addr: _ } => {
            return Err(usage("connect requires --bootstrap TOKEN"));
        }
        Command::ConnectBootstrap {
            addr,
            bootstrap_token,
        } => {
            connect(&store, addr, &bootstrap_token).map_err(|err| format!("connect: {err}"))?;
            println!("connected: {addr}");
        }
        Command::Generate {
            num_events,
            event_size,
        } => {
            let report = content::commands::generate(&store, num_events, event_size)
                .map_err(|err| format!("generate: {err}"))?;
            println!("generated_events: {}", report.inserted_events);
            println!("event_size_bytes: {event_size}");
            println!("first_timestamp: {}", report.first_timestamp);
            println!("last_timestamp: {}", report.last_timestamp);
        }
        Command::Sync {
            listen,
            accept_count,
            bootstrap_token,
        } => {
            if let Some(addr) = listen {
                let listener = TcpListener::bind(addr).map_err(|err| format!("listen: {err}"))?;
                println!(
                    "listening: {}",
                    listener.local_addr().map_err(|err| err.to_string())?
                );
                std::io::stdout()
                    .flush()
                    .map_err(|err| format!("flush stdout: {err}"))?;
                let report = serve(&store, listener, accept_count, bootstrap_token.as_deref())
                    .map_err(|err| format!("serve: {err}"))?;
                println!("accepted_connections: {}", report.accepted_connections);
                println!("received_events: {}", report.received_events);
            } else {
                let routes = connection::commands::transport_routes(&store)?;
                let report = sync_routes(&store, routes).map_err(|err| format!("sync: {err}"))?;
                println!("routes_synced: {}", report.routes_synced);
                println!("sent_events: {}", report.sent_events);
                println!("received_events: {}", report.received_events);
            }
        }
        Command::Count => {
            let count = store
                .event_count()
                .map_err(|err| format!("count events: {err}"))?;
            let bytes = store
                .payload_bytes()
                .map_err(|err| format!("count bytes: {err}"))?;
            println!("events: {count}");
            println!("payload_bytes: {bytes}");
            println!(
                "connections: {}",
                connection::commands::connection_count(&store)?
            );
            println!(
                "connection_events: {}",
                connection::commands::connection_event_count(&store)?
            );
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Connect {
        addr: SocketAddr,
    },
    ConnectBootstrap {
        addr: SocketAddr,
        bootstrap_token: String,
    },
    Generate {
        num_events: usize,
        event_size: usize,
    },
    Sync {
        listen: Option<SocketAddr>,
        accept_count: usize,
        bootstrap_token: Option<String>,
    },
    Count,
}

fn parse_args(args: Vec<String>) -> Result<(PathBuf, Command), String> {
    let mut iter = args.into_iter();
    let mut db_path = None;
    let mut rest = Vec::new();

    while let Some(arg) = iter.next() {
        if arg == "--db" {
            db_path = iter.next().map(PathBuf::from);
        } else {
            rest.push(arg);
            rest.extend(iter);
            break;
        }
    }

    let db_path = db_path.ok_or_else(|| usage("missing --db PATH"))?;
    let command = rest.first().ok_or_else(|| usage("missing command"))?;
    let parsed = match command.as_str() {
        "connect" => {
            let ip = rest
                .get(1)
                .ok_or_else(|| usage("connect requires IP PORT"))?;
            let port = rest
                .get(2)
                .ok_or_else(|| usage("connect requires IP PORT"))?;
            let addr = format!("{ip}:{port}")
                .parse::<SocketAddr>()
                .map_err(|_| usage("connect requires IP PORT"))?;
            let mut bootstrap_token = None;
            let mut idx = 3;
            while idx < rest.len() {
                match rest[idx].as_str() {
                    "--bootstrap" => {
                        bootstrap_token = rest.get(idx + 1).cloned();
                        idx += 2;
                    }
                    other => return Err(usage(&format!("unknown connect option `{other}`"))),
                }
            }
            if let Some(bootstrap_token) = bootstrap_token {
                Command::ConnectBootstrap {
                    addr,
                    bootstrap_token,
                }
            } else {
                Command::Connect { addr }
            }
        }
        "generate" => {
            let num_events = parse_usize(rest.get(1), "generate requires NUM_EVENTS EVENT_SIZE")?;
            let event_size = parse_usize(rest.get(2), "generate requires NUM_EVENTS EVENT_SIZE")?;
            Command::Generate {
                num_events,
                event_size,
            }
        }
        "sync" => {
            let mut listen = None;
            let mut accept_count = 1usize;
            let mut bootstrap_token = None;
            let mut idx = 1;
            while idx < rest.len() {
                match rest[idx].as_str() {
                    "--listen" => {
                        let ip = rest
                            .get(idx + 1)
                            .ok_or_else(|| usage("sync --listen requires IP PORT"))?;
                        let port = rest
                            .get(idx + 2)
                            .ok_or_else(|| usage("sync --listen requires IP PORT"))?;
                        listen = Some(
                            format!("{ip}:{port}")
                                .parse::<SocketAddr>()
                                .map_err(|_| usage("sync --listen requires IP PORT"))?,
                        );
                        idx += 3;
                    }
                    "--accept" => {
                        accept_count = parse_usize(
                            rest.get(idx + 1),
                            "sync --accept requires a positive integer",
                        )?;
                        idx += 2;
                    }
                    "--bootstrap" => {
                        bootstrap_token = rest.get(idx + 1).cloned();
                        idx += 2;
                    }
                    other => return Err(usage(&format!("unknown sync option `{other}`"))),
                }
            }
            if accept_count == 0 {
                return Err(usage("sync --accept requires a positive integer"));
            }
            Command::Sync {
                listen,
                accept_count,
                bootstrap_token,
            }
        }
        "count" | "status" => Command::Count,
        other => return Err(usage(&format!("unknown command `{other}`"))),
    };

    Ok((db_path, parsed))
}

fn parse_usize(value: Option<&String>, message: &str) -> Result<usize, String> {
    let value = value.ok_or_else(|| usage(message))?;
    let parsed = value.parse::<usize>().map_err(|_| usage(message))?;
    if parsed == 0 {
        return Err(usage(message));
    }
    Ok(parsed)
}

fn usage(message: &str) -> String {
    format!(
        "{message}\nusage:\n  topo --db PATH connect IP PORT --bootstrap TOKEN\n  topo --db PATH generate NUM_EVENTS EVENT_SIZE_BYTES\n  topo --db PATH sync [--listen IP PORT --accept N --bootstrap TOKEN]\n  topo --db PATH count"
    )
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ServeReport {
    accepted_connections: usize,
    received_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CliSyncReport {
    routes_synced: usize,
    sent_events: usize,
    received_events: usize,
}

fn connect(store: &Store, addr: SocketAddr, bootstrap_token: &str) -> Result<(), String> {
    let mut stream = network::connect(addr).map_err(|err| format!("open tcp stream: {err}"))?;
    let request = connection::commands::create_request(store, bootstrap_token)?;
    network::write_frame(&mut stream, &request.bytes)
        .map_err(|err| format!("send request: {err}"))?;
    let response = network::read_frame(&mut stream).map_err(|err| format!("read ack: {err}"))?;
    let result = connection::commands::accept_ack(
        store,
        response,
        request.local_endpoint,
        request.request_id,
    )?;
    let connection_id = result
        .connection_id
        .ok_or_else(|| "connection ack did not establish a connection".to_string())?;
    connection::commands::record_transport_target(store, connection_id, addr)?;
    Ok(())
}

fn serve(
    store: &Store,
    listener: TcpListener,
    accept_count: usize,
    bootstrap_token: Option<&str>,
) -> Result<ServeReport, String> {
    let mut report = ServeReport::default();
    for _ in 0..accept_count {
        let (mut stream, peer_addr) = listener
            .accept()
            .map_err(|err| format!("accept tcp stream: {err}"))?;
        let first_frame =
            network::read_frame(&mut stream).map_err(|err| format!("read first frame: {err}"))?;
        if connection::commands::is_connection_event(&first_frame) {
            let bootstrap_token = bootstrap_token
                .ok_or_else(|| "connection request requires --bootstrap TOKEN".to_string())?;
            let result = connection::commands::accept_request(store, first_frame, bootstrap_token)?;
            if let Some(response) = result.response {
                network::write_frame(&mut stream, &response)
                    .map_err(|err| format!("send connection response: {err}"))?;
            }
            let connection_id = result
                .connection_id
                .ok_or_else(|| "connection request did not establish a connection".to_string())?;
            connection::commands::record_transport_target(store, connection_id, peer_addr)?;
            report.accepted_connections += 1;
        } else {
            report.received_events += serve_sync_frames(store, &mut stream, first_frame)?;
            report.accepted_connections += 1;
        }
    }
    Ok(report)
}

fn sync_routes(
    store: &Store,
    routes: Vec<connection::commands::TransportRoute>,
) -> Result<CliSyncReport, String> {
    let mut report = CliSyncReport::default();
    for route in routes {
        let route_report = sync_route(store, route)?;
        report.routes_synced += 1;
        report.sent_events += route_report.sent_events;
        report.received_events += route_report.received_events;
    }
    Ok(report)
}

fn sync_route(
    store: &Store,
    route: connection::commands::TransportRoute,
) -> Result<CliSyncReport, String> {
    let mut stream =
        network::connect(route.addr).map_err(|err| format!("open tcp stream: {err}"))?;
    let mut report = CliSyncReport {
        routes_synced: 1,
        ..CliSyncReport::default()
    };

    let start = sync::commands::emit_start(store, route.connection_id, |bytes| {
        write_transport_frame(&mut stream, bytes)
    })?;
    report.sent_events += start.sent_events;

    let incoming = read_sync_group(store, &mut stream)?;
    let mut wrote_answer = false;
    let answer = sync::commands::emit_answer_response(store, incoming, |bytes| {
        wrote_answer = true;
        write_transport_frame(&mut stream, bytes)
    })?;
    report.sent_events += answer.sent_events;
    report.received_events += answer.received_events;
    if !wrote_answer {
        let _ = stream.shutdown(Shutdown::Write);
    }

    if let Some(incoming) = read_optional_sync_group(store, &mut stream)? {
        let final_report = sync::commands::finish(incoming);
        report.received_events += final_report.received_events;
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(report)
}

fn serve_sync_frames(
    store: &Store,
    stream: &mut TcpStream,
    first_frame: Vec<u8>,
) -> Result<usize, String> {
    let incoming = read_sync_group_from_first(store, stream, first_frame)?;
    let start_response = sync::commands::emit_start_response(store, incoming, |bytes| {
        write_transport_frame(stream, bytes)
    })?;
    let mut received_events = start_response.received_events;

    let Some(incoming) = read_optional_sync_group(store, stream)? else {
        return Ok(received_events);
    };
    let finish_response = sync::commands::emit_finish_response(store, incoming, |bytes| {
        write_transport_frame(stream, bytes)
    })?;
    received_events += finish_response.received_events;
    Ok(received_events)
}

fn read_sync_group(
    store: &Store,
    stream: &mut TcpStream,
) -> Result<sync::commands::Incoming, String> {
    let first = network::read_frame(stream).map_err(|err| format!("read sync frame: {err}"))?;
    read_sync_group_from_first(store, stream, first)
}

fn read_optional_sync_group(
    store: &Store,
    stream: &mut TcpStream,
) -> Result<Option<sync::commands::Incoming>, String> {
    match network::read_frame(stream) {
        Ok(first) => read_sync_group_from_first(store, stream, first).map(Some),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(format!("read sync frame: {err}")),
    }
}

fn read_sync_group_from_first(
    store: &Store,
    stream: &mut TcpStream,
    first: Vec<u8>,
) -> Result<sync::commands::Incoming, String> {
    let mut incoming = sync::commands::Incoming::default();
    let mut more = sync::commands::absorb_frame(store, &first, &mut incoming)?;
    while more {
        let bytes = network::read_frame(stream).map_err(|err| format!("read sync frame: {err}"))?;
        more = sync::commands::absorb_frame(store, &bytes, &mut incoming)?;
    }
    Ok(incoming)
}

fn write_transport_frame(stream: &mut TcpStream, bytes: Vec<u8>) -> Result<(), String> {
    network::write_frame(stream, &bytes).map_err(|err| format!("write frame: {err}"))
}
