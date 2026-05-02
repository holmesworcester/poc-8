mod event_modules;
mod network;
mod pipeline;
mod store;
mod wire;

use std::env;
use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;

use event_modules::{connection, content};
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
        Command::Connect { invite } => {
            let addr = connect(&store, &invite).map_err(|err| format!("connect: {err}"))?;
            println!("connected: {addr}");
        }
        Command::Invite { public_addr } => {
            let invite = connection::commands::create_invite(&store, public_addr)
                .map_err(|err| format!("invite: {err}"))?;
            println!("{invite}");
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
                let report =
                    serve(&store, listener, accept_count).map_err(|err| format!("serve: {err}"))?;
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
        invite: String,
    },
    Invite {
        public_addr: SocketAddr,
    },
    Generate {
        num_events: usize,
        event_size: usize,
    },
    Sync {
        listen: Option<SocketAddr>,
        accept_count: usize,
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
            if rest.len() != 2 {
                return Err(usage("connect requires INVITE_LINK"));
            }
            Command::Connect {
                invite: rest[1].clone(),
            }
        }
        "invite" => {
            let mut public_addr = None;
            let mut idx = 1;
            while idx < rest.len() {
                match rest[idx].as_str() {
                    "--public-addr" => {
                        public_addr = Some(
                            rest.get(idx + 1)
                                .ok_or_else(|| usage("invite requires --public-addr ADDR"))?
                                .parse::<SocketAddr>()
                                .map_err(|_| usage("invite requires --public-addr ADDR"))?,
                        );
                        idx += 2;
                    }
                    other => return Err(usage(&format!("unknown invite option `{other}`"))),
                }
            }
            Command::Invite {
                public_addr: public_addr
                    .ok_or_else(|| usage("invite requires --public-addr ADDR"))?,
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
                    other => return Err(usage(&format!("unknown sync option `{other}`"))),
                }
            }
            if accept_count == 0 {
                return Err(usage("sync --accept requires a positive integer"));
            }
            Command::Sync {
                listen,
                accept_count,
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
        "{message}\nusage:\n  topo --db PATH invite --public-addr ADDR\n  topo --db PATH connect INVITE_LINK\n  topo --db PATH generate NUM_EVENTS EVENT_SIZE_BYTES\n  topo --db PATH sync [--listen IP PORT --accept N]\n  topo --db PATH count"
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

fn connect(store: &Store, invite: &str) -> Result<SocketAddr, String> {
    let addr = connection::commands::invite_addr(invite)?;
    let mut stream = network::connect(addr).map_err(|err| format!("open tcp stream: {err}"))?;
    let request = connection::commands::create_request(store, invite)?;
    network::write_frames(&mut stream, vec![request.bytes])?;
    let report = drive_stream(
        store,
        &mut stream,
        addr,
        pipeline::IngestOptions {
            record_transport_target: true,
        },
        None,
    )?;
    if report.established_connections == 0 {
        return Err("connection was not established".to_string());
    }
    Ok(request.addr)
}

fn serve(store: &Store, listener: TcpListener, accept_count: usize) -> Result<ServeReport, String> {
    let mut report = ServeReport::default();
    for _ in 0..accept_count {
        let (mut stream, peer_addr) = listener
            .accept()
            .map_err(|err| format!("accept tcp stream: {err}"))?;
        let first_frame =
            network::read_frame(&mut stream).map_err(|err| format!("read first frame: {err}"))?;
        let stream_report = drive_stream(
            store,
            &mut stream,
            peer_addr,
            pipeline::IngestOptions {
                record_transport_target: false,
            },
            Some(first_frame),
        )?;
        report.received_events += stream_report.received_events;
        report.accepted_connections += 1;
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
    let start = pipeline::start_sync(store, route)?;
    report.sent_events += start.sent_events;
    network::write_frames(&mut stream, start.outgoing)?;
    let stream_report = drive_stream(
        store,
        &mut stream,
        route.addr,
        pipeline::IngestOptions {
            record_transport_target: false,
        },
        None,
    )?;
    report.sent_events += stream_report.sent_events;
    report.received_events += stream_report.received_events;
    Ok(report)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StreamReport {
    established_connections: usize,
    sent_events: usize,
    received_events: usize,
}

fn drive_stream(
    store: &Store,
    stream: &mut TcpStream,
    origin: SocketAddr,
    options: pipeline::IngestOptions,
    first_frame: Option<Vec<u8>>,
) -> Result<StreamReport, String> {
    let mut report = StreamReport::default();
    if let Some(bytes) = first_frame {
        let result = pipeline::ingest_frame(store, origin, bytes, options)?;
        apply_stream_result(stream, &mut report, result)?;
    }
    loop {
        match network::read_frame(stream) {
            Ok(bytes) => {
                let result = pipeline::ingest_frame(store, origin, bytes, options)?;
                apply_stream_result(stream, &mut report, result)?;
            }
            Err(err) if is_stream_closed(&err) => break,
            Err(err) => return Err(format!("read frame: {err}")),
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(report)
}

fn apply_stream_result(
    stream: &mut TcpStream,
    report: &mut StreamReport,
    result: pipeline::IngestResult,
) -> Result<(), String> {
    report.established_connections += result.established_connections;
    report.sent_events += result.sent_events;
    report.received_events += result.received_events;
    let has_outgoing = !result.outgoing.is_empty();
    network::write_frames(stream, result.outgoing)?;
    if !has_outgoing {
        let _ = stream.shutdown(Shutdown::Write);
    }
    Ok(())
}

fn is_stream_closed(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
    )
}
