mod event_modules;
mod network;
mod store;

use std::env;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
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
                let targets = connection::commands::transport_targets(&store)?;
                let report =
                    sync::commands::sync(&store, targets).map_err(|err| format!("sync: {err}"))?;
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
            let message = sync::codec::decode(&first_frame)?;
            report.received_events +=
                sync::commands::serve_first_message(store, &mut stream, message)?;
            report.accepted_connections += 1;
        }
    }
    Ok(report)
}
