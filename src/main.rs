use rusqlite::{params, Connection};
use std::env;
use std::path::PathBuf;
use topo::{event_modules, pipeline};

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let (db_path, command) = parse_args(args)?;
    let conn = pipeline::open_path(&db_path).map_err(|err| format!("open db: {err}"))?;
    let now_ms = now_ms();

    match command {
        Command::CreateWorkspace { name } => {
            let workspace_id = deterministic_id(b"workspace:", name.as_bytes());
            let bytes = event_modules::encode_workspace(workspace_id, &name);
            let event_id = pipeline::event_id(&bytes);
            pipeline::ingest_local(&conn, &bytes, now_ms)
                .map_err(|err| format!("ingest workspace: {err}"))?;
            pipeline::drain_ready(&conn, 64, now_ms)
                .map_err(|err| format!("project workspace: {err}"))?;

            println!("workspace: {name}");
            println!("workspace_id: {}", hex_id(&workspace_id));
            println!("workspace_event_id: {}", hex_id(&event_id));
        }
        Command::Send { body } => {
            let (workspace_id, workspace_event_id, workspace_name) = active_workspace(&conn)?;
            let bytes = event_modules::encode_message(
                workspace_id,
                workspace_event_id,
                [0; 32],
                [0; 32],
                &body,
            );
            let event_id = pipeline::event_id(&bytes);
            pipeline::ingest_local(&conn, &bytes, now_ms)
                .map_err(|err| format!("ingest message: {err}"))?;
            pipeline::drain_ready(&conn, 64, now_ms)
                .map_err(|err| format!("project message: {err}"))?;

            println!("workspace: {workspace_name}");
            println!("event_id: {}", hex_id(&event_id));
        }
        Command::View => {
            print_view(&conn)?;
        }
        Command::Status => {
            let events: i64 = conn
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .map_err(|err| format!("count events: {err}"))?;
            let messages: i64 = conn
                .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
                .map_err(|err| format!("count messages: {err}"))?;
            println!("events: {events}");
            println!("messages: {messages}");
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    CreateWorkspace { name: String },
    Send { body: String },
    View,
    Status,
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

    let db_path = db_path.ok_or_else(|| usage("missing --db <path>"))?;
    let command_name = rest.first().ok_or_else(|| usage("missing command"))?;
    let command = match command_name.as_str() {
        "create-workspace" => {
            let name = option_value(&rest[1..], "--workspace-name")?;
            Command::CreateWorkspace { name }
        }
        "send" => {
            let body = rest
                .get(1)
                .cloned()
                .ok_or_else(|| usage("send requires message text"))?;
            Command::Send { body }
        }
        "view" => Command::View,
        "status" => Command::Status,
        other => return Err(usage(&format!("unknown command `{other}`"))),
    };

    Ok((db_path, command))
}

fn option_value(args: &[String], name: &str) -> Result<String, String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            return iter
                .next()
                .cloned()
                .ok_or_else(|| usage(&format!("{name} needs a value")));
        }
    }
    Err(usage(&format!("missing {name}")))
}

fn active_workspace(conn: &Connection) -> Result<([u8; 32], [u8; 32], String), String> {
    conn.query_row(
        "SELECT workspace_id, source_event_id, name
         FROM workspaces
         ORDER BY name, source_event_id
         LIMIT 1",
        [],
        |row| {
            Ok((
                vec_to_id(row.get::<_, Vec<u8>>(0)?),
                vec_to_id(row.get::<_, Vec<u8>>(1)?),
                row.get::<_, String>(2)?,
            ))
        },
    )
    .map_err(|_| "no workspace; run create-workspace first".to_string())
}

fn print_view(conn: &Connection) -> Result<(), String> {
    let mut workspace_stmt = conn
        .prepare("SELECT workspace_id, name FROM workspaces ORDER BY name")
        .map_err(|err| format!("query workspaces: {err}"))?;
    let workspace_rows = workspace_stmt
        .query_map([], |row| {
            Ok((
                vec_to_id(row.get::<_, Vec<u8>>(0)?),
                row.get::<_, String>(1)?,
            ))
        })
        .map_err(|err| format!("read workspaces: {err}"))?;

    for workspace in workspace_rows {
        let (workspace_id, name) = workspace.map_err(|err| format!("workspace row: {err}"))?;
        println!("workspace: {name}");

        let mut message_stmt = conn
            .prepare(
                "SELECT body FROM messages
                 WHERE workspace_id = ?1
                 ORDER BY event_id",
            )
            .map_err(|err| format!("query messages: {err}"))?;
        let messages = message_stmt
            .query_map(params![workspace_id.to_vec()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|err| format!("read messages: {err}"))?;
        for message in messages {
            println!(
                "- {}",
                message.map_err(|err| format!("message row: {err}"))?
            );
        }
    }

    Ok(())
}

fn deterministic_id(prefix: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix);
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

fn vec_to_id(value: Vec<u8>) -> [u8; 32] {
    let mut id = [0; 32];
    id.copy_from_slice(&value);
    id
}

fn hex_id(id: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as i64
}

fn usage(message: &str) -> String {
    format!(
        "{message}\nusage:\n  topo --db PATH create-workspace --workspace-name NAME\n  topo --db PATH send TEXT\n  topo --db PATH view\n  topo --db PATH status"
    )
}
