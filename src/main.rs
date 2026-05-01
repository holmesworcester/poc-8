use rusqlite::{params, Connection};
use std::env;
use std::fs;
use std::path::PathBuf;
use topo::{event_modules, pipeline};

const DRAIN_BATCH: usize = 512;

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let (db_path, command) = parse_args(args)?;
    if let Command::Completions { shell } = command {
        println!("# topo {shell} completions");
        println!(
            "topo --db <path> create-workspace send generate send-file save-file messages files view workspaces event sync-from"
        );
        return Ok(());
    }

    let conn = pipeline::open_path(&db_path).map_err(|err| format!("open db: {err}"))?;
    let now_ms = now_ms();

    match command {
        Command::CreateWorkspace { name } => {
            let workspace_id = deterministic_id(b"workspace:", name.as_bytes());
            let bytes = event_modules::encode_workspace(workspace_id, &name);
            let event_id = pipeline::event_id(&bytes);
            pipeline::ingest_local(&conn, &bytes, now_ms)
                .map_err(|err| format!("ingest workspace: {err}"))?;
            drain_until_idle(&conn, now_ms)?;

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
            drain_until_idle(&conn, now_ms)?;

            println!("workspace: {workspace_name}");
            println!("event_id: {}", hex_id(&event_id));
        }
        Command::GenerateMessages { count, prefix } => {
            let (workspace_id, workspace_event_id, workspace_name) = active_workspace(&conn)?;
            let (inserted_events, projected_events) = with_immediate_transaction(&conn, || {
                let mut inserted_events = 0;
                for idx in 0..count {
                    let body = format!("{prefix} {idx:06}");
                    let bytes = event_modules::encode_message(
                        workspace_id,
                        workspace_event_id,
                        [0; 32],
                        [0; 32],
                        &body,
                    );
                    match pipeline::ingest_local(&conn, &bytes, now_ms)
                        .map_err(|err| format!("ingest generated message: {err}"))?
                    {
                        pipeline::IngestOutcome::InsertedReady { .. }
                        | pipeline::IngestOutcome::InsertedBlocked { .. } => inserted_events += 1,
                        pipeline::IngestOutcome::Duplicate { .. } => {}
                    }
                }
                let projected_events = drain_until_idle(&conn, now_ms)?;
                Ok((inserted_events, projected_events))
            })?;

            println!("workspace: {workspace_name}");
            println!("generated_messages: {inserted_events}");
            println!("projected_events: {projected_events}");
        }
        Command::SendFile { path } => {
            let (workspace_id, workspace_event_id, workspace_name) = active_workspace(&conn)?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| "send-file path must have a utf-8 file name".to_string())?
                .to_string();
            let bytes =
                fs::read(&path).map_err(|err| format!("read file {}: {err}", path.display()))?;
            let content_hash = blake3::hash(&bytes).to_hex().to_string();
            let encoded =
                event_modules::encode_file(workspace_id, workspace_event_id, &name, &bytes);
            let event_id = pipeline::event_id(&encoded);
            pipeline::ingest_local(&conn, &encoded, now_ms)
                .map_err(|err| format!("ingest file: {err}"))?;
            drain_until_idle(&conn, now_ms)?;

            println!("workspace: {workspace_name}");
            println!("file: {name}");
            println!("bytes: {}", bytes.len());
            println!("content_hash: {content_hash}");
            println!("event_id: {}", hex_id(&event_id));
        }
        Command::SaveFile { selector, out_path } => {
            let (name, bytes) = file_by_selector(&conn, &selector)?;
            fs::write(&out_path, &bytes)
                .map_err(|err| format!("write file {}: {err}", out_path.display()))?;

            println!("file: {name}");
            println!("bytes: {}", bytes.len());
            println!("content_hash: {}", blake3::hash(&bytes).to_hex());
            println!("wrote: {}", out_path.display());
        }
        Command::React { emoji, selector } => {
            let (workspace_id, message_event_id) = message_id_by_selector(&conn, &selector)?;
            let bytes = event_modules::encode_reaction(workspace_id, message_event_id, &emoji);
            let event_id = pipeline::event_id(&bytes);
            pipeline::ingest_local(&conn, &bytes, now_ms)
                .map_err(|err| format!("ingest reaction: {err}"))?;
            drain_until_idle(&conn, now_ms)?;

            println!("Reacted");
            println!("event_id: {}", hex_id(&event_id));
        }
        Command::DeleteMessage { selector } => {
            let (workspace_id, message_event_id) = message_id_by_selector(&conn, &selector)?;
            let bytes = event_modules::encode_message_deletion(workspace_id, message_event_id);
            let event_id = pipeline::event_id(&bytes);
            pipeline::ingest_local(&conn, &bytes, now_ms)
                .map_err(|err| format!("ingest message deletion: {err}"))?;
            drain_until_idle(&conn, now_ms)?;

            println!("Deleted");
            println!("event_id: {}", hex_id(&event_id));
        }
        Command::View => {
            print_view(&conn)?;
        }
        Command::Messages => {
            print_messages(&conn)?;
        }
        Command::Files => {
            print_files(&conn)?;
        }
        Command::Workspaces => {
            print_workspaces(&conn)?;
        }
        Command::EventList {
            ids_only,
            type_filter,
        } => {
            print_event_list(&conn, ids_only, type_filter.as_deref())?;
        }
        Command::EventTree => {
            print_event_tree(&conn)?;
        }
        Command::EventShow { prefix } => {
            print_event_show(&conn, &prefix)?;
        }
        Command::SyncFrom { peer_db } => {
            let report = sync_from(&conn, peer_db, now_ms)?;
            println!("imported_events: {}", report.imported_events);
            println!("projected_events: {}", report.projected_events);
        }
        Command::SyncRoundAll => {
            println!("sync round all: no configured peers");
        }
        Command::Status => {
            let events: i64 = conn
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
                .map_err(|err| format!("count events: {err}"))?;
            let messages: i64 = conn
                .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
                .map_err(|err| format!("count messages: {err}"))?;
            let files: i64 = conn
                .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
                .map_err(|err| format!("count files: {err}"))?;
            println!("events: {events}");
            println!("messages: {messages}");
            println!("files: {files}");
        }
        Command::Completions { .. } => unreachable!("handled before DB open"),
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    CreateWorkspace {
        name: String,
    },
    Send {
        body: String,
    },
    GenerateMessages {
        count: usize,
        prefix: String,
    },
    SendFile {
        path: PathBuf,
    },
    SaveFile {
        selector: String,
        out_path: PathBuf,
    },
    React {
        emoji: String,
        selector: String,
    },
    DeleteMessage {
        selector: String,
    },
    View,
    Messages,
    Files,
    Workspaces,
    EventList {
        ids_only: bool,
        type_filter: Option<String>,
    },
    EventTree,
    EventShow {
        prefix: String,
    },
    SyncFrom {
        peer_db: PathBuf,
    },
    SyncRoundAll,
    Status,
    Completions {
        shell: String,
    },
}

fn parse_args(args: Vec<String>) -> Result<(PathBuf, Command), String> {
    if args.first().is_some_and(|arg| arg == "completions") {
        let shell = args
            .get(1)
            .cloned()
            .ok_or_else(|| usage("completions requires a shell"))?;
        return Ok((PathBuf::from(":memory:"), Command::Completions { shell }));
    }

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
        "generate" => {
            let count = option_value(&rest[1..], "--count")?
                .parse::<usize>()
                .map_err(|_| usage("generate --count requires a positive integer"))?;
            if count == 0 {
                return Err(usage("generate --count requires a positive integer"));
            }
            let prefix =
                optional_value(&rest[1..], "--prefix").unwrap_or_else(|| "message".to_string());
            Command::GenerateMessages { count, prefix }
        }
        "send-file" => {
            let path = rest
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| usage("send-file requires a path"))?;
            Command::SendFile { path }
        }
        "save-file" => {
            let selector = rest
                .get(1)
                .cloned()
                .ok_or_else(|| usage("save-file requires a file selector"))?;
            let out_path = option_value(&rest[2..], "--out").map(PathBuf::from)?;
            Command::SaveFile { selector, out_path }
        }
        "react" => {
            let emoji = rest
                .get(1)
                .cloned()
                .ok_or_else(|| usage("react requires emoji"))?;
            let selector = rest
                .get(2)
                .cloned()
                .ok_or_else(|| usage("react requires message selector"))?;
            Command::React { emoji, selector }
        }
        "delete-message" => {
            let selector = rest
                .get(1)
                .cloned()
                .ok_or_else(|| usage("delete-message requires message selector"))?;
            Command::DeleteMessage { selector }
        }
        "view" => Command::View,
        "messages" => Command::Messages,
        "files" => Command::Files,
        "workspaces" => Command::Workspaces,
        "event" => parse_event_command(&rest[1..])?,
        "sync-from" => {
            let peer_db = rest
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| usage("sync-from requires peer DB path"))?;
            Command::SyncFrom { peer_db }
        }
        "sync"
            if rest.get(1).map(String::as_str) == Some("round")
                && rest.get(2).map(String::as_str) == Some("all") =>
        {
            Command::SyncRoundAll
        }
        "status" => Command::Status,
        other => return Err(usage(&format!("unknown command `{other}`"))),
    };

    Ok((db_path, command))
}

fn parse_event_command(args: &[String]) -> Result<Command, String> {
    match args.first().map(String::as_str) {
        Some("list") => {
            let mut ids_only = false;
            let mut type_filter = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--ids-only" => ids_only = true,
                    "--type" => {
                        i += 1;
                        type_filter = Some(
                            args.get(i)
                                .cloned()
                                .ok_or_else(|| usage("event list --type requires value"))?,
                        );
                    }
                    other => return Err(usage(&format!("unknown event list option `{other}`"))),
                }
                i += 1;
            }
            Ok(Command::EventList {
                ids_only,
                type_filter,
            })
        }
        Some("tree") => Ok(Command::EventTree),
        Some("show") => {
            let prefix = args
                .get(1)
                .cloned()
                .ok_or_else(|| usage("event show requires an id prefix"))?;
            Ok(Command::EventShow { prefix })
        }
        _ => Err(usage("event requires list, tree, or show")),
    }
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

fn optional_value(args: &[String], name: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            return iter.next().cloned();
        }
    }
    None
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

        for message in visible_messages(conn, Some(workspace_id))? {
            println!("- {}", message.body);
            for reaction in reactions_for(conn, &message.event_id)? {
                println!("  {reaction}");
            }
        }
    }

    Ok(())
}

fn print_messages(conn: &Connection) -> Result<(), String> {
    let messages = visible_messages(conn, None)?;
    println!("MESSAGES ({}):", messages.len());
    for (idx, message) in messages.iter().enumerate() {
        println!("{}. {}", idx + 1, message.body);
        for reaction in reactions_for(conn, &message.event_id)? {
            println!("   {reaction}");
        }
    }
    Ok(())
}

fn print_files(conn: &Connection) -> Result<(), String> {
    let files = file_rows(conn)?;
    println!("FILES ({}):", files.len());
    for (idx, file) in files.iter().enumerate() {
        println!(
            "{}. {} ({} bytes) {}",
            idx + 1,
            file.name,
            file.byte_len,
            file.content_hash
        );
    }
    Ok(())
}

fn print_workspaces(conn: &Connection) -> Result<(), String> {
    let mut stmt = conn
        .prepare("SELECT name FROM workspaces ORDER BY name")
        .map_err(|err| format!("query workspaces: {err}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|err| format!("read workspaces: {err}"))?;
    let names = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| err.to_string())?;

    println!("WORKSPACES ({}):", names.len());
    for (idx, name) in names.iter().enumerate() {
        println!("{}. {name}", idx + 1);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MessageRow {
    event_id: [u8; 32],
    workspace_id: [u8; 32],
    body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileRow {
    name: String,
    byte_len: i64,
    content_hash: String,
}

fn visible_messages(
    conn: &Connection,
    workspace_id: Option<[u8; 32]>,
) -> Result<Vec<MessageRow>, String> {
    let mut sql = String::from(
        "SELECT event_id, workspace_id, body
         FROM messages
         WHERE NOT EXISTS (
           SELECT 1 FROM deleted_messages
           WHERE deleted_messages.message_event_id = messages.event_id
         )",
    );
    if workspace_id.is_some() {
        sql.push_str(" AND workspace_id = ?1");
    }
    sql.push_str(" ORDER BY event_id");

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| format!("query messages: {err}"))?;
    let mapper = |row: &rusqlite::Row<'_>| {
        Ok(MessageRow {
            event_id: vec_to_id(row.get::<_, Vec<u8>>(0)?),
            workspace_id: vec_to_id(row.get::<_, Vec<u8>>(1)?),
            body: row.get::<_, String>(2)?,
        })
    };
    let rows = if let Some(workspace_id) = workspace_id {
        stmt.query_map(params![workspace_id.to_vec()], mapper)
            .map_err(|err| format!("read messages: {err}"))?
            .collect::<rusqlite::Result<Vec<_>>>()
    } else {
        stmt.query_map([], mapper)
            .map_err(|err| format!("read messages: {err}"))?
            .collect::<rusqlite::Result<Vec<_>>>()
    };
    rows.map_err(|err| format!("message row: {err}"))
}

fn file_rows(conn: &Connection) -> Result<Vec<FileRow>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT name, byte_len, content_hash
             FROM files
             ORDER BY event_id",
        )
        .map_err(|err| format!("query files: {err}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(FileRow {
                name: row.get::<_, String>(0)?,
                byte_len: row.get::<_, i64>(1)?,
                content_hash: row.get::<_, String>(2)?,
            })
        })
        .map_err(|err| format!("read files: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("file row: {err}"))
}

fn reactions_for(conn: &Connection, message_event_id: &[u8; 32]) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT emoji FROM reactions
             WHERE message_event_id = ?1
               AND NOT EXISTS (
                 SELECT 1 FROM deleted_messages
                 WHERE deleted_messages.message_event_id = reactions.message_event_id
               )
             ORDER BY event_id",
        )
        .map_err(|err| format!("query reactions: {err}"))?;
    let rows = stmt
        .query_map(params![message_event_id.to_vec()], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|err| format!("read reactions: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("reaction row: {err}"))
}

fn message_id_by_selector(
    conn: &Connection,
    selector: &str,
) -> Result<([u8; 32], [u8; 32]), String> {
    let number = selector
        .strip_prefix('#')
        .unwrap_or(selector)
        .parse::<usize>()
        .map_err(|_| "invalid message number".to_string())?;
    if number == 0 {
        return Err("invalid message number".to_string());
    }
    let messages = visible_messages(conn, None)?;
    let Some(message) = messages.get(number - 1) else {
        return Err("invalid message number".to_string());
    };
    Ok((message.workspace_id, message.event_id))
}

fn file_by_selector(conn: &Connection, selector: &str) -> Result<(String, Vec<u8>), String> {
    let number = selector
        .strip_prefix('#')
        .unwrap_or(selector)
        .parse::<usize>()
        .map_err(|_| "invalid file number".to_string())?;
    if number == 0 {
        return Err("invalid file number".to_string());
    }
    conn.query_row(
        "SELECT name, bytes
         FROM files
         ORDER BY event_id
         LIMIT 1 OFFSET ?1",
        params![(number - 1) as i64],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )
    .map_err(|_| "invalid file number".to_string())
}

fn print_event_list(
    conn: &Connection,
    ids_only: bool,
    type_filter: Option<&str>,
) -> Result<(), String> {
    let events = event_rows(conn, type_filter)?;
    if ids_only {
        println!("EVENT IDS ({}):", events.len());
        for event in events {
            println!("{}", hex_id(&event.event_id));
        }
        return Ok(());
    }
    if events.is_empty() {
        println!("no events");
        return Ok(());
    }
    for event in &events {
        println!(
            "{} {} deps: {}",
            event.type_name,
            short_hex(&event.event_id),
            event
                .deps
                .iter()
                .map(short_hex)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!("{} events. Sorted by insertion order.", events.len());
    Ok(())
}

fn print_event_tree(conn: &Connection) -> Result<(), String> {
    let events = event_rows(conn, None)?;
    if events.is_empty() {
        println!("no events");
        return Ok(());
    }
    for (idx, event) in events.iter().enumerate() {
        let connector = if idx + 1 == events.len() {
            "└──"
        } else {
            "├──"
        };
        let root = if event.deps.is_empty() { " root" } else { "" };
        println!(
            "{connector} {} {}{root}",
            event.type_name,
            short_hex(&event.event_id)
        );
    }
    println!("{} events.", events.len());
    Ok(())
}

fn print_event_show(conn: &Connection, prefix: &str) -> Result<(), String> {
    let matches = event_rows(conn, None)?
        .into_iter()
        .filter(|event| hex_id(&event.event_id).starts_with(prefix))
        .collect::<Vec<_>>();
    if matches.is_empty() {
        println!("No events matching that prefix.");
        return Ok(());
    }
    for event in matches {
        println!("{} {}", event.type_name, hex_id(&event.event_id));
        println!(
            "deps: {}",
            event.deps.iter().map(hex_id).collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EventListRow {
    event_id: [u8; 32],
    type_name: &'static str,
    deps: Vec<[u8; 32]>,
}

fn event_rows(conn: &Connection, type_filter: Option<&str>) -> Result<Vec<EventListRow>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT event_id, canonical_bytes FROM events
             WHERE status != 'purged'
             ORDER BY created_at_ms, event_id",
        )
        .map_err(|err| format!("query events: {err}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                vec_to_id(row.get::<_, Vec<u8>>(0)?),
                row.get::<_, Vec<u8>>(1)?,
            ))
        })
        .map_err(|err| format!("read events: {err}"))?;

    let mut events = Vec::new();
    for row in rows {
        let (event_id, bytes) = row.map_err(|err| format!("event row: {err}"))?;
        let event = event_modules::decode(&bytes).map_err(|err| format!("decode event: {err}"))?;
        let type_name = event_modules::event_type_name(&event);
        if type_filter.is_some_and(|filter| filter != type_name) {
            continue;
        }
        events.push(EventListRow {
            event_id,
            type_name,
            deps: event.dependency_ids(),
        });
    }
    Ok(events)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncReport {
    imported_events: usize,
    projected_events: usize,
}

fn sync_from(conn: &Connection, peer_db: PathBuf, now_ms: i64) -> Result<SyncReport, String> {
    if !peer_db.exists() {
        return Err(format!("peer db does not exist: {}", peer_db.display()));
    }
    let events = missing_peer_event_bytes(conn, peer_db)?;

    with_immediate_transaction(conn, || {
        let mut imported_events = 0;
        for event in &events {
            match pipeline::ingest_local(conn, event, now_ms)
                .map_err(|err| format!("ingest synced event: {err}"))?
            {
                pipeline::IngestOutcome::InsertedReady { .. }
                | pipeline::IngestOutcome::InsertedBlocked { .. } => imported_events += 1,
                pipeline::IngestOutcome::Duplicate { .. } => {}
            }
        }

        Ok(SyncReport {
            imported_events,
            projected_events: drain_until_idle(conn, now_ms)?,
        })
    })
}

fn missing_peer_event_bytes(conn: &Connection, peer_db: PathBuf) -> Result<Vec<Vec<u8>>, String> {
    let peer_db = peer_db.to_string_lossy().to_string();
    conn.execute("ATTACH DATABASE ?1 AS peer", params![peer_db])
        .map_err(|err| format!("attach peer db: {err}"))?;

    let result = (|| {
        let mut stmt = conn
            .prepare(
                "SELECT p.canonical_bytes
                 FROM peer.events p
                 WHERE p.status != 'purged'
                   AND NOT EXISTS (
                     SELECT 1 FROM main.events e
                     WHERE e.event_id = p.event_id
                   )
                 ORDER BY p.created_at_ms, p.event_id",
            )
            .map_err(|err| format!("query peer events: {err}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|err| format!("read peer events: {err}"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| format!("peer event row: {err}"))
    })();

    let detach = conn.execute_batch("DETACH DATABASE peer");
    match (result, detach) {
        (Ok(events), Ok(())) => Ok(events),
        (Err(err), _) => Err(err),
        (Ok(_), Err(err)) => Err(format!("detach peer db: {err}")),
    }
}

fn drain_until_idle(conn: &Connection, now_ms: i64) -> Result<usize, String> {
    let mut total = 0;
    loop {
        let outcomes = pipeline::drain_ready(conn, DRAIN_BATCH, now_ms)
            .map_err(|err| format!("project: {err}"))?;
        if outcomes.is_empty() {
            return Ok(total);
        }
        total += outcomes.len();
    }
}

fn with_immediate_transaction<T>(
    conn: &Connection,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|err| format!("begin transaction: {err}"))?;

    match f() {
        Ok(value) => {
            conn.execute_batch("COMMIT")
                .map_err(|err| format!("commit transaction: {err}"))?;
            Ok(value)
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
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

fn short_hex(id: &[u8; 32]) -> String {
    let hex = hex_id(id);
    format!("({})", &hex[..8])
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as i64
}

fn usage(message: &str) -> String {
    format!(
        "{message}\nusage:\n  topo --db PATH create-workspace --workspace-name NAME\n  topo --db PATH send TEXT\n  topo --db PATH generate --count N [--prefix TEXT]\n  topo --db PATH send-file PATH\n  topo --db PATH save-file N --out PATH\n  topo --db PATH sync-from PEER_DB\n  topo --db PATH view\n  topo --db PATH status"
    )
}
