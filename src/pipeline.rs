use crate::event_modules::{
    self, Event, EventError, Projection, ProjectionContext, ResolvedEvent, RowOp, SqlValue,
};
use rusqlite::{params, types::Value, Connection, OptionalExtension};
use std::collections::HashMap;
use thiserror::Error;

pub type EventId = [u8; 32];
pub type WorkspaceId = [u8; 32];
pub type ConnectionId = [u8; 32];

const STATUS_READY: &str = "ready";
const STATUS_BLOCKED: &str = "blocked";
const STATUS_APPLIED: &str = "applied";
const STATUS_PURGED: &str = "purged";

pub fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}

pub fn open_memory() -> rusqlite::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    ensure_schema(&conn)?;
    Ok(conn)
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS events (
            event_id BLOB PRIMARY KEY NOT NULL,
            canonical_bytes BLOB NOT NULL,
            scope TEXT NOT NULL,
            workspace_id BLOB NOT NULL,
            status TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            expires_at_ms INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_events_status
            ON events(status, created_at_ms);

        CREATE TABLE IF NOT EXISTS blocked_by_event (
            blocked_by_event_id BLOB NOT NULL,
            event_id BLOB NOT NULL,
            PRIMARY KEY(blocked_by_event_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_blocked_by_event_event_id
            ON blocked_by_event(event_id);

        CREATE TABLE IF NOT EXISTS labels (
            subject_event_id BLOB NOT NULL,
            label TEXT NOT NULL,
            source_event_id BLOB NOT NULL,
            PRIMARY KEY(subject_event_id, label, source_event_id)
        );

        CREATE TABLE IF NOT EXISTS outbox (
            connection_id BLOB NOT NULL,
            event_id BLOB NOT NULL,
            queued_at_ms INTEGER NOT NULL,
            PRIMARY KEY(connection_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_outbox_connection
            ON outbox(connection_id, queued_at_ms);

        CREATE TABLE IF NOT EXISTS jobs (
            job_name TEXT PRIMARY KEY NOT NULL,
            next_run_ms INTEGER NOT NULL,
            priority INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_jobs_ready
            ON jobs(next_run_ms, priority);
        ",
    )?;
    event_modules::ensure_schema(conn)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    InsertedReady {
        event_id: EventId,
    },
    InsertedBlocked {
        event_id: EventId,
        blocked_by: Vec<EventId>,
    },
    Duplicate {
        event_id: EventId,
        status: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectOutcome {
    Applied {
        event_id: EventId,
        emitted: Vec<EventId>,
        outbox_inserted: usize,
        unblocked: usize,
    },
    AlreadyApplied {
        event_id: EventId,
    },
}

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Event(#[from] EventError),
    #[error("event not found")]
    NotFound,
    #[error("event is not ready: {0}")]
    NotReady(String),
    #[error("invalid row operation for table {table}: {reason}")]
    InvalidRowOp {
        table: &'static str,
        reason: &'static str,
    },
}

pub fn ingest_local(
    conn: &Connection,
    bytes: &[u8],
    now_ms: i64,
) -> Result<IngestOutcome, PipelineError> {
    let id = event_id(bytes);
    if let Some(status) = get_status(conn, id)? {
        return Ok(IngestOutcome::Duplicate {
            event_id: id,
            status,
        });
    }

    let event = event_modules::decode(bytes)?;
    let blocked_by = missing_or_unapplied_deps(conn, &event)?;
    let status = if blocked_by.is_empty() {
        STATUS_READY
    } else {
        STATUS_BLOCKED
    };

    conn.execute(
        "INSERT INTO events (
            event_id,
            canonical_bytes,
            scope,
            workspace_id,
            status,
            created_at_ms,
            expires_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        params![
            id.to_vec(),
            bytes,
            event.scope().as_str(),
            event.workspace_id().to_vec(),
            status,
            now_ms
        ],
    )?;

    for dep in &blocked_by {
        conn.execute(
            "INSERT OR IGNORE INTO blocked_by_event (blocked_by_event_id, event_id)
             VALUES (?1, ?2)",
            params![dep.to_vec(), id.to_vec()],
        )?;
    }

    if blocked_by.is_empty() {
        Ok(IngestOutcome::InsertedReady { event_id: id })
    } else {
        Ok(IngestOutcome::InsertedBlocked {
            event_id: id,
            blocked_by,
        })
    }
}

pub fn project_ready(
    conn: &Connection,
    id: EventId,
    now_ms: i64,
) -> Result<ProjectOutcome, PipelineError> {
    let Some((bytes, status)) = event_row(conn, id)? else {
        return Err(PipelineError::NotFound);
    };

    match status.as_str() {
        STATUS_READY => {}
        STATUS_APPLIED => return Ok(ProjectOutcome::AlreadyApplied { event_id: id }),
        other => return Err(PipelineError::NotReady(other.to_string())),
    }

    let event = event_modules::decode(&bytes)?;
    let deps = load_deps(conn, &event)?;
    let labels = load_labels(conn, &event, id)?;
    let context = ProjectionContext {
        origin_connection_id: None,
        now_ms,
    };
    let projection = event_modules::project(id, &event, &deps, &labels, &context);

    let (outbox_inserted, emitted_events) = apply_projection(conn, id, now_ms, projection)?;

    conn.execute(
        "UPDATE events SET status = ?1 WHERE event_id = ?2",
        params![STATUS_APPLIED, id.to_vec()],
    )?;
    conn.execute(
        "DELETE FROM blocked_by_event WHERE blocked_by_event_id = ?1",
        params![id.to_vec()],
    )?;
    let unblocked = conn.execute(
        "UPDATE events
         SET status = ?1
         WHERE status = ?2
           AND NOT EXISTS (
             SELECT 1 FROM blocked_by_event
             WHERE blocked_by_event.event_id = events.event_id
           )",
        params![STATUS_READY, STATUS_BLOCKED],
    )?;

    let mut emitted = Vec::new();
    for emitted_bytes in emitted_events {
        match ingest_local(conn, &emitted_bytes, now_ms)? {
            IngestOutcome::InsertedReady { event_id }
            | IngestOutcome::InsertedBlocked { event_id, .. }
            | IngestOutcome::Duplicate { event_id, .. } => emitted.push(event_id),
        }
    }

    Ok(ProjectOutcome::Applied {
        event_id: id,
        emitted,
        outbox_inserted,
        unblocked,
    })
}

pub fn drain_ready(
    conn: &Connection,
    limit: usize,
    now_ms: i64,
) -> Result<Vec<ProjectOutcome>, PipelineError> {
    let ids = ready_ids(conn, limit)?;
    ids.into_iter()
        .map(|id| project_ready(conn, id, now_ms))
        .collect()
}

pub fn get_status(conn: &Connection, id: EventId) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT status FROM events WHERE event_id = ?1",
        params![id.to_vec()],
        |row| row.get(0),
    )
    .optional()
}

pub fn pending_outbox_count(conn: &Connection) -> rusqlite::Result<usize> {
    conn.query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
}

pub fn event_bytes(conn: &Connection, id: EventId) -> rusqlite::Result<Option<Vec<u8>>> {
    conn.query_row(
        "SELECT canonical_bytes FROM events WHERE event_id = ?1",
        params![id.to_vec()],
        |row| row.get(0),
    )
    .optional()
}

fn missing_or_unapplied_deps(
    conn: &Connection,
    event: &Event,
) -> Result<Vec<EventId>, PipelineError> {
    let mut blocked_by = Vec::new();
    for dep in event.dependency_ids() {
        let status = get_status(conn, dep)?;
        if status.as_deref() != Some(STATUS_APPLIED) {
            blocked_by.push(dep);
        }
    }
    Ok(blocked_by)
}

fn event_row(conn: &Connection, id: EventId) -> rusqlite::Result<Option<(Vec<u8>, String)>> {
    conn.query_row(
        "SELECT canonical_bytes, status FROM events WHERE event_id = ?1",
        params![id.to_vec()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

fn load_deps(conn: &Connection, event: &Event) -> Result<Vec<ResolvedEvent>, PipelineError> {
    let mut deps = Vec::new();
    for dep_id in event.dependency_ids() {
        if let Some(bytes) = event_bytes(conn, dep_id)? {
            deps.push(ResolvedEvent {
                event_id: dep_id,
                event: event_modules::decode(&bytes)?,
            });
        }
    }
    Ok(deps)
}

fn load_labels(
    conn: &Connection,
    event: &Event,
    event_id: EventId,
) -> Result<HashMap<EventId, Vec<String>>, PipelineError> {
    let mut labels = HashMap::new();
    let mut ids = event.dependency_ids();
    ids.push(event_id);

    for id in ids {
        let mut stmt = conn.prepare(
            "SELECT label FROM labels
             WHERE subject_event_id = ?1
             ORDER BY label",
        )?;
        let rows = stmt.query_map(params![id.to_vec()], |row| row.get::<_, String>(0))?;
        let values = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        labels.insert(id, values);
    }

    Ok(labels)
}

fn apply_projection(
    conn: &Connection,
    source_event_id: EventId,
    now_ms: i64,
    projection: Projection,
) -> Result<(usize, Vec<Vec<u8>>), PipelineError> {
    for op in projection.row_ops {
        apply_row_op(conn, op)?;
    }

    for label in projection.labels {
        conn.execute(
            "INSERT OR IGNORE INTO labels (subject_event_id, label, source_event_id)
             VALUES (?1, ?2, ?3)",
            params![
                label.subject_event_id.to_vec(),
                label.label,
                source_event_id.to_vec()
            ],
        )?;
    }

    let mut outbox_inserted = 0;
    for outbox in projection.outbox {
        outbox_inserted += conn.execute(
            "INSERT OR IGNORE INTO outbox (connection_id, event_id, queued_at_ms)
             VALUES (?1, ?2, ?3)",
            params![
                outbox.connection_id.to_vec(),
                outbox.event_id.to_vec(),
                now_ms
            ],
        )?;
    }

    for purged_event_id in projection.purges {
        conn.execute(
            "UPDATE events SET status = ?1 WHERE event_id = ?2",
            params![STATUS_PURGED, purged_event_id.to_vec()],
        )?;
    }

    Ok((outbox_inserted, projection.emitted_events))
}

fn apply_row_op(conn: &Connection, op: RowOp) -> Result<(), PipelineError> {
    if op.columns.is_empty() || op.columns.len() != op.values.len() {
        return Err(PipelineError::InvalidRowOp {
            table: op.table,
            reason: "column/value mismatch",
        });
    }

    let columns = op.columns.join(", ");
    let placeholders = (1..=op.columns.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let update = op
        .columns
        .iter()
        .map(|column| format!("{column} = excluded.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({}) ON CONFLICT DO UPDATE SET {}",
        op.table, columns, placeholders, update
    );
    let values = op
        .values
        .into_iter()
        .map(|value| match value {
            SqlValue::Blob(value) => Value::Blob(value),
            SqlValue::Integer(value) => Value::Integer(value),
            SqlValue::Text(value) => Value::Text(value),
        })
        .collect::<Vec<_>>();

    conn.execute(&sql, rusqlite::params_from_iter(values))?;
    Ok(())
}

fn ready_ids(conn: &Connection, limit: usize) -> rusqlite::Result<Vec<EventId>> {
    let mut stmt = conn.prepare(
        "SELECT event_id FROM events
         WHERE status = ?1
         ORDER BY created_at_ms, event_id
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![STATUS_READY, limit as i64], |row| {
        let bytes: Vec<u8> = row.get(0)?;
        Ok(vec_to_id(bytes))
    })?;
    rows.collect()
}

fn vec_to_id(bytes: Vec<u8>) -> EventId {
    let mut id = [0; 32];
    id.copy_from_slice(&bytes);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules;

    #[test]
    fn ingest_dedupes_by_event_id() {
        let conn = open_memory().unwrap();
        let bytes = event_modules::encode_workspace([1; 32], "team");
        let id = event_id(&bytes);

        assert_eq!(
            ingest_local(&conn, &bytes, 10).unwrap(),
            IngestOutcome::InsertedReady { event_id: id }
        );
        assert_eq!(
            ingest_local(&conn, &bytes, 11).unwrap(),
            IngestOutcome::Duplicate {
                event_id: id,
                status: STATUS_READY.to_string()
            }
        );
    }

    #[test]
    fn missing_deps_block_until_dependency_is_applied() {
        let conn = open_memory().unwrap();
        let workspace = event_modules::encode_workspace([1; 32], "team");
        let workspace_id = event_id(&workspace);
        let message = event_modules::encode_message([1; 32], workspace_id, [0; 32], [9; 32], "hi");
        let message_id = event_id(&message);

        assert_eq!(
            ingest_local(&conn, &message, 10).unwrap(),
            IngestOutcome::InsertedBlocked {
                event_id: message_id,
                blocked_by: vec![workspace_id]
            }
        );
        assert_eq!(
            get_status(&conn, message_id).unwrap().as_deref(),
            Some("blocked")
        );

        ingest_local(&conn, &workspace, 11).unwrap();
        project_ready(&conn, workspace_id, 12).unwrap();

        assert_eq!(
            get_status(&conn, message_id).unwrap().as_deref(),
            Some("ready")
        );
    }

    #[test]
    fn applying_message_projects_rows_and_idempotent_outbox() {
        let conn = open_memory().unwrap();
        let workspace = event_modules::encode_workspace([1; 32], "team");
        let workspace_id = event_id(&workspace);
        let message = event_modules::encode_message([1; 32], workspace_id, [0; 32], [9; 32], "hi");
        let message_id = event_id(&message);

        ingest_local(&conn, &workspace, 10).unwrap();
        project_ready(&conn, workspace_id, 11).unwrap();
        ingest_local(&conn, &message, 12).unwrap();

        assert_eq!(
            project_ready(&conn, message_id, 13).unwrap(),
            ProjectOutcome::Applied {
                event_id: message_id,
                emitted: Vec::new(),
                outbox_inserted: 1,
                unblocked: 0
            }
        );
        assert_eq!(
            project_ready(&conn, message_id, 14).unwrap(),
            ProjectOutcome::AlreadyApplied {
                event_id: message_id
            }
        );
        assert_eq!(pending_outbox_count(&conn).unwrap(), 1);
    }

    #[test]
    fn drain_ready_applies_in_created_order() {
        let conn = open_memory().unwrap();
        let a = event_modules::encode_workspace([1; 32], "a");
        let b = event_modules::encode_workspace([2; 32], "b");

        ingest_local(&conn, &b, 20).unwrap();
        ingest_local(&conn, &a, 10).unwrap();
        let outcomes = drain_ready(&conn, 10, 30).unwrap();

        assert_eq!(outcomes.len(), 2);
        assert_eq!(
            get_status(&conn, event_id(&a)).unwrap().as_deref(),
            Some("applied")
        );
        assert_eq!(
            get_status(&conn, event_id(&b)).unwrap().as_deref(),
            Some("applied")
        );
    }
}
