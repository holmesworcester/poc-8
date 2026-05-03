use rusqlite::{params, types::Type, Connection, OptionalExtension};
use std::io;
use std::path::Path;

pub type EventId = [u8; 32];
pub type WorkId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRow {
    pub table: &'static str,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRowDeletion {
    pub table: &'static str,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkRecord {
    pub lane: &'static str,
    pub kind: &'static str,
    pub dedupe_key: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkClaim {
    pub work_id: WorkId,
    pub lane: String,
    pub kind: String,
    pub payload: Vec<u8>,
    pub attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub timestamp: u64,
    pub body_len: usize,
    pub canonical_bytes: Vec<u8>,
    pub dependencies: Vec<EventId>,
    pub scope: EventScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventScope {
    Shared,
    Local,
    Connection,
}

impl EventScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Local => "local",
            Self::Connection => "connection",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionOutput {
    pub rows: Vec<TableRow>,
    pub deleted_rows: Vec<TableRowDeletion>,
    pub work: Vec<WorkRecord>,
}

impl ProjectionOutput {
    pub fn rows(rows: Vec<TableRow>) -> Self {
        Self {
            rows,
            deleted_rows: Vec::new(),
            work: Vec::new(),
        }
    }

    pub fn work(work: Vec<WorkRecord>) -> Self {
        Self {
            rows: Vec::new(),
            deleted_rows: Vec::new(),
            work,
        }
    }

    pub fn append(&mut self, mut other: Self) {
        self.rows.append(&mut other.rows);
        self.deleted_rows.append(&mut other.deleted_rows);
        self.work.append(&mut other.work);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleJobOutput {
    pub rows: Vec<TableRow>,
    pub deleted_rows: Vec<TableRowDeletion>,
    pub work: Vec<WorkRecord>,
    pub events: Vec<EventRecord>,
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput<T> {
    pub value: T,
    pub events: Vec<EventRecord>,
    pub work: Vec<WorkRecord>,
}

impl<T> CommandOutput<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            events: Vec::new(),
            work: Vec::new(),
        }
    }

    pub fn with_events(value: T, events: Vec<EventRecord>) -> Self {
        Self {
            value,
            events,
            work: Vec::new(),
        }
    }

    pub fn with_work(value: T, work: Vec<WorkRecord>) -> Self {
        Self {
            value,
            events: Vec::new(),
            work,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedEventEntry {
    pub apply_seq: u64,
    pub event_id: EventId,
    pub partition: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventStatusCounts {
    pub ready: usize,
    pub blocked: usize,
    pub applied: usize,
    pub rejected: usize,
    pub blocked_edges: usize,
}

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStatus {
    Ready,
    Blocked,
    Applied,
    Rejected,
}

impl EventStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Blocked => "blocked",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkStatus {
    Ready,
    Running,
    Failed,
}

impl WorkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Failed => "failed",
        }
    }
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.ensure_schema()?;
        Ok(store)
    }

    pub fn insert_table_rows(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        self.write_transaction(|store| store.insert_table_rows_in_tx(rows))
    }

    pub fn insert_table_rows_in_tx(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        let mut inserted = 0;
        for row in rows {
            inserted += self.conn.execute(
                "INSERT OR IGNORE INTO table_rows
                    (table_name, row_key, row_value)
                 VALUES (?1, ?2, ?3)",
                params![row.table, row.key, row.value],
            )?;
        }
        Ok(inserted)
    }

    pub fn insert_work_in_tx(&self, work: Vec<WorkRecord>) -> rusqlite::Result<usize> {
        let mut inserted = 0;
        for record in work {
            let work_id = work_id(&record);
            inserted += self.conn.execute(
                "INSERT OR IGNORE INTO work_queue
                    (work_id, lane, kind, dedupe_key, payload, status, attempts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                params![
                    work_id.to_vec(),
                    record.lane,
                    record.kind,
                    record.dedupe_key,
                    record.payload,
                    WorkStatus::Ready.as_str(),
                ],
            )?;
        }
        Ok(inserted)
    }

    pub fn claim_next_work_in_tx(&self) -> rusqlite::Result<Option<WorkClaim>> {
        let claim = self
            .conn
            .query_row(
                "SELECT work_id, lane, kind, payload, attempts
                 FROM work_queue
                 WHERE status = ?1
                 ORDER BY created_seq
                 LIMIT 1",
                params![WorkStatus::Ready.as_str()],
                |row| {
                    let id: Vec<u8> = row.get(0)?;
                    Ok(WorkClaim {
                        work_id: vec_to_id(id)?,
                        lane: row.get(1)?,
                        kind: row.get(2)?,
                        payload: row.get(3)?,
                        attempts: row.get::<_, i64>(4)? as u32,
                    })
                },
            )
            .optional()?;

        let Some(claim) = claim else {
            return Ok(None);
        };
        let changed = self.conn.execute(
            "UPDATE work_queue
             SET status = ?2, attempts = attempts + 1
             WHERE work_id = ?1 AND status = ?3",
            params![
                claim.work_id.to_vec(),
                WorkStatus::Running.as_str(),
                WorkStatus::Ready.as_str(),
            ],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(Some(WorkClaim {
            attempts: claim.attempts.saturating_add(1),
            ..claim
        }))
    }

    pub fn complete_work_in_tx(&self, work_id: &WorkId) -> rusqlite::Result<bool> {
        self.conn
            .execute(
                "DELETE FROM work_queue
                 WHERE work_id = ?1 AND status = ?2",
                params![work_id.to_vec(), WorkStatus::Running.as_str()],
            )
            .map(|changed| changed > 0)
    }

    pub fn fail_work_in_tx(&self, work_id: &WorkId, error: &str) -> rusqlite::Result<bool> {
        self.conn
            .execute(
                "UPDATE work_queue
                 SET status = ?2, last_error = ?3
                 WHERE work_id = ?1 AND status = ?4",
                params![
                    work_id.to_vec(),
                    WorkStatus::Failed.as_str(),
                    error,
                    WorkStatus::Running.as_str(),
                ],
            )
            .map(|changed| changed > 0)
    }

    pub fn work_count(&self) -> rusqlite::Result<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM work_queue", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
    }

    pub fn delete_table_rows_in_tx(
        &self,
        deleted_rows: Vec<TableRowDeletion>,
    ) -> rusqlite::Result<usize> {
        let mut deleted = 0;
        for row in deleted_rows {
            deleted += self.conn.execute(
                "DELETE FROM table_rows
                 WHERE table_name = ?1 AND row_key = ?2",
                params![row.table, row.key],
            )?;
        }
        Ok(deleted)
    }

    pub fn delete_table_rows(
        &self,
        table: &'static str,
        keys: Vec<Vec<u8>>,
    ) -> rusqlite::Result<usize> {
        self.write_transaction(|store| {
            let mut deleted = 0;
            for key in keys {
                deleted += store.conn.execute(
                    "DELETE FROM table_rows
                     WHERE table_name = ?1 AND row_key = ?2",
                    params![table, key],
                )?;
            }
            Ok(deleted)
        })
    }

    pub fn table_row(&self, table: &'static str, key: &[u8]) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT row_value FROM table_rows
                 WHERE table_name = ?1 AND row_key = ?2",
                params![table, key],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn table_row_count(&self, table: &'static str) -> rusqlite::Result<usize> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM table_rows WHERE table_name = ?1",
                params![table],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count as usize)
    }

    pub fn table_rows(&self, table: &'static str) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT row_key, row_value FROM table_rows
             WHERE table_name = ?1
             ORDER BY row_key",
        )?;
        let rows = stmt.query_map(params![table], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    pub fn write_transaction<T>(
        &self,
        apply: impl FnOnce(&Store) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = apply(self);
        match result {
            Ok(value) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(value)
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    pub fn insert_event(&self, event: &EventRecord, status: EventStatus) -> rusqlite::Result<bool> {
        let event_id = event_id(&event.canonical_bytes);
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO events
                (event_id, timestamp, body_len, event_partition, event_scope, status, canonical_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event_id.to_vec(),
                event.timestamp as i64,
                event.body_len as i64,
                i64::from(event_id[0]),
                event.scope.as_str(),
                status.as_str(),
                &event.canonical_bytes,
            ],
        )?;
        Ok(inserted > 0)
    }

    pub fn event_is_applied(&self, event_id: &EventId) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM events
                 WHERE event_id = ?1 AND status = ?2",
                params![event_id.to_vec(), EventStatus::Applied.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }

    pub fn insert_dependency_wait(
        &self,
        blocked_by_event_id: &EventId,
        event_id: &EventId,
    ) -> rusqlite::Result<bool> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO blocked_by_event
                    (blocked_by_event_id, event_id)
                 VALUES (?1, ?2)",
                params![blocked_by_event_id.to_vec(), event_id.to_vec()],
            )
            .map(|changed| changed > 0)
    }

    pub fn next_ready_event(&self) -> rusqlite::Result<Option<EventId>> {
        self.conn
            .query_row(
                "SELECT event_id FROM events
                 WHERE status = ?1
                 ORDER BY timestamp, event_id
                 LIMIT 1",
                params![EventStatus::Ready.as_str()],
                |row| {
                    let id: Vec<u8> = row.get(0)?;
                    vec_to_id(id)
                },
            )
            .optional()
    }

    pub fn set_event_status(
        &self,
        event_id: &EventId,
        from: EventStatus,
        to: EventStatus,
    ) -> rusqlite::Result<bool> {
        self.conn
            .execute(
                "UPDATE events
                 SET status = ?2,
                     apply_seq = CASE
                         WHEN ?2 = 'applied' AND apply_seq IS NULL THEN
                             (SELECT COALESCE(MAX(apply_seq), 0) + 1 FROM events)
                         ELSE apply_seq
                     END
                 WHERE event_id = ?1 AND status = ?3",
                params![event_id.to_vec(), to.as_str(), from.as_str()],
            )
            .map(|changed| changed > 0)
    }

    pub fn delete_dependency_waits_for(
        &self,
        blocked_by_event_id: &EventId,
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            "DELETE FROM blocked_by_event
             WHERE blocked_by_event_id = ?1",
            params![blocked_by_event_id.to_vec()],
        )
    }

    pub fn events_waiting_on(
        &self,
        blocked_by_event_id: &EventId,
    ) -> rusqlite::Result<Vec<EventId>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id FROM blocked_by_event
             WHERE blocked_by_event_id = ?1
             ORDER BY event_id",
        )?;
        let rows = stmt.query_map(params![blocked_by_event_id.to_vec()], |row| {
            let id: Vec<u8> = row.get(0)?;
            vec_to_id(id)
        })?;
        rows.collect()
    }

    pub fn event_has_dependency_waits(&self, event_id: &EventId) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM blocked_by_event
                 WHERE event_id = ?1
                 LIMIT 1",
                params![event_id.to_vec()],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }

    pub fn max_timestamp(&self) -> rusqlite::Result<u64> {
        let value = self
            .conn
            .query_row(
                "SELECT MAX(timestamp) FROM events WHERE event_scope = ?1",
                params![EventScope::Shared.as_str()],
                |row| row.get::<_, Option<i64>>(0),
            )?
            .unwrap_or(0);
        Ok(value.max(0) as u64)
    }

    pub fn event_count(&self) -> rusqlite::Result<usize> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_scope = ?1",
                params![EventScope::Shared.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count as usize)
    }

    pub fn status_counts(&self) -> rusqlite::Result<EventStatusCounts> {
        let ready = self.status_count(EventStatus::Ready)?;
        let blocked = self.status_count(EventStatus::Blocked)?;
        let applied = self.status_count(EventStatus::Applied)?;
        let rejected = self.status_count(EventStatus::Rejected)?;
        let blocked_edges =
            self.conn
                .query_row("SELECT COUNT(*) FROM blocked_by_event", [], |row| {
                    row.get::<_, i64>(0)
                })? as usize;
        Ok(EventStatusCounts {
            ready,
            blocked,
            applied,
            rejected,
            blocked_edges,
        })
    }

    fn status_count(&self, status: EventStatus) -> rusqlite::Result<usize> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE status = ?1 AND event_scope = ?2",
                params![status.as_str(), EventScope::Shared.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count as usize)
    }

    pub fn body_bytes(&self) -> rusqlite::Result<usize> {
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(body_len), 0) FROM events
                 WHERE event_scope = ?1",
                params![EventScope::Shared.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count as usize)
    }

    pub fn max_applied_shared_seq(&self) -> rusqlite::Result<u64> {
        let value = self
            .conn
            .query_row(
                "SELECT MAX(apply_seq) FROM events
                 WHERE event_scope = ?1 AND status = ?2",
                params![EventScope::Shared.as_str(), EventStatus::Applied.as_str()],
                |row| row.get::<_, Option<i64>>(0),
            )?
            .unwrap_or(0);
        Ok(value.max(0) as u64)
    }

    pub fn applied_shared_entries_after(
        &self,
        after_apply_seq: u64,
        limit: usize,
    ) -> rusqlite::Result<Vec<AppliedEventEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT apply_seq, event_id, event_partition FROM events
             WHERE event_scope = ?1
               AND status = ?2
               AND apply_seq IS NOT NULL
               AND apply_seq > ?3
             ORDER BY apply_seq
             LIMIT ?4",
        )?;
        let rows = stmt.query_map(
            params![
                EventScope::Shared.as_str(),
                EventStatus::Applied.as_str(),
                after_apply_seq as i64,
                limit as i64,
            ],
            |row| {
                let id: Vec<u8> = row.get(1)?;
                Ok(AppliedEventEntry {
                    apply_seq: row.get::<_, i64>(0)?.max(0) as u64,
                    event_id: vec_to_id(id)?,
                    partition: row.get::<_, i64>(2)? as u8,
                })
            },
        )?;
        rows.collect()
    }

    pub fn has_event(&self, event_id: &EventId) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM events WHERE event_id = ?1",
                params![event_id.to_vec()],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }

    pub fn has_shared_event(&self, event_id: &EventId) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM events
                 WHERE event_id = ?1 AND event_scope = ?2",
                params![event_id.to_vec(), EventScope::Shared.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }

    pub fn event_bytes(&self, event_id: &EventId) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT canonical_bytes FROM events WHERE event_id = ?1",
                params![event_id.to_vec()],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn shared_event_bytes(&self, event_id: &EventId) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT canonical_bytes FROM events
                 WHERE event_id = ?1 AND event_scope = ?2",
                params![event_id.to_vec(), EventScope::Shared.as_str()],
                |row| row.get(0),
            )
            .optional()
    }

    fn ensure_schema(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS events (
                event_id BLOB PRIMARY KEY NOT NULL,
                timestamp INTEGER NOT NULL,
                body_len INTEGER NOT NULL,
                event_partition INTEGER NOT NULL,
                event_scope TEXT NOT NULL DEFAULT 'shared',
                status TEXT NOT NULL,
                apply_seq INTEGER,
                canonical_bytes BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_partition
                ON events(event_partition, event_id);
            CREATE INDEX IF NOT EXISTS idx_events_status
                ON events(status, timestamp, event_id);
            CREATE INDEX IF NOT EXISTS idx_events_apply_seq
                ON events(event_scope, status, apply_seq);
            CREATE TABLE IF NOT EXISTS blocked_by_event (
                blocked_by_event_id BLOB NOT NULL,
                event_id BLOB NOT NULL,
                PRIMARY KEY (blocked_by_event_id, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_blocked_by_event_event
                ON blocked_by_event(event_id, blocked_by_event_id);

            CREATE TABLE IF NOT EXISTS table_rows (
                table_name TEXT NOT NULL,
                row_key BLOB NOT NULL,
                row_value BLOB NOT NULL,
                PRIMARY KEY (table_name, row_key)
            );

            CREATE TABLE IF NOT EXISTS work_queue (
                created_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                work_id BLOB UNIQUE NOT NULL,
                lane TEXT NOT NULL,
                kind TEXT NOT NULL,
                dedupe_key BLOB NOT NULL,
                payload BLOB NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_work_queue_ready
                ON work_queue(status, created_seq);
            ",
        )?;
        self.ensure_event_scope_column()?;
        self.ensure_apply_seq_column()
    }

    fn ensure_event_scope_column(&self) -> rusqlite::Result<()> {
        let mut stmt = self.conn.prepare("PRAGMA table_info(events)")?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !columns.iter().any(|column| column == "event_scope") {
            self.conn.execute_batch(
                "ALTER TABLE events ADD COLUMN event_scope TEXT NOT NULL DEFAULT 'shared';",
            )?;
        }
        Ok(())
    }

    fn ensure_apply_seq_column(&self) -> rusqlite::Result<()> {
        let mut stmt = self.conn.prepare("PRAGMA table_info(events)")?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !columns.iter().any(|column| column == "apply_seq") {
            self.conn
                .execute_batch("ALTER TABLE events ADD COLUMN apply_seq INTEGER;")?;
        }
        Ok(())
    }
}

pub fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}

pub fn work_id(record: &WorkRecord) -> WorkId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-work-v1");
    hasher.update(record.lane.as_bytes());
    hasher.update(&[0]);
    hasher.update(record.kind.as_bytes());
    hasher.update(&[0]);
    hasher.update(&record.dedupe_key);
    hasher.update(&[0]);
    hasher.update(&record.payload);
    *hasher.finalize().as_bytes()
}

fn vec_to_id(bytes: Vec<u8>) -> rusqlite::Result<EventId> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            Type::Blob,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected 32-byte event id, got {}", bytes.len()),
            )),
        )
    })
}
