use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub type EventId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRow {
    pub table: &'static str,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub timestamp: u64,
    pub payload_len: usize,
    pub canonical_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventHeader {
    pub event_id: EventId,
    pub bucket: u8,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.ensure_schema()?;
        Ok(store)
    }

    pub fn insert_module_rows(&self, rows: Vec<ModuleRow>) -> rusqlite::Result<usize> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let mut inserted = 0;
            for row in rows {
                inserted += self.conn.execute(
                    "INSERT OR IGNORE INTO module_rows
                        (table_name, row_key, row_value)
                     VALUES (?1, ?2, ?3)",
                    params![row.table, row.key, row.value],
                )?;
            }
            Ok::<usize, rusqlite::Error>(inserted)
        })();

        match result {
            Ok(inserted) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(inserted)
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    pub fn module_row(&self, table: &'static str, key: &[u8]) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT row_value FROM module_rows
                 WHERE table_name = ?1 AND row_key = ?2",
                params![table, key],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn module_row_count(&self, table: &'static str) -> rusqlite::Result<usize> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM module_rows WHERE table_name = ?1",
                params![table],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count as usize)
    }

    pub fn module_rows(&self, table: &'static str) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT row_key, row_value FROM module_rows
             WHERE table_name = ?1
             ORDER BY row_key",
        )?;
        let rows = stmt.query_map(params![table], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    pub fn insert_events(&self, events: Vec<EventRecord>) -> rusqlite::Result<usize> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let mut inserted = 0;
            for event in events {
                if self.insert_event_row(event)? {
                    inserted += 1;
                }
            }
            Ok::<usize, rusqlite::Error>(inserted)
        })();

        match result {
            Ok(inserted) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(inserted)
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    fn insert_event_row(&self, event: EventRecord) -> rusqlite::Result<bool> {
        let event_id = event_id(&event.canonical_bytes);
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO events
                (event_id, timestamp, payload_len, bucket, canonical_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event_id.to_vec(),
                event.timestamp as i64,
                event.payload_len as i64,
                i64::from(event_id[0]),
                event.canonical_bytes,
            ],
        )?;
        Ok(inserted > 0)
    }

    pub fn max_timestamp(&self) -> rusqlite::Result<u64> {
        let value = self
            .conn
            .query_row("SELECT MAX(timestamp) FROM events", [], |row| {
                row.get::<_, Option<i64>>(0)
            })?
            .unwrap_or(0);
        Ok(value.max(0) as u64)
    }

    pub fn event_count(&self) -> rusqlite::Result<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
    }

    pub fn payload_bytes(&self) -> rusqlite::Result<usize> {
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(payload_len), 0) FROM events",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count as usize)
    }

    pub fn headers(&self) -> rusqlite::Result<Vec<EventHeader>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_id, bucket FROM events ORDER BY event_id")?;
        let rows = stmt.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            Ok(EventHeader {
                event_id: vec_to_id(id),
                bucket: row.get::<_, i64>(1)? as u8,
            })
        })?;
        rows.collect()
    }

    pub fn ids_in_bucket(&self, bucket: u8) -> rusqlite::Result<Vec<EventId>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_id FROM events WHERE bucket = ?1 ORDER BY event_id")?;
        let rows = stmt.query_map(params![i64::from(bucket)], |row| {
            let id: Vec<u8> = row.get(0)?;
            Ok(vec_to_id(id))
        })?;
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

    pub fn event_bytes(&self, event_id: &EventId) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT canonical_bytes FROM events WHERE event_id = ?1",
                params![event_id.to_vec()],
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
                payload_len INTEGER NOT NULL,
                bucket INTEGER NOT NULL,
                canonical_bytes BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_bucket
                ON events(bucket, event_id);

            CREATE TABLE IF NOT EXISTS module_rows (
                table_name TEXT NOT NULL,
                row_key BLOB NOT NULL,
                row_value BLOB NOT NULL,
                PRIMARY KEY (table_name, row_key)
            );
            ",
        )
    }
}

pub fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}

fn vec_to_id(bytes: Vec<u8>) -> EventId {
    let mut id = [0; 32];
    id.copy_from_slice(&bytes);
    id
}
