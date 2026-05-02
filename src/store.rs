use rusqlite::{params, Connection, OptionalExtension};
use std::net::SocketAddr;
use std::path::Path;

pub type EventId = [u8; 32];

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

    pub fn insert_peer(&self, addr: SocketAddr) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO peers (addr) VALUES (?1)",
            params![addr.to_string()],
        )?;
        Ok(())
    }

    pub fn peers(&self) -> rusqlite::Result<Vec<SocketAddr>> {
        let mut stmt = self.conn.prepare("SELECT addr FROM peers ORDER BY addr")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let addr = row?.parse::<SocketAddr>().map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            out.push(addr);
        }
        Ok(out)
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

            CREATE TABLE IF NOT EXISTS peers (
                addr TEXT PRIMARY KEY NOT NULL
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
