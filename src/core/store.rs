//! A small SQLite-backed row store.
//!
//! This file is intentionally below the protocol. It knows how to apply declared
//! schemas, run transactions, and read or write keyed byte rows. It does not
//! know what any row means. Event admission, labels, missing-dep edges, network
//! targets, and sync queues are all protocol or IO concepts layered on top of
//! these primitives.
//!
//! The critical path is short:
//! 1. Open a store with the schemas declared by core IO and the selected
//!    protocol's module scopes.
//! 2. Use `write_transaction` to group rows that must become visible together.
//! 3. Use the row helpers to insert, replace, delete, and scan by key prefix or
//!    by an explicit key range.
//!
//! The only dynamic SQL in this file is generic row-table creation and
//! table-name interpolation for row operations. Values are always bound
//! parameters, and table names are accepted only from `TableName` after a
//! conservative identifier check.

use rusqlite::{params, Connection as SqliteConnection, OptionalExtension};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

/// A static, trusted row-table name.
///
/// Protocol and core IO modules declare these names next to the row encoders
/// that understand their values. Store validates the identifier before using
/// it in SQL, then treats rows as opaque bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TableName(&'static str);

impl TableName {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub fn as_str(self) -> &'static str {
        self.0
    }
}

/// Where a declared row table is expected to live.
///
/// Durable rows are normal SQLite tables. Memory rows are process-local maps
/// held by `Store`; they are not SQLite TEMP tables and are never visible to a
/// second store handle or another process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    Durable,
    Memory,
}

/// One schema fragment owned by a core IO module or protocol module scope.
///
/// Most modules should use `Schema::durable_row_table`: the module owns the
/// table name and persistence decision, while store supplies the uniform
/// `(row_key BLOB PRIMARY KEY, row_value BLOB)` shape. Raw SQL exists for
/// future specialized indexes, but it should be uncommon and reviewed harder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schema {
    pub id: &'static str,
    pub storage: StorageClass,
    pub definition: SchemaDefinition,
}

/// The concrete schema operation requested by a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaDefinition {
    RowTable(TableName),
    Sql(&'static str),
}

impl Schema {
    pub const fn row_table(id: &'static str, storage: StorageClass, table: TableName) -> Self {
        Self {
            id,
            storage,
            definition: SchemaDefinition::RowTable(table),
        }
    }

    pub const fn durable_row_table(id: &'static str, table: TableName) -> Self {
        Self::row_table(id, StorageClass::Durable, table)
    }

    pub const fn memory_row_table(id: &'static str, table: TableName) -> Self {
        Self::row_table(id, StorageClass::Memory, table)
    }

    pub const fn durable(id: &'static str, sql: &'static str) -> Self {
        Self {
            id,
            storage: StorageClass::Durable,
            definition: SchemaDefinition::Sql(sql),
        }
    }
}

/// One opaque key/value row in one declared table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRow {
    pub table: TableName,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

type MemoryRows = BTreeMap<Vec<u8>, Vec<u8>>;
type MemoryTables = HashMap<TableName, MemoryRows>;

/// The only durable substrate core offers protocol code.
pub struct Store {
    conn: SqliteConnection,
    table_storage: HashMap<TableName, StorageClass>,
    memory_tables: RefCell<MemoryTables>,
}

impl Store {
    /// Open a disk store without creating any protocol tables.
    ///
    /// Production callers should prefer `open_disk_with_schemas`; this form is
    /// kept for tests that exercise the bare row substrate.
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        Self::open_disk_with_schemas(path, &[])
    }

    /// Alias for `open`, kept so tests can name the backing medium explicitly.
    pub fn open_disk(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        Self::open_disk_with_schemas(path, &[])
    }

    /// Open a disk store and apply the caller-declared schemas.
    pub fn open_disk_with_schemas(
        path: impl AsRef<Path>,
        schemas: &[Schema],
    ) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open(path)?;
        Self::from_connection(conn, schemas)
    }

    /// Open an in-memory store without creating any protocol tables.
    pub fn open_memory() -> rusqlite::Result<Self> {
        Self::open_memory_with_schemas(&[])
    }

    /// Open an in-memory store and apply the caller-declared schemas.
    pub fn open_memory_with_schemas(schemas: &[Schema]) -> rusqlite::Result<Self> {
        let conn = SqliteConnection::open_in_memory()?;
        Self::from_connection(conn, schemas)
    }

    fn from_connection(conn: SqliteConnection, schemas: &[Schema]) -> rusqlite::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA secure_delete = ON;")?;
        let table_storage = table_storage_map(schemas)?;
        let memory_tables = table_storage
            .iter()
            .filter_map(|(table, storage)| {
                (*storage == StorageClass::Memory).then_some((*table, BTreeMap::new()))
            })
            .collect();
        let store = Self {
            conn,
            table_storage,
            memory_tables: RefCell::new(memory_tables),
        };
        store.apply_schemas(schemas)?;
        Ok(store)
    }

    // Critical path: callers put every atomic row mutation
    // through this closure, then use the transaction-local row helpers below.
    /// Run a write transaction.
    ///
    /// The closure sees its own writes through the same SQLite handle. Keep
    /// closures narrow: they are where callers express the atomic unit, while
    /// this store only supplies `BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK`.
    pub fn write_transaction<T>(
        &self,
        apply: impl FnOnce(&Store) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let memory_before = self.memory_tables.borrow().clone();
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = apply(self);
        match result {
            Ok(value) => match self.conn.execute_batch("COMMIT") {
                Ok(()) => Ok(value),
                Err(err) => {
                    *self.memory_tables.borrow_mut() = memory_before;
                    let _ = self.conn.execute_batch("ROLLBACK");
                    Err(err)
                }
            },
            Err(err) => {
                *self.memory_tables.borrow_mut() = memory_before;
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    // Row writes: these are intentionally table/key/value operations. Any
    // richer meaning belongs to the module that constructed the `TableRow`.
    /// Insert rows idempotently in their declared tables.
    pub fn insert_table_rows(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        self.write_transaction(|store| store.insert_table_rows_in_tx(rows))
    }

    /// Transaction-local form of `insert_table_rows`.
    pub fn insert_table_rows_in_tx(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        let mut inserted = 0;
        for row in rows {
            if self.storage_for(row.table) == StorageClass::Memory {
                inserted += self.insert_memory_row(row)?;
                continue;
            }
            let table_name = quoted_table_name(row.table)?;
            let changed = self.conn.execute(
                &format!(
                    "INSERT OR IGNORE INTO {table_name}
                        (row_key, row_value)
                     VALUES (?1, ?2)"
                ),
                params![row.key.as_slice(), row.value.as_slice()],
            )?;
            if changed == 0 {
                let existing = self
                    .conn
                    .query_row(
                        &format!("SELECT row_value FROM {table_name} WHERE row_key = ?1"),
                        params![row.key.as_slice()],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()?;
                if existing.as_deref() != Some(row.value.as_slice()) {
                    return Err(rusqlite::Error::InvalidParameterName(format!(
                        "conflicting row for {}",
                        row.table.as_str()
                    )));
                }
            }
            inserted += changed;
        }
        Ok(inserted)
    }

    /// Replace rows in their declared tables.
    pub fn replace_table_rows_in_tx(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        let mut replaced = 0;
        for row in rows {
            if self.storage_for(row.table) == StorageClass::Memory {
                self.memory_table_mut(row.table).insert(row.key, row.value);
                replaced += 1;
                continue;
            }
            let table_name = quoted_table_name(row.table)?;
            replaced += self.conn.execute(
                &format!(
                    "INSERT OR REPLACE INTO {table_name}
                        (row_key, row_value)
                     VALUES (?1, ?2)"
                ),
                params![row.key, row.value],
            )?;
        }
        Ok(replaced)
    }

    /// Delete rows by key from one declared table.
    pub fn delete_table_rows(
        &self,
        table: TableName,
        keys: Vec<Vec<u8>>,
    ) -> rusqlite::Result<usize> {
        self.write_transaction(|store| store.delete_table_rows_in_tx(table, keys))
    }

    /// Transaction-local form of `delete_table_rows`.
    pub fn delete_table_rows_in_tx(
        &self,
        table: TableName,
        keys: Vec<Vec<u8>>,
    ) -> rusqlite::Result<usize> {
        let mut deleted = 0;
        if self.storage_for(table) == StorageClass::Memory {
            let mut tables = self.memory_tables.borrow_mut();
            let rows = tables.entry(table).or_default();
            for key in keys {
                if rows.remove(&key).is_some() {
                    deleted += 1;
                }
            }
            return Ok(deleted);
        }
        let table_name = quoted_table_name(table)?;
        for key in keys {
            deleted += self.conn.execute(
                &format!("DELETE FROM {table_name} WHERE row_key = ?1"),
                params![key],
            )?;
        }
        Ok(deleted)
    }

    // Row reads: exact lookup, count, full scan, bounded prefix scan, and
    // bounded key-range scan are the complete read surface core exposes.
    /// Fetch one row value by exact key.
    pub fn table_row(&self, table: TableName, key: &[u8]) -> rusqlite::Result<Option<Vec<u8>>> {
        if self.storage_for(table) == StorageClass::Memory {
            return Ok(self
                .memory_tables
                .borrow()
                .get(&table)
                .and_then(|rows| rows.get(key).cloned()));
        }
        let table_name = quoted_table_name(table)?;
        self.conn
            .query_row(
                &format!("SELECT row_value FROM {table_name} WHERE row_key = ?1"),
                params![key],
                |row| row.get(0),
            )
            .optional()
    }

    /// Count rows in one declared table.
    pub fn table_row_count(&self, table: TableName) -> rusqlite::Result<usize> {
        if self.storage_for(table) == StorageClass::Memory {
            return Ok(self
                .memory_tables
                .borrow()
                .get(&table)
                .map(BTreeMap::len)
                .unwrap_or_default());
        }
        let table_name = quoted_table_name(table)?;
        self.conn
            .query_row(&format!("SELECT COUNT(*) FROM {table_name}"), [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
    }

    /// Scan one declared table in key order.
    pub fn table_rows(&self, table: TableName) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if self.storage_for(table) == StorageClass::Memory {
            return Ok(self
                .memory_tables
                .borrow()
                .get(&table)
                .map(|rows| {
                    rows.iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect()
                })
                .unwrap_or_default());
        }
        let table_name = quoted_table_name(table)?;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT row_key, row_value FROM {table_name}
                 ORDER BY row_key"
        ))?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    /// Scan one declared table by lexicographic key prefix.
    pub fn table_rows_with_key_prefix(
        &self,
        table: TableName,
        prefix: &[u8],
        limit: usize,
    ) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        if self.storage_for(table) == StorageClass::Memory {
            return Ok(self.memory_rows_with_key_prefix(table, prefix, limit));
        }
        let table_name = quoted_table_name(table)?;
        let Some(upper) = prefix_upper_bound(prefix) else {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT row_key, row_value FROM {table_name}
                     WHERE row_key >= ?1
                     ORDER BY row_key"
            ))?;
            let rows = stmt.query_map(params![prefix], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let row = row?;
                if !row.0.starts_with(prefix) || out.len() == limit {
                    break;
                }
                out.push(row);
            }
            return Ok(out);
        };

        let mut stmt = self.conn.prepare(&format!(
            "SELECT row_key, row_value FROM {table_name}
                 WHERE row_key >= ?1 AND row_key < ?2
                 ORDER BY row_key
                 LIMIT ?3"
        ))?;
        let rows = stmt.query_map(params![prefix, upper, limit as i64], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        rows.collect()
    }

    /// Scan one declared table by lexicographic key range.
    ///
    /// This is still a row-store primitive, not a protocol index. Protocol
    /// modules choose key encodings such as `(timestamp, event_id)` and store
    /// only asks SQLite for rows whose opaque keys fall in the requested span.
    pub fn table_rows_in_key_range(
        &self,
        table: TableName,
        lower_inclusive: &[u8],
        upper_exclusive: Option<&[u8]>,
        limit: usize,
    ) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        if self.storage_for(table) == StorageClass::Memory {
            return Ok(self.memory_rows_in_key_range(
                table,
                lower_inclusive,
                upper_exclusive,
                limit,
            ));
        }
        let table_name = quoted_table_name(table)?;
        match upper_exclusive {
            Some(upper) => {
                let mut stmt = self.conn.prepare(&format!(
                    "SELECT row_key, row_value FROM {table_name}
                         WHERE row_key >= ?1 AND row_key < ?2
                         ORDER BY row_key
                         LIMIT ?3"
                ))?;
                let rows = stmt
                    .query_map(params![lower_inclusive, upper, limit as i64], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })?;
                rows.collect()
            }
            None => {
                let mut stmt = self.conn.prepare(&format!(
                    "SELECT row_key, row_value FROM {table_name}
                         WHERE row_key >= ?1
                         ORDER BY row_key
                         LIMIT ?2"
                ))?;
                let rows = stmt.query_map(params![lower_inclusive, limit as i64], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })?;
                rows.collect()
            }
        }
    }

    // Schema helpers: core applies declarations from module scopes. It does not
    // build protocol tables from central knowledge.
    fn apply_schemas(&self, schemas: &[Schema]) -> rusqlite::Result<()> {
        validate_schema_ids(schemas)?;
        for schema in schemas {
            self.apply_schema(schema)?;
        }
        Ok(())
    }

    fn apply_schema(&self, schema: &Schema) -> rusqlite::Result<()> {
        match schema.definition {
            SchemaDefinition::RowTable(table) => self.apply_row_table_schema(schema.storage, table),
            SchemaDefinition::Sql(sql) => self.conn.execute_batch(sql),
        }
    }

    fn apply_row_table_schema(
        &self,
        storage: StorageClass,
        table: TableName,
    ) -> rusqlite::Result<()> {
        if storage == StorageClass::Memory {
            self.memory_tables.borrow_mut().entry(table).or_default();
            return Ok(());
        }
        let table_name = quoted_table_name(table)?;
        self.conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {table_name} (
                row_key BLOB PRIMARY KEY NOT NULL,
                row_value BLOB NOT NULL
            );"
        ))
    }

    fn storage_for(&self, table: TableName) -> StorageClass {
        self.table_storage
            .get(&table)
            .copied()
            .unwrap_or(StorageClass::Durable)
    }

    fn memory_table_mut(
        &self,
        table: TableName,
    ) -> std::cell::RefMut<'_, BTreeMap<Vec<u8>, Vec<u8>>> {
        std::cell::RefMut::map(self.memory_tables.borrow_mut(), |tables| {
            tables.entry(table).or_default()
        })
    }

    fn insert_memory_row(&self, row: TableRow) -> rusqlite::Result<usize> {
        use std::collections::btree_map::Entry;

        let mut rows = self.memory_table_mut(row.table);
        match rows.entry(row.key) {
            Entry::Vacant(entry) => {
                entry.insert(row.value);
                Ok(1)
            }
            Entry::Occupied(entry) if entry.get() == &row.value => Ok(0),
            Entry::Occupied(_) => Err(rusqlite::Error::InvalidParameterName(format!(
                "conflicting row for {}",
                row.table.as_str()
            ))),
        }
    }

    fn memory_rows_with_key_prefix(
        &self,
        table: TableName,
        prefix: &[u8],
        limit: usize,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let tables = self.memory_tables.borrow();
        let Some(rows) = tables.get(&table) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let Some(upper) = prefix_upper_bound(prefix) {
            for (key, value) in rows.range(prefix.to_vec()..upper) {
                if out.len() == limit {
                    break;
                }
                out.push((key.clone(), value.clone()));
            }
        } else {
            for (key, value) in rows.range(prefix.to_vec()..) {
                if !key.starts_with(prefix) || out.len() == limit {
                    break;
                }
                out.push((key.clone(), value.clone()));
            }
        }
        out
    }

    fn memory_rows_in_key_range(
        &self,
        table: TableName,
        lower_inclusive: &[u8],
        upper_exclusive: Option<&[u8]>,
        limit: usize,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let tables = self.memory_tables.borrow();
        let Some(rows) = tables.get(&table) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        match upper_exclusive {
            Some(upper) => {
                for (key, value) in rows.range(lower_inclusive.to_vec()..upper.to_vec()) {
                    if out.len() == limit {
                        break;
                    }
                    out.push((key.clone(), value.clone()));
                }
            }
            None => {
                for (key, value) in rows.range(lower_inclusive.to_vec()..) {
                    if out.len() == limit {
                        break;
                    }
                    out.push((key.clone(), value.clone()));
                }
            }
        }
        out
    }
}

fn table_storage_map(schemas: &[Schema]) -> rusqlite::Result<HashMap<TableName, StorageClass>> {
    let mut out = HashMap::new();
    for schema in schemas {
        if let SchemaDefinition::RowTable(table) = schema.definition {
            match out.insert(table, schema.storage) {
                Some(existing) if existing != schema.storage => {
                    return Err(rusqlite::Error::InvalidParameterName(format!(
                        "table {} declared with multiple storage classes",
                        table.as_str()
                    )));
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

fn validate_schema_ids(schemas: &[Schema]) -> rusqlite::Result<()> {
    for (left_index, left) in schemas.iter().enumerate() {
        validate_schema_id(left.id)?;
        for right in &schemas[left_index + 1..] {
            if left.id == right.id {
                return Err(rusqlite::Error::InvalidParameterName(format!(
                    "duplicate schema id {}",
                    left.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_schema_id(id: &str) -> rusqlite::Result<()> {
    if id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Ok(());
    }
    Err(rusqlite::Error::InvalidParameterName(format!(
        "invalid schema id {id}"
    )))
}

/// Compute the exclusive upper bound for a byte-prefix range.
fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    for byte in upper.iter_mut().rev() {
        if *byte != u8::MAX {
            *byte += 1;
            upper.truncate(
                prefix
                    .iter()
                    .rposition(|candidate| *candidate != u8::MAX)
                    .expect("position found")
                    + 1,
            );
            return Some(upper);
        }
    }
    None
}

/// Quote a trusted static table name after rejecting unsafe identifier bytes.
fn quoted_table_name(table: TableName) -> rusqlite::Result<String> {
    let name = table.as_str();
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
    {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "invalid table name {name}"
        )));
    }
    Ok(format!("\"{name}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ROWS: TableName = TableName::new("test.rows");
    const MEMORY_ROWS: TableName = TableName::new("test.memory_rows");

    #[test]
    fn duplicate_row_insert_is_idempotent_but_conflicting_value_rejects() {
        let store = Store::open_memory_with_schemas(&[Schema::durable_row_table(
            "test.rows.v1",
            TEST_ROWS,
        )])
        .expect("open store");
        let row = TableRow {
            table: TEST_ROWS,
            key: b"k".to_vec(),
            value: b"one".to_vec(),
        };

        assert_eq!(
            store.insert_table_rows(vec![row.clone()]).expect("insert"),
            1
        );
        assert_eq!(
            store
                .insert_table_rows(vec![row.clone()])
                .expect("idempotent insert"),
            0
        );

        let err = store
            .insert_table_rows(vec![TableRow {
                value: b"two".to_vec(),
                ..row
            }])
            .expect_err("conflicting insert must reject");

        assert!(err.to_string().contains("conflicting row for test.rows"));
    }

    #[test]
    fn memory_rows_are_store_local_and_not_sqlite_temp_tables() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("memory-rows.db");
        let schemas = [Schema::memory_row_table("test.memory_rows.v1", MEMORY_ROWS)];

        let store_a = Store::open_disk_with_schemas(&path, &schemas).expect("open store a");
        store_a
            .insert_table_rows(vec![TableRow {
                table: MEMORY_ROWS,
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            }])
            .expect("insert memory row");
        assert_eq!(store_a.table_row_count(MEMORY_ROWS).expect("count a"), 1);

        let store_b = Store::open_disk_with_schemas(&path, &schemas).expect("open store b");
        assert_eq!(
            store_b.table_row_count(MEMORY_ROWS).expect("count b"),
            0,
            "memory rows should be local to one Store handle"
        );

        assert!(
            store_a
                .conn
                .query_row(
                    "SELECT name FROM sqlite_temp_master WHERE type = 'table' AND name = ?1",
                    [MEMORY_ROWS.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .expect("query temp schema")
                .is_none(),
            "memory row tables should not be SQLite TEMP tables"
        );
    }

    #[test]
    fn memory_rows_roll_back_with_write_transaction() {
        let store = Store::open_memory_with_schemas(&[Schema::memory_row_table(
            "test.memory_rows.v1",
            MEMORY_ROWS,
        )])
        .expect("open store");

        let err = store
            .write_transaction(|store| {
                store.insert_table_rows_in_tx(vec![TableRow {
                    table: MEMORY_ROWS,
                    key: b"k".to_vec(),
                    value: b"v".to_vec(),
                }])?;
                Err::<(), _>(rusqlite::Error::InvalidParameterName(
                    "force rollback".to_string(),
                ))
            })
            .expect_err("transaction should roll back");

        assert!(err.to_string().contains("force rollback"));
        assert_eq!(
            store
                .table_row_count(MEMORY_ROWS)
                .expect("count after rollback"),
            0
        );
    }

    #[test]
    fn memory_prefix_scan_is_key_ordered_and_limited() {
        let store = Store::open_memory_with_schemas(&[Schema::memory_row_table(
            "test.memory_rows.v1",
            MEMORY_ROWS,
        )])
        .expect("open store");
        store
            .insert_table_rows(vec![
                TableRow {
                    table: MEMORY_ROWS,
                    key: b"b/2".to_vec(),
                    value: b"two".to_vec(),
                },
                TableRow {
                    table: MEMORY_ROWS,
                    key: b"b/1".to_vec(),
                    value: b"one".to_vec(),
                },
                TableRow {
                    table: MEMORY_ROWS,
                    key: b"c/1".to_vec(),
                    value: b"skip".to_vec(),
                },
            ])
            .expect("insert rows");

        let rows = store
            .table_rows_with_key_prefix(MEMORY_ROWS, b"b/", 1)
            .expect("scan prefix");
        assert_eq!(rows, vec![(b"b/1".to_vec(), b"one".to_vec())]);
    }
}
