-- Variant 03: Existing-minimal queue/blocking demo.
--
-- The schema is intentionally ordinary SQLite. The only "dataflow"
-- vocabulary used by the demo is:
--   queue   = a materialized boundary table or indexed status subset
--   blocked = event state plus explicit missing-dependency rows
--   ready   = an index over events.status, not a separate runtime

PRAGMA foreign_keys = ON;

CREATE TABLE module_catalog (
  table_name TEXT PRIMARY KEY,
  owner_module TEXT NOT NULL,
  storage_class TEXT NOT NULL CHECK (storage_class IN ('durable', 'memory', 'temp')),
  purpose TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE inbound_bytes (
  wire_id TEXT PRIMARY KEY,
  origin_connection_id TEXT NOT NULL,
  canonical_event_bytes BLOB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'processed', 'invalid')),
  not_before_ms INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  received_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX inbound_bytes_claim_idx
  ON inbound_bytes(status, not_before_ms, received_at_ms, wire_id);

CREATE TABLE events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT,
  workspace_id TEXT,
  canonical_event_bytes BLOB NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('durable', 'local', 'endpoint_local')),
  status TEXT NOT NULL CHECK (status IN ('processing', 'ready', 'blocked', 'applied', 'rejected')),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER,
  UNIQUE(canonical_event_bytes),
  CHECK (
    status = 'processing'
    OR (event_type IS NOT NULL AND workspace_id IS NOT NULL)
  )
) WITHOUT ROWID;

CREATE INDEX events_ready_idx
  ON events(status, created_at_ms, event_id);

CREATE INDEX events_workspace_status_idx
  ON events(workspace_id, status, event_id);

CREATE TABLE event_dependencies (
  event_id TEXT NOT NULL,
  depends_on_event_id TEXT NOT NULL,
  PRIMARY KEY(event_id, depends_on_event_id),
  FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX event_dependencies_dep_idx
  ON event_dependencies(depends_on_event_id, event_id);

CREATE TABLE blocked_by_event (
  blocked_by_event_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY(blocked_by_event_id, event_id),
  FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX blocked_by_event_event_idx
  ON blocked_by_event(event_id, blocked_by_event_id);

CREATE TABLE content_messages (
  event_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  message_name TEXT NOT NULL,
  body TEXT NOT NULL,
  applied_at_ms INTEGER NOT NULL,
  FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX content_messages_workspace_idx
  ON content_messages(workspace_id, message_name);

CREATE TABLE workspace_connections (
  workspace_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  PRIMARY KEY(workspace_id, connection_id)
) WITHOUT ROWID;

CREATE TABLE outbox (
  connection_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  queued_at_ms INTEGER NOT NULL,
  PRIMARY KEY(connection_id, event_id),
  FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX outbox_connection_idx
  ON outbox(connection_id, queued_at_ms, event_id);

INSERT INTO module_catalog(table_name, owner_module, storage_class, purpose) VALUES
  ('inbound_bytes', 'transport.ingress', 'durable', 'deduped transport ingress boundary claimed in bounded batches'),
  ('events', 'event_pipeline', 'durable', 'canonical event bytes plus projection state; ready rows are the event queue'),
  ('event_dependencies', 'event_pipeline', 'durable', 'parsed dependency metadata for audit and test checks'),
  ('blocked_by_event', 'event_pipeline', 'durable', 'missing-dependency wait edges; not a job queue'),
  ('content_messages', 'event_modules.content.message', 'durable', 'message projection owned by the message module'),
  ('workspace_connections', 'event_modules.connection', 'durable', 'connections subscribed to each workspace for projection-time outbox writes'),
  ('outbox', 'sender.connection', 'memory', 'deduped connection/event boundary consumed by one sender owner per connection');
