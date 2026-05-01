pub mod connection;
pub mod encrypted;
pub mod file;
pub mod file_slice;
pub mod forward_secret;
pub mod invite_accepted;
pub mod invite_secret;
pub mod key_request;
pub mod key_rotation;
pub mod key_secret;
pub mod key_shared;
pub mod layout;
pub mod message;
pub mod message_deletion;
pub mod peer_invite_shared;
pub mod peer_secret;
pub mod peer_shared;
pub mod reaction;
pub mod registry;
pub mod removal;
pub mod sync;
// TODO(plan.md Wave 1): tenant module retained as internal helper for the
// `tenants` projection table relied on by transport/discovery (see
// state/db/transport_creds.rs and runtime/peering). Event variant + registry
// entry stay until Wave 2 reshapes the identity chain.
pub mod tenant;
pub mod user;
pub mod user_invite_shared;
pub mod workspace;

use rusqlite::Connection;
use std::sync::OnceLock;

/// Human-readable field descriptions for CLI display.
/// Each event struct implements this to describe its "interesting" fields,
/// skipping IDs already shown as deps, signatures, and created_at.
pub trait Describe {
    fn human_fields(&self) -> Vec<(&'static str, String)>;
}

/// Format a 32-byte ID as short base64 (first 8 chars, parenthesized).
pub fn short_id_b64(id: &[u8; 32]) -> String {
    let b64 = crate::crypto::event_id_to_base64(id);
    let short = &b64[..b64.len().min(8)];
    format!("({})", short)
}

/// Truncated hex display for byte arrays.
pub fn trunc_hex(bytes: &[u8], max_hex_chars: usize) -> String {
    let h = hex::encode(bytes);
    if h.len() > max_hex_chars {
        format!("{}...", &h[..max_hex_chars])
    } else {
        h
    }
}

pub use connection::connection_prekey::ConnectionPrekeyEvent;
pub use connection::connection_prekey_shared::ConnectionPrekeySharedEvent;
pub use connection::intro::IntroEvent;
pub use connection::negentropy::NegentropyEvent;
pub use connection::observed_address::ObservedAddressEvent;
pub use connection::self_address::SelfAddressEvent;
pub use connection::sync_window::SyncWindowEvent;
pub use connection::ConnectionEvent;
pub use encrypted::EncryptedEvent;
pub use file::FileEvent;
pub use file_slice::FileSliceEvent;
pub use forward_secret::ForwardSecretEvent;
pub use invite_accepted::InviteAcceptedEvent;
pub use invite_secret::InviteSecretEvent;
pub use key_request::KeyRequestEvent;
pub use key_rotation::KeyRotationEvent;
pub use key_secret::KeySecretEvent;
pub use key_shared::KeySharedEvent;
pub use message::MessageEvent;
pub use message_deletion::MessageDeletionEvent;
pub use peer_invite_shared::DeviceInviteEvent;
pub use peer_secret::PeerSecretEvent;
pub use peer_shared::PeerSharedEvent;
pub use reaction::ReactionEvent;
pub use registry::{EventRegistry, EventTypeMeta, ShareScope, TransportPrivacy};
pub use removal::RemovalEvent;
pub use sync::compare::CompareEvent;
pub use sync::have::HaveEvent;
pub use sync::need::NeedEvent;
pub use tenant::TenantEvent;
pub use user::UserEvent;
pub use user_invite_shared::UserInviteEvent;
pub use workspace::WorkspaceEvent;

pub const EVENT_TYPE_MESSAGE: u8 = 1;
pub const EVENT_TYPE_REACTION: u8 = 2;
pub const EVENT_TYPE_ENCRYPTED: u8 = 5;
pub const EVENT_TYPE_KEY_SECRET: u8 = 6;
pub const EVENT_TYPE_MESSAGE_DELETION: u8 = 7;
pub const EVENT_TYPE_WORKSPACE: u8 = 8;
pub const EVENT_TYPE_INVITE_ACCEPTED: u8 = 9;
pub const EVENT_TYPE_USER_INVITE: u8 = 10;
pub const EVENT_TYPE_DEVICE_INVITE: u8 = 12;
pub const EVENT_TYPE_USER: u8 = 14;
pub const EVENT_TYPE_PEER_SHARED: u8 = 16;
pub const EVENT_TYPE_ADMIN: u8 = 18; // reserved (dropped admin event in Wave 1)
pub const EVENT_TYPE_KEY_SHARED: u8 = 22;
pub const EVENT_TYPE_PEER: u8 = 23; // reserved (retired local peer event)
// 24/25 are the legacy poc-7 slots; left reserved here so that legacy blobs
// don't accidentally collide with the new chain-friendly file/file_slice
// event types, which live at 45/46 (see below).
pub const EVENT_TYPE_FILE_LEGACY_RESERVED: u8 = 24;
pub const EVENT_TYPE_FILE_SLICE_LEGACY_RESERVED: u8 = 25;
pub const EVENT_TYPE_BENCH_DEP: u8 = 26; // reserved (dropped bench_dep event in Wave 1)
pub const EVENT_TYPE_PEER_SECRET: u8 = 27;
pub const EVENT_TYPE_INVITE_SECRET: u8 = 28;
pub const EVENT_TYPE_TENANT: u8 = 29;
pub const EVENT_TYPE_KEY_REQUEST: u8 = 30;
pub const EVENT_TYPE_REMOVAL: u8 = 31;
pub const EVENT_TYPE_KEY_ROTATION: u8 = 32;
// Phase 2 connection-related event type codes (per plan.md lines 204-218).
pub const EVENT_TYPE_CONNECTION: u8 = 33;
pub const EVENT_TYPE_CONNECTION_PREKEY: u8 = 34;
pub const EVENT_TYPE_CONNECTION_PREKEY_SHARED: u8 = 35;
pub const EVENT_TYPE_INTRO: u8 = 36;
pub const EVENT_TYPE_OBSERVED_ADDRESS: u8 = 37;
pub const EVENT_TYPE_SELF_ADDRESS: u8 = 38;
pub const EVENT_TYPE_NEGENTROPY: u8 = 39;
pub const EVENT_TYPE_SYNC_WINDOW: u8 = 40;
// sync event-module family (plan.md lines 295-430). 41/42/43 are claimed by
// the compare/have/need events; 44 is reserved for negentropy_tree-internal
// events if we promote any of its maintenance signals into the event
// pipeline later.
pub const EVENT_TYPE_COMPARE: u8 = 41;
pub const EVENT_TYPE_HAVE: u8 = 42;
pub const EVENT_TYPE_NEED: u8 = 43;
pub const EVENT_TYPE_NEGENTROPY_TREE_RESERVED: u8 = 44;
// File family (Wave 1 chain-friendly port — see plan.md and
// `event_modules/file{,_slice}/`). Wired in at 45/46 because the legacy
// poc-7 slots 24/25 are reserved (see `EVENT_TYPE_FILE_LEGACY_RESERVED`).
pub const EVENT_TYPE_FILE: u8 = 45;
pub const EVENT_TYPE_FILE_SLICE: u8 = 46;
pub const EVENT_TYPE_FORWARD_SECRET: u8 = 47;

/// Max event blob size: 64 MiB.
///
/// Raised from 1 MiB to admit FileEvents for large files: a 100 MiB
/// plaintext yields a ~6.4 MB bao_outboard plus the FileEvent fixed
/// prefix, so 64 MiB comfortably fits any FileEvent we currently
/// produce. Most non-file events stay well under 1 KiB; the cap exists
/// purely to bound the worst-case frame the protocol parser will
/// allocate for.
///
/// TODO(plan.md): if this limit ever becomes too lax for some events
/// (e.g. encrypted wrappers around big payloads), introduce a per-
/// event-type override on `EventTypeMeta` and split the FileEvent
/// outboard into a dedicated `file_outboard_chunk` event family. For
/// now a single global cap keeps the wire codec simple.
pub const EVENT_MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;

pub fn outer_semantic_type_code(blob: &[u8]) -> Option<u8> {
    match blob.first().copied() {
        Some(EVENT_TYPE_ENCRYPTED) => encrypted::outer_inner_type_code(blob),
        Some(type_code) => Some(type_code),
        None => None,
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    // Each event module's schema is now declared on its `EventTypeMeta` and
    // installed by `ensure_all_module_schemas`. The legacy umbrella stays
    // for callers that historically invoked it (the wave-1 `create_tables`
    // bootstrap path) and additionally installs `subscriptions`, which is
    // owned by `state::subscriptions`, not by any event module.
    ensure_all_module_schemas(conn)?;
    crate::state::subscriptions::ensure_schema(conn)?;
    Ok(())
}

/// Walk the event-type registry and call each module's declared
/// `ensure_schema` (`plan.md` "State and Registry", lines 124-176).
///
/// `state::db::ensure_infra_schema` calls this directly so domain-shape
/// knowledge stays in the owning event module — `state/db` only knows
/// about the boundary tables it owns (`events_canonical`,
/// `inbound_bytes`, `blocked_by_event`, `outbox`, `labels`,
/// `job_schedules`, `inbound_observations`).
pub fn ensure_all_module_schemas(conn: &Connection) -> rusqlite::Result<()> {
    for meta in registry().iter() {
        if let Some(ensure) = meta.ensure_schema {
            ensure(conn)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedEvent {
    Message(MessageEvent),
    Reaction(ReactionEvent),
    Encrypted(EncryptedEvent),
    KeySecret(KeySecretEvent),
    MessageDeletion(MessageDeletionEvent),
    Workspace(WorkspaceEvent),
    InviteAccepted(InviteAcceptedEvent),
    Removal(RemovalEvent),
    KeyRotation(KeyRotationEvent),
    KeyRequest(KeyRequestEvent),
    UserInvite(UserInviteEvent),
    DeviceInvite(DeviceInviteEvent),
    User(UserEvent),
    PeerShared(PeerSharedEvent),
    KeyShared(KeySharedEvent),
    Tenant(TenantEvent),
    PeerSecret(PeerSecretEvent),
    InviteSecret(InviteSecretEvent),
    // Phase 2 connection-related events (plan.md lines 204-218). They run
    // through the substrate inbound chain via `event_modules::connection`
    // helpers; see `runtime/control_loop/inbound_step` for the dispatch.
    Connection(ConnectionEvent),
    ConnectionPrekey(ConnectionPrekeyEvent),
    ConnectionPrekeyShared(ConnectionPrekeySharedEvent),
    Intro(IntroEvent),
    ObservedAddress(ObservedAddressEvent),
    SelfAddress(SelfAddressEvent),
    Negentropy(NegentropyEvent),
    SyncWindow(SyncWindowEvent),
    // sync event-module family (plan.md lines 295-430). Endpoint-local
    // hints; signed by the surrounding connection wrap, not by an event-
    // graph signature.
    Compare(CompareEvent),
    Have(HaveEvent),
    Need(NeedEvent),
    // File family (Wave 1 chain-friendly port).
    File(FileEvent),
    FileSlice(FileSliceEvent),
    ForwardSecret(ForwardSecretEvent),
}

impl ParsedEvent {
    pub fn created_at_ms(&self) -> u64 {
        match self {
            ParsedEvent::Message(m) => m.created_at_ms,
            ParsedEvent::Reaction(r) => r.created_at_ms,
            ParsedEvent::Encrypted(e) => e.created_at_ms,
            ParsedEvent::KeySecret(s) => s.created_at_ms,
            ParsedEvent::MessageDeletion(d) => d.created_at_ms,
            ParsedEvent::Workspace(w) => w.created_at_ms,
            ParsedEvent::InviteAccepted(a) => a.created_at_ms,
            ParsedEvent::Removal(r) => r.created_at_ms,
            ParsedEvent::KeyRotation(k) => k.created_at_ms,
            ParsedEvent::KeyRequest(k) => k.created_at_ms,
            ParsedEvent::UserInvite(u) => u.created_at_ms,
            ParsedEvent::DeviceInvite(d) => d.created_at_ms,
            ParsedEvent::User(u) => u.created_at_ms,
            ParsedEvent::PeerShared(p) => p.created_at_ms,
            ParsedEvent::KeyShared(s) => s.created_at_ms,
            ParsedEvent::Tenant(t) => t.created_at_ms,
            ParsedEvent::PeerSecret(l) => l.created_at_ms,
            ParsedEvent::InviteSecret(k) => k.created_at_ms,
            ParsedEvent::Connection(e) => e.created_at_ms,
            ParsedEvent::ConnectionPrekey(e) => e.created_at_ms,
            ParsedEvent::ConnectionPrekeyShared(e) => e.created_at_ms,
            ParsedEvent::Intro(e) => e.created_at_ms,
            ParsedEvent::ObservedAddress(e) => e.observed_at_ms,
            ParsedEvent::SelfAddress(e) => e.created_at_ms,
            ParsedEvent::Negentropy(e) => e.created_at_ms,
            ParsedEvent::SyncWindow(e) => e.created_at_ms,
            ParsedEvent::Compare(e) => e.created_at_ms,
            ParsedEvent::Have(e) => e.created_at_ms,
            ParsedEvent::Need(e) => e.created_at_ms,
            ParsedEvent::File(e) => e.created_at_ms,
            ParsedEvent::FileSlice(e) => e.created_at_ms,
            ParsedEvent::ForwardSecret(e) => e.created_at_ms,
        }
    }

    /// Extract dependency event IDs from schema-marked fields.
    /// Returns (field_name, raw_32_byte_id) pairs.
    ///
    /// Ordering is semantic: the most structural dep is listed first.
    pub fn dep_field_values(&self) -> Vec<(&'static str, [u8; 32])> {
        match self {
            ParsedEvent::Message(m) => vec![("author_id", m.author_id), ("signed_by", m.signed_by)],
            ParsedEvent::Reaction(r) => vec![
                ("target_event_id", r.target_event_id),
                ("author_id", r.author_id),
                ("signed_by", r.signed_by),
            ],
            ParsedEvent::Encrypted(e) => vec![("key_event_id", e.key_event_id)],
            ParsedEvent::KeySecret(_) => vec![],
            ParsedEvent::MessageDeletion(d) => vec![("signed_by", d.signed_by)],
            ParsedEvent::Workspace(_) => vec![],
            ParsedEvent::InviteAccepted(a) => vec![("tenant_event_id", a.tenant_event_id)],
            ParsedEvent::Removal(r) => {
                let slots = [r.parent_1, r.parent_2, r.parent_3, r.parent_4];
                let mut deps = removal::frontier_refs_from_slots(r.parent_count, &slots)
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(idx, id)| match idx {
                        0 => ("parent_1", id),
                        1 => ("parent_2", id),
                        2 => ("parent_3", id),
                        _ => ("parent_4", id),
                    })
                    .collect::<Vec<_>>();
                deps.push(("signed_by", r.signed_by));
                deps
            }
            ParsedEvent::KeyRotation(k) => {
                let slots = [
                    k.frontier_ref_1,
                    k.frontier_ref_2,
                    k.frontier_ref_3,
                    k.frontier_ref_4,
                ];
                let mut deps = removal::frontier_refs_from_slots(k.frontier_count, &slots)
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(idx, id)| match idx {
                        0 => ("frontier_ref_1", id),
                        1 => ("frontier_ref_2", id),
                        2 => ("frontier_ref_3", id),
                        _ => ("frontier_ref_4", id),
                    })
                    .collect::<Vec<_>>();
                deps.push(("signed_by", k.signed_by));
                deps
            }
            ParsedEvent::KeyRequest(k) => vec![("signed_by", k.signed_by)],
            ParsedEvent::UserInvite(u) => {
                vec![
                    ("authority_event_id", u.authority_event_id),
                    ("signed_by", u.signed_by),
                ]
            }
            ParsedEvent::DeviceInvite(d) => {
                vec![
                    ("authority_event_id", d.authority_event_id),
                    ("signed_by", d.signed_by),
                ]
            }
            ParsedEvent::User(u) => vec![("signed_by", u.signed_by)],
            ParsedEvent::PeerShared(p) => {
                vec![
                    ("user_event_id", p.user_event_id),
                    ("signed_by", p.signed_by),
                ]
            }
            ParsedEvent::KeyShared(s) => {
                let slots = [
                    s.frontier_ref_1,
                    s.frontier_ref_2,
                    s.frontier_ref_3,
                    s.frontier_ref_4,
                ];
                let mut deps = vec![("recipient_event_id", s.recipient_event_id)];
                deps.extend(
                    removal::frontier_refs_from_slots(s.frontier_count, &slots)
                        .unwrap_or_default()
                        .into_iter()
                        .enumerate()
                        .map(|(idx, id)| match idx {
                            0 => ("frontier_ref_1", id),
                            1 => ("frontier_ref_2", id),
                            2 => ("frontier_ref_3", id),
                            _ => ("frontier_ref_4", id),
                        }),
                );
                deps.push(("signed_by", s.signed_by));
                deps
            }
            ParsedEvent::Tenant(_) => vec![],
            ParsedEvent::PeerSecret(p) => vec![("signer_event_id", p.signer_event_id)],
            ParsedEvent::InviteSecret(_) => vec![],
            // Connection-related events: signers are endpoint identities,
            // not poc-7-style event IDs, so we intentionally surface no
            // dependency edges to the legacy ParsedEvent dep graph.
            ParsedEvent::Connection(_) => vec![],
            ParsedEvent::ConnectionPrekey(_) => vec![],
            ParsedEvent::ConnectionPrekeyShared(_) => vec![],
            ParsedEvent::Intro(_) => vec![],
            ParsedEvent::ObservedAddress(_) => vec![],
            ParsedEvent::SelfAddress(_) => vec![],
            ParsedEvent::Negentropy(_) => vec![],
            ParsedEvent::SyncWindow(_) => vec![],
            // sync events are endpoint-local hints; no dependency edges.
            ParsedEvent::Compare(_) => vec![],
            ParsedEvent::Have(_) => vec![],
            ParsedEvent::Need(_) => vec![],
            // File events: signed_by is the only graph-relevant dep.
            // The file event's `workspace_id` is informational, not a
            // dep edge in the legacy ParsedEvent graph (legacy chain
            // already gates on workspace via the projection-time check).
            ParsedEvent::File(f) => vec![("signed_by", f.signed_by)],
            ParsedEvent::FileSlice(s) => vec![
                ("file_event_id", s.file_event_id),
                ("signed_by", s.signed_by),
            ],
            ParsedEvent::ForwardSecret(_) => vec![],
        }
    }

    pub fn event_type_code(&self) -> u8 {
        match self {
            ParsedEvent::Message(_) => EVENT_TYPE_MESSAGE,
            ParsedEvent::Reaction(_) => EVENT_TYPE_REACTION,
            ParsedEvent::Encrypted(_) => EVENT_TYPE_ENCRYPTED,
            ParsedEvent::KeySecret(_) => EVENT_TYPE_KEY_SECRET,
            ParsedEvent::MessageDeletion(_) => EVENT_TYPE_MESSAGE_DELETION,
            ParsedEvent::Workspace(_) => EVENT_TYPE_WORKSPACE,
            ParsedEvent::InviteAccepted(_) => EVENT_TYPE_INVITE_ACCEPTED,
            ParsedEvent::Removal(_) => EVENT_TYPE_REMOVAL,
            ParsedEvent::KeyRotation(_) => EVENT_TYPE_KEY_ROTATION,
            ParsedEvent::KeyRequest(_) => EVENT_TYPE_KEY_REQUEST,
            ParsedEvent::UserInvite(_) => EVENT_TYPE_USER_INVITE,
            ParsedEvent::DeviceInvite(_) => EVENT_TYPE_DEVICE_INVITE,
            ParsedEvent::User(_) => EVENT_TYPE_USER,
            ParsedEvent::PeerShared(_) => EVENT_TYPE_PEER_SHARED,
            ParsedEvent::KeyShared(_) => EVENT_TYPE_KEY_SHARED,
            ParsedEvent::Tenant(_) => EVENT_TYPE_TENANT,
            ParsedEvent::PeerSecret(_) => EVENT_TYPE_PEER_SECRET,
            ParsedEvent::InviteSecret(_) => EVENT_TYPE_INVITE_SECRET,
            ParsedEvent::Connection(_) => EVENT_TYPE_CONNECTION,
            ParsedEvent::ConnectionPrekey(_) => EVENT_TYPE_CONNECTION_PREKEY,
            ParsedEvent::ConnectionPrekeyShared(_) => EVENT_TYPE_CONNECTION_PREKEY_SHARED,
            ParsedEvent::Intro(_) => EVENT_TYPE_INTRO,
            ParsedEvent::ObservedAddress(_) => EVENT_TYPE_OBSERVED_ADDRESS,
            ParsedEvent::SelfAddress(_) => EVENT_TYPE_SELF_ADDRESS,
            ParsedEvent::Negentropy(_) => EVENT_TYPE_NEGENTROPY,
            ParsedEvent::SyncWindow(_) => EVENT_TYPE_SYNC_WINDOW,
            ParsedEvent::Compare(_) => EVENT_TYPE_COMPARE,
            ParsedEvent::Have(_) => EVENT_TYPE_HAVE,
            ParsedEvent::Need(_) => EVENT_TYPE_NEED,
            ParsedEvent::File(_) => EVENT_TYPE_FILE,
            ParsedEvent::FileSlice(_) => EVENT_TYPE_FILE_SLICE,
            ParsedEvent::ForwardSecret(_) => EVENT_TYPE_FORWARD_SECRET,
        }
    }

    /// Return signer info for signed event types: (signer_event_id, signer_type).
    /// Returns None for unsigned types.
    pub fn signer_fields(&self) -> Option<([u8; 32], u8)> {
        match self {
            ParsedEvent::UserInvite(u) => Some((u.signed_by, u.signer_type)),
            ParsedEvent::DeviceInvite(d) => Some((d.signed_by, d.signer_type)),
            ParsedEvent::User(u) => Some((u.signed_by, u.signer_type)),
            ParsedEvent::PeerShared(p) => Some((p.signed_by, p.signer_type)),
            ParsedEvent::KeyShared(s) => Some((s.signed_by, s.signer_type)),
            ParsedEvent::Removal(r) => Some((r.signed_by, r.signer_type)),
            ParsedEvent::KeyRotation(k) => Some((k.signed_by, k.signer_type)),
            ParsedEvent::KeyRequest(k) => Some((k.signed_by, k.signer_type)),
            ParsedEvent::Message(m) => Some((m.signed_by, m.signer_type)),
            ParsedEvent::Reaction(r) => Some((r.signed_by, r.signer_type)),
            ParsedEvent::MessageDeletion(d) => Some((d.signed_by, d.signer_type)),
            ParsedEvent::File(f) => Some((f.signed_by, f.signer_type)),
            ParsedEvent::FileSlice(s) => Some((s.signed_by, s.signer_type)),
            ParsedEvent::Encrypted(_)
            | ParsedEvent::KeySecret(_)
            | ParsedEvent::Workspace(_)
            | ParsedEvent::InviteAccepted(_)
            | ParsedEvent::Tenant(_)
            | ParsedEvent::PeerSecret(_)
            | ParsedEvent::InviteSecret(_)
            // Connection-related events: signed by endpoint identities, not
            // by ParsedEvent-graph signer events, so they intentionally
            // return None here. Verification is done by their own
            // projectors.
            | ParsedEvent::Connection(_)
            | ParsedEvent::ConnectionPrekey(_)
            | ParsedEvent::ConnectionPrekeyShared(_)
            | ParsedEvent::Intro(_)
            | ParsedEvent::ObservedAddress(_)
            | ParsedEvent::SelfAddress(_)
            | ParsedEvent::Negentropy(_)
            | ParsedEvent::SyncWindow(_)
            | ParsedEvent::Compare(_)
            | ParsedEvent::Have(_)
            | ParsedEvent::Need(_)
            | ParsedEvent::ForwardSecret(_) => None,
        }
    }

    /// Human-readable field descriptions for CLI display.
    pub fn human_fields(&self) -> Vec<(&'static str, String)> {
        match self {
            ParsedEvent::Message(e) => e.human_fields(),
            ParsedEvent::Reaction(e) => e.human_fields(),
            ParsedEvent::Encrypted(e) => e.human_fields(),
            ParsedEvent::KeySecret(e) => e.human_fields(),
            ParsedEvent::MessageDeletion(e) => e.human_fields(),
            ParsedEvent::Workspace(e) => e.human_fields(),
            ParsedEvent::InviteAccepted(e) => e.human_fields(),
            ParsedEvent::Removal(e) => e.human_fields(),
            ParsedEvent::KeyRotation(e) => e.human_fields(),
            ParsedEvent::KeyRequest(e) => e.human_fields(),
            ParsedEvent::UserInvite(e) => e.human_fields(),
            ParsedEvent::DeviceInvite(e) => e.human_fields(),
            ParsedEvent::User(e) => e.human_fields(),
            ParsedEvent::PeerShared(e) => e.human_fields(),
            ParsedEvent::KeyShared(e) => e.human_fields(),
            ParsedEvent::PeerSecret(e) => e.human_fields(),
            ParsedEvent::Tenant(e) => e.human_fields(),
            ParsedEvent::InviteSecret(e) => e.human_fields(),
            ParsedEvent::Connection(e) => e.human_fields(),
            ParsedEvent::ConnectionPrekey(e) => e.human_fields(),
            ParsedEvent::ConnectionPrekeyShared(e) => e.human_fields(),
            ParsedEvent::Intro(e) => e.human_fields(),
            ParsedEvent::ObservedAddress(e) => e.human_fields(),
            ParsedEvent::SelfAddress(e) => e.human_fields(),
            ParsedEvent::Negentropy(e) => e.human_fields(),
            ParsedEvent::SyncWindow(e) => e.human_fields(),
            ParsedEvent::Compare(e) => e.human_fields(),
            ParsedEvent::Have(e) => e.human_fields(),
            ParsedEvent::Need(e) => e.human_fields(),
            ParsedEvent::File(e) => e.human_fields(),
            ParsedEvent::FileSlice(e) => e.human_fields(),
            ParsedEvent::ForwardSecret(e) => e.human_fields(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    TooShort { expected: usize, actual: usize },
    TrailingData { expected: usize, actual: usize },
    WrongType { expected: u8, actual: u8 },
    WrongVariant,
    ContentTooLong(usize),
    InvalidMetadata(&'static str),
    UnknownType(u8),
    TextSlot(layout::common::TextSlotError),
    InvalidEncryptedInnerType(u8),
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventError::TooShort { expected, actual } => {
                write!(
                    f,
                    "blob too short: expected {} bytes, got {}",
                    expected, actual
                )
            }
            EventError::TrailingData { expected, actual } => {
                write!(
                    f,
                    "blob has trailing data: expected exactly {} bytes, got {}",
                    expected, actual
                )
            }
            EventError::WrongType { expected, actual } => {
                write!(f, "wrong event type: expected {}, got {}", expected, actual)
            }
            EventError::WrongVariant => write!(f, "wrong ParsedEvent variant for encoder"),
            EventError::ContentTooLong(len) => write!(f, "content too long: {} bytes", len),
            EventError::InvalidMetadata(msg) => write!(f, "invalid metadata: {}", msg),
            EventError::UnknownType(t) => write!(f, "unknown event type: {}", t),
            EventError::TextSlot(e) => write!(f, "text slot error: {}", e),
            EventError::InvalidEncryptedInnerType(t) => {
                write!(f, "invalid encrypted inner type: {}", t)
            }
        }
    }
}

impl std::error::Error for EventError {}

/// Extract created_at_ms from the common 9-byte prefix without full parsing.
/// Returns None if blob is too short.
pub fn extract_created_at_ms(blob: &[u8]) -> Option<u64> {
    if blob.len() < 9 {
        return None;
    }
    Some(u64::from_le_bytes(blob[1..9].try_into().unwrap()))
}

/// Extract event_type from the first byte of the blob.
pub fn extract_event_type(blob: &[u8]) -> Option<u8> {
    blob.first().copied()
}

static REGISTRY: OnceLock<EventRegistry> = OnceLock::new();

pub fn registry() -> &'static EventRegistry {
    REGISTRY.get_or_init(|| {
        EventRegistry::new(&[
            &message::MESSAGE_META,
            &reaction::REACTION_TYPE_META,
            &encrypted::ENCRYPTED_META,
            &key_secret::KEY_SECRET_META,
            &message_deletion::MESSAGE_DELETION_META,
            &workspace::WORKSPACE_META,
            &invite_accepted::INVITE_ACCEPTED_META,
            &removal::REMOVAL_META,
            &key_rotation::KEY_ROTATION_META,
            &key_request::KEY_REQUEST_META,
            &user_invite_shared::USER_INVITE_META,
            &peer_invite_shared::DEVICE_INVITE_META,
            &user::USER_META,
            &peer_shared::PEER_SHARED_META,
            &key_shared::KEY_SHARED_META,
            &tenant::TENANT_META,
            &peer_secret::PEER_SECRET_META,
            &invite_secret::INVITE_SECRET_META,
            // Phase 9 (registry-wire-up): connection-related event types
            // 33..=40. Type code 33 (`connection`) is now wired with real
            // ed25519 signature verification (see connection/registry_meta.rs
            // and connection/event.rs::signing_bytes).
            &connection::CONNECTION_META,
            &connection::connection_prekey::CONNECTION_PREKEY_META,
            &connection::connection_prekey_shared::CONNECTION_PREKEY_SHARED_META,
            &connection::intro::INTRO_META,
            &connection::observed_address::OBSERVED_ADDRESS_META,
            &connection::self_address::SELF_ADDRESS_META,
            &connection::negentropy::NEGENTROPY_META,
            &connection::sync_window::SYNC_WINDOW_META,
            // sync event-module family (plan.md lines 295-430).
            &sync::compare::COMPARE_META,
            &sync::have::HAVE_META,
            &sync::need::NEED_META,
            // File family (Wave 1 chain-friendly port).
            &file::FILE_META,
            &file_slice::FILE_SLICE_META,
            &forward_secret::FORWARD_SECRET_META,
        ])
    })
}

/// Parse a blob using the global registry.
pub fn parse_event(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let type_code = blob.first().copied().ok_or(EventError::TooShort {
        expected: 1,
        actual: 0,
    })?;
    let meta = registry()
        .lookup(type_code)
        .ok_or(EventError::UnknownType(type_code))?;
    (meta.parse)(blob)
}

/// Encode a ParsedEvent using the global registry.
pub fn encode_event(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let type_code = event.event_type_code();
    let meta = registry()
        .lookup(type_code)
        .ok_or(EventError::UnknownType(type_code))?;
    (meta.encode)(event)
}

/// Generic post-projection-drain hooks.
pub fn post_drain_hooks(
    _conn: &rusqlite::Connection,
    _recorded_by: &str,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_roundtrip_user() {
        let e = UserEvent {
            created_at_ms: 500,
            workspace_id: [27u8; 32],
            public_key: [28u8; 32],
            username: "test-user".to_string(),
            signed_by: [29u8; 32],
            signer_type: 2,
            signature: [30u8; 64],
        };
        let event = ParsedEvent::User(e);
        let blob = encode_event(&event).unwrap();
        assert_eq!(blob.len(), user::USER_WIRE_SIZE);
        let parsed = parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_registry_encryptable_coverage() {
        let reg = registry();
        let encryptable_codes: Vec<u8> = (1..=29u8)
            .filter(|c| reg.lookup(*c).is_some_and(|m| m.encryptable))
            .collect();
        // Wave 1: file (24) and file_slice (25) dropped; only message-tier
        // events remain encryptable.
        assert_eq!(encryptable_codes, vec![1, 2, 6, 7]);

        for code in [5, 8, 9, 10, 12, 14, 16, 22, 27, 28, 29] {
            if let Some(meta) = reg.lookup(code) {
                assert!(
                    !meta.encryptable,
                    "type {} ({}) should not be encryptable",
                    code, meta.type_name
                );
            }
        }

        // Reserved/dropped codes have no registry entry.
        // Note: 24/25 are reserved as legacy file/file_slice slots; the new
        // chain-friendly file family lives at 45/46.
        for removed in [11, 13, 15, 17, 18, 19, 20, 21, 23, 24, 25, 26] {
            assert!(reg.lookup(removed).is_none());
        }
    }

    #[test]
    fn test_registry_transport_privacy_coverage() {
        let reg = registry();
        let required_codes: Vec<u8> = (1..=29u8)
            .filter(|c| {
                reg.lookup(*c)
                    .is_some_and(|m| m.transport_privacy() == TransportPrivacy::RequireEncrypted)
            })
            .collect();
        // Wave 1: file/file_slice dropped; only message + reaction +
        // message_deletion still require encryption.
        assert_eq!(required_codes, vec![1, 2, 7]);

        assert_eq!(
            reg.lookup(EVENT_TYPE_KEY_SECRET)
                .unwrap()
                .transport_privacy(),
            TransportPrivacy::Optional
        );

        for code in [5, 8, 9, 10, 12, 14, 16, 22, 27, 28, 29] {
            if let Some(meta) = reg.lookup(code) {
                assert_eq!(
                    meta.transport_privacy(),
                    TransportPrivacy::PlaintextOnly,
                    "type {} ({}) should remain plaintext-only",
                    code,
                    meta.type_name
                );
            }
        }
    }

    #[test]
    fn test_signer_fields_unsigned() {
        let ws = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: 100,
            workspace_id: [0u8; 32],
            public_key: [0u8; 32],
            name: "test-workspace".to_string(),
        });
        assert!(ws.signer_fields().is_none());
    }

    /// Phase 9 wire-up: ConnectionPrekey event must round-trip through the
    /// global event registry (parse_event → ParsedEvent::ConnectionPrekey)
    /// AND through the registry's pure projector dispatch, producing a row
    /// in `connection_prekeys`.
    ///
    /// Mirrors the task spec: encode → parse_event(type_code=34, blob) →
    /// project (via meta.projector) → state row exists.
    #[test]
    fn test_connection_prekey_registry_roundtrip_and_projection() {
        use crate::projection::contract::{SqlVal, WriteOp};
        use crate::projection::contract::ContextSnapshot;
        use crate::projection::decision::ProjectionDecision;
        use ed25519_dalek::{Signer, SigningKey};
        use rusqlite::Connection as SqlConnection;

        // Inline a minimal write executor matching state::projection::apply::
        // write_exec::execute_write_ops (which is pub(crate) and not exported
        // here). Keeps this test self-contained inside the event_modules
        // module without piercing the apply/ private boundary.
        fn run_write_ops(conn: &SqlConnection, ops: &[WriteOp]) {
            for op in ops {
                match op {
                    WriteOp::InsertOrIgnore { table, columns, values } => {
                        let cols = columns.join(", ");
                        let placeholders: Vec<String> =
                            (1..=values.len()).map(|i| format!("?{}", i)).collect();
                        let sql = format!(
                            "INSERT OR IGNORE INTO {} ({}) VALUES ({})",
                            table, cols, placeholders.join(", ")
                        );
                        let params: Vec<Box<dyn rusqlite::types::ToSql>> = values
                            .iter()
                            .map(|v| -> Box<dyn rusqlite::types::ToSql> {
                                match v {
                                    SqlVal::Text(s) => Box::new(s.clone()),
                                    SqlVal::Int(i) => Box::new(*i),
                                    SqlVal::Blob(b) => Box::new(b.clone()),
                                }
                            })
                            .collect();
                        let refs: Vec<&dyn rusqlite::types::ToSql> =
                            params.iter().map(|p| &**p).collect();
                        conn.execute(&sql, refs.as_slice()).unwrap();
                    }
                    WriteOp::Delete { table, where_clause } => {
                        let conds: Vec<String> = where_clause
                            .iter()
                            .enumerate()
                            .map(|(i, (c, _))| format!("{} = ?{}", c, i + 1))
                            .collect();
                        let sql = format!("DELETE FROM {} WHERE {}", table, conds.join(" AND "));
                        let params: Vec<Box<dyn rusqlite::types::ToSql>> = where_clause
                            .iter()
                            .map(|(_, v)| -> Box<dyn rusqlite::types::ToSql> {
                                match v {
                                    SqlVal::Text(s) => Box::new(s.clone()),
                                    SqlVal::Int(i) => Box::new(*i),
                                    SqlVal::Blob(b) => Box::new(b.clone()),
                                }
                            })
                            .collect();
                        let refs: Vec<&dyn rusqlite::types::ToSql> =
                            params.iter().map(|p| &**p).collect();
                        conn.execute(&sql, refs.as_slice()).unwrap();
                    }
                }
            }
        }

        // Construct a properly-signed ConnectionPrekey event.
        let sk = SigningKey::from_bytes(&[0xC1u8; 32]);
        let endpoint_id = sk.verifying_key().to_bytes();
        let mut ev = ConnectionPrekeyEvent {
            prekey_id: [0x42u8; 32],
            endpoint_id,
            private_key: [0x10u8; 32],
            public_key: [0x11u8; 32],
            created_at_ms: 1234,
            ttl_ms: 60_000,
            signature: [0u8; 64],
        };
        ev.signature = sk.sign(&ev.signing_bytes()).to_bytes();
        let parsed_in = ParsedEvent::ConnectionPrekey(ev.clone());

        // 1. Encode via the registry.
        let blob = encode_event(&parsed_in).expect("encode through registry");
        // First byte must be the connection_prekey type code (34).
        assert_eq!(blob[0], EVENT_TYPE_CONNECTION_PREKEY);

        // 2. Parse via the registry — exercises parse_event(blob) dispatch.
        let parsed = parse_event(&blob).expect("registry parse");
        assert_eq!(parsed, parsed_in);
        assert!(matches!(parsed, ParsedEvent::ConnectionPrekey(_)));

        // 3. Set up the schema and run the pure projector via the registry.
        let conn = SqlConnection::open_in_memory().unwrap();
        connection::ensure_schema(&conn).unwrap();

        let meta = registry()
            .lookup(EVENT_TYPE_CONNECTION_PREKEY)
            .expect("connection_prekey registered");
        let result = (meta.projector)("evt-cp-1", &parsed, &ContextSnapshot::default());
        assert!(matches!(result.decision, ProjectionDecision::Valid));
        run_write_ops(&conn, &result.write_ops);

        // 4. Assert the projected row exists.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM connection_prekeys WHERE prekey_id = ?1",
                rusqlite::params![&ev.prekey_id[..]],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // Also: a tampered signature must produce Reject (real verification).
        let mut tampered = ev.clone();
        tampered.signature[0] ^= 0xFF;
        let bad_parsed = ParsedEvent::ConnectionPrekey(tampered);
        let bad_result =
            (meta.projector)("evt-cp-2", &bad_parsed, &ContextSnapshot::default());
        assert!(matches!(
            bad_result.decision,
            ProjectionDecision::Reject { .. }
        ));
    }

    /// Phase 9 wire-up: Connection event (type code 33) must round-trip
    /// through the global event registry (parse_event →
    /// ParsedEvent::Connection) AND through the registry's pure projector
    /// dispatch, producing rows in `connections` and
    /// `connection_shared_workspaces`.
    ///
    /// Mirrors `test_connection_prekey_registry_roundtrip_and_projection`.
    #[test]
    fn test_connection_registry_roundtrip_and_projection() {
        use crate::projection::contract::ContextSnapshot;
        use crate::projection::contract::{SqlVal, WriteOp};
        use crate::projection::decision::ProjectionDecision;
        use ed25519_dalek::{Signer, SigningKey};
        use rusqlite::Connection as SqlConnection;
        use std::collections::BTreeSet;

        // Inline write executor (same as the connection_prekey test above).
        fn run_write_ops(conn: &SqlConnection, ops: &[WriteOp]) {
            for op in ops {
                match op {
                    WriteOp::InsertOrIgnore { table, columns, values } => {
                        let cols = columns.join(", ");
                        let placeholders: Vec<String> =
                            (1..=values.len()).map(|i| format!("?{}", i)).collect();
                        let sql = format!(
                            "INSERT OR IGNORE INTO {} ({}) VALUES ({})",
                            table, cols, placeholders.join(", ")
                        );
                        let params: Vec<Box<dyn rusqlite::types::ToSql>> = values
                            .iter()
                            .map(|v| -> Box<dyn rusqlite::types::ToSql> {
                                match v {
                                    SqlVal::Text(s) => Box::new(s.clone()),
                                    SqlVal::Int(i) => Box::new(*i),
                                    SqlVal::Blob(b) => Box::new(b.clone()),
                                }
                            })
                            .collect();
                        let refs: Vec<&dyn rusqlite::types::ToSql> =
                            params.iter().map(|p| &**p).collect();
                        conn.execute(&sql, refs.as_slice()).unwrap();
                    }
                    WriteOp::Delete { table, where_clause } => {
                        let conds: Vec<String> = where_clause
                            .iter()
                            .enumerate()
                            .map(|(i, (c, _))| format!("{} = ?{}", c, i + 1))
                            .collect();
                        let sql = format!("DELETE FROM {} WHERE {}", table, conds.join(" AND "));
                        let params: Vec<Box<dyn rusqlite::types::ToSql>> = where_clause
                            .iter()
                            .map(|(_, v)| -> Box<dyn rusqlite::types::ToSql> {
                                match v {
                                    SqlVal::Text(s) => Box::new(s.clone()),
                                    SqlVal::Int(i) => Box::new(*i),
                                    SqlVal::Blob(b) => Box::new(b.clone()),
                                }
                            })
                            .collect();
                        let refs: Vec<&dyn rusqlite::types::ToSql> =
                            params.iter().map(|p| &**p).collect();
                        conn.execute(&sql, refs.as_slice()).unwrap();
                    }
                }
            }
        }

        // Build a Connection event signed by `signer`. One workspace.
        let sk = SigningKey::from_bytes(&[0xA3u8; 32]);
        let signer_pk = sk.verifying_key().to_bytes();
        let mut shared = BTreeSet::new();
        shared.insert([0x77u8; 32]);
        let mut ev = ConnectionEvent {
            created_at_ms: 1_000_000,
            endpoint_a: [0x10u8; 32],
            endpoint_b: [0x20u8; 32],
            shared_workspaces: shared.clone(),
            signed_at_ms: 1_000_000,
            signer: signer_pk,
            signature: [0u8; 64],
        };
        ev.signature = sk.sign(&ev.signing_bytes()).to_bytes();
        let parsed_in = ParsedEvent::Connection(ev.clone());

        // 1. Encode via the registry.
        let blob = encode_event(&parsed_in).expect("encode through registry");
        assert_eq!(blob[0], EVENT_TYPE_CONNECTION);

        // 2. Parse via the registry.
        let parsed = parse_event(&blob).expect("registry parse");
        assert_eq!(parsed, parsed_in);
        assert!(matches!(parsed, ParsedEvent::Connection(_)));

        // 3. Set up schema and run the pure projector.
        let conn = SqlConnection::open_in_memory().unwrap();
        connection::ensure_schema(&conn).unwrap();

        let meta = registry()
            .lookup(EVENT_TYPE_CONNECTION)
            .expect("connection registered");
        // The pipeline computes the canonical event id from the encoded
        // blob; pass that exact id in here so the projector keys
        // `connection_shared_workspaces` rows the same way the runtime
        // would.
        let canonical_id = crate::crypto::hash_event(&blob);
        let canonical_id_b64 = crate::crypto::event_id_to_base64(&canonical_id);
        let result = (meta.projector)(
            &canonical_id_b64,
            &parsed,
            &ContextSnapshot::default(),
        );
        assert!(matches!(result.decision, ProjectionDecision::Valid));
        run_write_ops(&conn, &result.write_ops);

        // 4. Assert the projected rows exist.
        let conn_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM connections WHERE endpoint_a = ?1 AND endpoint_b = ?2",
                rusqlite::params![&ev.endpoint_a[..], &ev.endpoint_b[..]],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(conn_count, 1);

        // The `connection_shared_workspaces` row must be keyed by the
        // canonical event id (same value `hash_event(&blob)` produces).
        let ws_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM connection_shared_workspaces \
                 WHERE workspace_id = ?1 AND connection_id = ?2",
                rusqlite::params![&[0x77u8; 32][..], &canonical_id[..]],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ws_count, 1);
        // And `Connection::canonical_event_id()` must agree with the
        // pipeline-computed id.
        assert_eq!(ev.canonical_event_id(), canonical_id);

        // Also: tampered signature must produce Reject.
        let mut tampered = ev.clone();
        tampered.signature[0] ^= 0xFF;
        let bad_parsed = ParsedEvent::Connection(tampered);
        let bad_result = (meta.projector)(
            "evt-conn-2",
            &bad_parsed,
            &ContextSnapshot::default(),
        );
        assert!(matches!(
            bad_result.decision,
            ProjectionDecision::Reject { .. }
        ));
    }

    /// Regression: two `Connection` events sharing
    /// `(endpoint_a, endpoint_b, signed_at_ms)` but signed by different
    /// signing keys must produce DIFFERENT canonical event ids — because
    /// the canonical bytes include both `signer` and `signature`.
    ///
    /// Under the legacy `BLAKE3("poc9-connection-approx-id-v1" || endpoint_a
    /// || endpoint_b || signed_at_ms)` approximation these two events
    /// collided to the same id, which is the bug Codex flagged.
    #[test]
    fn test_connection_id_is_canonical_distinguishes_distinct_signers() {
        use ed25519_dalek::{Signer, SigningKey};
        use std::collections::BTreeSet;

        let mut shared = BTreeSet::new();
        shared.insert([0x77u8; 32]);

        // Same endpoint_a, endpoint_b, signed_at_ms; two distinct signers.
        let sk1 = SigningKey::from_bytes(&[0xA1u8; 32]);
        let signer1 = sk1.verifying_key().to_bytes();
        let mut ev1 = ConnectionEvent {
            created_at_ms: 1_000_000,
            endpoint_a: [0x10u8; 32],
            endpoint_b: [0x20u8; 32],
            shared_workspaces: shared.clone(),
            signed_at_ms: 1_000_000,
            signer: signer1,
            signature: [0u8; 64],
        };
        ev1.signature = sk1.sign(&ev1.signing_bytes()).to_bytes();

        let sk2 = SigningKey::from_bytes(&[0xB2u8; 32]);
        let signer2 = sk2.verifying_key().to_bytes();
        assert_ne!(signer1, signer2);
        let mut ev2 = ConnectionEvent {
            created_at_ms: 1_000_000,
            endpoint_a: [0x10u8; 32],
            endpoint_b: [0x20u8; 32],
            shared_workspaces: shared,
            signed_at_ms: 1_000_000,
            signer: signer2,
            signature: [0u8; 64],
        };
        ev2.signature = sk2.sign(&ev2.signing_bytes()).to_bytes();

        let id1 = ev1.canonical_event_id();
        let id2 = ev2.canonical_event_id();
        assert_ne!(
            id1, id2,
            "canonical connection_id must distinguish events that share \
             (endpoint_a, endpoint_b, signed_at_ms) but were signed by \
             different keys"
        );

        // And the canonical id must match the standard pipeline derivation.
        let blob1 = encode_event(&ParsedEvent::Connection(ev1.clone())).unwrap();
        let blob2 = encode_event(&ParsedEvent::Connection(ev2.clone())).unwrap();
        assert_eq!(crate::crypto::hash_event(&blob1), id1);
        assert_eq!(crate::crypto::hash_event(&blob2), id2);
    }
}
