//! Workspace event types.
//!
//! A workspace event is the shared root fact for identity. In p8, the
//! workspace id is the deterministic event id of this canonical event. The full
//! creator user/device/admin graph is intentionally owned by later identity
//! leaves; this event only carries the root public key and display name.

pub const WORKSPACE_NAME_BYTES: usize = 64;

pub type WorkspaceId = [u8; 32];
pub type WorkspacePublicKey = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEvent {
    pub created_at_ms: u64,
    pub public_key: WorkspacePublicKey,
    pub disappearing_ttl_minutes: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRow {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub public_key: WorkspacePublicKey,
    pub disappearing_ttl_minutes: u32,
    pub name: String,
}
