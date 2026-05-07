//! Topo CLI command registry.
//!
//! This file is intentionally a shell. Command names, argv parsing, help text,
//! worker calls, follow-up queries, and output formatting belong in the closest
//! scoped `cli.rs` under `event_modules/`. The protocol shell only assembles
//! those command specs, adds whole-protocol status aliases, and provides the
//! small context object those specs share.
//!
//! The runner lives in core and knows nothing about Topo. This registry is the
//! place where the current protocol says, "these are my commands." If command
//! behavior starts appearing here, move it back to the owning module.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::logical_clock;
use crate::core::network_queues::InboundNetworkRow;
use crate::core::store::Store;
use crate::protocol::event_modules::content::message;
use crate::protocol::event_modules::content::reaction;
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope, ReceiveMetadata};
use crate::protocol::event_modules::worker::{
    EventRegistry, EventWithContext, ProjectionOutput, ReceivedRecord,
};
use crate::protocol::{event_modules, Protocol};
use crate::workers::DaemonWorkerContext;

const CLOCK_USAGE: &str = "clock [set TIMESTAMP|advance DELTA|clear]";
const COUNT_USAGE: &str = "count";
const STATUS_USAGE: &str = "status";
const EVENT_USAGE: &str = "event tree";

pub struct Context {
    pub db_path: std::path::PathBuf,
    pub store: Store,
    pub protocol: Protocol,
}

impl Context {
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, String> {
        let db_path = db_path.as_ref().to_path_buf();
        Ok(Self {
            store: Protocol::open_store(&db_path).map_err(|err| format!("open store: {err}"))?,
            protocol: Protocol::new(),
            db_path,
        })
    }
}

// The shared CLI/daemon context delegates protocol behavior to `Protocol` while
// exposing the store and persistent worker state required by the generic runner.
impl EventRegistry for Context {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.protocol.record_from_bytes(bytes)
    }

    fn project_network_in(
        &self,
        store: &Store,
        inbound: &InboundNetworkRow,
    ) -> Result<ProjectionOutput, String> {
        self.protocol.project_network_in(store, inbound)
    }

    fn record_from_canonical_in(
        &self,
        store: &Store,
        bytes: Vec<u8>,
        receive: Option<ReceiveMetadata>,
        provenance: Option<crate::workers::schema::TransitProvenance>,
    ) -> Result<ReceivedRecord, String> {
        self.protocol
            .record_from_canonical_in(store, bytes, receive, provenance)
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        self.protocol.project_record(store, event)
    }
}

impl DaemonWorkerContext for Context {
    fn store(&self) -> &Store {
        &self.store
    }

    fn sync_index(&self) -> &event_modules::sync::SyncIndex {
        self.protocol.sync_index()
    }
}

pub fn commands() -> Vec<CliCommand<Context>> {
    let mut out = Vec::new();
    out.extend(event_modules::identity::admin::cli::commands());
    out.extend(event_modules::identity::user::cli::commands());
    out.extend(event_modules::identity::endpoint_shared::cli::commands());
    out.extend(event_modules::identity::cli::commands());
    out.extend(event_modules::connection::cli::commands());
    out.extend(event_modules::content::content_event::cli::commands());
    out.extend(event_modules::content::message::cli::commands());
    out.extend(event_modules::content::reaction::cli::commands());
    out.extend(event_modules::content::message_deletion::cli::commands());
    out.extend(event_modules::content::file::cli::commands());
    out.extend(event_modules::content::cli::commands());
    out.extend(event_modules::encryption::cli::commands());
    out.extend(event_modules::sync::cli::commands());
    out.extend(event_modules::test_events::event_with_deps::cli::commands());
    out.extend([
        clock_command(),
        count_command("count", COUNT_USAGE),
        count_command("status", STATUS_USAGE),
        event_command(),
    ]);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountSummary {
    pub events: usize,
    pub payload_bytes: usize,
    pub connections: usize,
    pub connection_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub applied_events: usize,
    pub rejected_events: usize,
    pub blocked_edges: usize,
}

impl CountSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("events: {}", self.events),
            format!("payload_bytes: {}", self.payload_bytes),
            format!("connections: {}", self.connections),
            format!("connection_events: {}", self.connection_events),
            format!("ready_events: {}", self.ready_events),
            format!("blocked_events: {}", self.blocked_events),
            format!("applied_events: {}", self.applied_events),
            format!("rejected_events: {}", self.rejected_events),
            format!("blocked_edges: {}", self.blocked_edges),
        ]
    }
}

fn count_command(name: &'static str, usage: &'static str) -> CliCommand<Context> {
    CliCommand {
        name,
        usage,
        help: "Print protocol-wide event counts.",
        run: run_count_command,
    }
}

fn run_count_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, COUNT_USAGE)?;
    let events =
        event_schema::event_count(&context.store).map_err(|err| format!("count events: {err}"))?;
    let payload_bytes =
        event_schema::body_bytes(&context.store).map_err(|err| format!("count bytes: {err}"))?;
    let connections = event_modules::connection::queries::connection_count(&context.store)?;
    let connection_events =
        event_modules::connection::queries::connection_event_count(&context.store)?;
    let statuses = event_schema::status_counts(&context.store)
        .map_err(|err| format!("count event statuses: {err}"))?;
    Ok(CliOutput::lines(
        CountSummary {
            events,
            payload_bytes,
            connections,
            connection_events,
            ready_events: statuses.ready,
            blocked_events: statuses.blocked,
            applied_events: statuses.applied,
            rejected_events: statuses.rejected,
            blocked_edges: statuses.blocked_edges,
        }
        .lines(),
    ))
}

fn clock_command() -> CliCommand<Context> {
    CliCommand {
        name: "clock",
        usage: CLOCK_USAGE,
        help: "Show or adjust this store's logical timestamp lower bound.",
        run: run_clock_command,
    }
}

fn run_clock_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    match args.values() {
        [] => {}
        [op, timestamp] if op == "set" => {
            logical_clock::set_logical_time(&context.store, parse_u64(timestamp)?)?;
        }
        [op, delta] if op == "advance" => {
            logical_clock::advance_logical_time(&context.store, parse_u64(delta)?)?;
        }
        [op] if op == "clear" => {
            logical_clock::clear_logical_time(&context.store)?;
        }
        _ => return Err(CLOCK_USAGE.to_string()),
    }
    clock_output(&context.store)
}

fn clock_output(store: &Store) -> Result<CliOutput, String> {
    let logical_time = logical_clock::logical_time(store)?;
    let max_event_timestamp =
        event_schema::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
    let next_timestamp = logical_clock::next_timestamp(store, max_event_timestamp)?;
    Ok(CliOutput::lines(vec![
        format!(
            "logical_time: {}",
            logical_time
                .map(|timestamp| timestamp.to_string())
                .unwrap_or_else(|| "unset".to_string())
        ),
        format!("max_event_timestamp: {max_event_timestamp}"),
        format!("next_timestamp: {next_timestamp}"),
    ]))
}

fn parse_u64(value: &str) -> Result<u64, String> {
    value.parse::<u64>().map_err(|_| CLOCK_USAGE.to_string())
}

// ---------------------------------------------------------------------------
// Event tree command
// ---------------------------------------------------------------------------

fn event_command() -> CliCommand<Context> {
    CliCommand {
        name: "event",
        usage: EVENT_USAGE,
        help: "Inspect the event graph (subcommand: tree).",
        run: run_event_command,
    }
}

fn run_event_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    match args.values() {
        [sub] if sub == "tree" => run_event_tree(&context.store),
        _ => Err(EVENT_USAGE.to_string()),
    }
}

fn run_event_tree(store: &Store) -> Result<CliOutput, String> {
    let listings = event_schema::all_events(store).map_err(|err| format!("load events: {err}"))?;
    let inner = decrypted_inner_by_event_id(store, &listings)?;

    let mut nodes = Vec::with_capacity(listings.len());
    for listing in &listings {
        let info = decode_event_info(&listing.canonical_bytes);
        nodes.push(TreeNode {
            event_id: listing.event_id,
            timestamp: listing.timestamp,
            scope: listing.scope,
            label: type_label(info.outer_tag, info.inner_tag),
            dependencies: info.dependencies,
        });
    }
    nodes.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    if nodes.is_empty() {
        return Ok(CliOutput::line("(no events)".to_string()));
    }

    let id_set: BTreeSet<EventId> = nodes.iter().map(|node| node.event_id).collect();
    let mut parent_of: BTreeMap<EventId, EventId> = BTreeMap::new();
    for node in &nodes {
        for dep in &node.dependencies {
            if id_set.contains(dep) && *dep != node.event_id {
                parent_of.insert(node.event_id, *dep);
                break;
            }
        }
    }
    let mut children: BTreeMap<EventId, Vec<EventId>> = BTreeMap::new();
    let mut order_index: BTreeMap<EventId, usize> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        order_index.insert(node.event_id, index);
        if let Some(parent) = parent_of.get(&node.event_id) {
            children.entry(*parent).or_default().push(node.event_id);
        }
    }
    for kids in children.values_mut() {
        kids.sort_by_key(|id| order_index.get(id).copied().unwrap_or(usize::MAX));
    }

    let node_map: BTreeMap<EventId, &TreeNode> =
        nodes.iter().map(|node| (node.event_id, node)).collect();

    let roots: Vec<EventId> = nodes
        .iter()
        .filter(|node| !parent_of.contains_key(&node.event_id))
        .map(|node| node.event_id)
        .collect();

    let mut lines = Vec::new();
    for (index, root) in roots.iter().enumerate() {
        if index > 0 {
            lines.push(String::new());
        }
        render_tree_node(
            *root,
            "",
            true,
            true,
            &children,
            &node_map,
            &parent_of,
            &inner,
            &mut lines,
        );
    }
    Ok(CliOutput::lines(lines))
}

#[derive(Debug, Clone)]
struct TreeNode {
    event_id: EventId,
    timestamp: u64,
    scope: EventScope,
    label: &'static str,
    dependencies: Vec<EventId>,
}

#[derive(Debug, Clone)]
struct DecryptedInner {
    label: &'static str,
    field_name: &'static str,
    field_value: String,
}

fn decrypted_inner_by_event_id(
    store: &Store,
    listings: &[event_schema::EventListing],
) -> Result<BTreeMap<EventId, DecryptedInner>, String> {
    let mut workspaces: BTreeSet<EventId> = BTreeSet::new();
    for listing in listings {
        if let Some(workspace_id) = listing.workspace_id {
            workspaces.insert(workspace_id);
        }
    }
    let mut inner: BTreeMap<EventId, DecryptedInner> = BTreeMap::new();
    for workspace_id in workspaces {
        if let Ok(messages) = message::cli::list_for_display(store, workspace_id, 0) {
            for entry in messages {
                inner.insert(
                    entry.message_id,
                    DecryptedInner {
                        label: type_label_for_inner_tag(0).unwrap_or("message — sends a message"),
                        field_name: "content",
                        field_value: entry.text.clone(),
                    },
                );
            }
        }
        if let Ok(rows) = reaction::cli::decrypted_for_workspace(store, workspace_id) {
            for row in rows {
                inner.insert(
                    row.reaction_id,
                    DecryptedInner {
                        label: "reaction \u{2014} reacts to a message",
                        field_name: "emoji",
                        field_value: row.emoji.clone(),
                    },
                );
            }
        }
    }
    Ok(inner)
}

fn type_label_for_inner_tag(_tag: u8) -> Option<&'static str> {
    None
}

#[allow(clippy::too_many_arguments)]
fn render_tree_node(
    id: EventId,
    prefix: &str,
    is_last: bool,
    is_root: bool,
    children: &BTreeMap<EventId, Vec<EventId>>,
    node_map: &BTreeMap<EventId, &TreeNode>,
    parent_of: &BTreeMap<EventId, EventId>,
    inner: &BTreeMap<EventId, DecryptedInner>,
    lines: &mut Vec<String>,
) {
    let Some(node) = node_map.get(&id) else {
        return;
    };
    let connector = if is_root {
        ""
    } else if is_last {
        "\u{2514}\u{2500}\u{2500} "
    } else {
        "\u{251c}\u{2500}\u{2500} "
    };
    let tree_parent = parent_of.get(&id).copied();
    let cross_refs: Vec<String> = node
        .dependencies
        .iter()
        .filter(|dep| Some(**dep) != tree_parent && **dep != node.event_id)
        .filter(|dep| node_map.contains_key(*dep))
        .map(|dep| format!("dep: {}", short_event_id(dep)))
        .collect();
    let suffix = if !cross_refs.is_empty() {
        format!("  [{}]", cross_refs.join(", "))
    } else if tree_parent.is_none() {
        " \u{2190} root".to_string()
    } else {
        String::new()
    };
    let scope_marker = match node.scope {
        EventScope::Local => " (local)",
        _ => "",
    };
    lines.push(format!(
        "{}{}({}) {}{}{}",
        prefix,
        connector,
        short_event_id(&node.event_id),
        node.label,
        scope_marker,
        suffix,
    ));
    if let Some(detail) = inner.get(&node.event_id) {
        let inner_prefix = if is_root {
            "  ".to_string()
        } else if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}\u{2502}   ")
        };
        lines.push(format!(
            "{}--- decrypted: {} ---",
            inner_prefix, detail.label
        ));
        lines.push(format!(
            "{}  {}: {}",
            inner_prefix, detail.field_name, detail.field_value
        ));
    }
    if let Some(kids) = children.get(&node.event_id) {
        let new_prefix = if is_root {
            String::new()
        } else if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}\u{2502}   ")
        };
        for (kid_index, kid) in kids.iter().enumerate() {
            let kid_is_last = kid_index == kids.len() - 1;
            render_tree_node(
                *kid,
                &new_prefix,
                kid_is_last,
                false,
                children,
                node_map,
                parent_of,
                inner,
                lines,
            );
        }
    }
}

fn short_event_id(event_id: &EventId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(8);
    for byte in event_id.iter().take(4) {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[derive(Debug, Clone)]
struct DecodedEventInfo {
    outer_tag: u8,
    inner_tag: Option<u8>,
    dependencies: Vec<EventId>,
}

fn decode_event_info(canonical_bytes: &[u8]) -> DecodedEventInfo {
    let outer_tag = canonical_bytes.first().copied().unwrap_or(0);
    let mut info = DecodedEventInfo {
        outer_tag,
        inner_tag: None,
        dependencies: Vec::new(),
    };
    if let Ok(record) =
        event_modules::record_from_bytes(canonical_bytes.to_vec())
    {
        info.dependencies = record.dependencies;
    }
    if outer_tag == event_modules::identity::signed::codec::TYPE_SIGNED {
        // Signed envelope: layout is type|signer_event_id(32)|signer_public_key(32)|inner_type(1)|...
        info.inner_tag = canonical_bytes.get(1 + 32 + 32).copied();
    } else if outer_tag == event_modules::content::content_event::codec::TYPE_SIGNED_CONTENT
        || outer_tag == event_modules::content::message::codec::TYPE_SIGNED_MESSAGE
        || outer_tag == event_modules::content::reaction::codec::TYPE_SIGNED_REACTION
        || outer_tag == event_modules::content::message_deletion::codec::TYPE_SIGNED_MESSAGE_DELETION
        || outer_tag == event_modules::content::file::codec::TYPE_SIGNED_FILE
        || outer_tag == event_modules::content::file_slice::codec::TYPE_SIGNED_FILE_SLICE
        || outer_tag == event_modules::encryption::recipient_key::codec::TYPE_SIGNED_RECIPIENT_KEY
        || outer_tag
            == event_modules::encryption::recipient_key_tombstone::codec::TYPE_SIGNED_RECIPIENT_KEY_TOMBSTONE
        || outer_tag
            == event_modules::encryption::removal_frontier::codec::TYPE_SIGNED_REMOVAL_FRONTIER
        || outer_tag == event_modules::encryption::key_wrap::codec::TYPE_SIGNED_KEY_WRAP
    {
        // Signed content/encryption envelopes have layout:
        //   type|signer_endpoint_shared_id(32)|signer_public_key(32)|payload_len(4)|payload(...)
        // The first byte of the payload is the inner type tag.
        info.inner_tag = canonical_bytes.get(1 + 32 + 32 + 4).copied();
    }
    info
}

fn type_label(outer_tag: u8, inner_tag: Option<u8>) -> &'static str {
    use event_modules::content::{
        content_event::codec as content_codec, file::codec as file_codec,
        file_slice::codec as file_slice_codec, message::codec as message_codec,
        message_deletion::codec as message_deletion_codec, reaction::codec as reaction_codec,
    };
    use event_modules::encryption::{
        key_wrap::codec as key_wrap_codec, local_history_node_secret::codec as local_history_codec,
        local_key_secret::codec as local_key_codec,
        local_recipient_key::codec as local_recipient_codec,
        recipient_key::codec as recipient_key_codec,
        recipient_key_tombstone::codec as tombstone_codec,
        removal_frontier::codec as frontier_codec,
    };
    use event_modules::identity::{
        admin::codec as admin_codec, device_invite::codec as device_invite_codec,
        endpoint::codec as endpoint_codec, endpoint_shared::codec as endpoint_shared_codec,
        invite::codec as invite_codec, invite_server::codec as invite_server_codec,
        signed::codec as signed_codec, user::codec as user_codec,
        user_invite::codec as user_invite_codec, workspace::codec as workspace_codec,
    };
    use event_modules::sync::{
        compare::codec as sync_compare_codec, have_id::codec as sync_have_codec,
        need_id::codec as sync_need_codec,
    };
    use event_modules::test_events::event_with_deps::codec as test_codec;

    if outer_tag == signed_codec::TYPE_SIGNED {
        return match inner_tag {
            Some(t) if t == admin_codec::TYPE_ADMIN => "admin — grants admin rights",
            Some(t) if t == device_invite_codec::TYPE_DEVICE_INVITE => {
                "device_invite — invites a device"
            }
            Some(t) if t == endpoint_shared_codec::TYPE_ENDPOINT_SHARED => {
                "endpoint_shared — publishes a shared endpoint identity"
            }
            Some(t) if t == invite_server_codec::TYPE_INVITE_SERVER => {
                "invite_server — invites an invite-server endpoint"
            }
            Some(t) if t == user_codec::TYPE_USER => "user — registers the user",
            Some(t) if t == user_invite_codec::TYPE_USER_INVITE => {
                "user_invite_shared — invites a user"
            }
            _ => "signed — signed envelope",
        };
    }
    if outer_tag == workspace_codec::TYPE_WORKSPACE {
        return "workspace — creates the workspace";
    }
    if outer_tag == endpoint_codec::TYPE_LOCAL_ENDPOINT {
        return "local_endpoint — stores a local signing key";
    }
    if outer_tag == invite_codec::TYPE_INVITE_SECRET {
        return "invite_secret — stores a local invite key";
    }
    if outer_tag == content_codec::TYPE_SIGNED_CONTENT {
        return "content — signs an inner content event";
    }
    if outer_tag == message_codec::TYPE_SIGNED_MESSAGE {
        return "message — sends a message";
    }
    if outer_tag == reaction_codec::TYPE_SIGNED_REACTION {
        return "reaction — reacts to a message";
    }
    if outer_tag == message_deletion_codec::TYPE_SIGNED_MESSAGE_DELETION {
        return "message_deletion — deletes a message";
    }
    if outer_tag == file_codec::TYPE_SIGNED_FILE {
        return "file — attaches a file";
    }
    if outer_tag == file_slice_codec::TYPE_SIGNED_FILE_SLICE {
        return "file_slice — stores a file chunk";
    }
    if outer_tag == recipient_key_codec::TYPE_SIGNED_RECIPIENT_KEY {
        return "recipient_key — shares a recipient key";
    }
    if outer_tag == tombstone_codec::TYPE_SIGNED_RECIPIENT_KEY_TOMBSTONE {
        return "recipient_key_tombstone — tombstones a recipient key";
    }
    if outer_tag == frontier_codec::TYPE_SIGNED_REMOVAL_FRONTIER {
        return "removal_frontier — advances the removal frontier";
    }
    if outer_tag == key_wrap_codec::TYPE_SIGNED_KEY_WRAP {
        return "key_wrap — wraps a content key";
    }
    if outer_tag == local_recipient_codec::TYPE_LOCAL_RECIPIENT_KEY {
        return "local_recipient_key — stores a local recipient key";
    }
    if outer_tag == local_key_codec::TYPE_LOCAL_KEY_SECRET {
        return "local_key_secret — stores a local content key";
    }
    if outer_tag == local_history_codec::TYPE_LOCAL_HISTORY_NODE_SECRET {
        return "local_history_node_secret — stores a key derivation node";
    }
    if outer_tag == sync_compare_codec::TYPE_SYNC_COMPARE {
        return "sync_compare — compares event sets";
    }
    if outer_tag == sync_have_codec::TYPE_SYNC_HAVE_ID {
        return "sync_have_id — announces an event we have";
    }
    if outer_tag == sync_need_codec::TYPE_SYNC_NEED_ID {
        return "sync_need_id — requests an event we need";
    }
    if outer_tag == test_codec::TYPE_EVENT_WITH_DEPS {
        return "event_with_deps — test event with declared dependencies";
    }
    if outer_tag == test_codec::TYPE_STAGED_EVENT_WITH_DEPS {
        return "staged_event_with_deps — staged test event";
    }
    "unknown event"
}
