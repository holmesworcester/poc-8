//! Ignored end-to-end projection perf tests for encrypted content events.
//!
//! These tests are intentionally not microbenchmarks. They create a real
//! workspace/auth graph, mint a real local content key, build encrypted/signed
//! content events, then drive the prebuilt events through the common
//! admission/projection pipeline. The timed path therefore excludes event
//! construction and includes admission-side canonical decode/signature checks,
//! projector-side signature checks, and row writes. File measurements also
//! include slice BAO proof verification during projection. They do not measure
//! network transit, sync start/stop, or disk filesystem reads.

use std::time::{Duration, Instant};

use topo::core::crypto::{self, XChaCha20Poly1305Key, XCHACHA20_POLY1305_TAG_BYTES};
use topo::core::store::Store;
use topo::protocol::event_modules::content::{file, file_slice, message};
use topo::protocol::event_modules::encryption::{local_key_secret, removal_frontier};
use topo::protocol::event_modules::identity::{
    admin, device_invite, endpoint, endpoint_shared, user, user_invite, workspace,
};
use topo::protocol::event_modules::types::EventId;
use topo::protocol::event_modules::worker::{self, CommandOutput, ProposedEvent};
use topo::protocol::Protocol;

const MIB: usize = 1024 * 1024;
const MESSAGE_BATCH: usize = 4096;
const FILE_SLICE_BATCH: u32 = 16;
const KEY_SECRET: XChaCha20Poly1305Key = [77; 32];

struct PerfFixture {
    protocol: Protocol,
    store: Store,
    workspace_id: EventId,
    author_user_id: EventId,
    signer_endpoint_shared_id: EventId,
    signer_private_key: [u8; 32],
    removal_frontier_id: EventId,
    local_key_secret_id: EventId,
    key_secret: XChaCha20Poly1305Key,
    next_timestamp: u64,
}

impl PerfFixture {
    fn new() -> Self {
        let protocol = Protocol::new();
        let store = Protocol::open_memory_store().expect("open memory store");
        let endpoint = admit(
            &store,
            &protocol,
            endpoint::commands::create_local_keypair(),
        );

        let workspace_id = admit(
            &store,
            &protocol,
            workspace::commands::create(workspace::commands::CreateWorkspace {
                created_at_ms: 1,
                public_key: endpoint.signing_public_key,
                name: "perf".to_string(),
            })
            .expect("create workspace"),
        )
        .workspace_id;

        let root_admin_id = admit(
            &store,
            &protocol,
            admin::commands::create_bootstrap(admin::commands::CreateBootstrapAdmin {
                created_at_ms: 2,
                workspace_id,
                root_public_key: endpoint.signing_public_key,
                root_user_event_id: workspace_id,
                signer_private_key: endpoint.signing_secret,
            })
            .expect("create root admin"),
        )
        .admin_id;

        let invite_private_key = [8; 32];
        let user_invite_id = admit(
            &store,
            &protocol,
            user_invite::commands::create(user_invite::commands::CreateUserInvite {
                created_at_ms: 3,
                public_key: crypto::ed25519_public_key(&invite_private_key),
                workspace_id,
                authority_event_id: workspace_id,
                signer_event_id: workspace_id,
                signer_private_key: endpoint.signing_secret,
            })
            .expect("create user invite"),
        )
        .user_invite_id;

        let author_user_id = admit(
            &store,
            &protocol,
            user::commands::create(user::commands::CreateUser {
                created_at_ms: 4,
                workspace_id,
                public_key: endpoint.signing_public_key,
                username: "perf-user".to_string(),
                user_invite_event_id: user_invite_id,
                user_invite_private_key: invite_private_key,
            })
            .expect("create user"),
        )
        .user_id;

        let user_admin_id = admit(
            &store,
            &protocol,
            admin::commands::sign_grant(admin::commands::SignGrantAdmin {
                grant: admin::commands::GrantAdmin {
                    created_at_ms: 5,
                    workspace_id,
                    authority_admin_id: root_admin_id,
                    target_user_event_id: author_user_id,
                    target_user_public_key: endpoint.signing_public_key,
                },
                signer_event_id: root_admin_id,
                signer_private_key: endpoint.signing_secret,
            })
            .expect("grant admin to perf user"),
        )
        .signed_event_id;

        let device_invite = admit(
            &store,
            &protocol,
            device_invite::commands::create(device_invite::commands::CreateDeviceInvite {
                created_at_ms: 6,
                workspace_id,
                user_authority_event_id: author_user_id,
                user_invite_event_id: Some(user_invite_id),
                signer_event_id: author_user_id,
                signer_private_key: endpoint.signing_secret,
            })
            .expect("create device invite"),
        );

        let signer_endpoint_shared_id = admit(
            &store,
            &protocol,
            endpoint_shared::commands::share_endpoint(
                &store,
                endpoint_shared::commands::ShareEndpoint {
                    created_at_ms: 7,
                    workspace_id,
                    user_authority_event_id: author_user_id,
                    endpoint_id: endpoint.endpoint,
                    signing_public_key: endpoint.signing_public_key,
                    endpoint_role: endpoint::types::EndpointRole::Device,
                    device_name: "perf-device".to_string(),
                    device_invite_id: device_invite.device_invite_id,
                    device_invite_private_key: device_invite.keypair.private_key,
                },
            )
            .expect("share endpoint"),
        )
        .endpoint_shared_id;

        let removal_frontier_id = admit(
            &store,
            &protocol,
            removal_frontier::commands::create(removal_frontier::commands::CreateRemovalFrontier {
                workspace_id,
                created_at_ms: 8,
                authority_admin_id: user_admin_id,
                signer_endpoint_shared_id,
                signer_private_key: endpoint.signing_secret,
                removal_event_ids: Vec::new(),
            })
            .expect("create removal frontier"),
        )
        .removal_frontier_id;

        let local_key_secret_id = admit(
            &store,
            &protocol,
            local_key_secret::commands::from_key_secret(
                workspace_id,
                removal_frontier_id,
                KEY_SECRET,
            )
            .expect("create local key secret"),
        )
        .local_key_secret_id;

        Self {
            protocol,
            store,
            workspace_id,
            author_user_id,
            signer_endpoint_shared_id,
            signer_private_key: endpoint.signing_secret,
            removal_frontier_id,
            local_key_secret_id,
            key_secret: KEY_SECRET,
            next_timestamp: 10_000,
        }
    }

    fn next_message(
        &mut self,
        sequence: usize,
    ) -> CommandOutput<message::commands::SendMessageOutput> {
        let created_at_ms = self.take_timestamp();
        message::commands::send(message::commands::SendMessage {
            workspace_id: self.workspace_id,
            created_at_ms,
            author_user_id: self.author_user_id,
            signer_endpoint_shared_id: self.signer_endpoint_shared_id,
            signer_private_key: self.signer_private_key,
            removal_frontier_id: self.removal_frontier_id,
            // Perf fixture points every message at the workspace-frontier
            // root key secret rather than at a real per-message leaf event
            // — this perf path exercises only the message admission +
            // projection cost (not the leaf-derive worker, which is timed
            // separately by `encryption_cli_test`). Each call advances
            // `take_timestamp` so messages have distinct identifying
            // canonical fields and therefore distinct event ids; if two
            // calls did collide on `(workspace, author, frontier, ms)`
            // they would be the same message by design (idempotent
            // re-author), which is correct, not a bug to compensate for.
            local_history_node_secret_id: self.local_key_secret_id,
            leaf_node_secret: self.key_secret,
            text: format!("perf message {sequence}"),
        })
        .expect("create encrypted signed message")
    }

    fn take_timestamp(&mut self) -> u64 {
        let timestamp = self.next_timestamp;
        self.next_timestamp = self.next_timestamp.saturating_add(1);
        timestamp
    }

    fn admit_events(&self, events: Vec<ProposedEvent>) -> worker::AdmitAndDrainReport<()> {
        worker::run(
            &self.store,
            &self.protocol,
            worker::AdmitAndDrain {
                output: CommandOutput::with_proposed_events((), events),
                batch_size: worker::DEFAULT_READY_BATCH,
            },
        )
        .expect("admit and project proposed events")
    }

    fn sealed_message_exists(&self, message_id: EventId) -> bool {
        let key = message::schema::message_key(self.workspace_id, message_id);
        self.store
            .table_row(message::schema::SEALED_MESSAGES, &key)
            .expect("load sealed message")
            .is_some()
    }

    fn sealed_file_exists(&self, file_event_id: EventId) -> bool {
        let key = file::schema::file_key(self.workspace_id, file_event_id);
        self.store
            .table_row(file::schema::FILES, &key)
            .expect("load sealed file")
            .is_some()
    }

    fn file_slice_exists(&self, file_id: EventId, slice_number: u32) -> bool {
        let key = file_slice::schema::file_slice_key(self.workspace_id, file_id, slice_number);
        self.store
            .table_row(file_slice::schema::FILE_SLICES, &key)
            .expect("load file slice")
            .is_some()
    }
}

/// Invariant: 1k prebuilt encrypted signed messages remain
/// admissible/projectable without timing command-side event construction.
#[test]
#[ignore]
fn messages_1k_projection_perf() {
    run_message_projection_perf(1_000);
}

/// Invariant: 10k encrypted signed messages remain admissible/projectable, and
/// one additional already-created message projects against the populated
/// workspace without needing a separate sync or decrypt pass.
#[test]
#[ignore]
fn messages_10k_projection_perf() {
    run_message_projection_perf(10_000);
}

/// Invariant: 100k encrypted signed messages keep the same admission/projection
/// contract as the small case; the measurement catches throughput cliffs from
/// dependency lookup, signature checking, and row writes.
#[test]
#[ignore]
fn messages_100k_projection_perf() {
    run_message_projection_perf(100_000);
}

/// Invariant: 500k encrypted signed messages are still a replayable event
/// history, and the latest-message projection path stays measurable after that
/// much prior content has been applied.
#[test]
#[ignore]
fn messages_500k_projection_perf() {
    run_message_projection_perf(500_000);
}

/// Invariant: one 10 MiB file uses the real message + descriptor + slice event
/// shape, with encrypted slices and BAO proof verification before slice rows
/// become visible.
#[test]
#[ignore]
fn file_10mib_projection_perf() {
    run_file_projection_perf(10);
}

/// Invariant: one 100 MiB file keeps file throughput dominated by bounded
/// file/slice events rather than by event construction.
#[test]
#[ignore]
fn file_100mib_projection_perf() {
    run_file_projection_perf(100);
}

/// Invariant: one 500 MiB file remains projectable as many fixed-size slice
/// events, giving an upper-scale MB/s check for signature checks, BAO
/// verification, and row writes.
#[test]
#[ignore]
fn file_500mib_projection_perf() {
    run_file_projection_perf(500);
}

fn run_message_projection_perf(count: usize) {
    assert!(count > 0, "message perf needs at least one message");
    let mut fixture = PerfFixture::new();
    let mut projection_elapsed = Duration::ZERO;
    let mut inserted_events = 0usize;

    if count > 1 {
        let prefix = admit_message_prefix(&mut fixture, count - 1);
        inserted_events += prefix.inserted_events;
        projection_elapsed += prefix.elapsed;
    }

    // The latest event is built before timing so `latest_project_ms` only
    // measures admission/projection against an already populated workspace.
    let latest = fixture.next_message(count - 1);
    let latest_message_id = latest.value.message_id;
    let latest_started = Instant::now();
    let latest_report = fixture.admit_events(latest.events);
    let latest_elapsed = latest_started.elapsed();
    projection_elapsed += latest_elapsed;
    inserted_events += latest_report.admitted.inserted_events;

    assert_eq!(inserted_events, count);
    assert!(fixture.sealed_message_exists(latest_message_id));

    println!(
        "perf messages count={} project_ms={:.3} project_messages_s={:.2} latest_project_ms={:.3}",
        count,
        millis(projection_elapsed),
        rate(count, projection_elapsed),
        millis(latest_elapsed)
    );
}

struct TimedAdmission {
    inserted_events: usize,
    elapsed: Duration,
}

fn admit_message_prefix(fixture: &mut PerfFixture, count: usize) -> TimedAdmission {
    let mut produced = 0usize;
    let mut inserted = 0usize;
    let mut elapsed = Duration::ZERO;
    while produced < count {
        let batch_len = (count - produced).min(MESSAGE_BATCH);
        let mut events = Vec::with_capacity(batch_len);
        let mut latest_message_id = [0u8; 32];
        for _ in 0..batch_len {
            let message = fixture.next_message(produced);
            latest_message_id = message.value.message_id;
            events.extend(message.events);
            produced += 1;
        }
        let started = Instant::now();
        let report = fixture.admit_events(events);
        elapsed += started.elapsed();
        assert_eq!(report.admitted.inserted_events, batch_len);
        assert!(fixture.sealed_message_exists(latest_message_id));
        inserted += report.admitted.inserted_events;
    }
    TimedAdmission {
        inserted_events: inserted,
        elapsed,
    }
}

fn run_file_projection_perf(mib: usize) {
    assert!(mib > 0, "file perf needs a non-empty payload");
    let mut fixture = PerfFixture::new();
    let mut projection_elapsed = Duration::ZERO;
    let blob_bytes = mib * MIB;
    let parent = fixture.next_message(0);
    let message_id = parent.value.message_id;
    let file_id = derive_file_id(&fixture, message_id, blob_bytes as u64);
    let slice_bytes = file_slice::types::FILE_SLICE_DATA_BYTES;
    let total_slices = blob_bytes.div_ceil(slice_bytes) as u32;

    let built = build_file_events(
        &mut fixture,
        0,
        parent,
        file_id,
        blob_bytes,
        total_slices,
        slice_bytes,
    );

    let started = Instant::now();
    let root_report = fixture.admit_events(built.root_events);
    projection_elapsed += started.elapsed();
    assert_eq!(root_report.admitted.inserted_events, 2);
    assert!(fixture.sealed_message_exists(message_id));
    assert!(fixture.sealed_file_exists(built.file_event_id));
    let mut inserted_events = root_report.admitted.inserted_events;

    for batch in built.slice_batches {
        let batch_len = batch.len();
        let started = Instant::now();
        let report = fixture.admit_events(batch);
        projection_elapsed += started.elapsed();
        assert_eq!(report.admitted.inserted_events, batch_len);
        inserted_events += report.admitted.inserted_events;
    }

    assert!(fixture.file_slice_exists(file_id, total_slices - 1));
    assert_eq!(inserted_events, 2 + total_slices as usize);

    println!(
        "perf file mib={} bytes={} slices={} project_ms={:.3} project_mib_s={:.2} events={}",
        mib,
        blob_bytes,
        total_slices,
        millis(projection_elapsed),
        rate(blob_bytes / MIB, projection_elapsed),
        inserted_events
    );
}

struct BuiltFileEvents {
    root_events: Vec<ProposedEvent>,
    slice_batches: Vec<Vec<ProposedEvent>>,
    file_event_id: EventId,
}

fn build_file_events(
    fixture: &mut PerfFixture,
    file_index: usize,
    parent: CommandOutput<message::commands::SendMessageOutput>,
    file_id: EventId,
    blob_bytes: usize,
    total_slices: u32,
    slice_bytes: usize,
) -> BuiltFileEvents {
    let message_id = parent.value.message_id;
    let mut ciphertext_total =
        Vec::with_capacity(blob_bytes + total_slices as usize * XCHACHA20_POLY1305_TAG_BYTES);
    let mut plaintext = vec![0u8; slice_bytes];
    for slice_number in 0..total_slices {
        let start = slice_number as usize * slice_bytes;
        let len = (blob_bytes - start).min(slice_bytes);
        fill_payload_slice(&mut plaintext[..len], slice_number);
        let ciphertext = file_slice::codec::seal_slice(
            &fixture.key_secret,
            &fixture.workspace_id,
            &file_id,
            slice_number,
            &fixture.signer_endpoint_shared_id,
            &plaintext[..len],
        )
        .expect("seal file slice");
        ciphertext_total.extend_from_slice(&ciphertext);
    }
    let (root_hash, outboard) = crypto::bao_outboard(&ciphertext_total).expect("bao outboard");

    let descriptor = file::commands::create(file::commands::CreateFile {
        workspace_id: fixture.workspace_id,
        created_at_ms: fixture.take_timestamp(),
        message_id,
        author_user_id: fixture.author_user_id,
        signer_endpoint_shared_id: fixture.signer_endpoint_shared_id,
        signer_private_key: fixture.signer_private_key,
        file_id,
        blob_bytes: blob_bytes as u64,
        total_slices,
        slice_bytes: slice_bytes as u32,
        root_hash,
        filename: format!("perf-{file_index}-{blob_bytes}b.bin"),
        mime_type: "application/octet-stream".to_string(),
        removal_frontier_id: fixture.removal_frontier_id,
        local_history_node_secret_id: fixture.local_key_secret_id,
        key_secret: fixture.key_secret,
    })
    .expect("create encrypted signed file descriptor");
    let file_event_id = descriptor.value.file_event_id;

    let mut root_events = parent.events;
    root_events.extend(descriptor.events);

    let mut slice_batches = Vec::new();
    let mut slice_number = 0u32;
    while slice_number < total_slices {
        let batch_start = slice_number;
        let end = (slice_number + FILE_SLICE_BATCH).min(total_slices);
        let batch_len = end - batch_start;
        let mut events = Vec::with_capacity(batch_len as usize);
        while slice_number < end {
            let plaintext_start = slice_number as usize * slice_bytes;
            let plaintext_len = (blob_bytes - plaintext_start).min(slice_bytes) as u32;
            let chunk_size = slice_bytes as u64 + XCHACHA20_POLY1305_TAG_BYTES as u64;
            let slice_start = slice_number as u64 * chunk_size;
            let slice_len = plaintext_len as u64 + XCHACHA20_POLY1305_TAG_BYTES as u64;
            let slice = file_slice::commands::slice_from_ciphertext(
                file_slice::commands::SliceFromCiphertext {
                    workspace_id: fixture.workspace_id,
                    created_at_ms: fixture.take_timestamp(),
                    file_id,
                    file_event_id,
                    slice_number,
                    signer_endpoint_shared_id: fixture.signer_endpoint_shared_id,
                    signer_private_key: fixture.signer_private_key,
                    local_history_node_secret_id: fixture.local_key_secret_id,
                    plaintext_len,
                    ciphertext: &ciphertext_total,
                    outboard: &outboard,
                    slice_start,
                    slice_len,
                },
            )
            .expect("create signed file slice");
            events.extend(slice.events);
            slice_number += 1;
        }
        slice_batches.push(events);
    }

    BuiltFileEvents {
        root_events,
        slice_batches,
        file_event_id,
    }
}

fn admit<T>(store: &Store, protocol: &Protocol, output: CommandOutput<T>) -> T {
    worker::run(
        store,
        protocol,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .expect("admit and project setup event")
    .value
}

fn derive_file_id(fixture: &PerfFixture, message_id: EventId, blob_bytes: u64) -> EventId {
    let mut input = Vec::with_capacity(32 + 32 + 32 + 8);
    input.extend_from_slice(&fixture.workspace_id);
    input.extend_from_slice(&fixture.signer_endpoint_shared_id);
    input.extend_from_slice(&message_id);
    input.extend_from_slice(&blob_bytes.to_be_bytes());
    crypto::hash(&input)
}

fn fill_payload_slice(out: &mut [u8], slice_number: u32) {
    let seed = slice_number.to_le_bytes();
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = seed[idx % seed.len()]
            .wrapping_add(idx as u8)
            .rotate_left((idx % 7) as u32);
    }
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn rate(units: usize, duration: Duration) -> f64 {
    units as f64 / duration.as_secs_f64().max(f64::EPSILON)
}
