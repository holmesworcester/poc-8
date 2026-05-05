//! Cross-module content CLI tests.
//!
//! These exercise the in-process CLI for a single workspace and assert the
//! semantic outcomes (rows projected, lists filtered, file bytes round-trip).
//! Black-box tests through the real `topo` binary live under `tests/`.

use std::fs;

use crate::core::cli;
use crate::core::crypto;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::{
    file, file_slice, message, message_deletion, reaction,
};
use crate::protocol::event_modules::content::message_deletion::types::deletion_label;
use crate::protocol::event_modules::identity::{
    device_invite, endpoint, endpoint_shared, user, user_invite, workspace,
};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::{EventId, EventRecord};
use crate::protocol::event_modules::worker::{self, CommandOutput};
use crate::protocol::Protocol;

fn hex_id(id: EventId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn admit<T>(store: &crate::core::store::Store, protocol: &Protocol, output: CommandOutput<T>) -> Vec<EventRecord> {
    let records = output
        .events
        .iter()
        .map(|event| event.record().clone())
        .collect::<Vec<_>>();
    worker::run(store, protocol, output).expect("admit command output");
    records
}

struct Bootstrap {
    workspace_id: EventId,
    user_id: EventId,
}

fn bootstrap_alice(context: &mut Context) -> Bootstrap {
    let local = endpoint::commands::create_local_keypair();
    let local_keypair = local.value;
    worker::run(&context.store, &context.protocol, local).expect("admit local endpoint");

    let workspace_private_key = [7; 32];
    let create_workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: crypto::ed25519_public_key(&workspace_private_key),
        name: "Content Suite".to_string(),
    })
    .expect("create workspace");
    let workspace_id = create_workspace.value.workspace_id;
    admit(&context.store, &context.protocol, create_workspace);

    let invite_private_key = [8; 32];
    let user_private_key = [9; 32];
    let user_invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: 2,
        public_key: crypto::ed25519_public_key(&invite_private_key),
        workspace_id,
        authority_event_id: workspace_id,
        signer_event_id: workspace_id,
        signer_private_key: workspace_private_key,
    })
    .expect("create user invite");
    let user_invite_id = user_invite.value.user_invite_id;
    admit(&context.store, &context.protocol, user_invite);

    let user_create = user::commands::create(user::commands::CreateUser {
        created_at_ms: 3,
        workspace_id,
        public_key: crypto::ed25519_public_key(&user_private_key),
        username: "alice".to_string(),
        user_invite_event_id: user_invite_id,
        user_invite_private_key: invite_private_key,
    })
    .expect("create user");
    let user_id = user_create.value.user_id;
    admit(&context.store, &context.protocol, user_create);

    let device_private_key = [10; 32];
    let device_invite = device_invite::commands::create_with_private_key(
        device_invite::commands::CreateDeviceInvite {
            created_at_ms: 4,
            workspace_id,
            user_authority_event_id: user_id,
            user_invite_event_id: Some(user_invite_id),
            signer_event_id: user_id,
            signer_private_key: user_private_key,
        },
        device_private_key,
    )
    .expect("create device invite");
    let device_invite_id = device_invite.value.device_invite_id;
    admit(&context.store, &context.protocol, device_invite);

    let shared = endpoint_shared::commands::share_endpoint(
        &context.store,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: 5,
            workspace_id,
            user_authority_event_id: user_id,
            endpoint_id: local_keypair.endpoint,
            signing_public_key: local_keypair.signing_public_key,
            device_name: "alice-laptop".to_string(),
            device_invite_id,
            device_invite_private_key: device_private_key,
        },
    )
    .expect("share endpoint");
    admit(&context.store, &context.protocol, shared);

    Bootstrap {
        workspace_id,
        user_id,
    }
}

#[test]
fn send_and_messages_lists_authored_text() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let db = tmp.path().join("send.db");
    let mut context = Context::open(&db).expect("open context");
    let bootstrap = bootstrap_alice(&mut context);
    let workspace_hex = hex_id(bootstrap.workspace_id);

    let send_one = cli::run(
        &super::message::cli::commands(),
        &mut context,
        &[
            "send".to_string(),
            workspace_hex.clone(),
            "first".to_string(),
        ],
    )
    .expect("first send");
    assert!(send_one.lines.iter().any(|line| line == "text: first"));

    let send_two = cli::run(
        &super::message::cli::commands(),
        &mut context,
        &[
            "send".to_string(),
            workspace_hex.clone(),
            "second".to_string(),
        ],
    )
    .expect("second send");
    assert!(send_two.lines.iter().any(|line| line == "text: second"));

    let listing = cli::run(
        &super::message::cli::commands(),
        &mut context,
        &["messages".to_string(), workspace_hex.clone()],
    )
    .expect("messages");
    assert!(listing.lines[0].starts_with("messages: 2"));
    let body = listing.lines.join("\n");
    assert!(body.contains("alice: first"), "{body}");
    assert!(body.contains("alice: second"), "{body}");
    let _ = bootstrap.user_id;
}

#[test]
fn react_appears_in_messages_listing() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let db = tmp.path().join("react.db");
    let mut context = Context::open(&db).expect("open context");
    let bootstrap = bootstrap_alice(&mut context);
    let workspace_hex = hex_id(bootstrap.workspace_id);

    cli::run(
        &message::cli::commands(),
        &mut context,
        &[
            "send".to_string(),
            workspace_hex.clone(),
            "hello".to_string(),
        ],
    )
    .expect("send");

    cli::run(
        &reaction::cli::commands(),
        &mut context,
        &[
            "react".to_string(),
            workspace_hex.clone(),
            "#1".to_string(),
            "🔥".to_string(),
        ],
    )
    .expect("react");

    let listing = cli::run(
        &message::cli::commands(),
        &mut context,
        &["messages".to_string(), workspace_hex.clone()],
    )
    .expect("messages");
    let body = listing.lines.join("\n");
    assert!(body.contains("reactions: 🔥"), "{body}");
}

#[test]
fn delete_message_marks_target_as_deleted_in_listing() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let db = tmp.path().join("delete.db");
    let mut context = Context::open(&db).expect("open context");
    let bootstrap = bootstrap_alice(&mut context);
    let workspace_hex = hex_id(bootstrap.workspace_id);

    cli::run(
        &message::cli::commands(),
        &mut context,
        &[
            "send".to_string(),
            workspace_hex.clone(),
            "regret".to_string(),
        ],
    )
    .expect("send");
    cli::run(
        &reaction::cli::commands(),
        &mut context,
        &[
            "react".to_string(),
            workspace_hex.clone(),
            "#1".to_string(),
            "💯".to_string(),
        ],
    )
    .expect("react");

    let before = cli::run(
        &message::cli::commands(),
        &mut context,
        &["messages".to_string(), workspace_hex.clone()],
    )
    .expect("messages before");
    let before = before.lines.join("\n");
    assert!(!before.contains("(deleted)"), "{before}");

    cli::run(
        &message_deletion::cli::commands(),
        &mut context,
        &[
            "delete-message".to_string(),
            workspace_hex.clone(),
            "#1".to_string(),
        ],
    )
    .expect("delete");

    let after = cli::run(
        &message::cli::commands(),
        &mut context,
        &["messages".to_string(), workspace_hex.clone()],
    )
    .expect("messages after");
    let after_text = after.lines.join("\n");
    assert!(after_text.contains("(deleted)"), "{after_text}");

    let messages = message::schema::list_for_workspace(&context.store, bootstrap.workspace_id)
        .expect("list messages");
    assert_eq!(messages.len(), 1);
    let labels = event_schema::event_labels(&context.store, &messages[0].message_id)
        .expect("load labels");
    assert!(
        labels
            .iter()
            .any(|label| label == &deletion_label(&messages[0].author_user_id)),
        "deletion projects a label authored by the message author"
    );
    assert_eq!(
        reaction::schema::count_for_workspace(&context.store, bootstrap.workspace_id)
            .expect("count reactions"),
        1,
        "reactions persist; display filters at read time"
    );
}

#[test]
fn send_file_creates_file_and_slices_and_save_file_round_trips() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let db = tmp.path().join("file.db");
    let mut context = Context::open(&db).expect("open context");
    let bootstrap = bootstrap_alice(&mut context);
    let workspace_hex = hex_id(bootstrap.workspace_id);

    let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("input.bin");
    fs::write(&in_path, &payload).expect("write input");

    cli::run(
        &super::cli::commands(),
        &mut context,
        &[
            "send-file".to_string(),
            workspace_hex.clone(),
            "see attached".to_string(),
            "--file".to_string(),
            in_path.to_string_lossy().to_string(),
            "--mime".to_string(),
            "application/octet-stream".to_string(),
        ],
    )
    .expect("send-file");

    let files = cli::run(
        &file::cli::commands(),
        &mut context,
        &["files".to_string(), workspace_hex.clone()],
    )
    .expect("files");
    let body = files.lines.join("\n");
    assert!(body.contains("input.bin"), "{body}");
    assert!(body.contains("4096"), "{body}");

    let out_path = tmp.path().join("out.bin");
    cli::run(
        &file::cli::commands(),
        &mut context,
        &[
            "save-file".to_string(),
            workspace_hex.clone(),
            "#1".to_string(),
            out_path.to_string_lossy().to_string(),
        ],
    )
    .expect("save-file");
    let out_bytes = fs::read(&out_path).expect("read output");
    assert_eq!(out_bytes, payload);

    let _ = file_slice::schema::count_for_workspace(&context.store, bootstrap.workspace_id)
        .expect("count slices");
}
