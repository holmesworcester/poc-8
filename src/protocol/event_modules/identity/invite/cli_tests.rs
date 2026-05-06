use crate::core::cli::{self, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::identity::endpoint;

use super::{commands, schema};

// Invariant: invite cli creates local endpoint and local invite secret.
#[test]
fn invite_cli_creates_local_endpoint_and_local_invite_secret() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let db = tmp.path().join("invite-cli.db");
    let mut context = Context::open(&db).expect("open context");
    let args = vec![
        "invite".to_string(),
        "--public-addr".to_string(),
        "127.0.0.1:43123".to_string(),
    ];

    let output = cli::run(&super::cli::commands(), &mut context, &args).expect("run invite CLI");

    let CliOutput { lines } = output;
    assert_eq!(lines.len(), 1);
    let invite = commands::parse(&lines[0]).expect("parse invite link");
    assert_eq!(
        invite.addr,
        "127.0.0.1:43123"
            .parse::<std::net::SocketAddr>()
            .expect("socket addr")
    );

    let endpoint_row = context
        .store
        .table_row(endpoint::schema::LOCAL_ENDPOINT, b"local")
        .expect("read local endpoint")
        .expect("local endpoint row");
    let endpoint_secret_row = context
        .store
        .table_row(endpoint::schema::LOCAL_ENDPOINT_SECRET, b"local")
        .expect("read local endpoint secret")
        .expect("local endpoint secret row");
    let invite_secret_row = context
        .store
        .table_row(
            schema::INVITE_SECRETS,
            &commands::secret_hash(&invite.bootstrap_secret),
        )
        .expect("read invite secret")
        .expect("invite secret row");

    assert_eq!(endpoint_row, invite.endpoint);
    assert_eq!(endpoint_secret_row.len(), 32);
    assert_eq!(invite_secret_row, invite.bootstrap_secret);
}
