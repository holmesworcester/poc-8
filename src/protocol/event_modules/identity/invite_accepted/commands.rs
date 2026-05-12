//! Commands for accepting an identity invite locally.
//!
//! This helper is the only accept-side constructor for scoped invite acceptance
//! state. It creates two local canonical events together:
//!
//! - `invite_secret`: the raw secret material learned from the invite link for
//!   the named workspace/invite.
//! - `invite_accepted`: the replayable provenance fact that this endpoint
//!   accepted that scoped invite secret.
//!
//! The command does not validate the shared invite event, create users/devices,
//! open sockets, or admit remote ancestry. Callers admit local proposed join
//! facts separately; missing remote ancestry converges later through ordinary
//! connection sync.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::identity::{endpoint::types::EndpointId, invite};
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;
use std::net::SocketAddr;

use super::{codec, types::InviteAcceptedEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptInvite {
    pub accepted_endpoint_id: EndpointId,
    pub bootstrap_secret: Ed25519PrivateKey,
    pub addr: SocketAddr,
    pub workspace_id: EventId,
    pub invite_event_id: EventId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptInviteOutput {
    pub invite_secret_event_id: EventId,
    pub invite_accepted_event_id: EventId,
    pub bootstrap_hash: EventId,
}

pub fn accept(input: AcceptInvite) -> Result<CommandOutput<AcceptInviteOutput>, String> {
    validate_id("accepted_endpoint_id", &input.accepted_endpoint_id)?;
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("invite_event_id", &input.invite_event_id)?;

    let secret = invite::types::InviteSecretEvent::scoped_with_addr(
        input.bootstrap_secret,
        input.workspace_id,
        input.invite_event_id,
        input.addr,
    );
    let secret_bytes = invite::codec::encode(&secret);
    let invite_secret_event_id = event_id(&secret_bytes);
    let secret_record = invite::codec::record_from_bytes(secret_bytes)?;

    let accepted = InviteAcceptedEvent {
        workspace_id: input.workspace_id,
        invite_event_id: input.invite_event_id,
        invite_secret_event_id,
        bootstrap_hash: secret.bootstrap_hash,
        accepted_endpoint_id: input.accepted_endpoint_id,
    };
    let accepted_bytes = codec::encode(&accepted);
    let invite_accepted_event_id = event_id(&accepted_bytes);
    let accepted_record = codec::record_from_bytes(accepted_bytes)?;

    Ok(CommandOutput::with_events(
        AcceptInviteOutput {
            invite_secret_event_id,
            invite_accepted_event_id,
            bootstrap_hash: secret.bootstrap_hash,
        },
        vec![secret_record, accepted_record],
    ))
}

fn validate_id(name: &str, id: &[u8; 32]) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::invite;

    use super::*;

    /// Invariant: accepting an invite link locally creates both the scoped secret
    /// and the acceptance event, with acceptance blocked on the secret event id.
    #[test]
    fn accept_creates_invite_secret_and_invite_accepted_events_together() {
        let output = accept(AcceptInvite {
            accepted_endpoint_id: [5; 32],
            bootstrap_secret: [7; 32],
            addr: "127.0.0.1:41000".parse().expect("addr"),
            workspace_id: [1; 32],
            invite_event_id: [2; 32],
        })
        .expect("accept invite");

        assert_eq!(output.events.len(), 2);
        assert_eq!(
            output.value.invite_secret_event_id,
            output.events[0].event_id()
        );
        assert_eq!(
            output.value.invite_accepted_event_id,
            output.events[1].event_id()
        );
        assert_eq!(
            output.events[1].record().dependencies,
            vec![output.events[0].event_id()]
        );

        let secret = invite::codec::decode(&output.events[0].record().canonical_bytes)
            .expect("decode secret");
        assert_eq!(secret.workspace_id, Some([1; 32]));
        assert_eq!(secret.invite_event_id, Some([2; 32]));
        assert_eq!(secret.addr, Some("127.0.0.1:41000".parse().expect("addr")));

        let accepted =
            codec::decode(&output.events[1].record().canonical_bytes).expect("decode accepted");
        assert_eq!(accepted.invite_secret_event_id, output.events[0].event_id());
        assert_eq!(accepted.bootstrap_hash, output.value.bootstrap_hash);
        assert_eq!(accepted.accepted_endpoint_id, [5; 32]);
    }

    /// Invariant: a local acceptance event cannot be constructed without the
    /// endpoint identity it is meant to bind.
    #[test]
    fn accept_rejects_empty_endpoint_id() {
        let err = accept(AcceptInvite {
            accepted_endpoint_id: [0; 32],
            bootstrap_secret: [7; 32],
            addr: "127.0.0.1:41000".parse().expect("addr"),
            workspace_id: [1; 32],
            invite_event_id: [2; 32],
        })
        .expect_err("empty endpoint id must fail");

        assert_eq!(err, "accepted_endpoint_id cannot be empty");
    }
}
