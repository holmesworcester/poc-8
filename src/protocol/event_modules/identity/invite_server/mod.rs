//! Invite-server identity facts.
//!
//! An invite-server invite is isomorphic to the user/device invite pattern: a
//! shared signed event publishes an invite public key, while the private key
//! travels only in the out-of-band invite link. Accepting it creates an
//! endpoint-shared event with the invite-server endpoint role.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod schema;
pub mod types;
