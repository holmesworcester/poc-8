//! Command for creating the local endpoint.
//!
//! The create command returns the generated keypair and proposes the local
//! endpoint event that will store it. The read helper below is intentionally
//! expressed against a narrow context trait rather than `Store`; callers decide
//! where the data comes from, and this module owns the keypair consistency
//! check.

use crate::core::crypto;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::{EndpointId, EndpointKeypair};

pub trait LocalEndpointRead {
    fn local_endpoint_secret(&self) -> Result<Option<Vec<u8>>, String>;
    fn local_endpoint(&self) -> Result<Option<Vec<u8>>, String>;
    fn local_endpoint_signing_public_key(&self) -> Result<Option<Vec<u8>>, String>;
    fn local_endpoint_signing_secret(&self) -> Result<Option<Vec<u8>>, String>;
}

pub fn create_local_keypair() -> CommandOutput<EndpointKeypair> {
    let secret = crypto::random_x25519_private_key();
    let endpoint = crypto::x25519_public_key(&secret);
    let signing_secret = crypto::random_ed25519_private_key();
    let signing_public_key = crypto::ed25519_public_key(&signing_secret);
    let event = EndpointKeypair {
        endpoint,
        secret,
        signing_public_key,
        signing_secret,
    };
    let bytes = codec::encode(&event);
    CommandOutput::with_events(
        event,
        vec![codec::record_from_bytes(bytes).expect("encoded local endpoint is valid")],
    )
}

pub fn local_or_create(
    context: &impl LocalEndpointRead,
) -> Result<CommandOutput<EndpointKeypair>, String> {
    match local_keypair(context)? {
        Some(local) => Ok(CommandOutput::new(local)),
        None => Ok(create_local_keypair()),
    }
}

pub fn local_keypair(context: &impl LocalEndpointRead) -> Result<Option<EndpointKeypair>, String> {
    let secret = context.local_endpoint_secret()?;
    let endpoint = context.local_endpoint()?;
    let signing_public_key = context.local_endpoint_signing_public_key()?;
    let signing_secret = context.local_endpoint_signing_secret()?;

    match (secret, endpoint, signing_public_key, signing_secret) {
        (Some(secret), Some(endpoint), Some(signing_public_key), Some(signing_secret)) => {
            let secret = endpoint_id(&secret)?;
            let endpoint = endpoint_id(&endpoint)?;
            let signing_public_key = endpoint_id(&signing_public_key)?;
            let signing_secret = endpoint_id(&signing_secret)?;
            let derived = crypto::x25519_public_key(&secret);
            if derived != endpoint {
                return Err("stored endpoint does not match local endpoint secret".to_string());
            }
            if crypto::ed25519_public_key(&signing_secret) != signing_public_key {
                return Err(
                    "stored endpoint signing key does not match local signing secret".to_string(),
                );
            }
            Ok(Some(EndpointKeypair {
                endpoint,
                secret,
                signing_public_key,
                signing_secret,
            }))
        }
        (None, None, None, None) => Ok(None),
        (None, _, _, _) => Err("local endpoint secret is missing".to_string()),
        (_, None, _, _) => Err("local endpoint public key is missing".to_string()),
        (_, _, None, _) => Err("local endpoint signing public key is missing".to_string()),
        (_, _, _, None) => Err("local endpoint signing secret is missing".to_string()),
    }
}

fn endpoint_id(bytes: &[u8]) -> Result<EndpointId, String> {
    if bytes.len() != 32 {
        return Err("stored endpoint id is malformed".to_string());
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    #[derive(Default)]
    struct ReadContext {
        endpoint: Option<Vec<u8>>,
        secret: Option<Vec<u8>>,
        signing_public_key: Option<Vec<u8>>,
        signing_secret: Option<Vec<u8>>,
    }

    impl LocalEndpointRead for ReadContext {
        fn local_endpoint_secret(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.secret.clone())
        }

        fn local_endpoint(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.endpoint.clone())
        }

        fn local_endpoint_signing_public_key(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.signing_public_key.clone())
        }

        fn local_endpoint_signing_secret(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.signing_secret.clone())
        }
    }

    // Invariant: create local keypair proposes local only matching secret event.
    #[test]
    fn create_local_keypair_proposes_local_only_matching_secret_event() {
        let output = create_local_keypair();

        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Local);
        assert!(!record.scope.is_shared());
        assert!(record.dependencies.is_empty());

        let decoded = codec::decode(&record.canonical_bytes).expect("decode local endpoint");
        assert_eq!(decoded, output.value);
    }

    // Invariant: local keypair rejects stored secret that does not match endpoint.
    #[test]
    fn local_keypair_rejects_stored_secret_that_does_not_match_endpoint() {
        let good = create_local_keypair().value;
        let bad = create_local_keypair().value;
        let context = ReadContext {
            endpoint: Some(good.endpoint.to_vec()),
            secret: Some(bad.secret.to_vec()),
            signing_public_key: Some(good.signing_public_key.to_vec()),
            signing_secret: Some(good.signing_secret.to_vec()),
        };

        let err = local_keypair(&context).expect_err("mismatched keypair must fail");

        assert_eq!(err, "stored endpoint does not match local endpoint secret");
    }

    // Invariant: local keypair rejects stored signing secret that does not match public key.
    #[test]
    fn local_keypair_rejects_stored_signing_secret_that_does_not_match_public_key() {
        let good = create_local_keypair().value;
        let bad = create_local_keypair().value;
        let context = ReadContext {
            endpoint: Some(good.endpoint.to_vec()),
            secret: Some(good.secret.to_vec()),
            signing_public_key: Some(good.signing_public_key.to_vec()),
            signing_secret: Some(bad.signing_secret.to_vec()),
        };

        let err = local_keypair(&context).expect_err("mismatched signing keypair must fail");

        assert_eq!(
            err,
            "stored endpoint signing key does not match local signing secret"
        );
    }

    // Invariant: local keypair reports missing side of local material.
    #[test]
    fn local_keypair_reports_missing_side_of_local_material() {
        let local = create_local_keypair().value;
        let missing_secret = ReadContext {
            endpoint: Some(local.endpoint.to_vec()),
            secret: None,
            signing_public_key: Some(local.signing_public_key.to_vec()),
            signing_secret: Some(local.signing_secret.to_vec()),
        };
        let missing_endpoint = ReadContext {
            endpoint: None,
            secret: Some(local.secret.to_vec()),
            signing_public_key: Some(local.signing_public_key.to_vec()),
            signing_secret: Some(local.signing_secret.to_vec()),
        };

        assert_eq!(
            local_keypair(&missing_secret).expect_err("missing secret must fail"),
            "local endpoint secret is missing"
        );
        assert_eq!(
            local_keypair(&missing_endpoint).expect_err("missing endpoint must fail"),
            "local endpoint public key is missing"
        );
    }
}
