//! Projector for `disappearing_messages_setting` events.
//!
//! Validation:
//!   * Signed envelope decodes; envelope signer matches inner authority
//!     admin.
//!   * Authority admin dependency is a signed admin event; its workspace
//!     matches the setting's workspace; the admin event's public key
//!     matches the envelope signer key.
//!   * `effective_at_minute == created_at_ms / 60_000` (codec already
//!     enforces this on decode).
//!   * Monotonic floor (`expires_at_or_before_minute`): if the event names
//!     a `previous_setting_id`, that dependency must decode as a signed
//!     setting for the same workspace and its floor must be <= this
//!     setting's floor. Equality is allowed (a no-op floor change is a
//!     loosening); strict greater is allowed (a tightening). A new floor
//!     strictly less than the predecessor's floor is rejected.
//!
//! Output: one row in `SETTINGS` per admitted setting. The active
//! setting is found by querying for the row with the highest
//! `(created_at_ms, event_id)` per workspace.

use crate::protocol::event_modules::identity::{admin, signed};
use crate::protocol::event_modules::types::{EventId, EventRecord};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::types::DisappearingMessagesSettingEvent;
use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let setting = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(setting.workspace_id) {
        return Err(
            "disappearing_messages_setting workspace metadata does not match event body"
                .to_string(),
        );
    }
    if envelope.authority_admin_event_id != setting.authority_admin_event_id {
        return Err("disappearing_messages_setting signer must be the authority admin".to_string());
    }

    let admin_event = decode_admin_dependency(event, setting.authority_admin_event_id)?;
    if admin_event.workspace_id != setting.workspace_id {
        return Err(
            "disappearing_messages_setting authority admin workspace does not match event"
                .to_string(),
        );
    }
    if admin_event.public_key != envelope.signer_public_key {
        return Err(
            "disappearing_messages_setting signer public key does not match authority admin"
                .to_string(),
        );
    }

    validate_monotonic_floor(event, &setting)?;

    Ok(ProjectionOutput::rows(vec![schema::setting_row(
        setting.workspace_id,
        event.context.event_id,
        setting.ttl_minutes,
        setting.effective_at_minute,
        setting.created_at_ms,
        setting.expires_at_or_before_minute,
    )]))
}

fn validate_monotonic_floor(
    event: &EventWithContext<'_>,
    setting: &DisappearingMessagesSettingEvent,
) -> Result<(), String> {
    let Some(previous_setting_id) = setting.previous_setting_id else {
        return Ok(());
    };
    let dependency = event.context.dependency(&previous_setting_id).ok_or_else(|| {
        "disappearing_messages_setting previous_setting_id dependency is missing".to_string()
    })?;
    let previous = decode_previous_setting(dependency, setting.workspace_id)?;
    if setting.expires_at_or_before_minute < previous.expires_at_or_before_minute {
        return Err(
            "disappearing setting floor must be monotonic non-decreasing".to_string(),
        );
    }
    Ok(())
}

fn decode_previous_setting(
    dependency: &EventRecord,
    expected_workspace_id: EventId,
) -> Result<DisappearingMessagesSettingEvent, String> {
    let envelope = codec::decode_signed(&dependency.canonical_bytes).map_err(|_| {
        "disappearing_messages_setting previous_setting_id dependency is not a signed setting"
            .to_string()
    })?;
    let previous = codec::decode(&envelope.payload).map_err(|_| {
        "disappearing_messages_setting previous_setting_id dependency is not a setting"
            .to_string()
    })?;
    if previous.workspace_id != expected_workspace_id {
        return Err(
            "disappearing_messages_setting previous_setting_id workspace does not match"
                .to_string(),
        );
    }
    Ok(previous)
}

fn decode_admin_dependency(
    event: &EventWithContext<'_>,
    authority_admin_event_id: EventId,
) -> Result<admin::types::AdminEvent, String> {
    let dependency = event
        .context
        .dependency(&authority_admin_event_id)
        .ok_or_else(|| {
            "disappearing_messages_setting authority admin dependency is missing".to_string()
        })?;
    let envelope = signed::codec::decode(&dependency.canonical_bytes).map_err(|_| {
        "disappearing_messages_setting authority admin dependency is not a signed event"
            .to_string()
    })?;
    if envelope.inner_type != admin::codec::TYPE_ADMIN {
        return Err(
            "disappearing_messages_setting authority admin dependency is not a signed admin event"
                .to_string(),
        );
    }
    admin::codec::decode(&envelope.payload).map_err(|_| {
        "disappearing_messages_setting authority admin dependency is not a valid admin event"
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{self, ED25519_PRIVATE_KEY_BYTES};
    use crate::protocol::event_modules::identity::admin;
    use crate::protocol::event_modules::identity::signed;
    use crate::protocol::event_modules::types::{event_id, EventId, EventRecord, EventScope};
    use crate::protocol::event_modules::worker::{DependencyContext, EventContext};
    use crate::workers::pipeline_helpers::event_pipeline::EventWithContext;

    use super::super::codec;
    use super::super::types::DisappearingMessagesSettingEvent;
    use super::*;

    fn admin_dependency_record(
        workspace_id: EventId,
        admin_public_key: [u8; 32],
    ) -> EventRecord
    {
        let admin_event = admin::types::AdminEvent {
            created_at_ms: 1_000_000,
            workspace_id,
            public_key: admin_public_key,
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        };
        let payload = admin::codec::encode(&admin_event);
        let signed_envelope = signed::commands::sign_payload(
            workspace_id,
            &[7; ED25519_PRIVATE_KEY_BYTES],
            payload,
        )
        .expect("sign admin payload")
        .value;
        let bytes = signed::codec::encode(&signed_envelope);
        signed::codec::record_from_bytes(bytes).expect("admin record")
    }

    fn build_setting_record(
        workspace_id: EventId,
        ttl_minutes: u32,
        admin_event_id: EventId,
        signer_private_key: [u8; ED25519_PRIVATE_KEY_BYTES],
        created_at_ms: u64,
        expires_at_or_before_minute: u64,
        previous_setting_id: Option<EventId>,
    ) -> EventRecord
    {
        let inner = DisappearingMessagesSettingEvent {
            created_at_ms,
            workspace_id,
            ttl_minutes,
            authority_admin_event_id: admin_event_id,
            effective_at_minute: created_at_ms / 60_000,
            expires_at_or_before_minute,
            previous_setting_id,
        };
        let payload = codec::encode(&inner);
        let envelope = codec::sign(admin_event_id, &signer_private_key, payload);
        let bytes = codec::encode_signed(&envelope);
        codec::signed_record_from_bytes(bytes).expect("setting record")
    }

    fn projector_input(
        workspace_id: EventId,
        ttl_minutes: u32,
        admin_event_id: EventId,
        admin_public_key: [u8; 32],
        signer_private_key: [u8; ED25519_PRIVATE_KEY_BYTES],
    ) -> (EventRecord, EventContext) {
        let record = build_setting_record(
            workspace_id,
            ttl_minutes,
            admin_event_id,
            signer_private_key,
            6_000_000,
            0,
            None,
        );
        let context = EventContext {
            event_id: event_id(&record.canonical_bytes),
            dependencies: vec![DependencyContext {
                event_id: admin_event_id,
                record: admin_dependency_record(workspace_id, admin_public_key),
            }],
            labels: Vec::new(),
            receive: None,
            now_unix_minute: None,
        };
        (record, context)
    }

    fn projector_input_with_previous(
        workspace_id: EventId,
        ttl_minutes: u32,
        admin_event_id: EventId,
        admin_public_key: [u8; 32],
        signer_private_key: [u8; ED25519_PRIVATE_KEY_BYTES],
        created_at_ms: u64,
        expires_at_or_before_minute: u64,
        previous_record: &EventRecord,
    ) -> (EventRecord, EventContext) {
        let previous_id = event_id(&previous_record.canonical_bytes);
        let record = build_setting_record(
            workspace_id,
            ttl_minutes,
            admin_event_id,
            signer_private_key,
            created_at_ms,
            expires_at_or_before_minute,
            Some(previous_id),
        );
        let context = EventContext {
            event_id: event_id(&record.canonical_bytes),
            dependencies: vec![
                DependencyContext {
                    event_id: admin_event_id,
                    record: admin_dependency_record(workspace_id, admin_public_key),
                },
                DependencyContext {
                    event_id: previous_id,
                    record: previous_record.clone(),
                },
            ],
            labels: Vec::new(),
            receive: None,
            now_unix_minute: None,
        };
        (record, context)
    }

    #[test]
    fn projects_one_active_setting_row_for_authorized_admin() {
        let private_key = [9; ED25519_PRIVATE_KEY_BYTES];
        let admin_public_key = crypto::ed25519_public_key(&private_key);
        let (record, context) =
            projector_input([1; 32], 5, [2; 32], admin_public_key, private_key);
        let event = EventWithContext {
            record: &record,
            context,
        };
        let output = project(&event).expect("project authorized setting");
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.deletes.len(), 0);
        assert_eq!(output.labels.len(), 0);
        let decoded = super::super::schema::decode_active_setting_row(
            &output.rows[0].key,
            &output.rows[0].value,
        )
        .expect("decode setting row");
        assert_eq!(decoded.ttl_minutes, 5);
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.expires_at_or_before_minute, 0);
    }

    #[test]
    fn rejects_signer_public_key_that_does_not_match_authority_admin() {
        let signer_private_key = [9; ED25519_PRIVATE_KEY_BYTES];
        let other_admin_public_key = crypto::ed25519_public_key(&[8; ED25519_PRIVATE_KEY_BYTES]);
        let (record, context) = projector_input(
            [1; 32],
            5,
            [2; 32],
            other_admin_public_key,
            signer_private_key,
        );
        let event = EventWithContext {
            record: &record,
            context,
        };
        let err = project(&event).expect_err("mismatched public key must fail");
        assert!(
            err.contains("signer public key does not match authority admin"),
            "{err}"
        );
    }

    #[test]
    fn rejects_admin_dependency_for_a_different_workspace() {
        let private_key = [9; ED25519_PRIVATE_KEY_BYTES];
        let admin_public_key = crypto::ed25519_public_key(&private_key);
        let record = build_setting_record(
            [1; 32],
            5,
            [2; 32],
            private_key,
            6_000_000,
            0,
            None,
        );
        let context = EventContext {
            event_id: event_id(&record.canonical_bytes),
            dependencies: vec![DependencyContext {
                event_id: [2; 32],
                record: admin_dependency_record([9; 32], admin_public_key),
            }],
            labels: Vec::new(),
            receive: None,
            now_unix_minute: None,
        };
        let event = EventWithContext {
            record: &record,
            context,
        };
        let err = project(&event).expect_err("wrong-workspace admin must fail");
        assert!(
            err.contains("authority admin workspace does not match event"),
            "{err}"
        );
    }

    #[test]
    fn record_record_rebuilds_to_shared_scope() {
        let private_key = [9; ED25519_PRIVATE_KEY_BYTES];
        let admin_public_key = crypto::ed25519_public_key(&private_key);
        let (record, _) = projector_input([1; 32], 5, [2; 32], admin_public_key, private_key);
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
    }

    #[test]
    fn roundtrips_setting_with_nonzero_floor_through_codec() {
        let inner = DisappearingMessagesSettingEvent {
            created_at_ms: 6_000_000,
            workspace_id: [1; 32],
            ttl_minutes: 5,
            authority_admin_event_id: [2; 32],
            effective_at_minute: 100,
            expires_at_or_before_minute: 99,
            previous_setting_id: Some([42; 32]),
        };
        let bytes = codec::encode(&inner);
        let decoded = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded.expires_at_or_before_minute, 99);
        assert_eq!(decoded.previous_setting_id, Some([42; 32]));
    }

    #[test]
    fn rejects_setting_whose_floor_is_below_previous_floor() {
        let private_key = [9; ED25519_PRIVATE_KEY_BYTES];
        let admin_public_key = crypto::ed25519_public_key(&private_key);
        let previous = build_setting_record(
            [1; 32],
            5,
            [2; 32],
            private_key,
            6_000_000,
            50,
            None,
        );
        let (record, context) = projector_input_with_previous(
            [1; 32],
            5,
            [2; 32],
            admin_public_key,
            private_key,
            6_060_000,
            49,
            &previous,
        );
        let event = EventWithContext {
            record: &record,
            context,
        };
        let err = project(&event).expect_err("decreasing floor must be rejected");
        assert!(err.contains("monotonic non-decreasing"), "{err}");
    }

    #[test]
    fn admits_setting_whose_floor_equals_previous_floor() {
        let private_key = [9; ED25519_PRIVATE_KEY_BYTES];
        let admin_public_key = crypto::ed25519_public_key(&private_key);
        let previous = build_setting_record(
            [1; 32],
            5,
            [2; 32],
            private_key,
            6_000_000,
            50,
            None,
        );
        let (record, context) = projector_input_with_previous(
            [1; 32],
            5,
            [2; 32],
            admin_public_key,
            private_key,
            6_060_000,
            50,
            &previous,
        );
        let event = EventWithContext {
            record: &record,
            context,
        };
        let output = project(&event).expect("equal floor must admit");
        assert_eq!(output.rows.len(), 1);
        let decoded = super::super::schema::decode_active_setting_row(
            &output.rows[0].key,
            &output.rows[0].value,
        )
        .expect("decode setting row");
        assert_eq!(decoded.expires_at_or_before_minute, 50);
    }

    #[test]
    fn admits_setting_whose_floor_is_above_previous_floor() {
        let private_key = [9; ED25519_PRIVATE_KEY_BYTES];
        let admin_public_key = crypto::ed25519_public_key(&private_key);
        let previous = build_setting_record(
            [1; 32],
            5,
            [2; 32],
            private_key,
            6_000_000,
            50,
            None,
        );
        let (record, context) = projector_input_with_previous(
            [1; 32],
            5,
            [2; 32],
            admin_public_key,
            private_key,
            6_060_000,
            75,
            &previous,
        );
        let event = EventWithContext {
            record: &record,
            context,
        };
        let output = project(&event).expect("higher floor must admit");
        assert_eq!(output.rows.len(), 1);
        let decoded = super::super::schema::decode_active_setting_row(
            &output.rows[0].key,
            &output.rows[0].value,
        )
        .expect("decode setting row");
        assert_eq!(decoded.expires_at_or_before_minute, 75);
    }
}
