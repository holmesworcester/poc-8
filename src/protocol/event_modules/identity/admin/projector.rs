//! Projector for admin grant events.
//!
//! Projection validates only immediate dependency records supplied by the common
//! worker, then writes one admin row. Bootstrap grants are signed by the
//! workspace root. Ongoing grants are signed by the authority admin key named by
//! the inner grant.
//!
//! Admin authority is workspace-local. A public key that is admin in workspace A
//! cannot authorize grants in workspace B unless there is a separate admin row
//! for workspace B, and the target user must also belong to the grant workspace.

use crate::protocol::event_modules::types::{EventId, EventRecord};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::super::{signed, user, workspace};
use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let _ = event;
    Err("admin must be signed".to_string())
}

pub fn project_signed(
    envelope: &signed::types::SignedEnvelope,
    event: &EventWithContext<'_>,
) -> Result<ProjectionOutput, String> {
    if envelope.inner_type != codec::TYPE_ADMIN {
        return Err("expected signed admin".to_string());
    }
    let admin = codec::decode(&envelope.payload)?;
    validate_signed_authority(envelope, &admin, event)?;
    validate_user_binding(&admin, event)?;
    project_admin(event.context.event_id, &admin)
}

fn project_admin(
    admin_id: EventId,
    admin: &super::types::AdminEvent,
) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::rows(vec![schema::admin_row(
        admin.workspace_id,
        admin_id,
        admin.created_at_ms,
        admin.public_key,
        admin.authority_event_id,
        admin.user_event_id,
    )]))
}

fn validate_signed_authority(
    envelope: &signed::types::SignedEnvelope,
    admin: &super::types::AdminEvent,
    event: &EventWithContext<'_>,
) -> Result<(), String> {
    let workspace_record = require_dependency(event, &admin.workspace_id, "workspace")?;
    let workspace = workspace::codec::decode(&workspace_record.canonical_bytes)
        .map_err(|_| "admin workspace dependency must be a workspace event".to_string())?;

    if admin.authority_event_id == admin.workspace_id {
        if envelope.signer_event_id != admin.workspace_id {
            return Err("bootstrap admin must use workspace as signer and authority".to_string());
        }
        if admin.user_event_id != admin.workspace_id {
            return Err("workspace admin authority can only bootstrap root admin".to_string());
        }
        if envelope.signer_public_key != workspace.public_key {
            return Err(
                "signed bootstrap admin signer key does not match workspace public key".to_string(),
            );
        }
        return Ok(());
    }
    if envelope.signer_event_id != admin.authority_event_id {
        return Err("signed admin grant signer must be the authority admin".to_string());
    }

    let authority_record = require_dependency(event, &admin.authority_event_id, "authority")?;
    let authority_admin = decode_admin_record(authority_record)
        .map_err(|_| "signed admin authority must be an admin event".to_string())?;
    if authority_admin.workspace_id != admin.workspace_id {
        return Err("admin authority belongs to a different workspace".to_string());
    }
    if envelope.signer_public_key != authority_admin.public_key {
        return Err("signed admin signer key does not match authority admin".to_string());
    }
    Ok(())
}

fn validate_user_binding(
    admin: &super::types::AdminEvent,
    event: &EventWithContext<'_>,
) -> Result<(), String> {
    let user_record = require_dependency(event, &admin.user_event_id, "user")?;
    if admin.user_event_id == admin.workspace_id {
        let workspace = workspace::codec::decode(&user_record.canonical_bytes)
            .map_err(|_| "root admin user dependency must be the workspace event".to_string())?;
        if workspace.public_key == admin.public_key {
            return Ok(());
        }
        return Err("admin public_key does not match root workspace public_key".to_string());
    }

    let user = decode_user_record(user_record)
        .map_err(|_| "admin user dependency must be a user event".to_string())?;
    if user.workspace_id != admin.workspace_id {
        return Err("admin user belongs to a different workspace".to_string());
    }
    if user.public_key == admin.public_key {
        return Ok(());
    }
    Err("admin public_key does not match user public_key".to_string())
}

fn require_dependency<'a>(
    event: &'a EventWithContext<'_>,
    event_id: &EventId,
    name: &'static str,
) -> Result<&'a EventRecord, String> {
    event
        .context
        .dependency(event_id)
        .ok_or_else(|| format!("admin missing {name} dependency"))
}

fn decode_admin_record(record: &EventRecord) -> Result<super::types::AdminEvent, String> {
    match record.canonical_bytes.first().copied() {
        Some(codec::TYPE_ADMIN) => codec::decode(&record.canonical_bytes),
        Some(signed::codec::TYPE_SIGNED) => {
            let envelope = signed::codec::decode(&record.canonical_bytes)?;
            if envelope.inner_type != codec::TYPE_ADMIN {
                return Err("expected signed admin".to_string());
            }
            codec::decode(&envelope.payload)
        }
        _ => Err("expected admin".to_string()),
    }
}

fn decode_user_record(record: &EventRecord) -> Result<user::types::UserEvent, String> {
    let envelope = signed::codec::decode(&record.canonical_bytes)?;
    if envelope.inner_type != user::codec::TYPE_USER {
        return Err("expected signed user".to_string());
    }
    user::codec::decode(&envelope.payload)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{signed, user, workspace};
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{DependencyContext, EventContext};

    use super::super::types::AdminEvent;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signer_public_key(private_key: &[u8; 32]) -> [u8; 32] {
        signed::commands::sign_payload([0; 32], private_key, vec![99])
            .expect("sign fixture")
            .value
            .signer_public_key
    }

    fn make_workspace_record(public_key: [u8; 32]) -> ([u8; 32], Record) {
        let bytes = workspace::codec::encode(&workspace::types::WorkspaceEvent {
            created_at_ms: 10,
            public_key,
            name: "Root".to_string(),
        })
        .expect("encode workspace");
        let id = event_id(&bytes);
        let record = workspace::codec::record_from_bytes(bytes).expect("workspace record");
        (id, record)
    }

    fn admin_record(event: AdminEvent) -> Record {
        codec::record_from_bytes(codec::encode(&event)).expect("admin record")
    }

    fn signed_user_record(workspace_id: EventId, public_key: [u8; 32]) -> (EventId, Record) {
        let user = user::types::UserEvent {
            created_at_ms: 25,
            workspace_id,
            public_key,
            username: "alice".to_string(),
        };
        let output = signed::commands::sign_payload(
            [90; 32],
            &[91; 32],
            user::codec::encode(&user).expect("encode user"),
        )
        .expect("sign user");
        let record = output.events[0].record().clone();
        (event_id(&record.canonical_bytes), record)
    }

    fn signed_admin_record(
        signer_event_id: EventId,
        signer_private_key: [u8; 32],
        admin: AdminEvent,
    ) -> (Record, signed::types::SignedEnvelope) {
        let output = signed::commands::sign_payload(
            signer_event_id,
            &signer_private_key,
            codec::encode(&admin),
        )
        .expect("sign admin");
        let record = output.events[0].record().clone();
        let envelope = signed::codec::decode(&record.canonical_bytes).expect("signed admin");
        (record, envelope)
    }

    fn context_for<'a>(
        record: &'a Record,
        dependencies: Vec<DependencyContext>,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies,
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    #[test]
    fn rejects_raw_admin_even_for_workspace_authority() {
        let (workspace_id, workspace_record) = make_workspace_record([7; 32]);
        let record = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: [7; 32],
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });
        let err = project(&context_for(
            &record,
            vec![DependencyContext {
                event_id: workspace_id,
                record: workspace_record,
            }],
        ))
        .expect_err("raw admin must reject");

        assert_eq!(err, "admin must be signed");
    }

    #[test]
    fn rejects_raw_admin_at_protocol_admission_boundary() {
        let (workspace_id, _workspace_record) = make_workspace_record([7; 32]);
        let record = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: [7; 32],
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });

        let err = crate::protocol::event_modules::record_from_bytes(record.canonical_bytes)
            .expect_err("raw admin must not be admitted");

        assert_eq!(err, "admin must be signed");
    }

    #[test]
    fn rejects_unsigned_ongoing_admin_grant_even_when_authority_dependency_exists() {
        let (workspace_id, workspace_record) = make_workspace_record([7; 32]);
        let authority = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: [7; 32],
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });
        let authority_id = event_id(&authority.canonical_bytes);
        let record = admin_record(AdminEvent {
            created_at_ms: 30,
            workspace_id,
            public_key: [7; 32],
            authority_event_id: authority_id,
            user_event_id: workspace_id,
        });

        let err = project(&context_for(
            &record,
            vec![
                DependencyContext {
                    event_id: workspace_id,
                    record: workspace_record,
                },
                DependencyContext {
                    event_id: authority_id,
                    record: authority,
                },
            ],
        ))
        .expect_err("unsigned ongoing admin grant must reject");

        assert_eq!(err, "admin must be signed");
    }

    #[test]
    fn projects_signed_root_admin_from_workspace_authority_and_root_user_binding() {
        let workspace_private_key = [7; 32];
        let workspace_public_key = signer_public_key(&workspace_private_key);
        let (workspace_id, workspace_record) = make_workspace_record(workspace_public_key);
        let admin = AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: workspace_public_key,
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        };
        let (record, envelope) = signed_admin_record(workspace_id, workspace_private_key, admin);

        let output = project_signed(
            &envelope,
            &context_for(
                &record,
                vec![DependencyContext {
                    event_id: workspace_id,
                    record: workspace_record,
                }],
            ),
        )
        .expect("project signed bootstrap admin");

        assert_eq!(output.labels.len(), 0);
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::ADMINS);
        assert_eq!(
            output.rows[0].key,
            schema::admin_key(&workspace_id, &event_id(&record.canonical_bytes))
        );
        let row =
            schema::decode_admin_row(&output.rows[0].key, &output.rows[0].value).expect("row");
        assert_eq!(row.workspace_id, workspace_id);
        assert_eq!(row.admin_id, event_id(&record.canonical_bytes));
        assert_eq!(row.public_key, workspace_public_key);
        assert_eq!(row.authority_event_id, workspace_id);
        assert_eq!(row.user_event_id, workspace_id);
    }

    #[test]
    fn rejects_signed_bootstrap_admin_when_signer_key_does_not_match_workspace() {
        let workspace_private_key = [7; 32];
        let workspace_public_key = signer_public_key(&workspace_private_key);
        let (workspace_id, workspace_record) = make_workspace_record(workspace_public_key);
        let admin = AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: workspace_public_key,
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        };
        let (record, envelope) = signed_admin_record(workspace_id, [8; 32], admin);

        let err = project_signed(
            &envelope,
            &context_for(
                &record,
                vec![DependencyContext {
                    event_id: workspace_id,
                    record: workspace_record,
                }],
            ),
        )
        .expect_err("wrong bootstrap signer key must reject");

        assert_eq!(
            err,
            "signed bootstrap admin signer key does not match workspace public key"
        );
    }

    #[test]
    fn rejects_bootstrap_public_key_that_does_not_match_root_workspace_user() {
        let workspace_private_key = [7; 32];
        let workspace_public_key = signer_public_key(&workspace_private_key);
        let (workspace_id, workspace_record) = make_workspace_record(workspace_public_key);
        let admin = AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: [8; 32],
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        };
        let (record, envelope) = signed_admin_record(workspace_id, workspace_private_key, admin);

        let err = project_signed(
            &envelope,
            &context_for(
                &record,
                vec![DependencyContext {
                    event_id: workspace_id,
                    record: workspace_record,
                }],
            ),
        )
        .expect_err("mismatched root key must reject");

        assert!(err.contains("admin public_key does not match root workspace public_key"));
    }

    #[test]
    fn rejects_signed_admin_authority_from_another_workspace() {
        let authority_private_key = [94; 32];
        let authority_public_key = signer_public_key(&authority_private_key);
        let (workspace_id, workspace_record) = make_workspace_record([7; 32]);
        let (other_workspace_id, _) = make_workspace_record(authority_public_key);
        let authority = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id: other_workspace_id,
            public_key: authority_public_key,
            authority_event_id: other_workspace_id,
            user_event_id: other_workspace_id,
        });
        let authority_id = event_id(&authority.canonical_bytes);
        let (target_user_id, target_user_record) = signed_user_record(workspace_id, [11; 32]);
        let (record, envelope) = signed_admin_record(
            authority_id,
            authority_private_key,
            AdminEvent {
                created_at_ms: 30,
                workspace_id,
                public_key: [11; 32],
                authority_event_id: authority_id,
                user_event_id: target_user_id,
            },
        );

        let err = project_signed(
            &envelope,
            &context_for(
                &record,
                vec![
                    DependencyContext {
                        event_id: workspace_id,
                        record: workspace_record,
                    },
                    DependencyContext {
                        event_id: authority_id,
                        record: authority,
                    },
                    DependencyContext {
                        event_id: target_user_id,
                        record: target_user_record,
                    },
                ],
            ),
        )
        .expect_err("cross-workspace authority must reject");

        assert_eq!(err, "admin authority belongs to a different workspace");
    }

    #[test]
    fn projects_signed_non_root_admin_when_user_public_key_matches_signed_user_dependency() {
        let authority_private_key = [94; 32];
        let authority_public_key = signer_public_key(&authority_private_key);
        let (workspace_id, workspace_record) = make_workspace_record(authority_public_key);
        let authority = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: authority_public_key,
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });
        let authority_id = event_id(&authority.canonical_bytes);
        let (user_id, user_record) = signed_user_record(workspace_id, [11; 32]);
        let (record, envelope) = signed_admin_record(
            authority_id,
            authority_private_key,
            AdminEvent {
                created_at_ms: 30,
                workspace_id,
                public_key: [11; 32],
                authority_event_id: authority_id,
                user_event_id: user_id,
            },
        );

        let output = project_signed(
            &envelope,
            &context_for(
                &record,
                vec![
                    DependencyContext {
                        event_id: authority_id,
                        record: authority,
                    },
                    DependencyContext {
                        event_id: workspace_id,
                        record: workspace_record,
                    },
                    DependencyContext {
                        event_id: user_id,
                        record: user_record,
                    },
                ],
            ),
        )
        .expect("project signed non-root admin");

        let row =
            schema::decode_admin_row(&output.rows[0].key, &output.rows[0].value).expect("row");
        assert_eq!(row.public_key, [11; 32]);
        assert_eq!(row.user_event_id, user_id);
        assert_eq!(row.authority_event_id, authority_id);
    }

    #[test]
    fn rejects_signed_non_root_admin_when_user_public_key_differs_from_user_dependency() {
        let authority_private_key = [94; 32];
        let authority_public_key = signer_public_key(&authority_private_key);
        let (workspace_id, workspace_record) = make_workspace_record(authority_public_key);
        let authority = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: authority_public_key,
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });
        let authority_id = event_id(&authority.canonical_bytes);
        let (user_id, user_record) = signed_user_record(workspace_id, [11; 32]);
        let (record, envelope) = signed_admin_record(
            authority_id,
            authority_private_key,
            AdminEvent {
                created_at_ms: 30,
                workspace_id,
                public_key: [12; 32],
                authority_event_id: authority_id,
                user_event_id: user_id,
            },
        );

        let err = project_signed(
            &envelope,
            &context_for(
                &record,
                vec![
                    DependencyContext {
                        event_id: authority_id,
                        record: authority,
                    },
                    DependencyContext {
                        event_id: workspace_id,
                        record: workspace_record,
                    },
                    DependencyContext {
                        event_id: user_id,
                        record: user_record,
                    },
                ],
            ),
        )
        .expect_err("mismatched user key must reject");

        assert_eq!(err, "admin public_key does not match user public_key");
    }

    #[test]
    fn rejects_signed_non_root_admin_when_user_belongs_to_another_workspace() {
        let authority_private_key = [94; 32];
        let authority_public_key = signer_public_key(&authority_private_key);
        let (workspace_id, workspace_record) = make_workspace_record(authority_public_key);
        let (other_workspace_id, _) = make_workspace_record([13; 32]);
        let authority = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: authority_public_key,
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });
        let authority_id = event_id(&authority.canonical_bytes);
        let (user_id, user_record) = signed_user_record(other_workspace_id, [11; 32]);
        let (record, envelope) = signed_admin_record(
            authority_id,
            authority_private_key,
            AdminEvent {
                created_at_ms: 30,
                workspace_id,
                public_key: [11; 32],
                authority_event_id: authority_id,
                user_event_id: user_id,
            },
        );

        let err = project_signed(
            &envelope,
            &context_for(
                &record,
                vec![
                    DependencyContext {
                        event_id: authority_id,
                        record: authority,
                    },
                    DependencyContext {
                        event_id: workspace_id,
                        record: workspace_record,
                    },
                    DependencyContext {
                        event_id: user_id,
                        record: user_record,
                    },
                ],
            ),
        )
        .expect_err("cross-workspace user must reject");

        assert_eq!(err, "admin user belongs to a different workspace");
    }

    #[test]
    fn projects_signed_admin_grant_from_authority_admin_key() {
        let authority_private_key = [94; 32];
        let authority_public_key = signer_public_key(&authority_private_key);
        let (workspace_id, workspace_record) = make_workspace_record(authority_public_key);
        let authority = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: authority_public_key,
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });
        let authority_id = event_id(&authority.canonical_bytes);
        let (target_user_id, target_user_record) = signed_user_record(workspace_id, [11; 32]);
        let (record, envelope) = signed_admin_record(
            authority_id,
            authority_private_key,
            AdminEvent {
                created_at_ms: 30,
                workspace_id,
                public_key: [11; 32],
                authority_event_id: authority_id,
                user_event_id: target_user_id,
            },
        );

        let output = project_signed(
            &envelope,
            &context_for(
                &record,
                vec![
                    DependencyContext {
                        event_id: workspace_id,
                        record: workspace_record,
                    },
                    DependencyContext {
                        event_id: authority_id,
                        record: authority,
                    },
                    DependencyContext {
                        event_id: target_user_id,
                        record: target_user_record,
                    },
                ],
            ),
        )
        .expect("project signed admin");

        let row =
            schema::decode_admin_row(&output.rows[0].key, &output.rows[0].value).expect("row");
        assert_eq!(row.admin_id, event_id(&record.canonical_bytes));
        assert_eq!(row.authority_event_id, authority_id);
        assert_eq!(row.user_event_id, target_user_id);
        assert_eq!(row.public_key, [11; 32]);
    }

    #[test]
    fn rejects_signed_admin_when_signer_is_not_authority_admin_id() {
        let authority_private_key = [94; 32];
        let authority_public_key = signer_public_key(&authority_private_key);
        let (workspace_id, workspace_record) = make_workspace_record(authority_public_key);
        let authority = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: authority_public_key,
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });
        let authority_id = event_id(&authority.canonical_bytes);
        let (target_user_id, target_user_record) = signed_user_record(workspace_id, [11; 32]);
        let (record, envelope) = signed_admin_record(
            [88; 32],
            authority_private_key,
            AdminEvent {
                created_at_ms: 30,
                workspace_id,
                public_key: [11; 32],
                authority_event_id: authority_id,
                user_event_id: target_user_id,
            },
        );

        let err = project_signed(
            &envelope,
            &context_for(
                &record,
                vec![
                    DependencyContext {
                        event_id: workspace_id,
                        record: workspace_record,
                    },
                    DependencyContext {
                        event_id: authority_id,
                        record: authority,
                    },
                    DependencyContext {
                        event_id: target_user_id,
                        record: target_user_record,
                    },
                ],
            ),
        )
        .expect_err("wrong signer user must reject");

        assert_eq!(err, "signed admin grant signer must be the authority admin");
    }

    #[test]
    fn rejects_signed_admin_when_signer_key_does_not_match_authority_admin() {
        let authority_private_key = [94; 32];
        let authority_public_key = signer_public_key(&authority_private_key);
        let wrong_private_key = [95; 32];
        let (workspace_id, workspace_record) = make_workspace_record(authority_public_key);
        let authority = admin_record(AdminEvent {
            created_at_ms: 20,
            workspace_id,
            public_key: authority_public_key,
            authority_event_id: workspace_id,
            user_event_id: workspace_id,
        });
        let authority_id = event_id(&authority.canonical_bytes);
        let (target_user_id, target_user_record) = signed_user_record(workspace_id, [11; 32]);
        let (record, envelope) = signed_admin_record(
            authority_id,
            wrong_private_key,
            AdminEvent {
                created_at_ms: 30,
                workspace_id,
                public_key: [11; 32],
                authority_event_id: authority_id,
                user_event_id: target_user_id,
            },
        );

        let err = project_signed(
            &envelope,
            &context_for(
                &record,
                vec![
                    DependencyContext {
                        event_id: workspace_id,
                        record: workspace_record,
                    },
                    DependencyContext {
                        event_id: authority_id,
                        record: authority,
                    },
                    DependencyContext {
                        event_id: target_user_id,
                        record: target_user_record,
                    },
                ],
            ),
        )
        .expect_err("wrong signer key must reject");

        assert_eq!(
            err,
            "signed admin signer key does not match authority admin"
        );
    }
}
