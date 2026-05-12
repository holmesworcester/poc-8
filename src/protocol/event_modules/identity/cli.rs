//! Identity CLI workflows.
//!
//! These commands are deliberately at the identity root because each workflow
//! spans several identity leaves. The leaf commands still construct the
//! canonical events; this adapter loads local authority rows, calls those
//! commands, admits the returned events through the common worker, and formats
//! operator-facing ids.

use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::crypto;
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::connection::connection_request;
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{self, CommandOutput};
use crate::workers::{connection as connection_worker, transit_in};

use super::{
    admin, device_invite, endpoint, endpoint_shared, invite, invite_accepted, invite_server, user,
    user_invite, workspace,
};

const CREATE_WORKSPACE_USAGE: &str =
    "create-workspace NAME [--username USER] [--devicename DEVICE] [--ttl-minutes N]";
const INVITE_USAGE: &str =
    "invite [--workspace WORKSPACE_ID_HEX] (--public-addr ADDR | --listen IP PORT [--accept N])";
const ACCEPT_USAGE: &str = "accept INVITE_LINK [--username USER] [--devicename DEVICE]";
const INVITE_SERVER_USAGE: &str =
    "invite-server WORKSPACE_ID_HEX (--public-addr ADDR | --listen IP PORT [--accept N])";
const ACCEPT_INVITE_SERVER_USAGE: &str = "accept-invite-server INVITE_LINK [--devicename DEVICE]";
const LINK_USAGE: &str =
    "link WORKSPACE_ID_HEX (--public-addr ADDR | --listen IP PORT [--accept N])";
const ACCEPT_LINK_USAGE: &str = "accept-link INVITE_LINK [--devicename DEVICE]";
const WORKSPACES_USAGE: &str = "workspaces";
const IDENTITY_USAGE: &str = "identity";
const CONNECT_WAIT: Duration = Duration::from_secs(2);

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "create-workspace",
            usage: CREATE_WORKSPACE_USAGE,
            help: "Create a workspace and local creator identity graph.",
            run: run_create_workspace_command,
        },
        CliCommand {
            name: "invite",
            usage: INVITE_USAGE,
            help: "Create a transport or workspace user invite.",
            run: run_invite_command,
        },
        CliCommand {
            name: "accept",
            usage: ACCEPT_USAGE,
            help: "Accept a workspace invite over real TCP.",
            run: run_accept_command,
        },
        CliCommand {
            name: "invite-server",
            usage: INVITE_SERVER_USAGE,
            help: "Create an invite-server workspace endpoint invite.",
            run: run_invite_server_command,
        },
        CliCommand {
            name: "accept-invite-server",
            usage: ACCEPT_INVITE_SERVER_USAGE,
            help: "Accept an invite-server workspace endpoint invite over real TCP.",
            run: run_accept_invite_server_command,
        },
        CliCommand {
            name: "link",
            usage: LINK_USAGE,
            help: "Create a device-link invite for the local user.",
            run: run_link_command,
        },
        CliCommand {
            name: "accept-link",
            usage: ACCEPT_LINK_USAGE,
            help: "Accept a device-link invite over real TCP.",
            run: run_accept_link_command,
        },
        CliCommand {
            name: "workspaces",
            usage: WORKSPACES_USAGE,
            help: "List joined workspaces.",
            run: run_workspaces_command,
        },
        CliCommand {
            name: "identity",
            usage: IDENTITY_USAGE,
            help: "Print local endpoint and workspace membership.",
            run: run_identity_command,
        },
    ]
}

fn run_create_workspace_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let options = CreateWorkspaceOptions::parse(args)?;
    let local = ensure_local_endpoint(context)?;
    let timestamp = next_timestamp(&context.store)?;

    let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: timestamp,
        public_key: local.signing_public_key,
        disappearing_ttl_minutes: options.disappearing_ttl_minutes,
        name: options.name,
    })?;
    let workspace_id = workspace.value.workspace_id;
    admit(context, workspace)?;

    let bootstrap = admin::commands::create_bootstrap(admin::commands::CreateBootstrapAdmin {
        created_at_ms: timestamp + 1,
        workspace_id,
        root_public_key: local.signing_public_key,
        root_user_event_id: workspace_id,
        signer_private_key: local.signing_secret,
    })?;
    let bootstrap_admin_id = bootstrap.value.admin_id;
    admit(context, bootstrap)?;

    let invite_private_key = crypto::random_ed25519_private_key();
    let user_invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: timestamp + 2,
        public_key: crypto::ed25519_public_key(&invite_private_key),
        workspace_id,
        authority_event_id: workspace_id,
        signer_event_id: workspace_id,
        signer_private_key: local.signing_secret,
    })?;
    let user_invite_id = user_invite.value.user_invite_id;
    admit(context, user_invite)?;

    let user = user::commands::create(user::commands::CreateUser {
        created_at_ms: timestamp + 3,
        workspace_id,
        public_key: local.signing_public_key,
        username: options.username,
        user_invite_event_id: user_invite_id,
        user_invite_private_key: invite_private_key,
    })?;
    let user_id = user.value.user_id;
    admit(context, user)?;

    let endpoint_join = create_endpoint_join(
        context,
        EndpointJoinInput {
            timestamp: timestamp + 4,
            workspace_id,
            user_id,
            user_invite_id: Some(user_invite_id),
            signer_event_id: user_id,
            signer_private_key: local.signing_secret,
            device_name: options.device_name,
        },
    )?;

    let creator_admin = admin::commands::sign_grant(admin::commands::SignGrantAdmin {
        grant: admin::commands::GrantAdmin {
            created_at_ms: timestamp + 6,
            workspace_id,
            authority_admin_id: bootstrap_admin_id,
            target_user_event_id: user_id,
            target_user_public_key: local.signing_public_key,
        },
        signer_event_id: bootstrap_admin_id,
        signer_private_key: local.signing_secret,
    })?;
    let admin_id = creator_admin.value.signed_event_id;
    admit(context, creator_admin)?;

    Ok(CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex(&workspace_id)),
        format!("user_id: {}", encode_hex(&user_id)),
        format!("endpoint_id: {}", encode_hex(&local.endpoint)),
        format!(
            "endpoint_shared_id: {}",
            encode_hex(&endpoint_join.endpoint_shared_id)
        ),
        format!("admin_id: {}", encode_hex(&admin_id)),
    ]))
}

fn run_invite_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let options = InviteOptions::parse(args, INVITE_USAGE)?;
    let local = ensure_local_endpoint(context)?;
    let public_addr = options.public_addr();
    let invite_link = if let Some(workspace_id) = options.workspace_id {
        create_user_invite_link(context, local, workspace_id, public_addr)?
    } else {
        let output = invite::commands::create(local, public_addr);
        worker::run(&context.store, &context.protocol, output)
            .map_err(|err| format!("apply invite: {err}"))?
            .0
    };
    maybe_listen(context, options.listen, &invite_link)
}

fn run_accept_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let options = AcceptOptions::parse(args, ACCEPT_USAGE)?;
    let invite = invite::commands::parse(&options.invite)?;
    if !invite.identity_scope {
        let connected = connect_invite(context, &options.invite)?;
        return Ok(CliOutput::line(format!("connected: {}", connected.addr)));
    }
    if invite.endpoint_role != endpoint::types::EndpointRole::Device {
        return Err("accept requires a user invite".to_string());
    }
    if let Some(local) = endpoint::commands::local_keypair(&context.store)? {
        reject_duplicate_join(&context.store, local.endpoint, invite.workspace_id)?;
    }
    let local = ensure_local_endpoint(context)?;
    let accepted_endpoint_id = local.endpoint;
    let timestamp = next_timestamp(&context.store)?;
    let user = user::commands::create(user::commands::CreateUser {
        created_at_ms: timestamp,
        workspace_id: invite.workspace_id,
        public_key: local.signing_public_key,
        username: options.username,
        user_invite_event_id: invite.invite_event_id,
        user_invite_private_key: invite.bootstrap_secret,
    })?;
    let user_id = user.value.user_id;

    let endpoint_join = prepare_endpoint_join(
        &context.store,
        local,
        EndpointJoinInput {
            timestamp: timestamp + 1,
            workspace_id: invite.workspace_id,
            user_id,
            user_invite_id: Some(invite.invite_event_id),
            signer_event_id: user_id,
            signer_private_key: local.signing_secret,
            device_name: options.device_name,
        },
    )?;
    let mut proposed = user.events;
    proposed.extend(endpoint_join.events);
    let connected = connect_invite(context, &options.invite)?;
    record_invite_acceptance(context, &invite, accepted_endpoint_id)?;
    admit_proposed_events(context, proposed)?;

    Ok(CliOutput::lines(vec![
        format!("connected: {}", connected.addr),
        format!("workspace_id: {}", encode_hex(&invite.workspace_id)),
        format!("user_id: {}", encode_hex(&user_id)),
        format!(
            "endpoint_shared_id: {}",
            encode_hex(&endpoint_join.endpoint_shared_id)
        ),
    ]))
}

fn run_invite_server_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let options = InviteServerOptions::parse(args)?;
    let local = ensure_local_endpoint(context)?;
    let membership = local_membership(&context.store, local.endpoint, options.workspace_id)?;
    let authority_admin_id = admin_for_user(
        &context.store,
        options.workspace_id,
        membership.user_authority_event_id,
    )?
    .ok_or_else(|| "local user is not an admin in this workspace".to_string())?;
    let invite_private_key = crypto::random_ed25519_private_key();
    let output = invite_server::commands::create(invite_server::commands::CreateInviteServer {
        created_at_ms: next_timestamp(&context.store)?,
        public_key: crypto::ed25519_public_key(&invite_private_key),
        workspace_id: options.workspace_id,
        authority_event_id: authority_admin_id,
        signer_event_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
    })?;
    let invite_server_id = output.value.invite_server_id;
    admit(context, output)?;
    let scoped = invite::commands::create_scoped_with_role(
        local,
        options.public_addr(),
        options.workspace_id,
        invite_server_id,
        invite_private_key,
        endpoint::types::EndpointRole::InviteServer,
        None,
    );
    let link = worker::run(&context.store, &context.protocol, scoped)
        .map_err(|err| format!("apply invite-server secret: {err}"))?
        .0;
    maybe_listen(context, options.listen, &link)
}

fn run_accept_invite_server_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let options = AcceptInviteServerOptions::parse(args)?;
    let invite = invite::commands::parse(&options.invite)?;
    if !invite.identity_scope || invite.endpoint_role != endpoint::types::EndpointRole::InviteServer
    {
        return Err("accept-invite-server requires an invite-server identity invite".to_string());
    }
    if invite.user_authority_event_id.is_some() {
        return Err("invite-server invite must not carry USER_ID".to_string());
    }
    if let Some(local) = endpoint::commands::local_keypair(&context.store)? {
        reject_duplicate_join(&context.store, local.endpoint, invite.workspace_id)?;
    }
    let local = ensure_local_endpoint(context)?;
    let shared = endpoint_shared::commands::share_endpoint(
        &context.store,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: next_timestamp(&context.store)?,
            workspace_id: invite.workspace_id,
            user_authority_event_id: invite.invite_event_id,
            endpoint_id: local.endpoint,
            signing_public_key: local.signing_public_key,
            endpoint_role: endpoint::types::EndpointRole::InviteServer,
            device_name: options.device_name,
            device_invite_id: invite.invite_event_id,
            device_invite_private_key: invite.bootstrap_secret,
        },
    )?;
    let endpoint_shared_id = shared.value.endpoint_shared_id;
    let connected = connect_invite(context, &options.invite)?;
    record_invite_acceptance(context, &invite, local.endpoint)?;
    admit(context, shared)?;
    Ok(CliOutput::lines(vec![
        format!("connected: {}", connected.addr),
        format!("workspace_id: {}", encode_hex(&invite.workspace_id)),
        format!("endpoint_shared_id: {}", encode_hex(&endpoint_shared_id)),
        "endpoint_role: invite-server".to_string(),
    ]))
}

fn run_link_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let options = LinkOptions::parse(args)?;
    let local = ensure_local_endpoint(context)?;
    let membership = local_membership(&context.store, local.endpoint, options.workspace_id)?;
    let device_invite_private_key = crypto::random_ed25519_private_key();
    let timestamp = next_timestamp(&context.store)?;
    let device = device_invite::commands::create_with_private_key(
        device_invite::commands::CreateDeviceInvite {
            created_at_ms: timestamp,
            workspace_id: options.workspace_id,
            user_authority_event_id: membership.user_authority_event_id,
            user_invite_event_id: None,
            signer_event_id: membership.endpoint_shared_id,
            signer_private_key: local.signing_secret,
        },
        device_invite_private_key,
    )?;
    let device_invite_id = device.value.device_invite_id;
    admit(context, device)?;
    let scoped = invite::commands::create_scoped_with_user_authority(
        local,
        options.public_addr(),
        options.workspace_id,
        device_invite_id,
        device_invite_private_key,
        Some(membership.user_authority_event_id),
    );
    let link = worker::run(&context.store, &context.protocol, scoped)
        .map_err(|err| format!("apply device link secret: {err}"))?
        .0;
    maybe_listen(context, options.listen, &link)
}

fn run_accept_link_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let options = AcceptLinkOptions::parse(args)?;
    let invite = invite::commands::parse(&options.invite)?;
    if !invite.identity_scope {
        return Err("accept-link requires an identity invite".to_string());
    }
    if invite.endpoint_role != endpoint::types::EndpointRole::Device {
        return Err("accept-link requires a device-link invite".to_string());
    }
    let user_authority_event_id = invite
        .user_authority_event_id
        .ok_or_else(|| "device link is missing USER_ID".to_string())?;
    if let Some(local) = endpoint::commands::local_keypair(&context.store)? {
        reject_duplicate_join(&context.store, local.endpoint, invite.workspace_id)?;
    }
    let local = ensure_local_endpoint(context)?;
    let shared = endpoint_shared::commands::share_endpoint(
        &context.store,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: next_timestamp(&context.store)?,
            workspace_id: invite.workspace_id,
            user_authority_event_id,
            endpoint_id: local.endpoint,
            signing_public_key: local.signing_public_key,
            endpoint_role: endpoint::types::EndpointRole::Device,
            device_name: options.device_name,
            device_invite_id: invite.invite_event_id,
            device_invite_private_key: invite.bootstrap_secret,
        },
    )?;
    let endpoint_shared_id = shared.value.endpoint_shared_id;
    let connected = connect_invite(context, &options.invite)?;
    record_invite_acceptance(context, &invite, local.endpoint)?;
    admit(context, shared)?;
    Ok(CliOutput::lines(vec![
        format!("connected: {}", connected.addr),
        format!("workspace_id: {}", encode_hex(&invite.workspace_id)),
        format!("endpoint_shared_id: {}", encode_hex(&endpoint_shared_id)),
    ]))
}

fn run_workspaces_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, WORKSPACES_USAGE)?;
    let local = ensure_local_endpoint(context)?;
    let mut lines = Vec::new();
    for workspace_id in
        endpoint_shared::schema::workspace_ids_for_endpoint(&context.store, local.endpoint)?
    {
        let row = workspace_row(&context.store, workspace_id)?;
        lines.push(format!("{} {}", encode_hex(&row.workspace_id), row.name));
    }
    Ok(CliOutput::lines(lines))
}

fn run_identity_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, IDENTITY_USAGE)?;
    let local = ensure_local_endpoint(context)?;
    let mut lines = vec![
        format!("endpoint_id: {}", encode_hex(&local.endpoint)),
        format!(
            "signing_public_key: {}",
            encode_hex(&local.signing_public_key)
        ),
    ];
    for workspace_id in
        endpoint_shared::schema::workspace_ids_for_endpoint(&context.store, local.endpoint)?
    {
        let membership = local_membership(&context.store, local.endpoint, workspace_id)?;
        let workspace = workspace_row(&context.store, workspace_id)?;
        lines.push(format!(
            "workspace: {} {} user_id={} endpoint_shared_id={} endpoint_role={}",
            encode_hex(&workspace_id),
            workspace.name,
            encode_hex(&membership.user_authority_event_id),
            encode_hex(&membership.endpoint_shared_id),
            membership.endpoint_role.as_str()
        ));
    }
    Ok(CliOutput::lines(lines))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreateWorkspaceOptions {
    name: String,
    username: String,
    device_name: String,
    disappearing_ttl_minutes: u32,
}

impl CreateWorkspaceOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let name = args
            .get(0)
            .ok_or_else(|| CREATE_WORKSPACE_USAGE.to_string())?
            .to_string();
        let mut username = "admin".to_string();
        let mut device_name = "device".to_string();
        let mut disappearing_ttl_minutes: u32 = 0;
        let mut idx = 1;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
                "--username" => {
                    username = args
                        .get(idx + 1)
                        .ok_or_else(|| CREATE_WORKSPACE_USAGE.to_string())?
                        .to_string();
                    idx += 2;
                }
                "--devicename" => {
                    device_name = args
                        .get(idx + 1)
                        .ok_or_else(|| CREATE_WORKSPACE_USAGE.to_string())?
                        .to_string();
                    idx += 2;
                }
                "--ttl-minutes" => {
                    let raw = args
                        .get(idx + 1)
                        .ok_or_else(|| CREATE_WORKSPACE_USAGE.to_string())?;
                    disappearing_ttl_minutes = raw.parse::<u32>().map_err(|_| {
                        format!("--ttl-minutes must be a u32: `{raw}`\n{CREATE_WORKSPACE_USAGE}")
                    })?;
                    idx += 2;
                }
                other => {
                    return Err(format!(
                        "unknown create-workspace option `{other}`\n{CREATE_WORKSPACE_USAGE}"
                    ));
                }
            }
        }
        Ok(Self {
            name,
            username,
            device_name,
            disappearing_ttl_minutes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenMode {
    Print {
        public_addr: SocketAddr,
    },
    Listen {
        listen: SocketAddr,
        accept_count: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InviteOptions {
    workspace_id: Option<EventId>,
    listen: ListenMode,
}

impl InviteOptions {
    fn parse(args: CliArgs<'_>, usage: &'static str) -> Result<Self, String> {
        let (workspace_id, listen) = parse_workspace_and_listen(args, true, usage)?;
        Ok(Self {
            workspace_id,
            listen,
        })
    }

    fn public_addr(self) -> SocketAddr {
        public_addr(self.listen)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinkOptions {
    workspace_id: EventId,
    listen: ListenMode,
}

impl LinkOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let workspace_id = decode_hex_32(
            args.get(0).ok_or_else(|| LINK_USAGE.to_string())?,
            LINK_USAGE,
        )?;
        let tail = CliArgs::new(&args.values()[1..]);
        let (_, listen) = parse_workspace_and_listen(tail, false, LINK_USAGE)?;
        Ok(Self {
            workspace_id,
            listen,
        })
    }

    fn public_addr(self) -> SocketAddr {
        public_addr(self.listen)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptOptions {
    invite: String,
    username: String,
    device_name: String,
}

impl AcceptOptions {
    fn parse(args: CliArgs<'_>, usage: &'static str) -> Result<Self, String> {
        let invite = args.get(0).ok_or_else(|| usage.to_string())?.to_string();
        let mut username = "user".to_string();
        let mut device_name = "device".to_string();
        let mut idx = 1;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
                "--username" => {
                    username = args
                        .get(idx + 1)
                        .ok_or_else(|| usage.to_string())?
                        .to_string();
                    idx += 2;
                }
                "--devicename" => {
                    device_name = args
                        .get(idx + 1)
                        .ok_or_else(|| usage.to_string())?
                        .to_string();
                    idx += 2;
                }
                other => return Err(format!("unknown accept option `{other}`\n{usage}")),
            }
        }
        Ok(Self {
            invite,
            username,
            device_name,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InviteServerOptions {
    workspace_id: EventId,
    listen: ListenMode,
}

impl InviteServerOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let workspace_id = decode_hex_32(
            args.get(0).ok_or_else(|| INVITE_SERVER_USAGE.to_string())?,
            INVITE_SERVER_USAGE,
        )?;
        let tail = CliArgs::new(&args.values()[1..]);
        let (_, listen) = parse_workspace_and_listen(tail, false, INVITE_SERVER_USAGE)?;
        Ok(Self {
            workspace_id,
            listen,
        })
    }

    fn public_addr(self) -> SocketAddr {
        public_addr(self.listen)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptInviteServerOptions {
    invite: String,
    device_name: String,
}

impl AcceptInviteServerOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let invite = args
            .get(0)
            .ok_or_else(|| ACCEPT_INVITE_SERVER_USAGE.to_string())?
            .to_string();
        let mut device_name = "invite-server".to_string();
        let mut idx = 1;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
                "--devicename" => {
                    device_name = args
                        .get(idx + 1)
                        .ok_or_else(|| ACCEPT_INVITE_SERVER_USAGE.to_string())?
                        .to_string();
                    idx += 2;
                }
                other => {
                    return Err(format!(
                        "unknown accept-invite-server option `{other}`\n{ACCEPT_INVITE_SERVER_USAGE}"
                    ));
                }
            }
        }
        Ok(Self {
            invite,
            device_name,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptLinkOptions {
    invite: String,
    device_name: String,
}

impl AcceptLinkOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let invite = args
            .get(0)
            .ok_or_else(|| ACCEPT_LINK_USAGE.to_string())?
            .to_string();
        let mut device_name = "device".to_string();
        let mut idx = 1;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
                "--devicename" => {
                    device_name = args
                        .get(idx + 1)
                        .ok_or_else(|| ACCEPT_LINK_USAGE.to_string())?
                        .to_string();
                    idx += 2;
                }
                other => {
                    return Err(format!(
                        "unknown accept-link option `{other}`\n{ACCEPT_LINK_USAGE}"
                    ));
                }
            }
        }
        Ok(Self {
            invite,
            device_name,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointJoinInput {
    timestamp: u64,
    workspace_id: EventId,
    user_id: EventId,
    user_invite_id: Option<EventId>,
    signer_event_id: EventId,
    signer_private_key: [u8; 32],
    device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointJoinOutput {
    device_invite_id: EventId,
    endpoint_shared_id: EventId,
    events: Vec<worker::ProposedEvent>,
}

fn parse_workspace_and_listen(
    args: CliArgs<'_>,
    allow_workspace_flag: bool,
    usage: &'static str,
) -> Result<(Option<EventId>, ListenMode), String> {
    let mut workspace_id = None;
    let mut public_addr = None;
    let mut listen = None;
    let mut accept_count = 1usize;
    let mut idx = 0;
    while idx < args.values().len() {
        match args.get(idx).expect("index in bounds") {
            "--workspace" if allow_workspace_flag => {
                workspace_id = Some(decode_hex_32(
                    args.get(idx + 1).ok_or_else(|| usage.to_string())?,
                    usage,
                )?);
                idx += 2;
            }
            "--public-addr" => {
                public_addr = Some(
                    args.get(idx + 1)
                        .ok_or_else(|| usage.to_string())?
                        .parse::<SocketAddr>()
                        .map_err(|_| usage.to_string())?,
                );
                idx += 2;
            }
            "--listen" => {
                let ip = args.get(idx + 1).ok_or_else(|| usage.to_string())?;
                let port = args.get(idx + 2).ok_or_else(|| usage.to_string())?;
                listen = Some(
                    format!("{ip}:{port}")
                        .parse::<SocketAddr>()
                        .map_err(|_| usage.to_string())?,
                );
                idx += 3;
            }
            "--accept" => {
                accept_count = args.parse_positive_usize(idx + 1, usage)?;
                idx += 2;
            }
            other => return Err(format!("unknown invite option `{other}`\n{usage}")),
        }
    }
    let listen = match (public_addr, listen) {
        (Some(public_addr), None) => ListenMode::Print { public_addr },
        (None, Some(listen)) => ListenMode::Listen {
            listen,
            accept_count,
        },
        _ => return Err(usage.to_string()),
    };
    Ok((workspace_id, listen))
}

fn public_addr(listen: ListenMode) -> SocketAddr {
    match listen {
        ListenMode::Print { public_addr } => public_addr,
        ListenMode::Listen { listen, .. } => listen,
    }
}

fn maybe_listen(
    context: &mut Context,
    listen: ListenMode,
    link: &str,
) -> Result<CliOutput, String> {
    match listen {
        ListenMode::Print { .. } => Ok(CliOutput::line(link.to_string())),
        ListenMode::Listen {
            listen,
            accept_count,
        } => {
            print_line_now(link)?;
            let output = transit_in::run(
                &context.store,
                &context.protocol,
                Some(context.protocol.sync_index()),
                transit_in::Work::Serve {
                    listen,
                    accept_count,
                },
            )?;
            let transit_in::Output::Served(report) = output else {
                return Err("transit_in worker returned non-serve output".to_string());
            };
            Ok(CliOutput::lines(serve_lines(&report)))
        }
    }
}

fn connect_invite(context: &mut Context, link: &str) -> Result<ConnectReport, String> {
    // Read the running daemon's bound listener (if any) from the core-owned
    // lock file so the request body can advertise it to the peer. CLI
    // processes that run alongside no daemon get `None` here, which is the
    // correct signal for "do not advertise a listener route".
    let from_listen_addr = crate::core::daemon::current_listen_addr(&context.db_path)?;
    let output =
        connection_request::commands::create_with_local(&context.store, link, from_listen_addr)?;
    let (request, _) = worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("record connection request: {err}"))?;
    let report = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::DrainUntilConnected {
            request_id: request.request_id,
            timeout: CONNECT_WAIT,
            fail_on_route_error: true,
        },
    )?;
    Ok(ConnectReport {
        addr: request.addr,
        sent_events: report.sent_events,
        received_events: 0,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectReport {
    addr: SocketAddr,
    sent_events: usize,
    received_events: usize,
}

fn create_user_invite_link(
    context: &mut Context,
    local: endpoint::types::EndpointKeypair,
    workspace_id: EventId,
    public_addr: SocketAddr,
) -> Result<String, String> {
    let membership = local_membership(&context.store, local.endpoint, workspace_id)?;
    let authority_admin_id = admin_for_user(
        &context.store,
        workspace_id,
        membership.user_authority_event_id,
    )?
    .ok_or_else(|| "local user is not an admin in this workspace".to_string())?;
    let invite_private_key = crypto::random_ed25519_private_key();
    let output = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: next_timestamp(&context.store)?,
        public_key: crypto::ed25519_public_key(&invite_private_key),
        workspace_id,
        authority_event_id: authority_admin_id,
        signer_event_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
    })?;
    let user_invite_id = output.value.user_invite_id;
    admit(context, output)?;
    let scoped = invite::commands::create_scoped(
        local,
        public_addr,
        workspace_id,
        user_invite_id,
        invite_private_key,
    );
    worker::run(&context.store, &context.protocol, scoped)
        .map_err(|err| format!("apply user invite secret: {err}"))
        .map(|(link, _)| link)
}

fn create_endpoint_join(
    context: &mut Context,
    input: EndpointJoinInput,
) -> Result<EndpointJoinOutput, String> {
    let local = ensure_local_endpoint(context)?;
    let output = prepare_endpoint_join(&context.store, local, input)?;
    admit_proposed_events(context, output.events.clone())?;
    Ok(output)
}

fn prepare_endpoint_join(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
    input: EndpointJoinInput,
) -> Result<EndpointJoinOutput, String> {
    let device = device_invite::commands::create(device_invite::commands::CreateDeviceInvite {
        created_at_ms: input.timestamp,
        workspace_id: input.workspace_id,
        user_authority_event_id: input.user_id,
        user_invite_event_id: input.user_invite_id,
        signer_event_id: input.signer_event_id,
        signer_private_key: input.signer_private_key,
    })?;
    let device_invite_id = device.value.device_invite_id;
    let device_invite_private_key = device.value.keypair.private_key;

    let shared = endpoint_shared::commands::share_endpoint(
        store,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: input.timestamp + 1,
            workspace_id: input.workspace_id,
            user_authority_event_id: input.user_id,
            endpoint_id: local.endpoint,
            signing_public_key: local.signing_public_key,
            endpoint_role: endpoint::types::EndpointRole::Device,
            device_name: input.device_name,
            device_invite_id,
            device_invite_private_key,
        },
    )?;
    let endpoint_shared_id = shared.value.endpoint_shared_id;
    let mut events = device.events;
    events.extend(shared.events);
    Ok(EndpointJoinOutput {
        device_invite_id,
        endpoint_shared_id,
        events,
    })
}

fn ensure_local_endpoint(
    context: &mut Context,
) -> Result<endpoint::types::EndpointKeypair, String> {
    let output = endpoint::commands::local_or_create(&context.store)?;
    let local = output.value;
    if !output.events.is_empty() {
        worker::run(&context.store, &context.protocol, output)
            .map_err(|err| format!("apply local endpoint: {err}"))?;
    }
    Ok(local)
}

fn record_invite_acceptance(
    context: &mut Context,
    invite: &invite::types::Invite,
    accepted_endpoint_id: endpoint::types::EndpointId,
) -> Result<(), String> {
    let output = invite_accepted::commands::accept(invite_accepted::commands::AcceptInvite {
        accepted_endpoint_id,
        bootstrap_secret: invite.bootstrap_secret,
        addr: invite.addr,
        workspace_id: invite.workspace_id,
        invite_event_id: invite.invite_event_id,
    })?;
    admit(context, output).map(|_| ())
}

fn reject_duplicate_join(
    store: &Store,
    endpoint_id: endpoint::types::EndpointId,
    workspace_id: EventId,
) -> Result<(), String> {
    if store
        .table_row(
            endpoint_shared::schema::ENDPOINT_MEMBERSHIPS,
            &endpoint_shared::schema::endpoint_membership_key(endpoint_id, workspace_id),
        )
        .map_err(|err| format!("load endpoint membership: {err}"))?
        .is_some()
    {
        return Err("endpoint is already joined to workspace".to_string());
    }
    let mut accepted_prefix = Vec::with_capacity(64);
    accepted_prefix.extend_from_slice(&endpoint_id);
    accepted_prefix.extend_from_slice(&workspace_id);
    if !store
        .table_rows_with_key_prefix(
            invite_accepted::schema::INVITES_ACCEPTED,
            &accepted_prefix,
            1,
        )
        .map_err(|err| format!("load accepted invites: {err}"))?
        .is_empty()
    {
        return Err("endpoint is already joined to workspace".to_string());
    }
    Ok(())
}

fn local_membership(
    store: &Store,
    endpoint_id: endpoint::types::EndpointId,
    workspace_id: EventId,
) -> Result<endpoint_shared::types::EndpointMembershipRow, String> {
    let key = endpoint_shared::schema::endpoint_membership_key(endpoint_id, workspace_id);
    let value = store
        .table_row(endpoint_shared::schema::ENDPOINT_MEMBERSHIPS, &key)
        .map_err(|err| format!("load endpoint membership: {err}"))?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    endpoint_shared::schema::decode_endpoint_membership_row(&key, &value)
}

fn workspace_row(
    store: &Store,
    workspace_id: EventId,
) -> Result<workspace::types::WorkspaceRow, String> {
    let value = store
        .table_row(workspace::schema::WORKSPACES, &workspace_id)
        .map_err(|err| format!("load workspace: {err}"))?
        .ok_or_else(|| "workspace row is missing".to_string())?;
    workspace::schema::decode_workspace_row(&workspace_id, &value)
}

fn admin_for_user(
    store: &Store,
    workspace_id: EventId,
    user_id: EventId,
) -> Result<Option<EventId>, String> {
    for (key, value) in store
        .table_rows_with_key_prefix(admin::schema::ADMINS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load admins: {err}"))?
    {
        let row = admin::schema::decode_admin_row(&key, &value)?;
        if row.user_event_id == user_id {
            return Ok(Some(row.admin_id));
        }
    }
    Ok(None)
}

fn next_timestamp(store: &Store) -> Result<u64, String> {
    let max_timestamp =
        event_schema::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
    logical_clock::next_timestamp(store, max_timestamp)
}

fn admit<T>(context: &mut Context, output: CommandOutput<T>) -> Result<T, String> {
    worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("apply identity event: {err}"))
        .map(|(value, _)| value)
}

fn admit_proposed_events(
    context: &mut Context,
    events: Vec<worker::ProposedEvent>,
) -> Result<(), String> {
    admit(context, CommandOutput::with_proposed_events((), events))
}

fn serve_lines(report: &transit_in::ServeReport) -> Vec<String> {
    let mut lines = vec![format!("listening: {}", report.local_addr)];
    lines.extend([
        format!("accepted_connections: {}", report.accepted_connections),
        format!("received_events: {}", report.received_events),
    ]);
    lines
}

fn print_line_now(line: &str) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{line}").map_err(|err| format!("write invite link: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("flush invite link: {err}"))
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    invite::commands::encode_hex(bytes)
}

fn decode_hex_32(value: &str, usage: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(usage.to_string());
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for idx in 0..32 {
        out[idx] = (hex_value(bytes[idx * 2], usage)? << 4) | hex_value(bytes[idx * 2 + 1], usage)?;
    }
    Ok(out)
}

fn hex_value(byte: u8, usage: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(usage.to_string()),
    }
}
