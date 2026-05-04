use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn event_modules_root(root: &Path) -> PathBuf {
    root.join("src/protocol/event_modules")
}

fn core_root(root: &Path) -> PathBuf {
    root.join("src/core")
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files
}

fn rust_files_named(root: &Path, file_name: &str) -> Vec<PathBuf> {
    rust_files(root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == file_name))
        .collect()
}

fn file_contains_violations(root: &Path, files: &[PathBuf], forbidden: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(path).expect("read rust file");
        let relative = path.strip_prefix(root).unwrap_or(path);
        for needle in forbidden {
            if text.contains(needle) {
                violations.push(format!("{} contains {needle}", relative.display()));
            }
        }
    }
    violations
}

struct ForbiddenRule {
    name: &'static str,
    files: Vec<PathBuf>,
    forbidden: Vec<&'static str>,
    message: &'static str,
}

fn repo_paths(root: &Path, files: &[&str]) -> Vec<PathBuf> {
    files.iter().map(|file| root.join(file)).collect()
}

fn assert_forbidden_rule(root: &Path, rule: ForbiddenRule) {
    let violations = file_contains_violations(root, &rule.files, &rule.forbidden);
    assert!(
        violations.is_empty(),
        "rule `{}` failed: {}\n{}",
        rule.name,
        rule.message,
        violations.join("\n")
    );
}

fn assert_forbidden_rules(root: &Path, rules: Vec<ForbiddenRule>) {
    for rule in rules {
        assert_forbidden_rule(root, rule);
    }
}

fn source_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn public_free_function_names(text: &str) -> Vec<String> {
    let mut depth = 0_i32;
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if depth == 0 && trimmed.starts_with("pub fn ") {
            let name = trimmed
                .trim_start_matches("pub fn ")
                .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .next()
                .unwrap_or_default()
                .to_string();
            names.push(name);
        }
        depth += line.chars().filter(|ch| *ch == '{').count() as i32;
        depth -= line.chars().filter(|ch| *ch == '}').count() as i32;
    }
    names
}

#[test]
fn event_modules_do_not_use_event_rs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let offenders = rust_files(&root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "event.rs"))
        .collect::<Vec<_>>();
    assert!(offenders.is_empty(), "event.rs is forbidden: {offenders:?}");
}

#[test]
fn event_modules_are_directories() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let offenders = std::fs::read_dir(root)
        .expect("read event modules")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| {
            path.file_name()
                .is_none_or(|name| name != "mod.rs" && name != "worker.rs" && name != "tables.rs")
                && path.file_name().is_none_or(|name| name != "types.rs")
        })
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "event modules must be directories: {offenders:?}"
    );
}

#[test]
fn core_file_set_stays_small_and_named() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core");
    let allowed = [
        "crux_runner.rs",
        "mod.rs",
        "network_queues.rs",
        "store.rs",
        "tcp.rs",
    ];
    let offenders = std::fs::read_dir(&root)
        .expect("read core")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| {
            path.is_dir()
                || !path
                    .file_name()
                    .is_some_and(|name| name.to_str().is_some_and(|name| allowed.contains(&name)))
        })
        .map(|path| path.strip_prefix(&root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "core should stay tiny and queue/storage-oriented; add protocol/domain behavior outside src/core:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn protocol_app_layer_does_not_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !root.join("src/protocol/app").exists(),
        "protocol/app is forbidden; CLI behavior belongs in scoped cli.rs files and Crux stays isolated in core"
    );
}

#[test]
fn domain_roots_contain_only_children_and_shared_domain_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let allowed_domain_files = [
        "mod.rs",
        "worker.rs",
        "tables.rs",
        "queries.rs",
        "types.rs",
        "cli.rs",
    ];
    let mut offenders = Vec::new();
    for domain in std::fs::read_dir(&root).expect("read event modules") {
        let path = domain.expect("dir entry").path();
        if !path.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&path).expect("read domain module") {
            let candidate = entry.expect("dir entry").path();
            if candidate.is_file()
                && !candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| allowed_domain_files.contains(&name))
            {
                offenders.push(candidate.strip_prefix(&root).unwrap().display().to_string());
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "domain roots may contain only shared domain files; put leaf commands/codecs/projectors in child event modules:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn event_module_files_use_only_standard_concern_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let allowed = [
        "cli.rs",
        "codec.rs",
        "commands.rs",
        "crypto.rs",
        "mod.rs",
        "projector.rs",
        "queries.rs",
        "registry_meta.rs",
        "tables.rs",
        "types.rs",
        "worker.rs",
    ];
    let offenders = rust_files(&event_root)
        .into_iter()
        .filter(|path| {
            !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| allowed.contains(&name))
        })
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "event modules use fixed concern filenames; split unusual concerns deliberately:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn child_event_module_directories_have_canonical_shape() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let mut offenders = Vec::new();
    for domain in std::fs::read_dir(&root).expect("read event modules") {
        let domain = domain.expect("dir entry").path();
        if !domain.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&domain).expect("read domain") {
            let child = entry.expect("dir entry").path();
            if !child.is_dir() {
                continue;
            }
            for required in ["mod.rs", "types.rs", "codec.rs", "tables.rs"] {
                if !child.join(required).exists() {
                    offenders.push(format!(
                        "{}/{}",
                        child.strip_prefix(&root).unwrap().display(),
                        required
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "child directories under event_modules are canonical event modules; shared tables/queues belong at the domain root:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn event_modules_do_not_use_dumping_ground_directories() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let forbidden = ["jobs", "cli_commands", "runtime", "state", "negentropy"];
    let mut offenders = Vec::new();
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read event module dir") {
            let path = entry.expect("dir entry").path();
            if !path.is_dir() {
                continue;
            }
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| forbidden.contains(&name))
            {
                offenders.push(path.strip_prefix(&root).unwrap().display().to_string());
            }
            pending.push(path);
        }
    }

    assert!(
        offenders.is_empty(),
        "event modules should be organized by domain/event type, not dumping-ground directories:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn worker_files_live_at_event_module_scope_roots() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut offenders = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "worker.rs"))
    {
        let parent = path.parent().expect("worker parent");
        let is_event_modules_scope = parent == event_root.as_path();
        let is_domain_scope = parent.parent() == Some(event_root.as_path());
        if !is_event_modules_scope && !is_domain_scope {
            offenders.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "workers live at event_modules/worker.rs or event_modules/<domain>/worker.rs, not inside leaf event modules:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn active_components_are_named_worker() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let protocol_root = root.join("src/protocol");
    let forbidden_paths = [
        protocol_root.join("workers.rs"),
        protocol_root.join("worker.rs"),
        protocol_root.join("actors.rs"),
        protocol_root.join("pipeline.rs"),
    ];
    let mut offenders = forbidden_paths
        .into_iter()
        .filter(|path| path.exists())
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();
    offenders.extend(
        rust_files(&protocol_root)
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name == "actor.rs" || name == "pipeline.rs")
            })
            .map(|path| path.strip_prefix(root).unwrap().display().to_string()),
    );
    offenders.sort();
    offenders.dedup();

    assert!(
        offenders.is_empty(),
        "active protocol components are worker.rs at the owning scope; do not add actor/pipeline files or protocol-root workers:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn worker_files_export_only_run_as_public_entrypoint() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut offenders = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "worker.rs"))
    {
        let names = public_free_function_names(&source_text(&path));
        if names != ["run"] {
            offenders.push(format!(
                "{} exports public free functions {:?}",
                path.strip_prefix(root).unwrap().display(),
                names
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "worker.rs files expose one obvious public entrypoint, run(); helpers stay private:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn codec_files_use_shared_binary_helpers_and_finish_reads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut violations = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "codec.rs"))
    {
        let text = source_text(&path);
        let relative = path.strip_prefix(root).unwrap().display();
        let manual_parse_needles = [
            ".copy_from_slice(&bytes[",
            "from_be_bytes(",
            "bytes.len() <",
            "bytes.len() !=",
        ];
        if manual_parse_needles
            .iter()
            .any(|needle| text.contains(needle))
            && !text.contains("Reader::new")
        {
            violations.push(format!("{relative} parses bytes without Reader"));
        }
        if text.contains("Reader::new") && !text.contains(".finish()?") {
            violations.push(format!("{relative} uses Reader without finish"));
        }
    }

    assert!(
        violations.is_empty(),
        "codec.rs should use shared fixed-field binary helpers and reject trailing bytes:\n{}",
        violations.join("\n")
    );
}

#[test]
fn codec_modules_have_type_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let mut offenders = Vec::new();
    for codec in rust_files(&root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "codec.rs"))
    {
        let types = codec.with_file_name("types.rs");
        if !types.exists() {
            offenders.push(codec.strip_prefix(&root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "modules with codec.rs must define semantic shapes in sibling types.rs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn forbidden_vocabulary_boundaries_hold() {
    let root = repo_root();
    let event_root = event_modules_root(&root);
    let core_root = core_root(&root);
    let this_file = root
        .join("tests/rules_boundary_test.rs")
        .canonicalize()
        .ok();

    assert_forbidden_rules(
        &root,
        vec![
            ForbiddenRule {
                name: "codec_files_do_not_define_public_types",
                files: rust_files_named(&event_root, "codec.rs"),
                forbidden: vec!["pub struct ", "pub enum ", "pub type "],
                message: "event module semantic types belong in types.rs; codec.rs is encode/decode only",
            },
            ForbiddenRule {
                name: "cli_harness_is_process_only",
                files: repo_paths(&root, &["tests/cli_harness/mod.rs"]),
                forbidden: vec![
                    "--db",
                    "\"invite\"",
                    "\"connect\"",
                    "\"generate\"",
                    "\"sync\"",
                    "\"count\"",
                    "topo://",
                    "start_listener",
                    "connect_with_",
                    "replace_invite",
                    "assert_eventually_count",
                    "connection_count",
                    "connection_event_count",
                ],
                message: "tests/cli_harness must stay process-only; scenario files own command params, retries, invite syntax, output keys, and expected results",
            },
            ForbiddenRule {
                name: "core_does_not_import_protocol",
                files: rust_files(&core_root),
                forbidden: vec!["crate::protocol"],
                message: "core must be protocol-agnostic; concrete protocols live under src/protocol",
            },
            ForbiddenRule {
                name: "event_modules_worker_has_no_domain_branching_vocabulary",
                files: repo_paths(&root, &["src/protocol/event_modules/worker.rs"]),
                forbidden: vec![
                    "connection",
                    "sync",
                    "transit",
                    "response",
                    "record_transport",
                    "is_connection_event",
                    "ingest_sync",
                ],
                message: "event_modules/worker.rs owns common admission/apply, but concrete branching belongs in event_modules::Modules or domain workers",
            },
            ForbiddenRule {
                name: "core_has_no_protocol_io_vocabulary",
                files: rust_files(&core_root),
                forbidden: vec!["TransportSend", "outbox", "connection_id", "transit"],
                message: "protocol-specific IO vocabulary belongs under src/protocol/event_modules, not src/core",
            },
            ForbiddenRule {
                name: "core_has_no_domain_vocabulary",
                files: rust_files(&core_root),
                forbidden: vec![
                    "workspace",
                    "content",
                    "endpoint",
                    "identity",
                    "invite",
                    "bootstrap",
                    "negentropy",
                    "message",
                    "reaction",
                    "file_transfer",
                ],
                message: "domain vocabulary belongs under src/protocol/event_modules, not src/core",
            },
            ForbiddenRule {
                name: "store_uses_generic_storage_vocabulary",
                files: repo_paths(&root, &["src/core/store.rs"]),
                forbidden: vec![
                    "bucket",
                    "EventLabel",
                    "event_labels",
                    "module_rows",
                    "payload_len",
                    "Network",
                    "Tcp",
                    "SocketAddr",
                ],
                message: "store owns generic mechanics, not sync buckets, module-row escape hatches, payload semantics, or network queue semantics",
            },
            ForbiddenRule {
                name: "core_network_queues_are_opaque_byte_rows",
                files: repo_paths(&root, &["src/core/network_queues.rs"]),
                forbidden: vec![
                    "EventRecord",
                    "canonical",
                    "event_id",
                    "connection_id",
                    "workspace",
                    "transit",
                    "invite",
                    "sync",
                    "bootstrap",
                    "outbox",
                ],
                message: "core/network_queues.rs owns opaque byte rows only, not protocol meaning",
            },
            ForbiddenRule {
                name: "core_tcp_is_opaque_frame_transport",
                files: repo_paths(&root, &["src/core/tcp.rs"]),
                forbidden: vec![
                    "EventRecord",
                    "canonical",
                    "event_id",
                    "connection_id",
                    "workspace",
                    "transit",
                    "invite",
                    "sync",
                    "bootstrap",
                    "outbox",
                ],
                message: "core/tcp.rs owns length-prefixed opaque frames only, not protocol meaning",
            },
            ForbiddenRule {
                name: "sync_event_module_does_not_own_transport_or_frame_io",
                files: rust_files(&event_root.join("sync")),
                forbidden: vec![
                    "TcpStream",
                    "TcpListener",
                    "crate::protocol::network",
                    "read_frame",
                    "write_frame",
                ],
                message: "sync event modules must not own TCP transport or frame IO",
            },
            ForbiddenRule {
                name: "event_module_commands_do_not_mutate_storage_directly",
                files: rust_files_named(&event_root, "commands.rs"),
                forbidden: vec![
                    "use crate::core::store::Store",
                    "&Store",
                    "Store,",
                    "Store)",
                    "ProjectionOutput",
                    "TableRow",
                    "with_changes",
                    ".rows",
                    "write_transaction",
                    "insert_table_rows",
                    "insert_event(",
                    "set_event_status",
                    "delete_dependency_wait",
                    "insert_blocked_event_missing_dep",
                    "delete_blocked_events_by_missing_dep",
                    "drain_until_idle",
                    "rusqlite",
                ],
                message: "commands receive explicit context and return CommandOutput events only; projectors/workers/store own rows and writes",
            },
            ForbiddenRule {
                name: "event_modules_do_not_import_runtime_worker_or_transport",
                files: rust_files(&event_root)
                    .into_iter()
                    .filter(|path| path != &event_root.join("mod.rs"))
                    .filter(|path| path.file_name().is_none_or(|name| name != "worker.rs"))
                    .collect(),
                forbidden: vec![
                    "crate::runtime",
                    "crate::state",
                    "crate::core::worker",
                    "crate::core::control_loop",
                    "crate::core::wire",
                    "PipelineActor",
                    "drain_until_idle",
                    "protocol::network",
                    "TcpStream",
                    "TcpListener",
                    "read_frame",
                    "write_frame",
                    "NetworkOp",
                    "StoreOp",
                    "ProtocolEffect",
                    "TransportSend",
                ],
                message: "event modules own protocol semantics, not runtime loops or transport implementation",
            },
            ForbiddenRule {
                name: "event_module_projectors_do_not_query_storage_directly",
                files: rust_files_named(&event_root, "projector.rs"),
                forbidden: vec![
                    "use crate::core::store::Store",
                    "&Store",
                    "Store,",
                    "Store)",
                    "table_row",
                    "event_bytes",
                    "has_event",
                    "write_transaction",
                    "rusqlite",
                ],
                message: "projectors are pure transforms over event plus explicit context; queries belong outside projector.rs",
            },
            ForbiddenRule {
                name: "event_module_queries_are_read_only",
                files: rust_files_named(&event_root, "queries.rs"),
                forbidden: vec![
                    "delete_table_rows",
                    "insert_table_rows",
                    "write_transaction",
                    "insert_event",
                    "set_event_status",
                    "delete_dependency_wait",
                    "insert_blocked_event_missing_dep",
                    "delete_blocked_events_by_missing_dep",
                ],
                message: "queries.rs is read-only; mutations belong in workers or core write paths",
            },
            ForbiddenRule {
                name: "event_module_projectors_do_not_do_transit_or_crypto_work",
                files: rust_files_named(&event_root, "projector.rs"),
                forbidden: vec!["transit", "crypto", "encrypt", "decrypt", "unwrap("],
                message: "projectors write rows; transit wrapping/unwrapping and crypto belong in commands/workers/helpers",
            },
            ForbiddenRule {
                name: "event_module_projectors_are_row_only_boundaries",
                files: rust_files_named(&event_root, "projector.rs"),
                forbidden: vec![
                    "CommandOutput",
                    "ProposedEvent",
                    "EventRecord {",
                    "ProtocolEffect",
                    "NetworkOp",
                    "StoreOp",
                    "TransportSend",
                    "TcpStream",
                    "TcpListener",
                    "create_connection(",
                    "create_bootstrap(",
                ],
                message: "projectors are row-only; emitting events/effects or doing transit work belongs in commands/workers",
            },
            ForbiddenRule {
                name: "event_module_types_do_not_store_encoded_event_artifacts",
                files: rust_files_named(&event_root, "types.rs")
                    .into_iter()
                    .filter(|path| path != &event_root.join("types.rs"))
                    .collect(),
                forbidden: vec!["canonical_bytes", "encoded_event", "wire_event"],
                message: "types.rs should define semantic shapes; canonical bytes live at codec/boundary layers",
            },
            ForbiddenRule {
                name: "sync_event_module_does_not_use_session_message_vocabulary",
                files: rust_files(&event_root.join("sync")),
                forbidden: vec!["Hello", "HelloAck", "Done", "Events"],
                message: "sync protocol items must be connection-scoped events, not session messages",
            },
            ForbiddenRule {
                name: "core_files_do_not_contain_sync_protocol_logic",
                files: repo_paths(
                    &root,
                    &[
                        "src/main.rs",
                        "src/core/store.rs",
                        "src/core/network_queues.rs",
                        "src/core/tcp.rs",
                        "src/protocol/event_modules/worker.rs",
                    ],
                ),
                forbidden: vec!["negentropy", "Compare", "Have", "Need", "differing_buckets"],
                message: "sync protocol logic belongs in protocol/event_modules/sync",
            },
            ForbiddenRule {
                name: "protocol_cli_does_not_use_socket_primitives",
                files: repo_paths(&root, &["src/protocol/cli.rs"]),
                forbidden: vec![
                    "TcpStream",
                    "TcpListener",
                    "Shutdown",
                    "read_frame",
                    "write_frame",
                    "connect_timeout",
                    ".accept()",
                    ".read_exact(",
                    ".write_all(",
                ],
                message: "protocol/cli.rs may invoke core TCP runtime helpers, but must not own socket/frame mechanics",
            },
            ForbiddenRule {
                name: "crux_core_is_isolated_to_core",
                files: rust_files(&root.join("src"))
                    .into_iter()
                    .filter(|path| !path.starts_with(&core_root))
                    .collect(),
                forbidden: vec!["crux_core", "ProtocolApp"],
                message: "Crux is a core runner detail; protocol code should not define Crux app/model/effect layers",
            },
            ForbiddenRule {
                name: "source_does_not_contain_fake_crypto_claims",
                files: rust_files(&root.join("src"))
                    .into_iter()
                    .chain(rust_files(&root.join("tests")))
                    .filter(|path| path.canonicalize().ok() != this_file)
                    .collect(),
                forbidden: vec![
                    "fake crypto",
                    "fake encryption",
                    "pass-through encryption",
                    "identity cipher",
                    "encrypted in name only",
                    "toy encryption",
                ],
                message: "do not name fake or placeholder crypto as real protection",
            },
            ForbiddenRule {
                name: "core_storage_and_transport_do_not_own_connection_or_bootstrap_schema",
                files: repo_paths(
                    &root,
                    &[
                        "src/core/store.rs",
                        "src/core/network_queues.rs",
                        "src/core/tcp.rs",
                    ],
                ),
                forbidden: vec![
                    "peer",
                    "bootstrap",
                    "connection_id",
                    "connection_events",
                    "connection.",
                ],
                message: "connection/bootstrap storage belongs in protocol/event_modules/connection",
            },
        ],
    );
}

#[test]
fn commands_files_live_only_in_event_modules() {
    let root = repo_root();
    let event_root = event_modules_root(&root);
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "commands.rs"))
        .filter(|path| !path.starts_with(&event_root))
        .map(|path| relative(&root, &path))
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "commands.rs is reserved for event modules; CLI adapters should use scoped cli.rs files:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cli_files_live_with_event_modules_or_the_protocol_shell() {
    let root = repo_root();
    let event_root = event_modules_root(&root);
    let protocol_cli = root.join("src/protocol/cli.rs");
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "cli.rs"))
        .filter(|path| !path.starts_with(&event_root) && path != &protocol_cli)
        .map(|path| relative(&root, &path))
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "CLI adapters belong beside event modules; only src/protocol/cli.rs may compose the protocol CLI:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn core_does_not_own_protocol_worker_or_wire_codec() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_root = root.join("src/core");
    let forbidden = ["blocking.rs", "worker.rs", "control_loop.rs", "wire.rs"];
    let offenders = forbidden
        .into_iter()
        .filter(|name| core_root.join(name).exists())
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "core maintains queues/storage only; protocol workers and wire codec helpers live under src/protocol/event_modules or src/protocol:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn network_queue_uses_single_target_indexed_outbound_table() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = source_text(&root.join("src/core/network_queues.rs"));
    assert_eq!(
        text.matches("TableName::new(\"core.network.outbound\")")
            .count(),
        1,
        "core/network_queues.rs should define one outbound table, not dynamic per-target tables"
    );
    assert!(
        text.contains("fn target_prefix(")
            && text.contains("table_rows_with_key_prefix(OUTBOUND_TABLE")
            && text.contains("pub fn claim_outbound_for_target("),
        "outbound network queue rows should carry target metadata in the key and be claimed by target prefix"
    );
    assert!(
        !text.contains("format!(\"core.network.outbound")
            && !text.contains("table_rows(OUTBOUND_TABLE"),
        "do not simulate per-target queues by dynamic table names or full-table scans"
    );
}

#[test]
fn store_exposes_generic_prefix_scan_not_network_methods() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = source_text(&root.join("src/core/store.rs"));
    assert!(
        text.contains("pub fn table_rows_with_key_prefix("),
        "store should expose generic key-prefix scans for indexed queue claims"
    );
    for forbidden in [
        "claim_outbound",
        "NetworkTarget",
        "OutboundNetworkRow",
        "InboundNetworkRow",
    ] {
        assert!(
            !text.contains(forbidden),
            "store.rs must not know network queue types or operations: contains {forbidden}"
        );
    }
}

#[test]
fn core_store_is_row_only_not_protocol_fact_storage() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = source_text(&root.join("src/core/store.rs"));
    let forbidden = [
        "EventRecord",
        "EventStatus",
        "EventScope",
        "EventIndexEntry",
        "EventStatusCounts",
        "canonical_bytes",
        "blocked_by_event",
        "dependency_wait",
        "event_id(",
        "blake3",
    ];
    for needle in forbidden {
        assert!(
            !text.contains(needle),
            "core/store.rs must be a generic row store; protocol fact storage belongs in protocol/event_modules/tables.rs: contains {needle}"
        );
    }
    assert!(
        text.contains("pub fn insert_table_rows_in_tx(")
            && text.contains("pub fn replace_table_rows_in_tx(")
            && text.contains("pub fn delete_table_rows_in_tx(")
            && text.contains("pub fn table_rows_with_key_prefix("),
        "core/store.rs should expose generic row write/read primitives only"
    );
}

#[test]
fn core_store_applies_only_declared_schemas() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = source_text(&root.join("src/core/store.rs"));
    assert!(
        text.contains("pub struct Schema")
            && text.contains("pub enum SchemaDefinition")
            && text.contains("pub const fn durable_row_table")
            && text.contains("fn apply_schemas(&self, schemas: &[Schema])")
            && text.contains("fn apply_schema(&self, schema: &Schema)")
            && text.contains("fn apply_row_table_schema("),
        "store schema creation should be driven by caller-declared Schema values, with only the generic row-table shape generated by store"
    );
    for forbidden in [
        "CREATE TABLE IF NOT EXISTS events",
        "CREATE TABLE IF NOT EXISTS blocked_by_event",
        "CREATE INDEX IF NOT EXISTS idx_events",
    ] {
        assert!(
            !text.contains(forbidden),
            "core/store.rs must not synthesize protocol schemas: contains {forbidden}"
        );
    }
}

#[test]
fn protocol_event_tables_own_common_fact_indexes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = source_text(&root.join("src/protocol/event_modules/tables.rs"));
    for required in [
        "pub const SCHEMAS",
        "pub const EVENTS",
        "pub const READY_EVENTS",
        "pub const PARTITION_EVENTS",
        "pub const BLOCKED_EVENTS_BY_MISSING_DEP",
        "pub const MISSING_DEPS_BY_BLOCKED_EVENT",
        "pub const EVENT_LABELS",
        "pub fn insert_event(",
        "pub fn event_labels(",
    ] {
        assert!(
            text.contains(required),
            "protocol/event_modules/tables.rs should own common protocol fact/index storage: missing {required}"
        );
    }
}

#[test]
fn tcp_uses_network_queue_helpers_not_table_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = source_text(&root.join("src/core/tcp.rs"));
    assert!(
        text.contains("network_queues::enqueue_inbound")
            && text.contains("network_queues::enqueue_outbound")
            && text.contains("network_queues::claim_outbound_for_target")
            && text.contains("network_queues::delete_outbound"),
        "core/tcp.rs should move bytes through core/network_queues helpers"
    );
    for forbidden in ["TableName", "TableRow", "OUTBOUND_TABLE", "INBOUND_TABLE"] {
        assert!(
            !text.contains(forbidden),
            "core/tcp.rs should not manage queue schema or row encoding directly: contains {forbidden}"
        );
    }
}

#[test]
fn table_names_are_declared_in_tables_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut violations = Vec::new();
    for path in rust_files(&event_root) {
        if path.file_name().is_some_and(|name| name == "tables.rs") {
            continue;
        }
        let text = source_text(&path);
        if text.contains("table: \"") || text.contains("TableName::new(") {
            violations.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "module table names belong in tables.rs as typed TableName declarations, with projectors/queries using those declarations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn table_declaration_files_declare_schemas() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut violations = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .chain([root.join("src/core/network_queues.rs")])
    {
        let text = source_text(&path);
        if text.contains("TableName::new(") && !text.contains("pub const SCHEMAS") {
            violations.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "every module/scope that names storage tables must also declare the schemas it owns:\n{}",
        violations.join("\n")
    );
}

#[test]
fn row_table_declarations_use_store_schema_helper() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut violations = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .chain([root.join("src/core/network_queues.rs")])
    {
        let text = source_text(&path);
        if text.contains("pub const SCHEMAS") && text.contains("CREATE TABLE IF NOT EXISTS") {
            violations.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "row table schemas should be declared with Schema::durable_row_table/temp_row_table so modules own names while store owns the generic row shape:\n{}",
        violations.join("\n")
    );
}

#[test]
fn store_table_rows_use_typed_table_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = source_text(&root.join("src/core/store.rs"));
    assert!(
        text.contains("pub struct TableName")
            && text.contains("pub struct TableRow")
            && text.contains("pub table: TableName")
            && text.contains("pub struct Schema")
            && text.contains("pub enum SchemaDefinition")
            && text.contains("RowTable(TableName)")
            && !text.contains("pub table: &'static str"),
        "Store rows should use typed TableName values, and schemas should be explicit declarations"
    );
    assert!(
        text.contains("pub fn open_memory()") && text.contains("pub fn open_disk("),
        "Store should make memory vs disk storage explicit"
    );
}

#[test]
fn event_records_are_constructed_only_by_codecs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_root = root.join("src");
    let mut violations = Vec::new();
    for path in rust_files(&src_root) {
        let is_codec = path.file_name().is_some_and(|name| name == "codec.rs");
        if is_codec {
            continue;
        }
        let text = source_text(&path);
        if text.lines().any(|line| {
            let line = line.trim_start();
            line.starts_with("EventRecord {") || line.contains("Ok(EventRecord {")
        }) {
            violations.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "EventRecord literals belong in codec constructors so metadata matches canonical bytes:\n{}",
        violations.join("\n")
    );
}

#[test]
fn command_output_contains_events_not_state_changes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/protocol/event_modules/worker.rs"))
        .expect("read worker");
    let start = text
        .find("pub struct CommandOutput")
        .expect("CommandOutput");
    let body = &text[start..text[start..].find("impl<T> CommandOutput").unwrap() + start];
    assert!(
        body.contains("pub events: Vec<ProposedEvent>") && !body.contains("ProjectionOutput"),
        "CommandOutput is command-facing and must carry proposed events only, not projector rows"
    );
}

#[test]
fn proposed_event_carries_deterministic_id_and_record() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/protocol/event_modules/worker.rs"))
        .expect("read worker");
    let start = text
        .find("pub struct ProposedEvent")
        .expect("ProposedEvent");
    let body = &text[start..text[start..].find("impl ProposedEvent").unwrap() + start];
    assert!(
        body.contains("event_id: EventId")
            && body.contains("record: EventRecord")
            && !body.contains("pub event_id")
            && !body.contains("pub record"),
        "ProposedEvent must make deterministic ids part of the command contract"
    );
    assert!(
        text.contains("event_id(&record.canonical_bytes)"),
        "ProposedEvent ids must be derived from canonical event bytes"
    );
}

#[test]
fn projection_output_contains_rows_and_labels_not_events() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/protocol/event_modules/worker.rs"))
        .expect("read worker");
    let start = text
        .find("pub struct ProjectionOutput")
        .expect("ProjectionOutput");
    let body = &text[start..text[start..].find("impl ProjectionOutput").unwrap() + start];
    assert!(
        body.contains("pub rows: Vec<TableRow>")
            && body.contains("pub labels: Vec<tables::EventLabel>")
            && !body.contains("EventRecord")
            && !body.contains("events"),
        "ProjectionOutput is projector-facing and must carry rows/labels only, not events"
    );
}

#[test]
fn protocol_network_module_does_not_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !root.join("src/protocol/network.rs").exists(),
        "protocol/network.rs is forbidden; raw TCP mechanics live in core/tcp.rs and protocol meaning lives in event modules"
    );
}
