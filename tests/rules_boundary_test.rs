use std::path::Path;

fn rust_files(root: &Path) -> Vec<std::path::PathBuf> {
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

fn file_contains_violations(
    root: &Path,
    files: &[std::path::PathBuf],
    forbidden: &[&str],
) -> Vec<String> {
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

fn source_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn module_doc_text(text: &str) -> String {
    let mut docs = Vec::new();
    for line in text.lines() {
        if let Some(doc) = line.strip_prefix("//!") {
            docs.push(doc.trim().to_string());
            continue;
        }
        if line.trim().is_empty() && !docs.is_empty() {
            continue;
        }
        break;
    }
    docs.join("\n")
}

fn production_text_before_unit_tests(text: &str) -> &str {
    text.find("#[cfg(test)]")
        .map(|idx| &text[..idx])
        .unwrap_or(text)
}

fn worker_implementation_files(root: &Path) -> Vec<std::path::PathBuf> {
    let common_root = root.join("src/workers/pipeline_helpers");
    rust_files(&root.join("src/workers"))
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_none_or(|name| name != "mod.rs" && name != "schema.rs")
        })
        .filter(|path| {
            !path.starts_with(&common_root)
                || path
                    .file_name()
                    .is_some_and(|name| name == "event_pipeline.rs")
        })
        .collect()
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

fn meaningful_mod_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("//!")
                && !line.starts_with("///")
                && !line.starts_with("//")
        })
        .collect()
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
                .is_none_or(|name| name != "mod.rs" && name != "worker.rs" && name != "schema.rs")
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
        "app.rs",
        "cli.rs",
        "crypto.rs",
        "crux_runner.rs",
        "daemon.rs",
        "logical_clock.rs",
        "mod.rs",
        "network_queues.rs",
        "runtime.rs",
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
fn daemon_runner_is_core_and_protocol_supplies_workers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        root.join("src/core/daemon.rs").exists(),
        "generic daemon runtime mechanics should live in core"
    );
    assert!(
        !root.join("src/daemon.rs").exists(),
        "the project root should use main.rs as the app shell instead of a second daemon module"
    );
    assert!(
        !root.join("src/protocol/daemon.rs").exists(),
        "daemon runtime orchestration must not be a protocol module"
    );

    let protocol_mod = source_text(&root.join("src/protocol/mod.rs"));
    assert!(
        !protocol_mod.contains("pub mod daemon"),
        "src/protocol/mod.rs must not export a daemon module"
    );
    assert!(
        protocol_mod.contains("impl EventRegistry for Protocol")
            && protocol_mod.contains("impl DaemonProtocol for Protocol")
            && protocol_mod.contains("impl ProtocolSpec for Protocol"),
        "src/protocol/mod.rs should stay focused on protocol assembly and core integration traits"
    );
    assert!(
        !protocol_mod.contains("pub fn modules"),
        "Protocol must expose registry traits, not its internal event-module collection"
    );
    assert!(
        !protocol_mod.contains("impl EventRegistry for cli::Context"),
        "context-specific worker trait impls belong beside protocol::cli::Context"
    );

    let protocol_cli = source_text(&root.join("src/protocol/cli.rs"));
    assert!(
        !protocol_cli.contains("daemon::commands"),
        "protocol command aggregation should not register application daemon commands"
    );
    assert!(
        protocol_cli.contains("impl EventRegistry for Context")
            && protocol_cli.contains("impl DaemonWorkerContext for Context"),
        "protocol::cli::Context should expose the store/registry shape shared by CLI and daemon workers"
    );

    let main = source_text(&root.join("src/main.rs"));
    assert!(
        main.contains("core::app::run::<topo::protocol::Protocol>"),
        "the binary entrypoint should choose a protocol spec and delegate to the generic app shell"
    );

    let daemon = source_text(&root.join("src/core/daemon.rs"));
    assert!(
        daemon.contains("runtime::run_round_robin")
            && daemon.contains("pub struct Worker<C>")
            && !daemon.contains("transit_in")
            && !daemon.contains("event_admission")
            && !daemon.contains("transit_out")
            && !daemon.contains("sync_tick"),
        "core daemon should run opaque worker objects without naming protocol workers"
    );

    let workers = source_text(&root.join("src/workers/mod.rs"));
    assert!(
        workers.contains("pub fn daemon_workers")
            && workers.contains("transport_accept::daemon_worker")
            && workers.contains("transit_in::daemon_worker")
            && workers.contains("event_admission::daemon_worker")
            && workers.contains("sync::daemon_worker"),
        "the worker catalog should aggregate protocol-owned daemon worker objects"
    );
}

#[test]
fn domain_roots_contain_only_children_and_shared_domain_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let allowed_domain_files = [
        "cli_tests.rs",
        "commands.rs",
        "mod.rs",
        "worker.rs",
        "schema.rs",
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
        "domain roots may contain only shared domain files; put leaf codecs/projectors in child event modules:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn leaf_mod_rs_files_are_declarations_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut offenders = Vec::new();
    for domain in std::fs::read_dir(&event_root).expect("read event modules") {
        let domain = domain.expect("dir entry").path();
        if !domain.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&domain).expect("read domain") {
            let child = entry.expect("dir entry").path();
            if !child.is_dir() {
                continue;
            }
            let mod_rs = child.join("mod.rs");
            if !mod_rs.exists() {
                continue;
            }
            let text = source_text(&mod_rs);
            let bad_lines = meaningful_mod_lines(&text)
                .into_iter()
                .filter(|line| {
                    !(line.starts_with("pub mod ") && line.ends_with(';') && !line.contains('{'))
                        && *line != "#[cfg(test)]"
                        && *line != "mod cli_tests;"
                })
                .collect::<Vec<_>>();
            if !bad_lines.is_empty() {
                offenders.push(format!(
                    "{} contains non-declaration lines: {}",
                    mod_rs.strip_prefix(root).unwrap().display(),
                    bad_lines.join(" | ")
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "leaf event-module mod.rs files are only concern declarations; move adapters/helpers to schema.rs, commands.rs, worker.rs, or cli.rs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn event_module_mod_rs_files_do_not_orchestrate_commands_or_work() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "mod.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "commands::",
        "queries::",
        "CommandOutput",
        "ProposedEvent",
        "crate::core::tcp",
        "tcp::",
        "TcpStream",
        "TcpListener",
        "NetworkTarget",
        "OutboundNetworkRow",
        "network_queues",
        "RefCell",
        "HashMap",
        "HashSet",
        "BTreeMap",
        "thread::",
        "Duration",
        "Instant",
        "connect_exchange",
        "accept_available",
        "worker::run",
        "Work::",
        "insert_table_rows",
        "delete_table_rows",
        "table_rows",
        "table_row(",
        "table_row_count",
        "write_transaction",
        "pub fn create_",
        "pub fn generate_",
        "pub fn stage_",
        "pub fn start_",
        "pub fn drain_",
        "pub fn mark_",
        "fn local_keypair",
        "fn existing_local_keypair",
        "fn merge_outputs",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "mod.rs files are plumbing: declarations, schema aggregation, and shallow codec/projector dispatch only:\n{}",
        violations.join("\n")
    );
}

#[test]
fn scoped_cli_files_do_not_own_transport_or_cross_cli_operations() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "cli.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "crate::core::tcp",
        "core::network_queues",
        "network_queues::",
        "InboundNetworkRow",
        "OutboundNetworkRow",
        "NetworkTarget",
        "RefCell",
        "HashMap",
        "thread::",
        "thread::sleep",
        "Instant",
        "connect_exchange",
        "accept_available",
        "DrainUntilIdle",
        "DrainReadyBatch",
        "::cli::run_",
        "::cli::drain_",
        "::cli::exchange_",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "scoped cli.rs files parse args, call commands/workers, and format reports; transport, send bookkeeping, and cross-cli operational helpers belong in workers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn sync_cli_is_deprecated() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = source_text(&root.join("src/protocol/event_modules/sync/cli.rs"));
    let forbidden = [
        "CliArgs",
        "CliOutput",
        "DrainUntilIdle",
        "DrainReadyBatch",
        "sync_worker::run",
        "Work::ExchangeOutboundRoutes",
        "Work::StartSyncRoutes",
        "SyncSelection",
        "transit_in",
        "--listen",
        "--accept",
    ];
    let violations = forbidden
        .into_iter()
        .filter(|needle| text.contains(needle))
        .collect::<Vec<_>>();

    assert!(
        violations.is_empty() && text.contains("Vec::new()"),
        "manual sync CLI serving is deprecated; ongoing sync is daemon worker-loop work:\n{}",
        violations.join("\n")
    );
}

#[test]
fn domain_root_cli_requires_cross_child_scope() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/event_modules");
    let mut offenders = Vec::new();
    for domain in std::fs::read_dir(&root).expect("read event modules") {
        let path = domain.expect("dir entry").path();
        if !path.is_dir() || !path.join("cli.rs").exists() {
            continue;
        }
        let child_modules = std::fs::read_dir(&path)
            .expect("read domain module")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|candidate| candidate.is_dir())
            .count();
        if child_modules <= 1 {
            offenders.push(path.strip_prefix(&root).unwrap().display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "domain-root cli.rs is only for commands spanning multiple child modules; otherwise put the command in the leaf module:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn event_module_files_use_only_standard_concern_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let allowed = [
        "cli.rs",
        "cli_tests.rs",
        "codec.rs",
        "commands.rs",
        "crypto.rs",
        "mod.rs",
        "projector.rs",
        "queries.rs",
        "registry_meta.rs",
        "schema.rs",
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
            for required in ["mod.rs", "types.rs", "codec.rs"] {
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
        "child directories under event_modules are canonical event modules; shared schema/queues belong at the domain root:\n{}",
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
fn worker_implementations_live_in_workers_folder() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut offenders = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "worker.rs"))
    {
        offenders.push(path.strip_prefix(root).unwrap().display().to_string());
    }

    assert!(
        offenders.is_empty(),
        "worker implementations live under src/workers; event modules may re-export them but must not own worker.rs files:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn workers_folder_has_standard_catalog_shape() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workers_root = root.join("src/workers");
    let required = [
        "mod.rs",
        "README.md",
        "pipeline_helpers",
        "pipeline_helpers/mod.rs",
        "pipeline_helpers/event_pipeline.rs",
        "pipeline_helpers/event_lifecycle.rs",
        "pipeline_helpers/purging.rs",
        "bootstrap_exchange.rs",
        "transport_accept.rs",
        "transit_in.rs",
        "content_purge.rs",
        "event_admission.rs",
        "event_projection.rs",
        "dependency_unblock.rs",
        "transit_out.rs",
        "schema.rs",
        "sync.rs",
    ];
    let missing = required
        .into_iter()
        .filter(|name| !workers_root.join(name).exists())
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "src/workers is the worker catalog and must contain the contract plus current worker implementations:\n{}",
        missing.join("\n")
    );
}

#[test]
fn socket_receive_is_transport_accept_transit_in_and_outbound_is_transit_out() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !root.join("src/workers/connection_io.rs").exists(),
        "transit mechanics should live behind transport_accept, transit_in, and transit_out"
    );
    assert!(
        !root.join("src/workers/connection.rs").exists(),
        "connection facts belong to event modules/projectors; transit helpers should stay inside transit_in/transit_out or protocol helpers"
    );

    let catalog = source_text(&root.join("src/workers/mod.rs"));
    assert!(
        catalog.contains("transit_in::daemon_worker()")
            && catalog.contains("transport_accept::daemon_worker()")
            && catalog.contains("event_admission::daemon_worker()")
            && catalog.contains("transit_out::daemon_worker()"),
        "the daemon catalog should schedule transport_accept, transit_in, event_admission, and transit_out workers"
    );
    assert!(
        !catalog.contains("connection_io::daemon_worker()"),
        "connection_io must not be a scheduled worker"
    );
}

#[test]
fn worker_files_export_only_run_as_public_entrypoint() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in worker_implementation_files(root) {
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
        "worker implementation files expose one obvious public entrypoint, run(); helpers stay private:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn worker_files_do_not_own_cli_parsing_or_user_formatting() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = worker_implementation_files(root);
    let forbidden = [
        "crate::core::cli",
        "CliArgs",
        "CliCommand",
        "CliOutput",
        "pub fn commands()",
        "usage:",
        "help:",
        "println!",
        "eprintln!",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "worker files manage queued/operational work; CLI parsing, command specs, and user-facing formatting stay in cli.rs:\n{}",
        violations.join("\n")
    );
}

#[test]
fn codec_files_do_not_define_public_types() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "codec.rs"))
        .collect::<Vec<_>>();
    let forbidden = ["pub struct ", "pub enum ", "pub type "];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "event module semantic types belong in types.rs; codec.rs is encode/decode only:\n{}",
        violations.join("\n")
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
fn commands_files_live_only_in_event_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "commands.rs"))
        .filter(|path| !path.starts_with(&event_root))
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "commands.rs is reserved for event modules; CLI adapters should use scoped cli.rs files:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cli_files_live_with_event_modules_or_the_protocol_shell() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let core_cli = root.join("src/core/cli.rs");
    let protocol_cli = root.join("src/protocol/cli.rs");
    let offenders = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "cli.rs"))
        .filter(|path| !path.starts_with(&event_root) && path != &protocol_cli && path != &core_cli)
        .map(|path| path.strip_prefix(root).unwrap().display().to_string())
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "CLI adapters belong beside event modules; src/protocol/cli.rs may aggregate protocol commands and src/core/cli.rs may run generic command specs:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn cli_harness_is_process_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = source_text(&root.join("tests/cli_harness/mod.rs"));
    let forbidden = [
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
    ];
    let violations = forbidden
        .into_iter()
        .filter(|needle| text.contains(needle))
        .collect::<Vec<_>>();

    assert!(
        violations.is_empty(),
        "tests/cli_harness must stay process-only; scenario files own command params, retries, invite syntax, output keys, and expected results:\n{}",
        violations.join("\n")
    );
}

#[test]
fn functional_cli_and_network_tests_use_black_box_setup() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let test_files = [
        "tests/black_box_sync_test.rs",
        "tests/cascade_cli_test.rs",
        "tests/content_cli_test.rs",
        "tests/daemon_lifecycle_cli_test.rs",
        "tests/encryption_cli_test.rs",
        "tests/generate_cli_test.rs",
        "tests/invite_accept_cli_test.rs",
    ];
    let forbidden = [
        "use topo::core::",
        "use topo::protocol::",
        "topo::core::",
        "topo::protocol::",
        "Protocol::",
        "worker::run",
        "open_store",
        "insert_table_rows",
        "install_workspace_graph",
        "workspace_graph",
        "EventRecord",
        "CommandOutput",
    ];
    let mut violations = Vec::new();

    for file in test_files {
        let text = source_text(&root.join(file));
        for needle in forbidden {
            if text.contains(needle) {
                violations.push(format!("{file} contains {needle}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "functional CLI/network tests must set up initial state through public CLI/process/network boundaries, not protocol/store internals:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_does_not_import_protocol() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_files = rust_files(&root.join("src/core"));
    let mut violations = Vec::new();

    for file in core_files {
        let text = std::fs::read_to_string(&file).expect("read core file");
        for (line_idx, line) in text.lines().enumerate() {
            if line.contains("crate::protocol") {
                violations.push(format!(
                    "{}:{}: {line}",
                    file.strip_prefix(root).unwrap().display(),
                    line_idx + 1
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "core must be protocol-agnostic; concrete protocols live under src/protocol:\n{}",
        violations.join("\n")
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
        "core maintains queues/storage only; worker implementations live under src/workers and wire codec helpers live under src/protocol:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn common_event_pipeline_has_no_domain_branching_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [root.join("src/workers/pipeline_helpers/event_pipeline.rs")];
    let forbidden = [
        "connection",
        "sync",
        "response",
        "record_transport",
        "is_connection_event",
        "ingest_sync",
        "OutboundNetworkRow",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "src/workers/pipeline_helpers/event_pipeline.rs owns common admission/apply, but concrete branching belongs in event_modules::Modules or domain workers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_has_no_protocol_io_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_root = root.join("src/core");
    let files = rust_files(&core_root);
    let forbidden = ["TransportSend", "outbox", "connection_id", "transit"];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "protocol-specific IO vocabulary belongs under src/protocol/event_modules, not src/core:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_has_no_domain_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_root = root.join("src/core");
    let files = rust_files(&core_root);
    let forbidden = [
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
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "domain vocabulary belongs under src/protocol/event_modules, not src/core:\n{}",
        violations.join("\n")
    );
}

#[test]
fn store_uses_generic_storage_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [root.join("src/core/store.rs")];
    let forbidden = [
        "bucket",
        "EventLabel",
        "event_labels",
        "module_rows",
        "payload_len",
        "Network",
        "Tcp",
        "SocketAddr",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "store owns generic mechanics, not sync ranges, module-row escape hatches, payload semantics, or network queue semantics:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_network_queues_are_opaque_byte_rows() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [root.join("src/core/network_queues.rs")];
    let forbidden = [
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
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "core/network_queues.rs owns opaque byte rows only, not protocol meaning:\n{}",
        violations.join("\n")
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
        text.contains("Schema::memory_row_table(\"core.network.outbound.v1\", OUTBOUND_TABLE)")
            && text
                .contains("Schema::memory_row_table(\"core.network.inbound.v1\", INBOUND_TABLE)"),
        "core network queues should be memory-local operational queues, not durable protocol truth"
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
        text.contains("pub fn table_rows_with_key_prefix(")
            && text.contains("pub fn table_rows_in_key_range("),
        "store should expose generic key-prefix and key-range scans for indexed queue claims"
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
            "core/store.rs must be a generic row store; protocol fact storage belongs in protocol/event_modules/schema.rs: contains {needle}"
        );
    }
    assert!(
        text.contains("pub fn insert_table_rows_in_tx(")
            && text.contains("pub fn replace_table_rows_in_tx(")
            && text.contains("pub fn delete_table_rows_in_tx(")
            && text.contains("pub fn table_rows_with_key_prefix(")
            && text.contains("pub fn table_rows_in_key_range("),
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
fn protocol_event_schema_owns_common_fact_indexes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = source_text(&root.join("src/protocol/event_modules/schema.rs"));
    for required in [
        "pub const SCHEMAS",
        "pub const EVENTS",
        "pub const READY_EVENTS",
        "pub const TIMESTAMP_EVENTS",
        "pub const BLOCKED_EVENTS_BY_MISSING_DEP",
        "pub const MISSING_DEPS_BY_BLOCKED_EVENT",
        "pub const EVENT_LABELS",
        "pub(crate) fn event_row(",
        "pub fn event_labels(",
    ] {
        assert!(
            text.contains(required),
            "protocol/event_modules/schema.rs should own common protocol fact/index storage: missing {required}"
        );
    }
}

#[test]
fn event_store_lifecycle_is_worker_owned_not_schema_owned() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let protocol_schema = source_text(&root.join("src/protocol/event_modules/schema.rs"));
    for forbidden in [
        "pub fn insert_event(",
        "pub fn set_event_status(",
        "pub fn insert_blocked_event_missing_dep(",
        "pub fn delete_blocked_events_by_missing_dep(",
    ] {
        assert!(
            !protocol_schema.contains(forbidden),
            "protocol/event_modules/schema.rs should define rows and keys only; event lifecycle belongs in workers/pipeline_helpers/event_lifecycle.rs"
        );
    }

    let event_lifecycle =
        source_text(&root.join("src/workers/pipeline_helpers/event_lifecycle.rs"));
    for required in [
        "pub(crate) fn insert_event(",
        "pub(crate) fn set_event_status(",
        "pub(crate) fn insert_blocked_event_missing_dep(",
        "pub(crate) fn delete_blocked_events_by_missing_dep(",
    ] {
        assert!(
            event_lifecycle.contains(required),
            "workers/pipeline_helpers/event_lifecycle.rs should own generic event lifecycle operation {required}"
        );
    }
}

#[test]
fn local_retention_purge_is_worker_owned_not_schema_owned() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let protocol_schema = source_text(&root.join("src/protocol/event_modules/schema.rs"));
    assert!(
        !protocol_schema.contains("purge_event"),
        "protocol/event_modules/schema.rs declares event-store rows and codecs; local retention purge belongs in workers"
    );

    let purging = source_text(&root.join("src/workers/pipeline_helpers/purging.rs"));
    assert!(
        purging.contains("fn purge_event_storage_in_tx")
            && purging.contains("local retention cleanup only")
            && purging.contains("not a protocol deletion event"),
        "workers/pipeline_helpers should own and document event-byte retention cleanup"
    );
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
fn core_tcp_is_opaque_frame_transport() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [root.join("src/core/tcp.rs")];
    let forbidden = [
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
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "core/tcp.rs owns length-prefixed opaque frames only, not protocol meaning:\n{}",
        violations.join("\n")
    );
}

#[test]
fn sync_event_module_does_not_own_transport_or_frame_io() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sync_root = root.join("src/protocol/event_modules/sync");
    let files = rust_files(&sync_root);
    let forbidden = [
        "TcpStream",
        "TcpListener",
        "crate::protocol::network",
        "read_frame",
        "write_frame",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "sync event modules must not own TCP transport or frame IO:\n{}",
        violations.join("\n")
    );
}

#[test]
fn sync_worker_drains_projected_rows_not_direct_ingest_work() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let worker = source_text(&root.join("src/workers/sync.rs"));
    assert!(
        worker.contains("DrainIn"),
        "sync worker should drain projected sync in rows"
    );
    assert!(
        worker.contains("Tick"),
        "sync worker should expose one daemon-facing tick that owns index/start/inbound sequencing"
    );
    assert!(
        !worker.contains("IngestFrame") && !worker.contains("IngestedFrame"),
        "sync worker should not expose direct ingest-frame work; received sync events project to sync-owned rows first"
    );
}

#[test]
fn sync_has_no_protocol_frame_event_module() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sync_root = root.join("src/protocol/event_modules/sync");
    assert!(
        !sync_root.join("frame").exists() && !sync_root.join("data").exists(),
        "sync should emit compare/have/need ids and durable event ids, not protocol frame/data packet modules"
    );
}

#[test]
fn sync_canonical_bytes_do_not_encode_inbound_or_outbound_direction() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sync_root = root.join("src/protocol/event_modules/sync");
    let files = rust_files(&sync_root);
    let forbidden = ["SyncDirection", "direction: SyncDirection"];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "sync direction is connection-scope projection context, not canonical event-body data:\n{}",
        violations.join("\n")
    );
}

#[test]
fn transit_out_is_id_only_and_transit_batches_inner_events() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema = source_text(&root.join("src/workers/schema.rs"));
    assert!(
        schema.contains("pub fn transit_out_row(")
            && schema.contains("Schema::memory_row_table(\"transit.out.v1\", TRANSIT_OUT)")
            && schema.contains("value: Vec::new()"),
        "transit out rows should be memory-local id-only send work; bytes resolve at the transit boundary"
    );

    let transit_commands =
        source_text(&root.join("src/protocol/event_modules/connection/transit/commands.rs"));
    let transit_codec =
        source_text(&root.join("src/protocol/event_modules/connection/transit/codec.rs"));
    assert!(
        transit_commands.contains("pub fn create_connection_batch")
            && !transit_commands.contains("pub fn create_connection(")
            && transit_codec.contains("encode_inner_events")
            && transit_codec.contains("decode_inner_events"),
        "transit should batch canonical inner events; core TCP still frames only opaque transit bytes"
    );
}

#[test]
fn network_admission_does_not_reconstruct_connection_request_dependencies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let transit_projector =
        source_text(&root.join("src/protocol/event_modules/connection/transit/projector.rs"));
    let registry = source_text(&root.join("src/protocol/event_modules/mod.rs"));
    let request_codec = source_text(
        &root.join("src/protocol/event_modules/connection/connection_request/codec.rs"),
    );
    assert!(
        !transit_projector.contains("INVITE_SECRETS")
            && !transit_projector.contains("authorized_invite_secret_event_id")
            && !transit_projector.contains("record.dependencies.push")
            && !registry.contains("record.dependencies.push"),
        "network admission must not synthesize invite dependencies from projected invite state"
    );
    assert!(
        request_codec.contains("invite_secret_event_id")
            && request_codec.contains("dependencies: vec![event.invite_secret_event_id]"),
        "connection request bytes should declare their local invite-secret dependency"
    );
}

#[test]
fn connection_routes_are_projected_from_receive_metadata() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let connection_root = root.join("src/protocol/event_modules/connection");
    assert!(
        !connection_root.join("transport_target").exists(),
        "transport targets are receive-derived connection rows, not a separate event module"
    );

    let schema = source_text(&connection_root.join("schema.rs"));
    let request_projector = source_text(&connection_root.join("connection_request/projector.rs"));
    let response_projector = source_text(&connection_root.join("connection_response/projector.rs"));
    assert!(
        schema.contains("const TRANSPORT_TARGETS")
            && request_projector.contains("context.receive")
            && request_projector.contains("transport_target_row")
            && response_projector.contains("context.receive")
            && response_projector.contains("transport_target_row"),
        "connection request/response projection should atomically write route rows from receive metadata"
    );
}

#[test]
fn event_module_commands_do_not_mutate_storage_directly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "commands.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
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
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "commands receive explicit context and return CommandOutput events only; projectors/workers/store own rows and writes:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_commands_do_not_drive_workers_cli_or_transport_queues() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "commands.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "worker::run",
        "DrainUntilIdle",
        "DrainReadyBatch",
        "crate::core::cli",
        "CliArgs",
        "CliCommand",
        "CliOutput",
        "crate::core::tcp",
        "core::network_queues",
        "network_queues::",
        "InboundNetworkRow",
        "OutboundNetworkRow",
        "NetworkTarget",
        "thread::",
        "Instant",
        "println!",
        "eprintln!",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "commands.rs files construct canonical events or transport bytes from explicit params/context; worker driving, CLI, TCP, and queue bookkeeping belong elsewhere:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_modules_do_not_import_runtime_worker_or_transport() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path != &event_root.join("mod.rs"))
        .filter(|path| path.file_name().is_none_or(|name| name != "worker.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
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
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "event modules own protocol semantics, not runtime loops or transport implementation:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_projectors_do_not_query_storage_directly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| {
            path.file_name().is_some_and(|name| name == "projector.rs")
                && !path.ends_with("connection/transit/projector.rs")
        })
        .collect::<Vec<_>>();
    let forbidden = [
        "use crate::core::store::Store",
        "&Store",
        "Store,",
        "Store)",
        "table_row",
        "event_bytes",
        "has_event",
        "write_transaction",
        "rusqlite",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "projectors are pure transforms over event plus explicit context; queries belong outside projector.rs:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_queries_are_read_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "queries.rs"))
        .collect::<Vec<_>>();
    let forbidden = [
        "delete_table_rows",
        "insert_table_rows",
        "write_transaction",
        "insert_event",
        "set_event_status",
        "delete_dependency_wait",
        "insert_blocked_event_missing_dep",
        "delete_blocked_events_by_missing_dep",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "queries.rs is read-only; mutations belong in workers or core write paths:\n{}",
        violations.join("\n")
    );
}

#[test]
fn worker_and_command_logic_do_not_call_query_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                name == "worker.rs" || name == "commands.rs" || name == "projector.rs"
            })
        })
        .collect::<Vec<_>>();
    let violations = file_contains_violations(root, &files, &["queries::", "::queries::"]);
    assert!(
        violations.is_empty(),
        "queries.rs is for read-only CLI/reporting surfaces; active worker/command reads stay with their owning work:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_projectors_do_not_do_transit_or_crypto_work() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| {
            path.file_name().is_some_and(|name| name == "projector.rs")
                && !path.ends_with("connection/transit/projector.rs")
        })
        .collect::<Vec<_>>();
    let forbidden = [
        "transit::",
        "::transit::",
        "crypto",
        "encrypt",
        "decrypt",
        "unwrap(",
    ];
    let mut violations = Vec::new();
    for path in files {
        let text = source_text(&path);
        let production_text = production_text_before_unit_tests(&text);
        let relative = path.strip_prefix(root).unwrap_or(&path);
        for needle in forbidden {
            if production_text.contains(needle) {
                violations.push(format!("{} contains {needle}", relative.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "projectors may write worker queue rows, but transit wrapping/unwrapping and crypto belong in commands/workers/helpers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_projectors_are_row_only_boundaries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| {
            path.file_name().is_some_and(|name| name == "projector.rs")
                && !path.ends_with("connection/transit/projector.rs")
        })
        .collect::<Vec<_>>();
    let forbidden = [
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
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "projectors are row-only; emitting events/effects or doing transit work belongs in commands/workers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_module_types_do_not_store_encoded_event_artifacts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let files = rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "types.rs"))
        .filter(|path| path != &event_root.join("types.rs"))
        .collect::<Vec<_>>();
    let forbidden = ["canonical_bytes", "encoded_event", "wire_event"];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "types.rs should define semantic shapes; canonical bytes live at codec/boundary layers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn table_names_are_declared_in_schema_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut violations = Vec::new();
    for path in rust_files(&event_root) {
        if path.file_name().is_some_and(|name| name == "schema.rs") {
            continue;
        }
        let text = source_text(&path);
        if text.contains("table: \"") || text.contains("TableName::new(") {
            violations.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "module table names belong in schema.rs as typed TableName declarations, with projectors/queries using those declarations:\n{}",
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
fn schema_files_are_not_empty_placeholders() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut violations = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "schema.rs"))
    {
        let text = source_text(&path);
        if !text.contains("TableName::new(") || !text.contains("pub const SCHEMAS") {
            violations.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "omit schema.rs when a module owns no tables; schema files must declare real table names and schemas:\n{}",
        violations.join("\n")
    );
}

#[test]
fn new_poc8_modules_document_responsibility_boundaries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![
        root.join("src/core/logical_clock.rs"),
        root.join("src/protocol/event_modules/content/cli.rs"),
        root.join("src/protocol/event_modules/identity/cli.rs"),
        root.join("src/workers/bootstrap_exchange.rs"),
        root.join("src/workers/transport_accept.rs"),
        root.join("src/workers/pipeline_helpers/mod.rs"),
        root.join("src/workers/content_purge.rs"),
        root.join("src/workers/encryption.rs"),
        root.join("tests/content_cli_test.rs"),
        root.join("tests/encryption_cli_test.rs"),
        root.join("tests/invite_accept_cli_test.rs"),
    ];
    for relative in [
        "src/protocol/event_modules/content/file",
        "src/protocol/event_modules/content/file_slice",
        "src/protocol/event_modules/content/message",
        "src/protocol/event_modules/content/message_deletion",
        "src/protocol/event_modules/content/reaction",
        "src/protocol/event_modules/encryption",
        "src/protocol/event_modules/identity/invite_server",
    ] {
        files.extend(rust_files(&root.join(relative)));
    }

    let mut violations = Vec::new();
    for path in files {
        let text = source_text(&path);
        let docs = module_doc_text(&text);
        let doc_lines = docs.lines().filter(|line| !line.is_empty()).count();
        let names_boundary = [
            "does not",
            "do not",
            "not ",
            "relies",
            "owns",
            "Inputs:",
            "authority",
            "belongs",
            "canonical",
            "dependency",
            "depends",
            "invariant",
            "local",
            "must",
            "only",
            "projection",
            "scope",
            "shared",
            "worker",
        ]
        .iter()
        .any(|needle| docs.contains(needle));
        if doc_lines < 4 || !names_boundary {
            violations.push(format!(
                "{} has weak module docs",
                path.strip_prefix(root).unwrap().display()
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "new modules should document purpose, invariants, dependencies, and non-responsibilities:\n{}",
        violations.join("\n")
    );
}

#[test]
fn projector_files_are_not_empty_placeholders() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut violations = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "projector.rs"))
    {
        let text = source_text(&path);
        if !text.contains("ProjectionOutput::rows")
            && !text.contains("ProjectionOutput::deletes")
            && !text.contains("ProjectionOutput::with")
        {
            violations.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "omit projector.rs when a module has no row/label/delete projection; projector files must write real projection output:\n{}",
        violations.join("\n")
    );
}

#[test]
fn projector_files_have_pure_functional_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_root = root.join("src/protocol/event_modules");
    let mut violations = Vec::new();
    for path in rust_files(&event_root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "projector.rs"))
    {
        let text = source_text(&path);
        if !text.contains("#[cfg(test)]")
            || !(text.contains("mod tests") || text.contains("mod projector_tests"))
        {
            violations.push(path.strip_prefix(root).unwrap().display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "every projector.rs should carry pure functional behavior tests for row/label output and rejection paths:\n{}",
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
        "row table schemas should be declared with Schema::durable_row_table/memory_row_table so modules own names while store owns the generic row shape:\n{}",
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
    let text = std::fs::read_to_string(root.join("src/workers/pipeline_helpers/event_pipeline.rs"))
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
    let text = std::fs::read_to_string(root.join("src/workers/pipeline_helpers/event_pipeline.rs"))
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
fn projection_output_contains_rows_deletes_and_labels_not_events() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("src/workers/pipeline_helpers/event_pipeline.rs"))
        .expect("read worker");
    let start = text
        .find("pub struct ProjectionOutput")
        .expect("ProjectionOutput");
    let body = &text[start..text[start..].find("impl ProjectionOutput").unwrap() + start];
    assert!(
        body.contains("pub rows: Vec<TableRow>")
            && body.contains("pub deletes: Vec<TableDelete>")
            && body.contains("pub labels: Vec<schema::EventLabel>")
            && !body.contains("EventRecord")
            && !body.contains("events"),
        "ProjectionOutput is projector-facing and must carry rows/labels/deletes only, not events"
    );
}

#[test]
fn sync_event_module_does_not_use_session_message_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sync_root = root.join("src/protocol/event_modules/sync");
    let files = rust_files(&sync_root);
    let forbidden = ["Hello", "HelloAck", "Done", "Events"];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "sync protocol items must be connection-scoped events, not session messages:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_files_do_not_contain_sync_protocol_logic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [
        "src/main.rs",
        "src/core/store.rs",
        "src/core/network_queues.rs",
        "src/core/tcp.rs",
        "src/workers/pipeline_helpers/event_pipeline.rs",
    ];
    let forbidden = ["negentropy", "Compare", "Have", "Need", "differing_buckets"];
    let mut violations = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(root.join(file)).expect("read file");
        for needle in forbidden {
            if text.contains(needle) {
                violations.push(format!("{file} contains {needle}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "sync protocol logic belongs in protocol/event_modules/sync:\n{}",
        violations.join("\n")
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

#[test]
fn protocol_cli_does_not_use_socket_primitives() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [root.join("src/protocol/cli.rs")];
    let forbidden = [
        "TcpStream",
        "TcpListener",
        "Shutdown",
        "read_frame",
        "write_frame",
        "connect_timeout",
        ".accept()",
        ".read_exact(",
        ".write_all(",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "protocol/cli.rs may invoke core TCP runtime helpers, but must not own socket/frame mechanics:\n{}",
        violations.join("\n")
    );
}

#[test]
fn crux_core_is_isolated_to_core() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_root = root.join("src/core");
    let files = rust_files(&root.join("src"))
        .into_iter()
        .filter(|path| !path.starts_with(&core_root))
        .collect::<Vec<_>>();
    let violations = file_contains_violations(root, &files, &["crux_core", "ProtocolApp"]);
    assert!(
        violations.is_empty(),
        "Crux is a core runner detail; protocol code should not define Crux app/model/effect layers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn source_does_not_contain_fake_crypto_claims() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let this_file = root
        .join("tests/rules_boundary_test.rs")
        .canonicalize()
        .ok();
    let files = rust_files(&root.join("src"))
        .into_iter()
        .chain(rust_files(&root.join("tests")))
        .filter(|path| path.canonicalize().ok() != this_file)
        .collect::<Vec<_>>();
    let forbidden = [
        "fake crypto",
        "fake encryption",
        "pass-through encryption",
        "identity cipher",
        "encrypted in name only",
        "toy encryption",
    ];
    let violations = file_contains_violations(root, &files, &forbidden);
    assert!(
        violations.is_empty(),
        "do not name fake or placeholder crypto as real protection:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_storage_and_transport_do_not_own_connection_or_bootstrap_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = [
        "src/core/store.rs",
        "src/core/network_queues.rs",
        "src/core/tcp.rs",
    ];
    let forbidden = [
        "peer",
        "bootstrap",
        "connection_id",
        "connection_events",
        "connection.",
    ];
    let mut violations = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(root.join(file)).expect("read file");
        for needle in forbidden {
            if text.contains(needle) {
                violations.push(format!("{file} contains {needle}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "connection/bootstrap storage belongs in protocol/event_modules/connection:\n{}",
        violations.join("\n")
    );
}
