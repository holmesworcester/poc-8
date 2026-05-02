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

#[test]
fn event_modules_do_not_use_event_rs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/event_modules");
    let offenders = rust_files(&root)
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "event.rs"))
        .collect::<Vec<_>>();
    assert!(offenders.is_empty(), "event.rs is forbidden: {offenders:?}");
}

#[test]
fn event_modules_are_directories() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/event_modules");
    let offenders = std::fs::read_dir(root)
        .expect("read event modules")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| !path.file_name().is_some_and(|name| name == "mod.rs"))
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "event modules must be directories: {offenders:?}"
    );
}

#[test]
fn sync_event_module_does_not_own_transport_or_frame_io() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sync_root = root.join("src/event_modules/sync");
    let files = rust_files(&sync_root);
    let forbidden = [
        "TcpStream",
        "TcpListener",
        "crate::network",
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
fn sync_event_module_does_not_use_session_message_vocabulary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sync_root = root.join("src/event_modules/sync");
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
        "src/pipeline.rs",
        "src/store.rs",
        "src/network.rs",
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
        "sync protocol logic belongs in event_modules/sync:\n{}",
        violations.join("\n")
    );
}

#[test]
fn core_storage_and_transport_do_not_own_connection_or_bootstrap_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = ["src/store.rs", "src/network.rs"];
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
        "connection/bootstrap storage belongs in event_modules/connection:\n{}",
        violations.join("\n")
    );
}
