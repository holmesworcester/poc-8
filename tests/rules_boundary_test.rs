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
fn core_files_do_not_contain_sync_protocol_logic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = ["src/main.rs", "src/store.rs", "src/network.rs"];
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
