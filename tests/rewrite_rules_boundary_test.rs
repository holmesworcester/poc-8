use std::path::Path;

fn read_rs_files(root: &Path) -> Vec<(std::path::PathBuf, String)> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).expect("read dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path).expect("read source file");
                files.push((path, text));
            }
        }
    }
    files
}

#[test]
fn event_modules_do_not_import_old_core_or_storage() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/event_modules");
    let forbidden = ["crate::runtime", "crate::state", "rusqlite", "Transaction"];

    let mut violations = Vec::new();
    for (path, text) in read_rs_files(&root) {
        for needle in forbidden {
            if text.contains(needle) {
                violations.push(format!("{} contains `{needle}`", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "event modules must target the clean kernel contract:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_modules_do_not_use_event_rs_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/event_modules");
    let offenders = read_rs_files(&root)
        .into_iter()
        .map(|(path, _)| path)
        .filter(|path| path.file_name().is_some_and(|name| name == "event.rs"))
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "event structs belong in codec.rs, not event.rs:\n{}",
        offenders
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn event_modules_are_directories_not_collapsed_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/event_modules");
    let offenders = std::fs::read_dir(&root)
        .expect("read event_modules")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| {
            !path
                .file_name()
                .is_some_and(|name| name == "mod.rs" || name == "codec.rs")
        })
        .collect::<Vec<_>>();

    assert!(
        offenders.is_empty(),
        "event modules must be directories with codec/commands/projector files:\n{}",
        offenders
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn kernel_files_do_not_contain_sync_protocol_semantics() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let kernel_files = ["src/pipeline.rs", "src/control_loop.rs", "src/network.rs"];
    let forbidden = [
        "negentropy",
        "SyncCompare",
        "SyncHave",
        "SyncNeed",
        "sync_compare",
        "sync_have",
        "sync_need",
        "compare/have/need",
    ];

    let mut violations = Vec::new();
    for relative in kernel_files {
        let path = manifest_dir.join(relative);
        let text = std::fs::read_to_string(&path).expect("read kernel file");
        for needle in forbidden {
            if text.contains(needle) {
                violations.push(format!("{relative} contains `{needle}`"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "kernel files must stay protocol-agnostic; sync belongs in event modules:\n{}",
        violations.join("\n")
    );
}
