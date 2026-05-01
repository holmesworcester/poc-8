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
