# Topo POC Rewrite

This worktree is a small rewrite experiment for the POC kernel.

The live crate surface is intentionally narrow:

```text
src/pipeline.rs       canonical events, dependency blocking, projector apply
src/control_loop.rs   bounded scheduling over generic queues
src/network.rs        per-connection outbox draining and frame send
src/event_modules/    toy event modules with pure projectors
src/main.rs           CLI adapter over the new pipeline
```

The CLI is the first external contract:

```bash
cargo run -- --db demo.db create-workspace --workspace-name demo
cargo run -- --db demo.db send "hello"
cargo run -- --db demo.db view
cargo run -- --db demo.db status
```

Run the current validation set with:

```bash
cargo test
```
