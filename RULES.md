# Rules

- Never use fake, placeholder, toy, XOR, commitment-only, label-derived, or hash-only encryption in code or tests that claim encryption, secrecy, forward secrecy, or recoverability. Use real cryptographic primitives and prove behavior with decrypt and negative-decrypt tests, or explicitly mark the code as non-cryptographic and avoid security claims.
- Keep event module pieces split into their own files. Wire/codec layout, projectors, commands, tests, and related module concerns should live in dedicated files such as `wire.rs`/`codec.rs`, `projector.rs`, and `commands.rs` instead of being bundled into one catch-all module file.
