# Rewrite Tests

Functional coverage is CLI black-box coverage. Tests should run the real
`topo` binary and, for sync or transport behavior, move bytes over real sockets.

Pure projector or module command tests may exist as local checks, and static
boundary tests may enforce source-level rules. They do not prove product
functionality.
