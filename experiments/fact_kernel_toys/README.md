# Fact kernel toy variants

This experiment plays out three kernel structures against the same toy workload:

```
MessageCreated(A)
MessageCreated(B, deps=[A])
MessageDeleted(B)
Have(A)
Need(B)
```

The workload exercises the core design questions:

- canonical facts vs event-only language,
- blocking on missing dependencies,
- bounded unblocking after a dependency appears,
- negative semantics as tombstone facts,
- bounded sweeps over existing projections,
- queue rows as obligations,
- deterministic simulation and traceability.

The variants:

1. `variants/01_event_pipeline.md` keeps the current event-pipeline vocabulary.
2. `variants/02_fact_roles.md` uses semantic modules that own fact roles.
3. `variants/03_stage_projectors.md` makes pipeline stages projector-shaped modules.

Evaluation criteria:

- readability of the mental model,
- concision of module and table definitions,
- whether blocking/unblocking needs special kernel logic,
- whether deletes/removals stay monotone,
- how naturally large writes become bounded work,
- how well the structure supports deterministic simulation.
