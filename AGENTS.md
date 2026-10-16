# MOLT Genesis project guidance

- Read `README.md` before changing behavior. It documents the implemented scope and known host limitations.
- Preserve fail-closed execution: generated source/tests may run only through the Crucible bubblewrap sandbox. Never add an unsandboxed fallback or automatic deployment/hot-swap.
- Keep seed/artifact signatures, append-only audit verification, and event-replayed database state checks intact. A pass is not a proof of safety.
- Do not add placeholder Supermolt, Raft, CRDT, Tailscale, or Firecracker behavior. Mark infrastructure-dependent features as unimplemented until they are real and testable.
- Validate with `cargo fmt --check`, `cargo test --locked`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo build --release --locked`.
