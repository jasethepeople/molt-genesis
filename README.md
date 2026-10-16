# MOLT Genesis

MOLT Genesis is a local Rust runtime for signed task planning, model-assisted code proposals, fail-closed validation, offline-root peer identity provisioning, and signed benchmark measurements. It is deliberately bounded: this is not a simulated cluster, autonomous self-rewriting kernel, or live production deployment system.

## Implemented

- `molt init --root-key-out PATH` creates the seed, a distinct runtime-node key, and signed genesis state. The root private key is written directly to the required external path, never into `MOLT_HOME`.
- Every command except initialization requires the independently recorded `MOLT_TRUSTED_ROOT_SHA256`. Root pinning is checked before seed or bundle parsing; missing, malformed, or mismatched pins fail closed.
- `molt plan`, `molt work`, `molt crucible`, and `molt approve` implement a signed task/proposal pipeline. Generated source is inert until tested and approved by a person; approval stages a file and never hot-swaps code.
- Crucible parses candidate Rust, rejects unsafe constructs, FFI, mutable statics, process APIs, and user-defined macros, then uses bubblewrap with private user/PID/network/mount namespaces, a dropped UID/GID, read-only inputs, bounded temporary files, process limits, a wall timeout, and bounded output capture. If isolation setup fails, the candidate is recorded as blocked; there is no unsandboxed fallback.
- Peer provisioning is a real proof-of-possession flow. The target creates and keeps its node private key; an offline root signs a fresh, root-pinned request; the primary records the certificate in the signed append-only SQLite event log; and the target verifies the cluster/seed binding and installs the certificate. Replayed nonces and changed keys for an existing node ID are rejected. Installed peer certificates are re-verified at startup.
- `molt bench` signs a suite containing public prompts/tests and hashes of private held-out tests, requests candidates using public information only, scores them with the real Crucible, and stores signed score records in the same audit log. If the public Crucible run fails or is blocked, held-out tests are not read. There is no mock scorer or automatic approval loop.
- `molt verify` replays the signed event history, verifies the hash chain and artifacts, and prints the chain-head hash for recording outside the runtime directory.

## Build and initialize

Requires stable Rust and Linux. Crucible needs bubblewrap, a compatible `rustc` on `PATH`, and kernel support for its isolation namespaces. A model API key is only needed for planning, work, or benchmark proposals.

Build with the committed dependency lock:

```sh
cargo build --release --locked
```

Initialize using a root-key destination outside `MOLT_HOME`—ideally removable storage that can be taken offline:

```sh
./target/release/molt init --root-key-out /media/offline/root.key
```

Record the printed SHA-256 fingerprint separately before enrolling any peers; do not use a bundle or local `root.pub` as the trust-on-first-use source. Export it as `MOLT_TRUSTED_ROOT_SHA256` for every subsequent command. Keep independent offline backups of `root.key`. MOLT uses the separately certified `node.key` during ordinary operation and does not need the root key.

```sh
export MOLT_TRUSTED_ROOT_SHA256='<fingerprint printed by init>'
./target/release/molt verify
./target/release/molt status
./target/release/molt plan "Add a bounded CSV parser with clear error handling"
```

Copy a task UUID printed by `plan` into `TASK_ID` before using these commands (the angle-bracket form is not shell syntax):

```sh
TASK_ID='<task UUID>'
./target/release/molt work "$TASK_ID"
```

Use the printed patch UUID similarly:

```sh
PATCH_ID='<patch UUID>'
./target/release/molt crucible "$PATCH_ID"
./target/release/molt approve "$PATCH_ID"
```

## Offline-root peer provisioning

This provisions identities only; it does not start a network listener or replicate state. Each target generates its own Ed25519 key. Bundles contain public data, so confidentiality is unnecessary; signature, root pin, cluster/seed binding, role, freshness, and proof-of-possession are verified.

1. On the initialized primary, export the public signing context. It contains no private keys:
   ```sh
   molt peer export-root-context --output /media/offline/molt-root-context
   ```
2. On each target, create a local request using the fingerprint recorded independently from initialization:
   ```sh
   molt peer request --node-id node-edge-pi-1 --role validator --root-fingerprint "$MOLT_TRUSTED_ROOT_SHA256"
   ```
   Transfer `node.request.json` to the offline signer. Never transfer `node.key`.
3. On the offline signer, point `MOLT_HOME` at the exported public context, set the same independently recorded root pin, and sign with the offline `root.key`:
   ```sh
   MOLT_HOME=/media/offline/molt-root-context MOLT_TRUSTED_ROOT_SHA256='<recorded fingerprint>' molt peer sign --request /media/in/node.request.json --root-key /media/offline/root.key --bundle /media/out/node-edge-pi-1.bundle
   ```
4. On the primary, register the public bundle in the signed audit history; record the resulting audit-chain head outside `MOLT_HOME`:
   ```sh
   molt peer register --bundle /media/in/node-edge-pi-1.bundle
   molt verify
   ```
5. On the target, join with the same independent pin:
   ```sh
   molt peer join --bundle /media/in/node-edge-pi-1.bundle
   molt verify
   ```

Repeat with a distinct node ID for other peers. Roles are signed attestations; no scheduler or network service consumes them yet. The signer checks its own root pin and does not trust a fingerprint supplied only by the request. This release has no key rotation or revocation command: a compromised node key cannot be revoked, and a lost root key cannot issue replacements. Root-signed revocation and expiry are not implemented.

## Signed benchmark workflow

Keep held-out tests outside `MOLT_HOME` in a private directory (directory mode `0700`; each test file mode `0600`). Create a JSON manifest with `version: 1` and a `tasks` array. Each task has `id`, `prompt`, `public_tests`, and positive integer `weight_milli`; place its held-out Rust test source at `<held-out-dir>/<id>.rs`. The suite stores only each held-out file's SHA-256 digest, never its contents.

1. Sign and audit the suite:
   ```sh
   molt bench sign-suite --manifest /path/tasks.json --held-out-dir /secure/held-out --output /path/suite.json
   ```
2. Generate one candidate. The proposer receives the prompt, public tests, and only explicitly named, human-approved context patches. E0 uses no context; E1 can include approved patches with repeated `--context-patch` options:
   ```sh
   molt bench propose --suite /path/suite.json --task-id TASK_ID --iteration 0 --output /path/candidate.rs
   ```
3. Score that exact, audit-recorded candidate. The real Crucible runs public tests first; held-out tests are accessed only after the public run passes:
   ```sh
   molt bench score --suite /path/suite.json --held-out-dir /secure/held-out --task-id TASK_ID --iteration 0 --source /path/candidate.rs
   ```
   Use the same iteration and context-patch IDs used for proposal. Iterations are unique per suite/task. `passed`, `failed`, `blocked`, and `not_run` are distinct recorded outcomes. A blocked sandbox never triggers a fallback.
4. Export signed records for analysis:
   ```sh
   molt bench export-csv --output /path/scores.csv
   ```

No experiment is run automatically; the model call, Crucible execution, and approval remain separate steps. This host's gVisor currently prevents bubblewrap from creating the required network namespace (`RTM_NEWADDR`), and no Tailscale installation or remote nodes are available. Crucible correctly reports blocked here, so held-out scoring cannot produce a result on this host until the isolation prerequisites are genuinely available.

## Model provider

Set `MOLT_API_KEY` or `OPENAI_API_KEY`; `MOLT_API_KEY` takes precedence if both are set. Optional settings are `MOLT_MODEL` (default `gpt-4.1-mini`) and `MOLT_OPENAI_BASE_URL` (default `https://api.openai.com/v1`). Non-loopback endpoints must use HTTPS. Model requests send objective/task text and run outside the generated-code sandbox. Model output is untrusted; a signature establishes provenance, not correctness. Only a human may approve a passed patch.

## Boundaries and recovery

There is no live kernel replacement, automatic promotion, autonomous recursive modification, Tailscale transport, peer listener, Raft, CRDT, distributed scheduler, hardware discovery, Firecracker, or host-wide cgroup enforcement. Peer identity provisioning does not claim transport or quorum.

A passing test suite does not prove the program safe, and it does not prove the sandbox held; those are separate claims. `molt verify` establishes cryptographic provenance, internal audit-chain consistency, and agreement between replayed state and the signed log—not code correctness or node trustworthiness. Record the reported chain head externally to detect later truncation or replacement. A compromised runtime-node key can still append events; root-signed external checkpoints are not implemented.

There is no backup/restore command. Stop the runtime before copying its data directory; do not edit audit rows by hand. A lost root key prevents authorizing replacements. There is no revocation list, key rotation, or certificate expiry, so rebuilding with a fresh key does not mark old certificates revoked.

## Checks

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
```
