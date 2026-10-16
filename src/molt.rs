use crate::agents;
use crate::crucible::{self, Outcome};
use crate::peering;
use crate::seed::Seed;
use crate::store::{self, PatchEnvelope, Store};
use anyhow::{bail, Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

pub struct Runtime {
    seed: Seed,
    store: Store,
}

impl Runtime {
    pub fn open() -> Result<Self> {
        let seed = Seed::load()?;
        let store = Store::open(&seed)?;
        let runtime = Self { seed, store };
        runtime.verify_integrity()?;
        Ok(runtime)
    }

    pub fn verify(&self) -> Result<()> {
        let (audit, patches) = self.verify_integrity()?;
        println!(
            "Audit events: {}; signed patches: {patches}",
            audit.event_count
        );
        println!("Audit chain head SHA-256: {}", audit.head_hash);
        println!("Record this head outside the runtime directory as an external checkpoint.");
        Ok(())
    }

    fn verify_integrity(&self) -> Result<(store::AuditVerification, usize)> {
        let audit = self.store.verify_audit_log(&self.seed)?;
        let patches = self.store.verify_patch_records(&self.seed)?;
        self.store.verify_state_consistency(&self.seed)?;
        Ok((audit, patches))
    }

    pub fn status(&self) -> Result<()> {
        let tasks = self.store.tasks()?;
        let patches = self.store.patches()?;
        println!("Runtime: {}", self.seed.home.display());
        println!(
            "Seed: v{} | cluster {} | node {} ({}) | sandbox required | generated-code network disabled | max {} MiB",
            self.seed.config.seed.version,
            self.seed.cluster_id,
            self.seed.node_id,
            self.seed.role,
            self.seed.config.invariants.max_memory_mb
        );
        if tasks.is_empty() {
            println!("Tasks: none");
        } else {
            println!("Tasks:");
            for task in tasks {
                println!(
                    "  {} [{} / {}] {}",
                    task.id, task.role, task.status, task.description
                );
            }
        }
        if patches.is_empty() {
            println!("Patches: none");
        } else {
            println!("Patches:");
            for patch in patches {
                println!("  {} [{}] task={}", patch.id, patch.status, patch.task_id);
                if let Some(report) = patch
                    .report_json
                    .as_deref()
                    .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
                {
                    if let Some(note) = report.get("note").and_then(serde_json::Value::as_str) {
                        println!("    Crucible: {note}");
                    }
                }
            }
        }
        Ok(())
    }

    pub fn export_root_context(&self, output: &Path) -> Result<()> {
        peering::export_root_context(&self.seed, output)?;
        Ok(())
    }

    pub fn register_peer(&mut self, bundle_path: &Path) -> Result<()> {
        let issued = peering::read_issued_peer(&self.seed, bundle_path)?;
        if issued.request.body.node_id == self.seed.node_id {
            bail!("A node cannot register itself as a peer");
        }
        let payload = serde_json::json!({
            "node_id": issued.request.body.node_id,
            "role": issued.request.body.role,
            "key_fingerprint": issued.key_fingerprint,
            "request": issued.request,
            "certificate": issued.certificate,
        });
        self.store
            .record_peer_identity(&self.seed, &issued.request.body.node_id, payload)?;
        println!(
            "Registered root-authorized peer {} ({}) in the signed audit log.",
            issued.request.body.node_id, issued.request.body.role
        );
        println!("This records trust only; it does not start a network listener or enable synchronization.");
        Ok(())
    }

    pub fn bench_sign_suite(
        &mut self,
        manifest: &Path,
        held_out_dir: &Path,
        output: &Path,
    ) -> Result<()> {
        crate::bench::sign_suite(&self.seed, &mut self.store, manifest, held_out_dir, output)?;
        println!("Signed benchmark suite saved to {}", output.display());
        Ok(())
    }

    pub fn bench_propose(
        &mut self,
        suite_path: &Path,
        task_id: &str,
        iteration: u64,
        context_patch_ids: &[String],
        output: &Path,
    ) -> Result<()> {
        if context_patch_ids.len() > 64 {
            bail!("At most 64 previously approved patches may be provided as context");
        }
        self.store.verify_patch_records(&self.seed)?;
        let mut unique = std::collections::HashSet::new();
        let mut context = String::new();
        for patch_id in context_patch_ids {
            let canonical = Uuid::parse_str(patch_id)?.to_string();
            if canonical != *patch_id || !unique.insert(patch_id) {
                bail!("Context patch IDs must be unique canonical UUIDs");
            }
            let patch = self.store.patch(patch_id)?;
            if patch.status != "approved" {
                bail!("Benchmark context may include approved patches only");
            }
            let source_path = self
                .seed
                .home
                .join("approved")
                .join(format!("{patch_id}.rs"));
            let source = fs::read_to_string(&source_path).with_context(|| {
                format!("Cannot read approved context {}", source_path.display())
            })?;
            if store::sha256(source.as_bytes()) != patch.source_sha256 {
                bail!("Approved context patch {patch_id} no longer matches its signed digest");
            }
            context.push_str(&format!("\n\nApproved patch {patch_id}:\n"));
            context.push_str(&source);
            if context.len() > 256 * 1024 {
                bail!("Approved benchmark context exceeds 256 KiB");
            }
        }
        let mut bench_context = crate::bench::BenchContext {
            seed: &self.seed,
            store: &mut self.store,
        };
        crate::bench::propose_source(
            &mut bench_context,
            suite_path,
            task_id,
            iteration,
            context_patch_ids,
            &context,
            output,
        )?;
        Ok(())
    }

    pub fn bench_score(
        &mut self,
        suite_path: &Path,
        held_out_dir: &Path,
        task_id: &str,
        iteration: u64,
        context_patch_ids: &[String],
        source: &Path,
    ) -> Result<()> {
        let mut bench_context = crate::bench::BenchContext {
            seed: &self.seed,
            store: &mut self.store,
        };
        crate::bench::score_source(
            &mut bench_context,
            suite_path,
            held_out_dir,
            task_id,
            iteration,
            context_patch_ids,
            source,
        )?;
        Ok(())
    }

    pub fn bench_export_csv(&self, output: &Path) -> Result<()> {
        crate::bench::export_audit_csv(&self.store, &self.seed, output)
    }

    pub fn plan(&mut self, objective: &str) -> Result<()> {
        let drafts = agents::plan(objective)?;
        let ids = self.store.create_tasks(&self.seed, &drafts)?;
        println!("Created signed, append-only task DAG:");
        for (index, (id, draft)) in ids.iter().zip(drafts.iter()).enumerate() {
            let dependency_ids: Vec<&String> =
                draft.dependencies.iter().map(|&dep| &ids[dep]).collect();
            println!(
                "  {} {} [{}] deps={:?} — {}",
                index + 1,
                id,
                draft.role,
                dependency_ids,
                draft.description
            );
        }
        println!("Each generated patch remains inert until it passes the real Crucible sandbox and you run `molt approve <patch-id>`. Approval stages files only; it does not hot-swap or execute them in the live runtime.");
        Ok(())
    }

    pub fn work(&mut self, task_id: &str) -> Result<()> {
        Uuid::parse_str(task_id).context("Task ID must be a UUID")?;
        let task = self.store.task(task_id)?;
        if task.status != "planned" {
            bail!("Task is {}, not planned", task.status);
        }
        if task.role != "Engineer" {
            bail!("Task role is {}; only Engineer tasks produce Rust patches. Auditor checks are performed by the local Crucible, not delegated to a model", task.role);
        }
        if !self.store.dependencies_approved(&task)? {
            bail!("Task dependencies must all be approved before engineering can start");
        }
        let generated = agents::generate_code(&task.description)?;
        if generated.source.len() > self.seed.config.invariants.max_source_bytes
            || generated.tests.len() > self.seed.config.invariants.max_test_bytes
        {
            bail!("Generated source or tests exceed the signed seed size limit");
        }
        let patch_id = Uuid::new_v4().to_string();
        let patch_dir = self.seed.home.join("patches");
        create_private_dir(&patch_dir)?;
        let source_path = patch_dir.join(format!("{patch_id}.rs"));
        let tests_path = patch_dir.join(format!("{patch_id}.tests.rs"));
        write_new_private(&source_path, generated.source.as_bytes())?;
        if let Err(error) = write_new_private(&tests_path, generated.tests.as_bytes()) {
            let _ = fs::remove_file(&source_path);
            return Err(error);
        }
        let envelope = PatchEnvelope {
            patch_id: patch_id.clone(),
            task_id: task.id.clone(),
            source_sha256: store::sha256(generated.source.as_bytes()),
            tests_sha256: store::sha256(generated.tests.as_bytes()),
            root_public_key: self.seed.root_public_key_hex(),
        };
        let envelope_json = serde_json::to_string(&envelope)?;
        let signature = hex::encode(self.seed.sign(envelope_json.as_bytes()).to_bytes());
        if let Err(error) = self.store.insert_patch(&self.seed, &envelope, &signature) {
            let _ = fs::remove_file(&source_path);
            let _ = fs::remove_file(&tests_path);
            return Err(error);
        }
        println!("Proposed signed patch {patch_id} for task {task_id}; source is inert and has not been run.\nRun `molt crucible {patch_id}` to parse, compile, and test it inside bubblewrap with network isolation. If this host cannot provide that sandbox, the patch will be blocked rather than tested unsafely.");
        Ok(())
    }

    pub fn crucible(&mut self, patch_id: &str) -> Result<()> {
        Uuid::parse_str(patch_id).context("Patch ID must be a UUID")?;
        self.store.verify_patch_records(&self.seed)?;
        let patch = self.store.patch(patch_id)?;
        if patch.status == "approved" {
            bail!("Approved patches are immutable and cannot be re-evaluated");
        }
        let (source, tests) = self.read_patch_files(&patch.id)?;
        let report = crucible::evaluate(&self.seed, &source, &tests)?;
        let status = match report.outcome {
            Outcome::Passed => "passed",
            Outcome::Rejected => "rejected",
            Outcome::Blocked => "blocked",
        };
        let report_json = serde_json::to_value(&report)?;
        self.store
            .set_crucible_report(&self.seed, patch_id, status, &report_json)?;
        println!(
            "{}: {}\n{}",
            status.to_ascii_uppercase(),
            patch_id,
            serde_json::to_string_pretty(&report_json)?
        );
        Ok(())
    }

    pub fn approve(&mut self, patch_id: &str) -> Result<()> {
        Uuid::parse_str(patch_id).context("Patch ID must be a UUID")?;
        self.store.verify_patch_records(&self.seed)?;
        let patch = self.store.patch(patch_id)?;
        if patch.status != "passed" {
            bail!(
                "Patch must pass the Crucible before approval; current state is {}",
                patch.status
            );
        }
        let (source, tests) = self.read_patch_files(patch_id)?;
        if store::sha256(source.as_bytes()) != patch.source_sha256
            || store::sha256(tests.as_bytes()) != patch.tests_sha256
        {
            bail!("Patch bytes no longer match their signed hashes");
        }
        let signature = ed25519_dalek::Signature::from_bytes(&decode_signature(&patch.signature)?);
        self.seed
            .verifying_key
            .verify_strict(patch.envelope_json.as_bytes(), &signature)
            .context("Patch signature verification failed")?;
        let approved_dir = self.seed.home.join("approved");
        create_private_dir(&approved_dir)?;
        let final_source = approved_dir.join(format!("{patch_id}.rs"));
        let final_tests = approved_dir.join(format!("{patch_id}.tests.rs"));
        if final_source.exists() || final_tests.exists() {
            bail!("Approved output already exists; refusing to overwrite files");
        }
        atomic_new(&final_source, source.as_bytes())?;
        if let Err(error) = atomic_new(&final_tests, tests.as_bytes()) {
            let _ = fs::remove_file(&final_source);
            return Err(error);
        }
        if let Err(error) = self.store.approve_patch(&self.seed, patch_id) {
            let _ = fs::remove_file(&final_source);
            let _ = fs::remove_file(&final_tests);
            return Err(error);
        }
        println!("Approved and staged signed patch {patch_id} in {}. No deployment, hot-swap, or automatic execution occurred.", approved_dir.display());
        Ok(())
    }

    fn read_patch_files(&self, patch_id: &str) -> Result<(String, String)> {
        let id = Uuid::parse_str(patch_id)?.to_string();
        let dir = self.seed.home.join("patches");
        let source = fs::read_to_string(dir.join(format!("{id}.rs")))
            .context("Cannot read proposed Rust source")?;
        let tests = fs::read_to_string(dir.join(format!("{id}.tests.rs")))
            .context("Cannot read proposed tests")?;
        Ok((source, tests))
    }
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("Cannot create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("Cannot create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn atomic_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    write_new_private(&temp, bytes)?;
    fs::rename(&temp, path).with_context(|| format!("Cannot stage {}", path.display()))?;
    Ok(())
}

fn decode_signature(text: &str) -> Result<[u8; 64]> {
    let bytes = hex::decode(text)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Malformed patch signature"))
}
