use crate::agents;
use crate::crucible::{self, Outcome};
use crate::seed::{self, Seed};
use crate::store::Store;
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_SUITE_TASKS: usize = 100;
const MAX_TEST_BYTES: usize = 64 * 1024;
const DOMAIN_SUITE: &[u8] = b"MOLT-bench-suite-v1\0";
const DOMAIN_SCORE: &[u8] = b"MOLT-bench-score-v1\0";

pub struct BenchContext<'a> {
    pub seed: &'a Seed,
    pub store: &'a mut Store,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskManifest {
    pub id: String,
    pub prompt: String,
    pub public_tests: String,
    pub weight_milli: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub tasks: Vec<TaskManifest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuiteTask {
    pub id: String,
    pub prompt: String,
    pub public_tests: String,
    pub held_out_sha256: String,
    pub weight_milli: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedSuite {
    pub version: u32,
    pub cluster_id: String,
    pub root_fingerprint: String,
    pub node_id: String,
    pub node_public_key: String,
    pub tasks: Vec<SuiteTask>,
    pub signature: String,
}

impl SignedSuite {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DOMAIN_SUITE);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        write_str(&mut bytes, &self.cluster_id)?;
        write_str(&mut bytes, &self.root_fingerprint)?;
        write_str(&mut bytes, &self.node_id)?;
        bytes.extend_from_slice(&seed::decode_fixed::<32>(
            &self.node_public_key,
            "suite node public key",
        )?);
        let count = u32::try_from(self.tasks.len()).context("Too many benchmark tasks")?;
        bytes.extend_from_slice(&count.to_le_bytes());
        for task in &self.tasks {
            write_str(&mut bytes, &task.id)?;
            write_str(&mut bytes, &task.prompt)?;
            write_str(&mut bytes, &task.public_tests)?;
            bytes.extend_from_slice(&seed::decode_fixed::<32>(
                &task.held_out_sha256,
                "held-out test digest",
            )?);
            bytes.extend_from_slice(&task.weight_milli.to_le_bytes());
        }
        Ok(bytes)
    }

    pub fn verify(&self, seed: &Seed) -> Result<()> {
        if self.version != 1
            || self.cluster_id != seed.cluster_id
            || self.root_fingerprint != seed.root_fingerprint_sha256()
            || self.node_id != seed.node_id
            || self.node_public_key != seed.node_public_key_hex()
            || self.tasks.is_empty()
            || self.tasks.len() > MAX_SUITE_TASKS
        {
            bail!("Benchmark suite is not bound to this pinned MOLT node and cluster");
        }
        validate_tasks(&self.tasks)?;
        let signature = seed::decode_fixed::<64>(&self.signature, "benchmark suite signature")?;
        seed.verifying_key
            .verify_strict(&self.canonical_bytes()?, &Signature::from_bytes(&signature))
            .context("Benchmark suite signature verification failed")
    }

    pub fn sha256(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreOutcome {
    Passed,
    Failed,
    Blocked,
    NotRun,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreRecord {
    pub score_id: String,
    pub suite_sha256: String,
    pub task_id: String,
    pub iteration: u64,
    pub weight_milli: u32,
    pub context_patch_ids: Vec<String>,
    pub candidate_sha256: String,
    pub public_outcome: ScoreOutcome,
    pub held_out_outcome: ScoreOutcome,
    pub timestamp_unix_ms: u64,
    pub node_public_key: String,
    pub signature: String,
}

impl ScoreRecord {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DOMAIN_SCORE);
        write_str(&mut bytes, &self.score_id)?;
        write_str(&mut bytes, &self.suite_sha256)?;
        write_str(&mut bytes, &self.task_id)?;
        bytes.extend_from_slice(&self.iteration.to_le_bytes());
        bytes.extend_from_slice(&self.weight_milli.to_le_bytes());
        let context_count = u32::try_from(self.context_patch_ids.len())
            .context("Too many approved context patches")?;
        bytes.extend_from_slice(&context_count.to_le_bytes());
        for patch_id in &self.context_patch_ids {
            write_str(&mut bytes, patch_id)?;
        }
        write_str(&mut bytes, &self.candidate_sha256)?;
        bytes.push(outcome_tag(self.public_outcome));
        bytes.push(outcome_tag(self.held_out_outcome));
        bytes.extend_from_slice(&self.timestamp_unix_ms.to_le_bytes());
        bytes.extend_from_slice(&seed::decode_fixed::<32>(
            &self.node_public_key,
            "score node public key",
        )?);
        Ok(bytes)
    }

    pub fn verify(&self, seed: &Seed) -> Result<()> {
        if Uuid::parse_str(&self.score_id)?.to_string() != self.score_id
            || self.node_public_key != seed.node_public_key_hex()
            || !is_digest(&self.suite_sha256)
            || !is_digest(&self.candidate_sha256)
            || self.weight_milli == 0
            || self.weight_milli > 100_000
            || self.context_patch_ids.len() > 64
            || self
                .context_patch_ids
                .iter()
                .any(|id| Uuid::parse_str(id).is_err())
        {
            bail!("Malformed or foreign benchmark score record");
        }
        let signature = seed::decode_fixed::<64>(&self.signature, "benchmark score signature")?;
        seed.verifying_key
            .verify_strict(&self.canonical_bytes()?, &Signature::from_bytes(&signature))
            .context("Benchmark score signature verification failed")
    }

    fn sign(mut self, key: &SigningKey) -> Result<Self> {
        self.node_public_key = hex::encode(key.verifying_key().as_bytes());
        self.signature = hex::encode(key.sign(&self.canonical_bytes()?).to_bytes());
        Ok(self)
    }
}

pub fn sign_suite(
    seed: &Seed,
    store: &mut Store,
    manifest_path: &Path,
    held_out_dir: &Path,
    output_path: &Path,
) -> Result<SignedSuite> {
    seed::reject_symlink_dir(held_out_dir)?;
    let held_out_dir = fs::canonicalize(held_out_dir).with_context(|| {
        format!(
            "Cannot access held-out directory {}",
            held_out_dir.display()
        )
    })?;
    seed::verify_private_dir(&held_out_dir)?;
    let runtime = fs::canonicalize(&seed.home)?;
    if held_out_dir.starts_with(&runtime) {
        bail!("Held-out tests must be outside MOLT_HOME");
    }
    let manifest_bytes = read_regular_file(manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .context("Benchmark manifest must be strict JSON with only version and public tasks")?;
    if manifest.version != 1 || manifest.tasks.is_empty() || manifest.tasks.len() > MAX_SUITE_TASKS
    {
        bail!("Benchmark manifest version must be 1 and contain 1-100 tasks");
    }
    let mut tasks = Vec::with_capacity(manifest.tasks.len());
    for task in manifest.tasks {
        validate_task(
            &task.id,
            &task.prompt,
            &task.public_tests,
            task.weight_milli,
        )?;
        let held_out_path = held_out_dir.join(format!("{}.rs", task.id));
        let held_out = seed::read_private_file(&held_out_path, MAX_TEST_BYTES, "held-out tests")?;
        std::str::from_utf8(&held_out).context("Held-out tests must be UTF-8 Rust source")?;
        tasks.push(SuiteTask {
            id: task.id,
            prompt: task.prompt,
            public_tests: task.public_tests,
            held_out_sha256: hex::encode(Sha256::digest(&held_out)),
            weight_milli: task.weight_milli,
        });
    }
    validate_tasks(&tasks)?;
    let mut suite = SignedSuite {
        version: 1,
        cluster_id: seed.cluster_id.clone(),
        root_fingerprint: seed.root_fingerprint_sha256(),
        node_id: seed.node_id.clone(),
        node_public_key: seed.node_public_key_hex(),
        tasks,
        signature: String::new(),
    };
    suite.signature = hex::encode(seed.sign(&suite.canonical_bytes()?).to_bytes());
    suite.verify(seed)?;
    let serialized = serde_json::to_vec_pretty(&suite)?;
    create_new_file(output_path, &serialized)?;
    let hash = suite.sha256()?;
    if let Err(error) = store.record(
        seed,
        "benchmark_suite_signed",
        serde_json::json!({
            "suite_sha256": hash,
            "task_count": suite.tasks.len(),
            "node_public_key": suite.node_public_key,
            "suite": &suite,
        }),
    ) {
        let _ = fs::remove_file(output_path);
        return Err(error);
    }
    println!("Signed benchmark suite {} with {} tasks. Held-out test contents were not put in the suite, model request, or audit log.", hash, suite.tasks.len());
    Ok(suite)
}

pub fn load_signed_suite(seed: &Seed, suite_path: &Path) -> Result<SignedSuite> {
    let bytes = read_regular_file(suite_path, MAX_MANIFEST_BYTES)?;
    let suite: SignedSuite =
        serde_json::from_slice(&bytes).context("Invalid signed benchmark suite")?;
    suite.verify(seed)?;
    Ok(suite)
}

pub fn propose_source(
    context: &mut BenchContext<'_>,
    suite_path: &Path,
    task_id: &str,
    iteration: u64,
    context_patch_ids: &[String],
    approved_context: &str,
    output_path: &Path,
) -> Result<String> {
    let seed = context.seed;
    let store = &mut *context.store;
    if context_patch_ids.len() > 64
        || context_patch_ids
            .iter()
            .any(|id| Uuid::parse_str(id).is_err())
        || approved_context.len() > 256 * 1024
    {
        bail!("Benchmark proposer context is malformed or exceeds its signed limits");
    }
    let suite = load_signed_suite(seed, suite_path)?;
    let suite_hash = suite.sha256()?;
    if !store.benchmark_suite_signed(&suite_hash)? {
        bail!("Benchmark suite is not recorded in this runtime's signed audit history");
    }
    if store.benchmark_iteration_exists(&suite_hash, task_id, iteration)? {
        bail!("This suite task already has a proposal for iteration {iteration}");
    }
    let task = suite
        .tasks
        .iter()
        .find(|task| task.id == task_id)
        .context("Task ID is not present in the signed benchmark suite")?;
    let description = format!(
        "{}\n\nPublic tests (the held-out tests are not available to you):\n{}\n\nPreviously approved code context (empty in E0):\n{}",
        task.prompt, task.public_tests, approved_context
    );
    let generated = agents::generate_code(&description)?;
    if generated.source.len() > seed.config.invariants.max_source_bytes {
        bail!("Generated benchmark source exceeds the signed source-size limit");
    }
    create_new_file(output_path, generated.source.as_bytes())?;
    let candidate_sha256 = hex::encode(Sha256::digest(generated.source.as_bytes()));
    let payload = serde_json::json!({
        "suite_sha256": suite_hash,
        "task_id": task.id,
        "iteration": iteration,
        "candidate_sha256": candidate_sha256,
        "context_patch_ids": context_patch_ids,
    });
    if let Err(error) = store.record(seed, "benchmark_candidate_proposed", payload) {
        let _ = fs::remove_file(output_path);
        return Err(error);
    }
    println!(
        "Generated inert benchmark candidate for {} at iteration {} (sha256 {}). Only the public prompt/tests were sent to the model.",
        task.id, iteration, candidate_sha256
    );
    Ok(candidate_sha256)
}

pub fn score_source(
    context: &mut BenchContext<'_>,
    suite_path: &Path,
    held_out_dir: &Path,
    task_id: &str,
    iteration: u64,
    context_patch_ids: &[String],
    source_path: &Path,
) -> Result<ScoreRecord> {
    let seed = context.seed;
    let store = &mut *context.store;
    let suite_bytes = read_regular_file(suite_path, MAX_MANIFEST_BYTES)?;
    let suite: SignedSuite =
        serde_json::from_slice(&suite_bytes).context("Invalid signed benchmark suite")?;
    suite.verify(seed)?;
    let suite_hash = suite.sha256()?;
    if !store.benchmark_suite_signed(&suite_hash)? {
        bail!("Benchmark suite is not recorded in this runtime's signed audit history");
    }
    let task = suite
        .tasks
        .iter()
        .find(|task| task.id == task_id)
        .context("Task ID is not present in the signed benchmark suite")?;
    let source = read_regular_file(source_path, seed.config.invariants.max_source_bytes)?;
    let source_text =
        std::str::from_utf8(&source).context("Candidate source must be UTF-8 Rust")?;
    let source_hash = hex::encode(Sha256::digest(&source));
    if !store.benchmark_candidate_proposed(
        &suite_hash,
        task_id,
        iteration,
        &source_hash,
        context_patch_ids,
    )? {
        bail!("Candidate is not recorded as this task's signed benchmark proposal");
    }
    let public = crucible::evaluate(seed, source_text, &task.public_tests)?;
    let public_outcome = score_outcome(&public.outcome);
    let held_out_outcome = if public_outcome != ScoreOutcome::Passed {
        ScoreOutcome::NotRun
    } else {
        seed::reject_symlink_dir(held_out_dir)?;
        let held_out_dir = fs::canonicalize(held_out_dir).with_context(|| {
            format!(
                "Cannot access held-out directory {}",
                held_out_dir.display()
            )
        })?;
        seed::verify_private_dir(&held_out_dir)?;
        if held_out_dir.starts_with(fs::canonicalize(&seed.home)?) {
            bail!("Held-out tests must be outside MOLT_HOME");
        }
        let held_out_path = held_out_dir.join(format!("{}.rs", task.id));
        let held_out = seed::read_private_file(&held_out_path, MAX_TEST_BYTES, "held-out tests")?;
        if hex::encode(Sha256::digest(&held_out)) != task.held_out_sha256 {
            bail!("Held-out test digest does not match the signed benchmark suite");
        }
        let held_out_text =
            std::str::from_utf8(&held_out).context("Held-out tests must be UTF-8 Rust source")?;
        let held_out_report = crucible::evaluate(seed, source_text, held_out_text)?;
        score_outcome(&held_out_report.outcome)
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?
        .as_millis();
    let timestamp_unix_ms = u64::try_from(now).context("System clock timestamp overflow")?;
    let score = ScoreRecord {
        score_id: Uuid::new_v4().to_string(),
        suite_sha256: suite_hash,
        task_id: task.id.clone(),
        iteration,
        weight_milli: task.weight_milli,
        context_patch_ids: context_patch_ids.to_vec(),
        candidate_sha256: source_hash,
        public_outcome,
        held_out_outcome,
        timestamp_unix_ms,
        node_public_key: String::new(),
        signature: String::new(),
    }
    .sign(&seed.signing_key)?;
    score.verify(seed)?;
    store.record(seed, "benchmark_scored", serde_json::to_value(&score)?)?;
    println!("Benchmark score {}: public={}, held-out={}. A blocked public run does not read held-out tests. No approval or deployment occurred.", score.score_id, format_outcome(score.public_outcome), format_outcome(score.held_out_outcome));
    Ok(score)
}

pub fn export_csv(records: &[ScoreRecord], output: &mut impl Write) -> Result<()> {
    writeln!(output, "score_id,suite_sha256,task_id,iteration,weight_milli,context_patch_ids,candidate_sha256,public_outcome,held_out_outcome,timestamp_unix_ms")?;
    for record in records {
        writeln!(
            output,
            "{},{},{},{},{},{},{},{},{},{}",
            csv(&record.score_id),
            record.suite_sha256,
            csv(&record.task_id),
            record.iteration,
            record.weight_milli,
            csv(&record.context_patch_ids.join(";")),
            record.candidate_sha256,
            format_outcome(record.public_outcome),
            format_outcome(record.held_out_outcome),
            record.timestamp_unix_ms
        )?;
    }
    Ok(())
}

fn validate_tasks(tasks: &[SuiteTask]) -> Result<()> {
    if tasks.is_empty() || tasks.len() > MAX_SUITE_TASKS {
        bail!("Signed benchmark suite must contain 1-100 tasks");
    }
    let mut ids = std::collections::HashSet::new();
    for task in tasks {
        validate_task(
            &task.id,
            &task.prompt,
            &task.public_tests,
            task.weight_milli,
        )?;
        seed::decode_fixed::<32>(&task.held_out_sha256, "held-out test digest")?;
        if !ids.insert(&task.id) {
            bail!("Benchmark task IDs must be unique");
        }
    }
    Ok(())
}

fn validate_task(id: &str, prompt: &str, tests: &str, weight_milli: u32) -> Result<()> {
    if id.is_empty()
        || id.len() > 63
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || prompt.trim().is_empty()
        || prompt.len() > 8_000
        || tests.trim().is_empty()
        || tests.len() > MAX_TEST_BYTES
        || weight_milli == 0
        || weight_milli > 100_000
    {
        bail!("Invalid benchmark task; use a lowercase ID, bounded prompt/tests, and weight 1-100000 milli-units");
    }
    Ok(())
}

fn write_str(out: &mut Vec<u8>, value: &str) -> Result<()> {
    let len = u32::try_from(value.len()).context("Benchmark field is too large")?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn outcome_tag(outcome: ScoreOutcome) -> u8 {
    match outcome {
        ScoreOutcome::Passed => 0,
        ScoreOutcome::Failed => 1,
        ScoreOutcome::Blocked => 2,
        ScoreOutcome::NotRun => 3,
    }
}

fn score_outcome(outcome: &Outcome) -> ScoreOutcome {
    match outcome {
        Outcome::Passed => ScoreOutcome::Passed,
        Outcome::Rejected => ScoreOutcome::Failed,
        Outcome::Blocked => ScoreOutcome::Blocked,
    }
}

fn format_outcome(outcome: ScoreOutcome) -> &'static str {
    match outcome {
        ScoreOutcome::Passed => "passed",
        ScoreOutcome::Failed => "failed",
        ScoreOutcome::Blocked => "blocked",
        ScoreOutcome::NotRun => "not_run",
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn csv(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn read_regular_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("Cannot inspect {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes as u64 {
        bail!(
            "{} must be a regular file no larger than {max_bytes} bytes",
            path.display()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("Cannot read {}", path.display()))?;
    if bytes.len() > max_bytes {
        bail!("{} exceeds {max_bytes} bytes", path.display());
    }
    Ok(bytes)
}

fn create_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        bail!("Refusing to overwrite benchmark suite {}", path.display());
    }
    let mut options = fs::OpenOptions::new();
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

pub fn scores_from_audit(store: &Store, seed: &Seed) -> Result<Vec<ScoreRecord>> {
    let records = store.benchmark_scores(seed)?;
    for record in &records {
        record.verify(seed)?;
    }
    Ok(records)
}

pub fn export_audit_csv(store: &Store, seed: &Seed, output_path: &Path) -> Result<()> {
    let records = scores_from_audit(store, seed)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(output_path)
        .with_context(|| format!("Cannot create benchmark CSV {}", output_path.display()))?;
    if let Err(error) = export_csv(&records, &mut file) {
        let _ = fs::remove_file(output_path);
        return Err(error);
    }
    file.sync_all()?;
    println!(
        "Exported {} signed benchmark score records to {}",
        records.len(),
        output_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    #[test]
    fn signed_suite_scores_only_through_the_real_fail_closed_crucible() {
        let home = std::env::temp_dir().join(format!("molt-bench-test-{}", Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let held_out = std::env::temp_dir().join(format!("molt-heldout-test-{}", Uuid::new_v4()));
        fs::create_dir(&held_out).unwrap();
        fs::set_permissions(&held_out, fs::Permissions::from_mode(0o700)).unwrap();
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let config: crate::seed::SeedConfig =
            toml::from_str(include_str!("../config/seed.toml")).unwrap();
        let seed = Seed {
            home: home.clone(),
            config,
            signing_key,
            verifying_key,
            root_verifying_key: verifying_key,
            cluster_id: Uuid::new_v4().to_string(),
            node_id: "node-primary".into(),
            role: "control".into(),
        };
        let hidden_source = b"#[test] fn held_out_addition() { assert_eq!(add(4, 9), 13); }";
        let hidden_path = held_out.join("bounded-add.rs");
        let mut hidden_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&hidden_path)
            .unwrap();
        hidden_file.write_all(hidden_source).unwrap();
        hidden_file.sync_all().unwrap();
        let manifest_path = home.join("manifest.json");
        let manifest = serde_json::json!({
            "version": 1,
            "tasks": [{
                "id": "bounded-add",
                "prompt": "Implement a checked integer addition function.",
                "public_tests": "#[test] fn addition() { assert_eq!(add(2, 3), 5); }",
                "weight_milli": 1000
            }]
        });
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let suite_path = home.join("suite.json");
        Store::initialize(&seed).unwrap();
        let mut store = Store::open(&seed).unwrap();
        let suite = sign_suite(&seed, &mut store, &manifest_path, &held_out, &suite_path).unwrap();
        let source_path = home.join("candidate.rs");
        let source = b"pub fn add(a: i32, b: i32) -> i32 { a + b }";
        fs::write(&source_path, source).unwrap();
        let suite_hash = suite.sha256().unwrap();
        let candidate_hash = hex::encode(Sha256::digest(source));
        store
            .record(
                &seed,
                "benchmark_candidate_proposed",
                serde_json::json!({
                    "suite_sha256": suite_hash,
                    "task_id": "bounded-add",
                    "iteration": 0,
                    "candidate_sha256": candidate_hash,
                    "context_patch_ids": [],
                }),
            )
            .unwrap();
        let mut context = BenchContext {
            seed: &seed,
            store: &mut store,
        };
        let score = score_source(
            &mut context,
            &suite_path,
            &held_out,
            "bounded-add",
            0,
            &[],
            &source_path,
        )
        .unwrap();
        score.verify(&seed).unwrap();
        if score.public_outcome != ScoreOutcome::Passed {
            assert_eq!(score.held_out_outcome, ScoreOutcome::NotRun);
        }
        store.verify_state_consistency(&seed).unwrap();
        drop(store);
        fs::remove_dir_all(home).unwrap();
        fs::remove_dir_all(held_out).unwrap();
    }
}
