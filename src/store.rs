use crate::peering::{self, PeerRequest};
use crate::seed::{NodeCertificate, Seed};
use anyhow::{bail, Context, Result};
use ed25519_dalek::Signature;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskDraft {
    pub description: String,
    pub role: String,
    pub dependencies: Vec<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Task {
    pub id: String,
    pub description: String,
    pub role: String,
    pub dependencies: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatchEnvelope {
    pub patch_id: String,
    pub task_id: String,
    pub source_sha256: String,
    pub tests_sha256: String,
    pub root_public_key: String,
}

#[derive(Clone, Debug)]
pub struct Patch {
    pub id: String,
    pub task_id: String,
    pub source_sha256: String,
    pub tests_sha256: String,
    pub envelope_json: String,
    pub signature: String,
    pub status: String,
    pub report_json: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct EventBody {
    sequence: i64,
    timestamp_unix_ms: i64,
    kind: String,
    payload: Value,
    previous_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditVerification {
    pub event_count: usize,
    pub head_hash: String,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn initialize(seed: &Seed) -> Result<()> {
        let mut store = Self::open_database(seed, true)?;
        store.record(
            seed,
            "seed_initialized",
            serde_json::json!({
                "version": seed.config.seed.version,
                "root_public_key": seed.root_public_key_hex(),
                "node_public_key": seed.node_public_key_hex(),
                "cluster_id": seed.cluster_id,
                "node_id": seed.node_id,
                "role": seed.role,
            }),
        )?;
        Ok(())
    }

    pub fn open(seed: &Seed) -> Result<Self> {
        let db_path = seed.home.join("molt.sqlite3");
        if !db_path.is_file() {
            bail!("Runtime database is missing; refusing to recreate state. Restore a trusted backup or initialize a new runtime.");
        }
        Self::open_database(seed, false)
    }

    fn open_database(seed: &Seed, create: bool) -> Result<Self> {
        let db_path = seed.home.join("molt.sqlite3");
        let conn = if create {
            Connection::open(&db_path)
        } else {
            Connection::open_with_flags(
                &db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_FULL_MUTEX,
            )
        }
        .with_context(|| format!("Cannot open {}", db_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600))?;
        }
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS tasks (
                 task_id TEXT PRIMARY KEY,
                 description TEXT NOT NULL,
                 role TEXT NOT NULL,
                 dependencies_json TEXT NOT NULL,
                 status TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS patches (
                 patch_id TEXT PRIMARY KEY,
                 task_id TEXT NOT NULL REFERENCES tasks(task_id),
                 source_sha256 TEXT NOT NULL,
                 tests_sha256 TEXT NOT NULL,
                 envelope_json TEXT NOT NULL,
                 signature TEXT NOT NULL,
                 status TEXT NOT NULL,
                 report_json TEXT,
                 created_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS events (
                 sequence INTEGER PRIMARY KEY,
                 body_json TEXT NOT NULL,
                 event_hash TEXT NOT NULL UNIQUE,
                 signature TEXT NOT NULL
             );
             CREATE TRIGGER IF NOT EXISTS events_no_update
                 BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
             CREATE TRIGGER IF NOT EXISTS events_no_delete
                 BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;"
        )?;
        Ok(Self { conn })
    }

    pub fn record(&mut self, seed: &Seed, kind: &str, payload: Value) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        append_event(&tx, seed, kind, payload)?;
        tx.commit()?;
        Ok(())
    }

    pub fn benchmark_suite_signed(&self, suite_hash: &str) -> Result<bool> {
        let mut statement = self
            .conn
            .prepare("SELECT body_json FROM events ORDER BY sequence")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let body: EventBody = serde_json::from_str(&row?)?;
            if body.kind == "benchmark_suite_signed"
                && body.payload.get("suite_sha256").and_then(Value::as_str) == Some(suite_hash)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn benchmark_candidate_proposed(
        &self,
        suite_hash: &str,
        task_id: &str,
        iteration: u64,
        candidate_sha256: &str,
        context_patch_ids: &[String],
    ) -> Result<bool> {
        let mut statement = self
            .conn
            .prepare("SELECT body_json FROM events ORDER BY sequence")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let body: EventBody = serde_json::from_str(&row?)?;
            let payload = &body.payload;
            if body.kind == "benchmark_candidate_proposed"
                && payload.get("suite_sha256").and_then(Value::as_str) == Some(suite_hash)
                && payload.get("task_id").and_then(Value::as_str) == Some(task_id)
                && payload.get("iteration").and_then(Value::as_u64) == Some(iteration)
                && payload.get("candidate_sha256").and_then(Value::as_str) == Some(candidate_sha256)
            {
                let recorded_context: Vec<String> = serde_json::from_value(
                    payload
                        .get("context_patch_ids")
                        .cloned()
                        .context("Benchmark candidate event is missing its context")?,
                )?;
                if recorded_context != context_patch_ids {
                    continue;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn benchmark_iteration_exists(
        &self,
        suite_hash: &str,
        task_id: &str,
        iteration: u64,
    ) -> Result<bool> {
        let mut statement = self
            .conn
            .prepare("SELECT body_json FROM events ORDER BY sequence")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let body: EventBody = serde_json::from_str(&row?)?;
            let payload = &body.payload;
            if body.kind == "benchmark_candidate_proposed"
                && payload.get("suite_sha256").and_then(Value::as_str) == Some(suite_hash)
                && payload.get("task_id").and_then(Value::as_str) == Some(task_id)
                && payload.get("iteration").and_then(Value::as_u64) == Some(iteration)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn benchmark_scores(&self, seed: &Seed) -> Result<Vec<crate::bench::ScoreRecord>> {
        let mut records = Vec::new();
        let mut statement = self
            .conn
            .prepare("SELECT body_json FROM events ORDER BY sequence")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let body: EventBody = serde_json::from_str(&row?)?;
            if body.kind == "benchmark_scored" {
                let record: crate::bench::ScoreRecord = serde_json::from_value(body.payload)?;
                record.verify(seed)?;
                records.push(record);
            }
        }
        Ok(records)
    }

    pub fn record_peer_identity(
        &mut self,
        seed: &Seed,
        node_id: &str,
        payload: Value,
    ) -> Result<()> {
        if payload.get("node_id").and_then(Value::as_str) != Some(node_id) {
            bail!("Peer issuance event node ID does not match its payload");
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut statement = tx.prepare("SELECT body_json FROM events ORDER BY sequence")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                let body: EventBody = serde_json::from_str(&row?)?;
                if body.kind == "peer_identity_issued"
                    && body.payload.get("node_id").and_then(Value::as_str) == Some(node_id)
                {
                    let prior: crate::peering::PeerRequest = serde_json::from_value(
                        body.payload
                            .get("request")
                            .cloned()
                            .context("Peer audit entry is missing its signed request")?,
                    )?;
                    let incoming: crate::peering::PeerRequest = serde_json::from_value(
                        payload
                            .get("request")
                            .cloned()
                            .context("Peer registration is missing its signed request")?,
                    )?;
                    if prior.body.public_key != incoming.body.public_key {
                        bail!("Node ID {node_id} is already bound to a different public key");
                    }
                    if prior.body.nonce == incoming.body.nonce {
                        bail!("Peer request nonce has already been registered");
                    }
                }
            }
        }
        append_event(&tx, seed, "peer_identity_issued", payload)?;
        tx.commit()?;
        Ok(())
    }

    pub fn create_tasks(&mut self, seed: &Seed, drafts: &[TaskDraft]) -> Result<Vec<String>> {
        if drafts.is_empty() || drafts.len() > 8 {
            bail!("Architect plan must contain between 1 and 8 tasks");
        }
        let ids: Vec<String> = (0..drafts.len())
            .map(|_| uuid::Uuid::new_v4().to_string())
            .collect();
        for (index, draft) in drafts.iter().enumerate() {
            if draft.description.trim().is_empty() || draft.description.len() > 2000 {
                bail!("Task {} has an empty or oversized description", index + 1);
            }
            if draft.role != "Engineer" {
                bail!("Task {} must use the implemented Engineer role", index + 1);
            }
            let mut unique_dependencies = std::collections::HashSet::new();
            if draft
                .dependencies
                .iter()
                .any(|dependency| !unique_dependencies.insert(*dependency))
            {
                bail!("Task {} contains a duplicate dependency", index + 1);
            }
            if draft
                .dependencies
                .iter()
                .any(|&dependency| dependency >= index)
            {
                bail!("Task dependencies must refer only to earlier tasks; rejected non-DAG plan");
            }
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_ms()?;
        for (index, draft) in drafts.iter().enumerate() {
            let dependencies: Vec<String> =
                draft.dependencies.iter().map(|&i| ids[i].clone()).collect();
            tx.execute(
                "INSERT INTO tasks(task_id, description, role, dependencies_json, status, created_at_ms) VALUES (?1, ?2, ?3, ?4, 'planned', ?5)",
                params![ids[index], draft.description.trim(), draft.role, serde_json::to_string(&dependencies)?, now],
            )?;
        }
        append_event(
            &tx,
            seed,
            "objective_planned",
            serde_json::json!({"task_ids": ids, "tasks": drafts}),
        )?;
        tx.commit()?;
        Ok(ids)
    }

    pub fn task(&self, task_id: &str) -> Result<Task> {
        let row = self.conn.query_row(
            "SELECT task_id, description, role, dependencies_json, status FROM tasks WHERE task_id = ?1",
            [task_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?)),
        ).optional()?.with_context(|| format!("Unknown task ID: {task_id}"))?;
        Ok(Task {
            id: row.0,
            description: row.1,
            role: row.2,
            dependencies: serde_json::from_str(&row.3)?,
            status: row.4,
        })
    }

    pub fn dependencies_approved(&self, task: &Task) -> Result<bool> {
        for dep in &task.dependencies {
            let status: Option<String> = self
                .conn
                .query_row(
                    "SELECT status FROM tasks WHERE task_id = ?1",
                    [dep],
                    |row| row.get(0),
                )
                .optional()?;
            if status.as_deref() != Some("approved") {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn insert_patch(
        &mut self,
        seed: &Seed,
        envelope: &PatchEnvelope,
        signature: &str,
    ) -> Result<()> {
        if uuid::Uuid::parse_str(&envelope.patch_id)?.to_string() != envelope.patch_id
            || uuid::Uuid::parse_str(&envelope.task_id)?.to_string() != envelope.task_id
        {
            bail!("Patch and task IDs must be canonical UUIDs");
        }
        if !is_sha256(&envelope.source_sha256) || !is_sha256(&envelope.tests_sha256) {
            bail!("Patch artifact digests must be lowercase SHA-256 hex");
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let task = tx
            .query_row(
                "SELECT status FROM tasks WHERE task_id = ?1",
                [&envelope.task_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .context("Patch refers to a missing task")?;
        if task != "planned" {
            bail!("Task is not in the planned state");
        }
        let json = serde_json::to_string(envelope)?;
        tx.execute(
            "INSERT INTO patches(patch_id, task_id, source_sha256, tests_sha256, envelope_json, signature, status, report_json, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'proposed', NULL, ?7)",
            params![envelope.patch_id, envelope.task_id, envelope.source_sha256, envelope.tests_sha256, json, signature, now_ms()?],
        )?;
        tx.execute(
            "UPDATE tasks SET status = 'patch-proposed' WHERE task_id = ?1",
            [&envelope.task_id],
        )?;
        append_event(
            &tx,
            seed,
            "patch_proposed",
            serde_json::json!({"patch_id": envelope.patch_id, "task_id": envelope.task_id, "source_sha256": envelope.source_sha256, "tests_sha256": envelope.tests_sha256}),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn patch(&self, patch_id: &str) -> Result<Patch> {
        let row = self.conn.query_row(
            "SELECT patch_id, task_id, source_sha256, tests_sha256, envelope_json, signature, status, report_json FROM patches WHERE patch_id = ?1",
            [patch_id],
            |row| Ok(Patch {
                id: row.get(0)?, task_id: row.get(1)?, source_sha256: row.get(2)?, tests_sha256: row.get(3)?,
                envelope_json: row.get(4)?, signature: row.get(5)?, status: row.get(6)?, report_json: row.get(7)?,
            }),
        ).optional()?.with_context(|| format!("Unknown patch ID: {patch_id}"))?;
        Ok(row)
    }

    pub fn set_crucible_report(
        &mut self,
        seed: &Seed,
        patch_id: &str,
        status: &str,
        report: &Value,
    ) -> Result<()> {
        if !matches!(status, "passed" | "rejected" | "blocked") {
            bail!("Invalid Crucible result");
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = tx
            .query_row(
                "SELECT status, task_id FROM patches WHERE patch_id = ?1",
                [patch_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .with_context(|| format!("Unknown patch ID: {patch_id}"))?;
        if current.0 == "approved" {
            bail!("An approved patch cannot be re-evaluated in place");
        }
        tx.execute(
            "UPDATE patches SET status = ?2, report_json = ?3 WHERE patch_id = ?1",
            params![patch_id, status, serde_json::to_string(report)?],
        )?;
        let task_status = if status == "rejected" {
            "planned"
        } else {
            "patch-proposed"
        };
        tx.execute(
            "UPDATE tasks SET status = ?2 WHERE task_id = ?1",
            params![current.1, task_status],
        )?;
        append_event(
            &tx,
            seed,
            "crucible_completed",
            serde_json::json!({"patch_id": patch_id, "status": status, "report": report}),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn approve_patch(&mut self, seed: &Seed, patch_id: &str) -> Result<Patch> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let patch = tx.query_row(
            "SELECT patch_id, task_id, source_sha256, tests_sha256, envelope_json, signature, status, report_json FROM patches WHERE patch_id = ?1",
            [patch_id],
            |row| Ok(Patch {
                id: row.get(0)?, task_id: row.get(1)?, source_sha256: row.get(2)?, tests_sha256: row.get(3)?,
                envelope_json: row.get(4)?, signature: row.get(5)?, status: row.get(6)?, report_json: row.get(7)?,
            }),
        ).optional()?.with_context(|| format!("Unknown patch ID: {patch_id}"))?;
        if patch.status != "passed" {
            bail!("Only patches that passed the Crucible can be approved");
        }
        let dependencies_json: String = tx.query_row(
            "SELECT dependencies_json FROM tasks WHERE task_id = ?1",
            [&patch.task_id],
            |row| row.get(0),
        )?;
        let dependencies: Vec<String> = serde_json::from_str(&dependencies_json)?;
        for dependency in dependencies {
            let status: String = tx.query_row(
                "SELECT status FROM tasks WHERE task_id = ?1",
                [&dependency],
                |row| row.get(0),
            )?;
            if status != "approved" {
                bail!("Task dependencies must all be approved before this patch can be approved");
            }
        }
        tx.execute(
            "UPDATE patches SET status = 'approved' WHERE patch_id = ?1",
            [patch_id],
        )?;
        tx.execute(
            "UPDATE tasks SET status = 'approved' WHERE task_id = ?1",
            [&patch.task_id],
        )?;
        append_event(
            &tx,
            seed,
            "patch_approved",
            serde_json::json!({"patch_id": patch_id, "task_id": patch.task_id}),
        )?;
        tx.commit()?;
        Ok(patch)
    }

    pub fn tasks(&self) -> Result<Vec<Task>> {
        let mut statement = self.conn.prepare("SELECT task_id, description, role, dependencies_json, status FROM tasks ORDER BY created_at_ms, task_id")?;
        let rows = statement.query_map([], |row| {
            let dependencies: String = row.get(3)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                dependencies,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut tasks = Vec::new();
        for row in rows {
            let row = row?;
            tasks.push(Task {
                id: row.0,
                description: row.1,
                role: row.2,
                dependencies: serde_json::from_str(&row.3)?,
                status: row.4,
            });
        }
        Ok(tasks)
    }

    pub fn patches(&self) -> Result<Vec<Patch>> {
        let mut statement = self.conn.prepare("SELECT patch_id, task_id, source_sha256, tests_sha256, envelope_json, signature, status, report_json FROM patches ORDER BY created_at_ms, patch_id")?;
        let rows = statement.query_map([], |row| {
            Ok(Patch {
                id: row.get(0)?,
                task_id: row.get(1)?,
                source_sha256: row.get(2)?,
                tests_sha256: row.get(3)?,
                envelope_json: row.get(4)?,
                signature: row.get(5)?,
                status: row.get(6)?,
                report_json: row.get(7)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Cannot list patches")
    }

    pub fn verify_audit_log(&self, seed: &Seed) -> Result<AuditVerification> {
        let mut statement = self.conn.prepare(
            "SELECT sequence, body_json, event_hash, signature FROM events ORDER BY sequence",
        )?;
        let mut rows = statement.query([])?;
        let mut expected_sequence = 1_i64;
        let mut previous_hash = String::new();
        while let Some(row) = rows.next()? {
            let sequence: i64 = row.get(0)?;
            let body_json: String = row.get(1)?;
            let event_hash: String = row.get(2)?;
            let signature_hex: String = row.get(3)?;
            if sequence != expected_sequence {
                bail!("Audit sequence gap or truncation detected at event {expected_sequence}");
            }
            let body: EventBody =
                serde_json::from_str(&body_json).context("Malformed audit event")?;
            if body.sequence != sequence || body.previous_hash != previous_hash {
                bail!("Audit-chain link mismatch at event {sequence}");
            }
            let calculated = hex::encode(Sha256::digest(body_json.as_bytes()));
            if calculated != event_hash {
                bail!("Audit event hash mismatch at event {sequence}");
            }
            let signature = Signature::from_bytes(&decode_fixed::<64>(&signature_hex)?);
            seed.verifying_key
                .verify_strict(event_hash.as_bytes(), &signature)
                .with_context(|| format!("Audit event signature mismatch at event {sequence}"))?;
            previous_hash = event_hash;
            expected_sequence += 1;
        }
        if expected_sequence == 1 {
            bail!("Audit log is empty; refusing to treat runtime as initialized");
        }
        Ok(AuditVerification {
            event_count: (expected_sequence - 1) as usize,
            head_hash: previous_hash,
        })
    }

    pub fn verify_state_consistency(&self, seed: &Seed) -> Result<()> {
        #[derive(Clone)]
        struct ReplayedTask {
            description: String,
            role: String,
            dependencies: Vec<String>,
            status: String,
        }
        #[derive(Clone)]
        struct ReplayedPatch {
            task_id: String,
            source_sha256: String,
            tests_sha256: String,
            status: String,
            report: Option<Value>,
        }

        let mut issued_peers =
            std::collections::HashMap::<String, (String, std::collections::HashSet<String>)>::new();
        let mut signed_suites =
            std::collections::HashMap::<String, std::collections::HashSet<String>>::new();
        let mut candidate_proposals =
            std::collections::HashSet::<(String, String, u64, String, Vec<String>)>::new();
        let mut scored_candidates = std::collections::HashSet::new();
        let mut score_ids = std::collections::HashSet::<String>::new();
        let mut tasks = std::collections::HashMap::<String, ReplayedTask>::new();
        let mut patches = std::collections::HashMap::<String, ReplayedPatch>::new();
        let mut statement = self
            .conn
            .prepare("SELECT body_json FROM events ORDER BY sequence")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let body: EventBody = serde_json::from_str(&row?)?;
            let payload = &body.payload;
            match body.kind.as_str() {
                "seed_initialized" => {
                    if body.sequence != 1
                        || payload.get("version").and_then(Value::as_str)
                            != Some(seed.config.seed.version.as_str())
                        || payload.get("root_public_key").and_then(Value::as_str)
                            != Some(seed.root_public_key_hex().as_str())
                        || payload.get("node_public_key").and_then(Value::as_str)
                            != Some(seed.node_public_key_hex().as_str())
                        || payload.get("cluster_id").and_then(Value::as_str)
                            != Some(seed.cluster_id.as_str())
                        || payload.get("node_id").and_then(Value::as_str)
                            != Some(seed.node_id.as_str())
                        || payload.get("role").and_then(Value::as_str) != Some(seed.role.as_str())
                    {
                        bail!("Genesis event does not match the signed seed");
                    }
                }
                "peer_identity_issued" => {
                    let certificate: NodeCertificate = serde_json::from_value(
                        payload
                            .get("certificate")
                            .cloned()
                            .context("Peer issuance event is missing its certificate")?,
                    )?;
                    let request: PeerRequest = serde_json::from_value(
                        payload
                            .get("request")
                            .cloned()
                            .context("Peer issuance event is missing its signed request")?,
                    )?;
                    peering::verify_request_signature(&request)?;
                    seed.verify_peer_certificate(&certificate)?;
                    let identity = &certificate.identity;
                    let key_fingerprint =
                        hex::encode(Sha256::digest(hex::decode(&identity.node_public_key)?));
                    if identity.cluster_id != seed.cluster_id
                        || identity.node_id == seed.node_id
                        || identity.node_id != request.body.node_id
                        || identity.role != request.body.role
                        || identity.node_public_key != request.body.public_key
                        || payload.get("node_id").and_then(Value::as_str)
                            != Some(identity.node_id.as_str())
                        || payload.get("role").and_then(Value::as_str)
                            != Some(identity.role.as_str())
                        || payload.get("key_fingerprint").and_then(Value::as_str)
                            != Some(key_fingerprint.as_str())
                    {
                        bail!("Invalid root-signed peer identity in audit history");
                    }
                    let nonce = request.body.nonce.clone();
                    let state = issued_peers
                        .entry(identity.node_id.clone())
                        .or_insert_with(|| {
                            (
                                identity.node_public_key.clone(),
                                std::collections::HashSet::new(),
                            )
                        });
                    if state.0 != identity.node_public_key || !state.1.insert(nonce) {
                        bail!("Conflicting key or replayed nonce in peer audit history");
                    }
                }
                "benchmark_suite_signed" => {
                    let suite: crate::bench::SignedSuite = serde_json::from_value(
                        payload
                            .get("suite")
                            .cloned()
                            .context("Benchmark suite event is missing its suite")?,
                    )?;
                    suite.verify(seed)?;
                    let suite_hash = suite.sha256()?;
                    let task_ids: std::collections::HashSet<String> =
                        suite.tasks.iter().map(|task| task.id.clone()).collect();
                    if payload.get("suite_sha256").and_then(Value::as_str)
                        != Some(suite_hash.as_str())
                        || payload.get("task_count").and_then(Value::as_u64)
                            != Some(suite.tasks.len() as u64)
                        || signed_suites.insert(suite_hash, task_ids).is_some()
                    {
                        bail!("Invalid or duplicate signed benchmark suite in audit history");
                    }
                }
                "benchmark_candidate_proposed" => {
                    let suite_hash = payload
                        .get("suite_sha256")
                        .and_then(Value::as_str)
                        .context("Benchmark candidate is missing its suite hash")?;
                    let task_id = payload
                        .get("task_id")
                        .and_then(Value::as_str)
                        .context("Benchmark candidate is missing its task ID")?;
                    let iteration = payload
                        .get("iteration")
                        .and_then(Value::as_u64)
                        .context("Benchmark candidate is missing its iteration")?;
                    let candidate_hash = payload
                        .get("candidate_sha256")
                        .and_then(Value::as_str)
                        .context("Benchmark candidate is missing its digest")?;
                    let contexts: Vec<String> = serde_json::from_value(
                        payload
                            .get("context_patch_ids")
                            .cloned()
                            .context("Benchmark candidate is missing its context list")?,
                    )?;
                    if !is_sha256(suite_hash)
                        || !is_sha256(candidate_hash)
                        || !signed_suites
                            .get(suite_hash)
                            .is_some_and(|tasks| tasks.contains(task_id))
                    {
                        bail!("Benchmark candidate refers to an unregistered suite/task or invalid digest");
                    }
                    let mut unique_context = std::collections::HashSet::new();
                    for patch_id in &contexts {
                        let patch = patches
                            .get(patch_id)
                            .context("Benchmark context refers to an unknown approved patch")?;
                        if patch.status != "approved"
                            || uuid::Uuid::parse_str(patch_id)?.to_string() != *patch_id
                            || !unique_context.insert(patch_id)
                        {
                            bail!("Benchmark context must contain unique approved patch IDs");
                        }
                    }
                    if !candidate_proposals.insert((
                        suite_hash.to_string(),
                        task_id.to_string(),
                        iteration,
                        candidate_hash.to_string(),
                        contexts,
                    )) {
                        bail!("Duplicate benchmark candidate proposal in audit history");
                    }
                }
                "benchmark_scored" => {
                    let score: crate::bench::ScoreRecord = serde_json::from_value(payload.clone())?;
                    score.verify(seed)?;
                    let key = (
                        score.suite_sha256.clone(),
                        score.task_id.clone(),
                        score.iteration,
                        score.candidate_sha256.clone(),
                        score.context_patch_ids.clone(),
                    );
                    if !signed_suites
                        .get(&score.suite_sha256)
                        .is_some_and(|tasks| tasks.contains(&score.task_id))
                        || !candidate_proposals.contains(&key)
                        || !scored_candidates.insert(key)
                        || !score_ids.insert(score.score_id.clone())
                    {
                        bail!("Benchmark score has invalid proposal lineage or a duplicate ID");
                    }
                }
                "objective_planned" => {
                    let ids: Vec<String> = serde_json::from_value(
                        payload
                            .get("task_ids")
                            .cloned()
                            .context("Plan event is missing task IDs")?,
                    )?;
                    let drafts: Vec<TaskDraft> = serde_json::from_value(
                        payload
                            .get("tasks")
                            .cloned()
                            .context("Plan event is missing task definitions")?,
                    )?;
                    if ids.len() != drafts.len() || ids.is_empty() || ids.len() > 8 {
                        bail!("Malformed task-plan audit event");
                    }
                    for (index, (id, draft)) in ids.iter().zip(drafts.iter()).enumerate() {
                        if uuid::Uuid::parse_str(id)?.to_string() != *id
                            || draft.role != "Engineer"
                            || draft
                                .dependencies
                                .iter()
                                .any(|dependency| *dependency >= index)
                        {
                            bail!("Invalid task identity or dependency in audit history");
                        }
                        let dependencies = draft
                            .dependencies
                            .iter()
                            .map(|&dependency| ids[dependency].clone())
                            .collect();
                        if tasks
                            .insert(
                                id.clone(),
                                ReplayedTask {
                                    description: draft.description.trim().to_string(),
                                    role: draft.role.clone(),
                                    dependencies,
                                    status: "planned".to_string(),
                                },
                            )
                            .is_some()
                        {
                            bail!("Duplicate task ID in audit history: {id}");
                        }
                    }
                }
                "patch_proposed" => {
                    let id = payload
                        .get("patch_id")
                        .and_then(Value::as_str)
                        .context("Patch event is missing its ID")?;
                    let task_id = payload
                        .get("task_id")
                        .and_then(Value::as_str)
                        .context("Patch event is missing its task ID")?;
                    let source_sha256 = payload
                        .get("source_sha256")
                        .and_then(Value::as_str)
                        .context("Patch event is missing its source hash")?;
                    let tests_sha256 = payload
                        .get("tests_sha256")
                        .and_then(Value::as_str)
                        .context("Patch event is missing its test hash")?;
                    if uuid::Uuid::parse_str(id)?.to_string() != id {
                        bail!("Invalid patch ID in audit history");
                    }
                    let task = tasks
                        .get_mut(task_id)
                        .context("Patch event refers to an unknown task")?;
                    if task.status != "planned" || patches.contains_key(id) {
                        bail!("Invalid patch-proposal state transition in audit history");
                    }
                    task.status = "patch-proposed".to_string();
                    patches.insert(
                        id.to_string(),
                        ReplayedPatch {
                            task_id: task_id.to_string(),
                            source_sha256: source_sha256.to_string(),
                            tests_sha256: tests_sha256.to_string(),
                            status: "proposed".to_string(),
                            report: None,
                        },
                    );
                }
                "crucible_completed" => {
                    let id = payload
                        .get("patch_id")
                        .and_then(Value::as_str)
                        .context("Crucible event is missing its patch ID")?;
                    let status = payload
                        .get("status")
                        .and_then(Value::as_str)
                        .context("Crucible event is missing its status")?;
                    if !matches!(status, "passed" | "rejected" | "blocked") {
                        bail!("Invalid Crucible state in audit history");
                    }
                    let patch = patches
                        .get_mut(id)
                        .context("Crucible event refers to an unknown patch")?;
                    if patch.status == "approved" {
                        bail!("Approved patch was re-evaluated in audit history");
                    }
                    let report = payload
                        .get("report")
                        .cloned()
                        .context("Crucible event is missing its report")?;
                    patch.status = status.to_string();
                    patch.report = Some(report);
                    let task = tasks
                        .get_mut(&patch.task_id)
                        .context("Crucible event refers to an unknown task")?;
                    task.status = if status == "rejected" {
                        "planned"
                    } else {
                        "patch-proposed"
                    }
                    .to_string();
                }
                "patch_approved" => {
                    let id = payload
                        .get("patch_id")
                        .and_then(Value::as_str)
                        .context("Approval event is missing its patch ID")?;
                    let task_id = payload
                        .get("task_id")
                        .and_then(Value::as_str)
                        .context("Approval event is missing its task ID")?;
                    let patch = patches
                        .get_mut(id)
                        .context("Approval event refers to an unknown patch")?;
                    if patch.task_id != task_id || patch.status != "passed" {
                        bail!("Invalid patch approval transition in audit history");
                    }
                    patch.status = "approved".to_string();
                    tasks
                        .get_mut(task_id)
                        .context("Approval event refers to an unknown task")?
                        .status = "approved".to_string();
                }
                _ => bail!("Unknown signed audit event type: {}", body.kind),
            }
        }

        let stored_tasks = self.tasks()?;
        if stored_tasks.len() != tasks.len() {
            bail!("Task database does not match signed audit history");
        }
        for task in stored_tasks {
            let replayed = tasks
                .get(&task.id)
                .context("Task database contains an unsigned task")?;
            if task.description != replayed.description
                || task.role != replayed.role
                || task.dependencies != replayed.dependencies
                || task.status != replayed.status
            {
                bail!("Task state differs from signed audit history: {}", task.id);
            }
        }

        let stored_patches = self.patches()?;
        if stored_patches.len() != patches.len() {
            bail!("Patch database does not match signed audit history");
        }
        for patch in stored_patches {
            let replayed = patches
                .get(&patch.id)
                .context("Patch database contains an unsigned patch")?;
            if patch.task_id != replayed.task_id
                || patch.source_sha256 != replayed.source_sha256
                || patch.tests_sha256 != replayed.tests_sha256
                || patch.status != replayed.status
                || patch
                    .report_json
                    .as_deref()
                    .map(serde_json::from_str::<Value>)
                    .transpose()?
                    != replayed.report
            {
                bail!(
                    "Patch state differs from signed audit history: {}",
                    patch.id
                );
            }
        }
        Ok(())
    }

    pub fn verify_patch_records(&self, seed: &Seed) -> Result<usize> {
        let patches = self.patches()?;
        for patch in &patches {
            if uuid::Uuid::parse_str(&patch.id)?.to_string() != patch.id
                || uuid::Uuid::parse_str(&patch.task_id)?.to_string() != patch.task_id
                || !is_sha256(&patch.source_sha256)
                || !is_sha256(&patch.tests_sha256)
            {
                bail!("Invalid patch identity or digest in runtime database");
            }
            let envelope: PatchEnvelope = serde_json::from_str(&patch.envelope_json)?;
            if envelope.patch_id != patch.id
                || envelope.task_id != patch.task_id
                || envelope.source_sha256 != patch.source_sha256
                || envelope.tests_sha256 != patch.tests_sha256
                || envelope.root_public_key != seed.root_public_key_hex()
            {
                bail!("Patch metadata mismatch for {}", patch.id);
            }
            let sig = Signature::from_bytes(&decode_fixed::<64>(&patch.signature)?);
            seed.verifying_key
                .verify_strict(patch.envelope_json.as_bytes(), &sig)
                .with_context(|| format!("Patch signature invalid for {}", patch.id))?;
            let source = seed.home.join("patches").join(format!("{}.rs", patch.id));
            let tests = seed
                .home
                .join("patches")
                .join(format!("{}.tests.rs", patch.id));
            if source.exists() && sha256_file(&source)? != patch.source_sha256 {
                bail!("Source artifact hash mismatch for {}", patch.id);
            }
            if tests.exists() && sha256_file(&tests)? != patch.tests_sha256 {
                bail!("Test artifact hash mismatch for {}", patch.id);
            }
            if !source.exists() && patch.status != "approved" {
                bail!("Missing proposed source artifact for {}", patch.id);
            }
            if !tests.exists() && patch.status != "approved" {
                bail!("Missing proposed test artifact for {}", patch.id);
            }
            if patch.status == "approved" {
                let approved_source = seed.home.join("approved").join(format!("{}.rs", patch.id));
                let approved_tests = seed
                    .home
                    .join("approved")
                    .join(format!("{}.tests.rs", patch.id));
                if !approved_source.exists()
                    || !approved_tests.exists()
                    || sha256_file(&approved_source)? != patch.source_sha256
                    || sha256_file(&approved_tests)? != patch.tests_sha256
                {
                    bail!("Approved artifact missing or altered for {}", patch.id);
                }
            }
        }
        Ok(patches.len())
    }
}

fn append_event(tx: &Transaction<'_>, seed: &Seed, kind: &str, payload: Value) -> Result<()> {
    let last: Option<(i64, String)> = tx
        .query_row(
            "SELECT sequence, event_hash FROM events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (sequence, previous_hash) = last
        .map(|(seq, hash)| (seq + 1, hash))
        .unwrap_or((1, String::new()));
    let body = EventBody {
        sequence,
        timestamp_unix_ms: now_ms()?,
        kind: kind.to_string(),
        payload,
        previous_hash,
    };
    let body_json = serde_json::to_string(&body)?;
    let event_hash = hex::encode(Sha256::digest(body_json.as_bytes()));
    let signature = hex::encode(seed.sign(event_hash.as_bytes()).to_bytes());
    tx.execute(
        "INSERT INTO events(sequence, body_json, event_hash, signature) VALUES (?1, ?2, ?3, ?4)",
        params![sequence, body_json, event_hash, signature],
    )?;
    Ok(())
}

fn now_ms() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Current timestamp is out of range"))
}

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256(&fs::read(path).with_context(|| {
        format!("Cannot read {}", path.display())
    })?))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn decode_fixed<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(text).context("Malformed signature hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Unexpected signature length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn fixture() -> (Seed, std::path::PathBuf) {
        let home = std::env::temp_dir().join(format!("molt-store-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let config: crate::seed::SeedConfig =
            toml::from_str(include_str!("../config/seed.toml")).unwrap();
        (
            Seed {
                home: home.clone(),
                config,
                signing_key,
                verifying_key,
                root_verifying_key: verifying_key,
                cluster_id: uuid::Uuid::new_v4().to_string(),
                node_id: "node-primary".into(),
                role: "control".into(),
            },
            home,
        )
    }

    #[test]
    fn signed_audit_and_state_replay_validate() {
        let (seed, home) = fixture();
        Store::initialize(&seed).unwrap();
        let mut store = Store::open(&seed).unwrap();
        assert_eq!(store.verify_audit_log(&seed).unwrap().event_count, 1);
        let task_ids = store
            .create_tasks(
                &seed,
                &[TaskDraft {
                    description: "Implement a bounded parser".into(),
                    role: "Engineer".into(),
                    dependencies: Vec::new(),
                }],
            )
            .unwrap();
        assert_eq!(store.task(&task_ids[0]).unwrap().status, "planned");
        assert_eq!(store.verify_audit_log(&seed).unwrap().event_count, 2);
        store.verify_state_consistency(&seed).unwrap();
        drop(store);
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn direct_database_state_edits_are_detected_by_signed_replay() {
        let (seed, home) = fixture();
        Store::initialize(&seed).unwrap();
        let mut store = Store::open(&seed).unwrap();
        let task_ids = store
            .create_tasks(
                &seed,
                &[TaskDraft {
                    description: "Implement a bounded parser".into(),
                    role: "Engineer".into(),
                    dependencies: Vec::new(),
                }],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE tasks SET status = 'approved' WHERE task_id = ?1",
                [&task_ids[0]],
            )
            .unwrap();
        assert!(store.verify_state_consistency(&seed).is_err());
        drop(store);
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn signed_audit_tampering_is_detected() {
        let (seed, home) = fixture();
        Store::initialize(&seed).unwrap();
        let store = Store::open(&seed).unwrap();
        store
            .conn
            .execute("DROP TRIGGER events_no_update", [])
            .unwrap();
        store
            .conn
            .execute("UPDATE events SET body_json = '{}' WHERE sequence = 1", [])
            .unwrap();
        assert!(store.verify_audit_log(&seed).is_err());
        drop(store);
        fs::remove_dir_all(home).unwrap();
    }
}
