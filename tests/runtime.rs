use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use uuid::Uuid;

fn runtime_home() -> PathBuf {
    std::env::temp_dir().join(format!("molt-cli-test-{}", Uuid::new_v4()))
}

fn run(home: &PathBuf, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_molt"));
    command.env("MOLT_HOME", home);
    if let Ok(root) = fs::read_to_string(home.join("root.pub")) {
        if let Ok(bytes) = hex::decode(root.trim()) {
            command.env(
                "MOLT_TRUSTED_ROOT_SHA256",
                hex::encode(Sha256::digest(bytes)),
            );
        }
    }
    if args == ["init"] {
        let root_key_out = home.with_extension("root.key");
        command.arg("init").arg("--root-key-out").arg(root_key_out);
    } else {
        command.args(args);
    }
    command.output().unwrap()
}

fn run_pinned(home: &PathBuf, args: &[&str], pin: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_molt"))
        .env("MOLT_HOME", home)
        .env("MOLT_TRUSTED_ROOT_SHA256", pin)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn initialization_verification_permissions_and_tamper_detection() {
    let home = runtime_home();
    let init = run(&home, &["init"]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert_eq!(
        fs::metadata(&home).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let external_root_key = home.with_extension("root.key");
    assert_eq!(
        fs::metadata(&external_root_key)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!home.join("root.key").exists());
    assert_eq!(
        fs::metadata(home.join("node.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let verify = run(&home, &["verify"]);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("Audit events: 1; signed patches: 0"));

    let status = run(&home, &["status"]);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(String::from_utf8_lossy(&status.stdout).contains("Tasks: none"));

    let root_offline = run(&home, &["verify"]);
    assert!(
        root_offline.status.success(),
        "Runtime unexpectedly required its offline root private key: {}",
        String::from_utf8_lossy(&root_offline.stderr)
    );

    let mut seed = fs::read_to_string(home.join("seed.toml")).unwrap();
    seed.push_str("\n# altered after signing\n");
    fs::write(home.join("seed.toml"), seed).unwrap();
    let tampered = run(&home, &["verify"]);
    assert!(!tampered.status.success());
    assert!(
        String::from_utf8_lossy(&tampered.stderr).contains("Seed signature verification failed")
    );
    fs::remove_dir_all(home).unwrap();
    fs::remove_file(external_root_key).unwrap();
}

#[test]
fn offline_root_provisions_and_joins_a_real_node_identity() {
    let workspace = runtime_home();
    fs::create_dir(&workspace).unwrap();
    let primary = workspace.join("primary");
    let edge = workspace.join("edge-pi-1");
    let primary_root = primary.with_extension("root.key");
    let offline_root = workspace.join("offline-root.key");
    let offline_context = workspace.join("offline-context");
    let request = edge.join("node.request.json");
    let bundle = workspace.join("node-edge-pi-1.bundle");

    let init = run(&primary, &["init"]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    fs::rename(&primary_root, &offline_root).unwrap();
    assert!(!primary.join("root.key").exists());

    let pin = {
        let root =
            hex::decode(fs::read_to_string(primary.join("root.pub")).unwrap().trim()).unwrap();
        hex::encode(Sha256::digest(root))
    };
    let export = run(
        &primary,
        &[
            "peer",
            "export-root-context",
            "--output",
            offline_context.to_str().unwrap(),
        ],
    );
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert!(!offline_context.join("root.key").exists());
    assert!(!offline_context.join("node.key").exists());

    let request_result = run_pinned(
        &edge,
        &[
            "peer",
            "request",
            "--node-id",
            "node-edge-pi-1",
            "--role",
            "validator",
            "--root-fingerprint",
            &pin,
        ],
        &pin,
    );
    assert!(
        request_result.status.success(),
        "{}",
        String::from_utf8_lossy(&request_result.stderr)
    );
    assert_eq!(
        fs::metadata(edge.join("node.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let wrong_edge = workspace.join("wrong-root-edge");
    let wrong_request = run_pinned(
        &wrong_edge,
        &[
            "peer",
            "request",
            "--node-id",
            "node-wrong-root",
            "--role",
            "validator",
            "--root-fingerprint",
            &pin,
        ],
        &pin,
    );
    assert!(wrong_request.status.success());
    #[derive(serde::Deserialize, serde::Serialize)]
    struct RequestBody {
        version: String,
        node_id: String,
        role: String,
        root_fingerprint: String,
        public_key: String,
        nonce: String,
        issued_at_unix: u64,
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    struct Request {
        body: RequestBody,
        proof_of_possession: String,
    }
    let wrong_request_path = wrong_edge.join("node.request.json");
    let mut wrong_request: Request =
        serde_json::from_slice(&fs::read(&wrong_request_path).unwrap()).unwrap();
    wrong_request.body.root_fingerprint = "00".repeat(32);
    let wrong_key_bytes: [u8; 32] = hex::decode(
        fs::read_to_string(wrong_edge.join("node.key"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let wrong_key = ed25519_dalek::SigningKey::from_bytes(&wrong_key_bytes);
    wrong_request.proof_of_possession = hex::encode(
        ed25519_dalek::Signer::sign(
            &wrong_key,
            &serde_json::to_vec(&wrong_request.body).unwrap(),
        )
        .to_bytes(),
    );
    fs::write(
        &wrong_request_path,
        serde_json::to_vec(&wrong_request).unwrap(),
    )
    .unwrap();
    let wrong_bundle = workspace.join("wrong-root.bundle");
    let wrong_sign = run(
        &offline_context,
        &[
            "peer",
            "sign",
            "--request",
            wrong_edge.join("node.request.json").to_str().unwrap(),
            "--root-key",
            offline_root.to_str().unwrap(),
            "--bundle",
            wrong_bundle.to_str().unwrap(),
        ],
    );
    assert!(!wrong_sign.status.success());
    assert!(!wrong_bundle.exists());

    let sign = run(
        &offline_context,
        &[
            "peer",
            "sign",
            "--request",
            request.to_str().unwrap(),
            "--root-key",
            offline_root.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
        ],
    );
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );
    assert!(!bundle.join("node.key").exists());
    assert!(!bundle.join("root.key").exists());
    assert!(bundle.join("primary.cert").is_file());
    assert!(!bundle.join("node.key").exists());
    assert!(!bundle.join("root.key").exists());

    let registration = run(
        &primary,
        &["peer", "register", "--bundle", bundle.to_str().unwrap()],
    );
    assert!(
        registration.status.success(),
        "{}",
        String::from_utf8_lossy(&registration.stderr)
    );
    assert!(run(&primary, &["verify"]).status.success());

    let join = Command::new(env!("CARGO_BIN_EXE_molt"))
        .env("MOLT_HOME", &edge)
        .env("MOLT_TRUSTED_ROOT_SHA256", &pin)
        .args(["peer", "join", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(
        join.status.success(),
        "{}",
        String::from_utf8_lossy(&join.stderr)
    );
    assert!(edge.join("peers/node-primary.cert").is_file());
    assert!(!edge.join("root.key").exists());
    assert!(run(&edge, &["verify"]).status.success());

    let bad_edge = workspace.join("tampered-peer");
    fs::create_dir(&bad_edge).unwrap();
    for name in ["node.key", "node.request.json"] {
        let target = bad_edge.join(name);
        fs::copy(edge.join(name), &target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let primary_certificate_path = bundle.join("primary.cert");
    let mut primary_certificate: serde_json::Value =
        serde_json::from_slice(&fs::read(&primary_certificate_path).unwrap()).unwrap();
    primary_certificate["root_signature"] = serde_json::Value::String("00".repeat(64));
    fs::write(
        &primary_certificate_path,
        serde_json::to_vec(&primary_certificate).unwrap(),
    )
    .unwrap();
    let tampered_join = Command::new(env!("CARGO_BIN_EXE_molt"))
        .env("MOLT_HOME", &bad_edge)
        .env("MOLT_TRUSTED_ROOT_SHA256", &pin)
        .args(["peer", "join", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!tampered_join.status.success());
    assert!(!bad_edge.join("root.pub").exists());
    assert!(!bad_edge.join("molt.sqlite3").exists());
    assert!(bad_edge.join("node.key").exists());

    let primary_cert_path = edge.join("peers/node-primary.cert");
    let mut primary_cert: serde_json::Value =
        serde_json::from_slice(&fs::read(&primary_cert_path).unwrap()).unwrap();
    primary_cert["root_signature"] = serde_json::Value::String("00".repeat(64));
    fs::write(
        &primary_cert_path,
        serde_json::to_vec(&primary_cert).unwrap(),
    )
    .unwrap();
    let tampered_registry = run(&edge, &["verify"]);
    assert!(!tampered_registry.status.success());
    assert!(String::from_utf8_lossy(&tampered_registry.stderr)
        .contains("Node certificate signature verification failed"));

    let duplicate = run(
        &primary,
        &["peer", "register", "--bundle", bundle.to_str().unwrap()],
    );
    assert!(!duplicate.status.success());
    fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn trusted_root_fingerprint_can_be_pinned() {
    let home = runtime_home();
    let init = run(&home, &["init"]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let init_stdout = String::from_utf8_lossy(&init.stdout).into_owned();
    let fingerprint = init_stdout
        .lines()
        .find_map(|line| line.strip_prefix("Root public-key fingerprint (SHA-256): "))
        .unwrap()
        .to_string();
    let unpinned = Command::new(env!("CARGO_BIN_EXE_molt"))
        .env("MOLT_HOME", &home)
        .arg("verify")
        .output()
        .unwrap();
    assert!(!unpinned.status.success());
    assert!(
        String::from_utf8_lossy(&unpinned.stderr).contains("MOLT_TRUSTED_ROOT_SHA256 is required")
    );

    let good = Command::new(env!("CARGO_BIN_EXE_molt"))
        .env("MOLT_HOME", &home)
        .env("MOLT_TRUSTED_ROOT_SHA256", fingerprint)
        .arg("verify")
        .output()
        .unwrap();
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    let bad = Command::new(env!("CARGO_BIN_EXE_molt"))
        .env("MOLT_HOME", &home)
        .env("MOLT_TRUSTED_ROOT_SHA256", "00".repeat(32))
        .arg("verify")
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("does not match MOLT_TRUSTED_ROOT_SHA256")
    );
    fs::remove_dir_all(home).unwrap();
}
