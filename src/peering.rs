use crate::seed::{
    self, decode_fixed, set_private_dir, write_new, NodeCertificate, NodeIdentity, Seed, SeedTrust,
};
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PeerRequestBody {
    pub version: String,
    pub node_id: String,
    pub role: String,
    pub root_fingerprint: String,
    pub public_key: String,
    pub nonce: String,
    pub issued_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PeerRequest {
    pub body: PeerRequestBody,
    pub proof_of_possession: String,
}

pub(crate) struct IssuedPeer {
    pub request: PeerRequest,
    pub certificate: NodeCertificate,
    pub bundle_path: PathBuf,
    pub key_fingerprint: String,
}

pub(crate) fn request_identity(node_id: &str, role: &str, root_fingerprint: &str) -> Result<()> {
    let trusted_pin = seed::trusted_root_sha256()?;
    let requested_pin = decode_fixed::<32>(root_fingerprint, "root fingerprint")?;
    let difference = trusted_pin
        .iter()
        .zip(requested_pin)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if difference != 0 {
        bail!("Request fingerprint does not match MOLT_TRUSTED_ROOT_SHA256");
    }
    seed::validate_node_id(node_id)?;
    seed::validate_role(role)?;
    let root_fingerprint = hex::encode(trusted_pin);
    let home = seed::home_dir()?;
    fs::create_dir_all(&home)
        .with_context(|| format!("Cannot create runtime directory {}", home.display()))?;
    seed::prepare_private_dir(&home)?;
    for name in [
        "root.pub",
        "seed.toml",
        "seed.sig",
        "node.cert",
        "molt.sqlite3",
        "node.key",
        "node.request.json",
    ] {
        if home.join(name).exists() {
            bail!(
                "{} already exists; refusing to replace it",
                home.join(name).display()
            );
        }
    }

    let mut rng = rand_core::OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let issued_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?
        .as_secs();
    let body = PeerRequestBody {
        version: "2".into(),
        node_id: node_id.to_string(),
        role: role.to_string(),
        root_fingerprint,
        public_key: hex::encode(signing_key.verifying_key().as_bytes()),
        nonce: hex::encode(nonce),
        issued_at_unix,
    };
    let signature = signing_key.sign(&serde_json::to_vec(&body)?);
    let request = PeerRequest {
        body,
        proof_of_possession: hex::encode(signature.to_bytes()),
    };
    let key_path = home.join("node.key");
    write_new(
        &key_path,
        format!("{}\n", hex::encode(signing_key.to_bytes())).as_bytes(),
        true,
    )?;
    if let Err(error) = write_new(
        &home.join("node.request.json"),
        &serde_json::to_vec_pretty(&request)?,
        true,
    ) {
        let _ = fs::remove_file(key_path);
        return Err(error);
    }
    println!("Created a local node key and signed public request for {node_id} ({role}).");
    println!(
        "Private key stays at {}; it is not included in the request.",
        home.join("node.key").display()
    );
    println!(
        "Copy {} to the offline-root signer.",
        home.join("node.request.json").display()
    );
    println!(
        "Node-key fingerprint (SHA-256): {}",
        hex::encode(Sha256::digest(signing_key.verifying_key().as_bytes()))
    );
    Ok(())
}

pub(crate) fn read_request(path: &Path) -> Result<PeerRequest> {
    let bytes = read_regular_file(path, 16 * 1024)?;
    let request: PeerRequest = serde_json::from_slice(&bytes)
        .with_context(|| format!("Invalid peer request: {}", path.display()))?;
    verify_request(&request)?;
    Ok(request)
}

pub(crate) fn verify_request_signature(request: &PeerRequest) -> Result<()> {
    let body = &request.body;
    if body.version != "2" {
        bail!("Unsupported peer request version");
    }
    seed::validate_node_id(&body.node_id)?;
    seed::validate_role(&body.role)?;
    decode_fixed::<32>(&body.root_fingerprint, "peer root fingerprint")?;
    let nonce = decode_fixed::<32>(&body.nonce, "peer request nonce")?;
    if nonce == [0; 32] {
        bail!("Peer request nonce must not be zero");
    }
    let public = decode_fixed::<32>(&body.public_key, "peer public key")?;
    let verifying_key = VerifyingKey::from_bytes(&public).context("Invalid peer public key")?;
    let signature = decode_fixed::<64>(&request.proof_of_possession, "peer proof of possession")?;
    verifying_key
        .verify_strict(
            &serde_json::to_vec(body)?,
            &Signature::from_bytes(&signature),
        )
        .context("Peer request proof-of-possession verification failed")
}

pub(crate) fn verify_request(request: &PeerRequest) -> Result<()> {
    verify_request_signature(request)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?
        .as_secs();
    if request.body.issued_at_unix > now.saturating_add(5 * 60)
        || now.saturating_sub(request.body.issued_at_unix) > 30 * 24 * 60 * 60
    {
        bail!("Peer request has expired or is future-dated; generate a fresh request");
    }
    Ok(())
}

pub(crate) fn export_root_context(seed: &Seed, output: &Path) -> Result<PathBuf> {
    if seed.node_id != "node-primary" || seed.role != "control" {
        bail!("Only node-primary can export the initial offline-root signing context");
    }
    let destination = create_bundle_path(output, &seed.home)?;
    let result = (|| -> Result<()> {
        for name in ["root.pub", "seed.toml", "seed.sig", "node.cert"] {
            write_new(
                &destination.join(name),
                &read_regular_file(&seed.home.join(name), 64 * 1024)?,
                false,
            )?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&destination);
        return Err(error);
    }
    println!(
        "Exported public root-signing context to {}. It contains no private keys.",
        destination.display()
    );
    Ok(destination)
}

pub(crate) fn sign_request(
    seed: &SeedTrust,
    request_path: &Path,
    root_key_path: &Path,
    bundle_path: &Path,
) -> Result<IssuedPeer> {
    let request = read_request(request_path)?;
    if request.body.node_id == seed.node_id {
        bail!("A node cannot issue a second identity for itself");
    }
    if seed.node_id != "node-primary" || seed.role != "control" {
        bail!("Peer identities can only be issued from the root-certified primary control context");
    }
    if request.body.root_fingerprint != seed.root_fingerprint_sha256() {
        bail!("Peer request is bound to a different offline root fingerprint");
    }
    let root_metadata = fs::symlink_metadata(root_key_path).with_context(|| {
        format!(
            "Cannot inspect offline root key {}",
            root_key_path.display()
        )
    })?;
    if !root_metadata.is_file() || root_metadata.file_type().is_symlink() {
        bail!("Offline root key must be a regular, non-symlink file");
    }
    let root_path = fs::canonicalize(root_key_path)
        .with_context(|| format!("Cannot access offline root key {}", root_key_path.display()))?;
    let runtime_path = fs::canonicalize(&seed.home)?;
    if root_path.starts_with(&runtime_path) {
        bail!("The root signing key must be kept outside the offline public signing context");
    }
    let root_key_bytes = seed::read_private_file(&root_path, 1024, "offline root key")?;
    let root_secret =
        decode_fixed::<32>(std::str::from_utf8(&root_key_bytes)?, "root private key")?;
    let root_signing_key = SigningKey::from_bytes(&root_secret);
    if root_signing_key.verifying_key() != seed.root_verifying_key {
        bail!("Offline root key does not match the runtime's pinned root certificate");
    }

    let identity = NodeIdentity {
        version: "2".into(),
        root_public_key: seed.root_public_key_hex(),
        node_public_key: request.body.public_key.clone(),
        seed_sha256: hex::encode(Sha256::digest(fs::read(seed.home.join("seed.toml"))?)),
        cluster_id: seed.cluster_id.clone(),
        node_id: request.body.node_id.clone(),
        role: request.body.role.clone(),
    };
    let certificate = NodeCertificate {
        root_signature: hex::encode(
            root_signing_key
                .sign(&serde_json::to_vec(&identity)?)
                .to_bytes(),
        ),
        identity,
    };
    seed.verify_peer_certificate(&certificate)?;
    let bundle_path = create_bundle_path(bundle_path, &seed.home)?;
    let bundle_result = (|| -> Result<()> {
        write_new(
            &bundle_path.join("root.pub"),
            &fs::read(seed.home.join("root.pub"))?,
            false,
        )?;
        write_new(
            &bundle_path.join("seed.toml"),
            &fs::read(seed.home.join("seed.toml"))?,
            false,
        )?;
        write_new(
            &bundle_path.join("seed.sig"),
            &fs::read(seed.home.join("seed.sig"))?,
            false,
        )?;
        write_new(
            &bundle_path.join("node.cert"),
            &serde_json::to_vec_pretty(&certificate)?,
            false,
        )?;
        write_new(
            &bundle_path.join("primary.cert"),
            &serde_json::to_vec_pretty(&seed.primary_certificate)?,
            false,
        )?;
        write_new(
            &bundle_path.join("request.json"),
            &serde_json::to_vec_pretty(&request)?,
            false,
        )?;
        Ok(())
    })();
    if let Err(error) = bundle_result {
        let _ = fs::remove_dir_all(&bundle_path);
        return Err(error);
    }
    Ok(IssuedPeer {
        key_fingerprint: hex::encode(Sha256::digest(hex::decode(&request.body.public_key)?)),
        request,
        certificate,
        bundle_path,
    })
}

pub(crate) fn read_issued_peer(seed: &Seed, bundle: &Path) -> Result<IssuedPeer> {
    let original = bundle;
    let metadata = fs::symlink_metadata(original)
        .with_context(|| format!("Cannot inspect peer bundle {}", original.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("Peer bundle must be a real directory, not a symlink");
    }
    let bundle = fs::canonicalize(original)?;
    let allowed = [
        "root.pub",
        "seed.toml",
        "seed.sig",
        "node.cert",
        "primary.cert",
        "request.json",
    ];
    for entry in fs::read_dir(&bundle)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || !allowed.iter().any(|name| entry.file_name() == *name) {
            bail!(
                "Peer bundle contains an unexpected or non-regular entry: {}",
                entry.path().display()
            );
        }
    }
    let root_public = read_regular_file(&bundle.join("root.pub"), 1024)?;
    let config = read_regular_file(&bundle.join("seed.toml"), 64 * 1024)?;
    let seed_signature = read_regular_file(&bundle.join("seed.sig"), 1024)?;
    let certificate: NodeCertificate =
        serde_json::from_slice(&read_regular_file(&bundle.join("node.cert"), 16 * 1024)?)?;
    let primary: NodeCertificate =
        serde_json::from_slice(&read_regular_file(&bundle.join("primary.cert"), 16 * 1024)?)?;
    let request = read_request(&bundle.join("request.json"))?;
    if root_public != fs::read(seed.home.join("root.pub"))?
        || config != fs::read(seed.home.join("seed.toml"))?
        || seed_signature != fs::read(seed.home.join("seed.sig"))?
    {
        bail!("Peer bundle belongs to a different root or seed");
    }
    seed.verify_peer_certificate(&certificate)?;
    seed.verify_peer_certificate(&primary)?;
    let identity = &certificate.identity;
    if identity.node_id == seed.node_id
        || identity.node_id != request.body.node_id
        || identity.role != request.body.role
        || identity.node_public_key != request.body.public_key
        || request.body.root_fingerprint != seed.root_fingerprint_sha256()
        || primary.identity.node_id != seed.node_id
        || primary.identity.node_public_key != seed.node_public_key_hex()
        || primary.identity.role != seed.role
    {
        bail!("Peer or control-node certificate does not match the signed request and active seed");
    }
    let key_fingerprint = hex::encode(Sha256::digest(hex::decode(&identity.node_public_key)?));
    Ok(IssuedPeer {
        request,
        certificate,
        bundle_path: bundle,
        key_fingerprint,
    })
}

pub(crate) fn join_bundle(bundle: &Path) -> Result<()> {
    let trusted_pin = seed::trusted_root_sha256()?;
    let bundle = fs::canonicalize(bundle)
        .with_context(|| format!("Cannot access peer bundle {}", bundle.display()))?;
    let metadata = fs::symlink_metadata(&bundle)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("Peer bundle must be a real directory, not a symlink");
    }
    let root_public = read_regular_file(&bundle.join("root.pub"), 1024)?;
    let root_public_bytes =
        decode_fixed::<32>(std::str::from_utf8(&root_public)?, "bundle root public key")?;
    seed::verify_trusted_root(&root_public_bytes, &trusted_pin)?;
    let config = read_regular_file(&bundle.join("seed.toml"), 64 * 1024)?;
    let seed_signature = read_regular_file(&bundle.join("seed.sig"), 1024)?;
    let certificate_bytes = read_regular_file(&bundle.join("node.cert"), 16 * 1024)?;
    let primary_certificate_bytes = read_regular_file(&bundle.join("primary.cert"), 16 * 1024)?;
    let bundled_request_bytes = read_regular_file(&bundle.join("request.json"), 16 * 1024)?;
    let bundled_request: PeerRequest = serde_json::from_slice(&bundled_request_bytes)?;
    verify_request(&bundled_request)?;

    let home = seed::home_dir()?;
    fs::create_dir_all(&home)
        .with_context(|| format!("Cannot create runtime directory {}", home.display()))?;
    seed::prepare_private_dir(&home)?;
    let node_key_path = home.join("node.key");
    let local_request_path = home.join("node.request.json");
    let local_key_bytes = seed::read_private_file(&node_key_path, 1024, "node private key")
        .context("Run `molt peer request` on this node before joining")?;
    let local_secret = decode_fixed::<32>(
        std::str::from_utf8(&local_key_bytes)?,
        "local node private key",
    )?;
    let local_signing_key = SigningKey::from_bytes(&local_secret);
    let local_request: PeerRequest =
        serde_json::from_slice(&read_regular_file(&local_request_path, 16 * 1024)?)
            .context("Missing or invalid local signed node request")?;
    verify_request(&local_request)?;
    if hex::encode(local_signing_key.verifying_key().as_bytes()) != local_request.body.public_key {
        bail!("Local private key does not match the signed peer request");
    }
    if local_request.body.node_id != bundled_request.body.node_id
        || local_request.body.role != bundled_request.body.role
        || local_request.body.public_key != bundled_request.body.public_key
        || local_request.body.nonce != bundled_request.body.nonce
        || local_request.proof_of_possession != bundled_request.proof_of_possession
    {
        bail!("Peer bundle does not correspond to the request and private key on this node");
    }
    for name in [
        "root.pub",
        "seed.toml",
        "seed.sig",
        "node.cert",
        "molt.sqlite3",
    ] {
        if home.join(name).exists() {
            bail!(
                "{} already exists; refusing to replace initialized runtime state",
                home.join(name).display()
            );
        }
    }
    if home.join("peers").exists() {
        bail!("Peer trust directory already exists; refusing to replace it");
    }

    let created_home = fs::read_dir(&home)?.next().is_none();
    let installed = ["root.pub", "seed.toml", "seed.sig", "node.cert"];
    let mut peer_dir_created = false;
    let result = (|| -> Result<()> {
        write_new(&home.join("root.pub"), &root_public, false)?;
        write_new(&home.join("seed.toml"), &config, false)?;
        write_new(&home.join("seed.sig"), &seed_signature, false)?;
        write_new(&home.join("node.cert"), &certificate_bytes, false)?;
        let joined_seed = Seed::load()?;
        if joined_seed.node_id == "node-primary"
            || joined_seed.node_id != local_request.body.node_id
            || joined_seed.role != local_request.body.role
            || joined_seed.node_public_key_hex() != local_request.body.public_key
            || joined_seed.root_fingerprint_sha256() != local_request.body.root_fingerprint
        {
            bail!("Node certificate does not match this node's signed key request");
        }
        let primary_certificate: NodeCertificate =
            serde_json::from_slice(&primary_certificate_bytes)?;
        joined_seed.verify_peer_certificate(&primary_certificate)?;
        if primary_certificate.identity.node_id != "node-primary"
            || primary_certificate.identity.role != "control"
            || primary_certificate.identity.cluster_id != joined_seed.cluster_id
        {
            bail!("Bundle does not contain the matching cluster control-node certificate");
        }
        let peers_dir = home.join("peers");
        fs::create_dir(&peers_dir)?;
        set_private_dir(&peers_dir)?;
        peer_dir_created = true;
        write_new(
            &peers_dir.join("node-primary.cert"),
            &primary_certificate_bytes,
            false,
        )?;
        crate::store::Store::initialize(&joined_seed)?;
        println!(
            "Joined cluster {} as {} ({}) at {}.",
            joined_seed.cluster_id,
            joined_seed.node_id,
            joined_seed.role,
            home.display()
        );
        println!("The offline root private key was not transferred; the node key remains local.");
        Ok(())
    })();
    if let Err(error) = result {
        for name in installed {
            let _ = fs::remove_file(home.join(name));
        }
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(home.join(format!("molt.sqlite3{suffix}")));
        }
        if peer_dir_created {
            let _ = fs::remove_dir_all(home.join("peers"));
        }
        if created_home {
            let _ = fs::remove_dir(&home);
        }
        return Err(error);
    }
    Ok(())
}

fn create_bundle_path(requested: &Path, runtime_home: &Path) -> Result<PathBuf> {
    let requested = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        env::current_dir()?.join(requested)
    };
    let name = requested
        .file_name()
        .context("Peer bundle path must name a new directory")?;
    let parent = requested
        .parent()
        .context("Peer bundle path must have a parent directory")?;
    fs::create_dir_all(parent)?;
    let parent = fs::canonicalize(parent)?;
    let destination = parent.join(name);
    let runtime_home = fs::canonicalize(runtime_home)?;
    if destination.starts_with(runtime_home) {
        bail!("Peer bundle must be outside the online runtime directory");
    }
    fs::create_dir(&destination).with_context(|| {
        format!(
            "Peer bundle destination already exists: {}",
            destination.display()
        )
    })?;
    set_private_dir(&destination)?;
    Ok(destination)
}

fn read_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("Cannot inspect {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        bail!(
            "{} must be a regular file no larger than {max_bytes} bytes",
            path.display()
        );
    }
    Ok(fs::read(path)?)
}
