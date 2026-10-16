use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize)]
pub struct SeedConfig {
    pub seed: SeedMetadata,
    pub invariants: Invariants,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SeedMetadata {
    pub version: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Invariants {
    pub allow_arbitrary_network_outbound: bool,
    pub require_cryptographic_signatures: bool,
    pub deny_unsafe_rust: bool,
    pub max_memory_mb: u64,
    pub max_cpu_seconds: u64,
    pub max_wall_seconds: u64,
    pub max_source_bytes: usize,
    pub max_test_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct NodeIdentity {
    pub(crate) version: String,
    pub(crate) root_public_key: String,
    pub(crate) node_public_key: String,
    pub(crate) seed_sha256: String,
    pub(crate) cluster_id: String,
    pub(crate) node_id: String,
    pub(crate) role: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct NodeCertificate {
    pub(crate) identity: NodeIdentity,
    pub(crate) root_signature: String,
}

pub struct SeedTrust {
    pub home: PathBuf,
    pub root_verifying_key: VerifyingKey,
    pub cluster_id: String,
    pub node_id: String,
    pub role: String,
    pub(crate) primary_certificate: NodeCertificate,
}

impl SeedTrust {
    pub fn load() -> Result<Self> {
        let trusted_pin = trusted_root_sha256()?;
        let home = home_dir()?;
        verify_private_dir(&home)?;
        let root_public_text = fs::read_to_string(home.join("root.pub"))?;
        if root_public_text.len() > 1024 {
            bail!("Root public key exceeds the 1 KiB limit");
        }
        let root_public = decode_fixed::<32>(&root_public_text, "root public key")?;
        verify_trusted_root(&root_public, &trusted_pin)?;
        let config_bytes = fs::read(home.join("seed.toml"))
            .context("Offline signer context is missing seed.toml")?;
        let root_verifying_key =
            VerifyingKey::from_bytes(&root_public).context("Invalid root public key")?;
        let seed_signature = decode_fixed::<64>(
            &fs::read_to_string(home.join("seed.sig"))?,
            "seed signature",
        )?;
        root_verifying_key
            .verify_strict(&config_bytes, &Signature::from_bytes(&seed_signature))
            .context("Seed signature verification failed; offline signing refused")?;
        let config: SeedConfig = toml::from_str(std::str::from_utf8(&config_bytes)?)
            .context("Invalid signed seed configuration")?;
        validate_config(&config)?;
        let primary_certificate: NodeCertificate =
            serde_json::from_slice(&fs::read(home.join("node.cert"))?)
                .context("Invalid primary-node certificate")?;
        verify_node_identity(&primary_certificate.identity, &root_public, &config_bytes)?;
        let signature = decode_fixed::<64>(
            &primary_certificate.root_signature,
            "primary-node certificate signature",
        )?;
        root_verifying_key
            .verify_strict(
                &serde_json::to_vec(&primary_certificate.identity)?,
                &Signature::from_bytes(&signature),
            )
            .context("Primary-node certificate signature verification failed")?;
        if primary_certificate.identity.node_id != "node-primary"
            || primary_certificate.identity.role != "control"
        {
            bail!("Offline signer context is not the root-certified primary control node");
        }
        Ok(Self {
            home,
            root_verifying_key,
            cluster_id: primary_certificate.identity.cluster_id.clone(),
            node_id: primary_certificate.identity.node_id.clone(),
            role: primary_certificate.identity.role.clone(),
            primary_certificate,
        })
    }

    pub fn root_public_key_hex(&self) -> String {
        hex::encode(self.root_verifying_key.as_bytes())
    }

    pub fn root_fingerprint_sha256(&self) -> String {
        hex::encode(Sha256::digest(self.root_verifying_key.as_bytes()))
    }

    pub(crate) fn verify_peer_certificate(&self, certificate: &NodeCertificate) -> Result<()> {
        let config_bytes = fs::read(self.home.join("seed.toml"))?;
        verify_node_identity(
            &certificate.identity,
            self.root_verifying_key.as_bytes(),
            &config_bytes,
        )?;
        if certificate.identity.cluster_id != self.cluster_id {
            bail!("Peer certificate belongs to a different MOLT cluster");
        }
        let signature =
            decode_fixed::<64>(&certificate.root_signature, "peer certificate signature")?;
        self.root_verifying_key
            .verify_strict(
                &serde_json::to_vec(&certificate.identity)?,
                &Signature::from_bytes(&signature),
            )
            .context("Peer certificate signature verification failed")
    }
}

pub struct Seed {
    pub home: PathBuf,
    pub config: SeedConfig,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub root_verifying_key: VerifyingKey,
    pub cluster_id: String,
    pub node_id: String,
    pub role: String,
}

impl Seed {
    pub fn load() -> Result<Self> {
        let trusted_pin = trusted_root_sha256()?;
        let home = home_dir()?;
        verify_private_dir(&home)?;
        let root_public_bytes = decode_fixed::<32>(
            &fs::read_to_string(home.join("root.pub"))?,
            "root public key",
        )?;
        verify_trusted_root(&root_public_bytes, &trusted_pin)?;
        let root_verifying_key =
            VerifyingKey::from_bytes(&root_public_bytes).context("Invalid root public key")?;
        let config_bytes = fs::read(home.join("seed.toml"))
            .context("Seed is not initialized; run `molt init` first")?;
        let seed_signature = decode_fixed::<64>(
            &fs::read_to_string(home.join("seed.sig"))?,
            "seed signature",
        )?;
        root_verifying_key
            .verify_strict(&config_bytes, &Signature::from_bytes(&seed_signature))
            .context("Seed signature verification failed; refusing to start")?;
        let config: SeedConfig = toml::from_str(std::str::from_utf8(&config_bytes)?)
            .context("Invalid signed seed configuration")?;
        validate_config(&config)?;

        let certificate: NodeCertificate =
            serde_json::from_slice(&fs::read(home.join("node.cert"))?)
                .context("Invalid node certificate")?;
        verify_node_identity(&certificate.identity, &root_public_bytes, &config_bytes)?;
        let node_public_bytes =
            decode_fixed::<32>(&certificate.identity.node_public_key, "node public key")?;
        let verifying_key =
            VerifyingKey::from_bytes(&node_public_bytes).context("Invalid node public key")?;
        let certificate_signature =
            decode_fixed::<64>(&certificate.root_signature, "node certificate signature")?;
        root_verifying_key
            .verify_strict(
                &serde_json::to_vec(&certificate.identity)?,
                &Signature::from_bytes(&certificate_signature),
            )
            .context("Node certificate signature verification failed")?;

        let node_key_path = home.join("node.key");
        let node_key_bytes = read_private_file(&node_key_path, 1024, "node private key")?;
        let node_secret =
            decode_fixed::<32>(std::str::from_utf8(&node_key_bytes)?, "node private key")?;
        let signing_key = SigningKey::from_bytes(&node_secret);
        if signing_key.verifying_key() != verifying_key {
            bail!("Node private key does not match its root-signed certificate");
        }
        let seed = Self {
            home,
            config,
            signing_key,
            verifying_key,
            root_verifying_key,
            cluster_id: certificate.identity.cluster_id,
            node_id: certificate.identity.node_id,
            role: certificate.identity.role,
        };
        seed.verify_peer_registry()?;
        Ok(seed)
    }

    pub(crate) fn verify_peer_registry(&self) -> Result<()> {
        let directory = self.home.join("peers");
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        verify_private_dir(&directory)?;
        let mut peer_ids = std::collections::HashSet::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let name = entry.file_name();
            if !kind.is_file()
                || kind.is_symlink()
                || entry.path().extension().is_none_or(|ext| ext != "cert")
            {
                bail!(
                    "Peer registry contains a non-certificate or non-regular entry: {}",
                    entry.path().display()
                );
            }
            let metadata = entry.metadata()?;
            if metadata.len() > 16 * 1024 {
                bail!(
                    "Peer certificate is larger than 16 KiB: {}",
                    entry.path().display()
                );
            }
            let certificate: NodeCertificate = serde_json::from_slice(&fs::read(entry.path())?)
                .with_context(|| format!("Invalid peer certificate: {}", entry.path().display()))?;
            self.verify_peer_certificate(&certificate)?;
            let node_id = &certificate.identity.node_id;
            if node_id == &self.node_id
                || name.to_string_lossy() != format!("{node_id}.cert")
                || !peer_ids.insert(node_id.clone())
            {
                bail!(
                    "Peer registry filename or identity is invalid: {}",
                    entry.path().display()
                );
            }
        }
        Ok(())
    }

    pub(crate) fn verify_node_certificate(&self, certificate: &NodeCertificate) -> Result<()> {
        let root_public = self.root_verifying_key.as_bytes();
        let config_bytes = fs::read(self.home.join("seed.toml"))?;
        verify_node_identity(&certificate.identity, root_public, &config_bytes)?;
        let signature =
            decode_fixed::<64>(&certificate.root_signature, "node certificate signature")?;
        self.root_verifying_key
            .verify_strict(
                &serde_json::to_vec(&certificate.identity)?,
                &Signature::from_bytes(&signature),
            )
            .context("Node certificate signature verification failed")
    }

    pub(crate) fn verify_peer_certificate(&self, certificate: &NodeCertificate) -> Result<()> {
        self.verify_node_certificate(certificate)?;
        if certificate.identity.cluster_id != self.cluster_id {
            bail!("Peer certificate belongs to a different MOLT cluster");
        }
        Ok(())
    }

    pub fn sign(&self, bytes: &[u8]) -> Signature {
        self.signing_key.sign(bytes)
    }

    pub fn node_public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    pub fn root_public_key_hex(&self) -> String {
        hex::encode(self.root_verifying_key.as_bytes())
    }

    pub fn root_fingerprint_sha256(&self) -> String {
        hex::encode(Sha256::digest(self.root_verifying_key.as_bytes()))
    }
}

pub fn initialize(root_key_out: &Path) -> Result<()> {
    let home = home_dir()?;
    fs::create_dir_all(&home)
        .with_context(|| format!("Cannot create runtime directory {}", home.display()))?;
    prepare_private_dir(&home)?;
    let parent = root_key_out.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).with_context(|| {
        format!(
            "Root-key parent directory does not exist: {}",
            parent.display()
        )
    })?;
    let filename = root_key_out
        .file_name()
        .context("Root-key output must name a file")?;
    let root_key_path = parent.join(filename);
    if root_key_path.starts_with(fs::canonicalize(&home)?) {
        bail!("Root private key must be written outside MOLT_HOME");
    }
    if fs::symlink_metadata(&root_key_path).is_ok() {
        bail!(
            "Root-key output already exists; refusing to overwrite it: {}",
            root_key_path.display()
        );
    }
    for name in [
        "seed.toml",
        "seed.sig",
        "root.pub",
        "node.key",
        "node.cert",
        "molt.sqlite3",
    ] {
        if home.join(name).exists() {
            bail!(
                "{} already exists; refusing to replace existing runtime state",
                home.join(name).display()
            );
        }
    }

    let root_signing_key = SigningKey::generate(&mut OsRng);
    let root_verifying_key = root_signing_key.verifying_key();
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let config_bytes = include_bytes!("../config/seed.toml");
    let config: SeedConfig = toml::from_str(std::str::from_utf8(config_bytes)?)?;
    validate_config(&config)?;
    let seed_signature = root_signing_key.sign(config_bytes);
    let cluster_id = uuid::Uuid::new_v4().to_string();
    let identity = NodeIdentity {
        version: "2".into(),
        root_public_key: hex::encode(root_verifying_key.as_bytes()),
        node_public_key: hex::encode(verifying_key.as_bytes()),
        seed_sha256: hex::encode(Sha256::digest(config_bytes)),
        cluster_id: cluster_id.clone(),
        node_id: "node-primary".into(),
        role: "control".into(),
    };
    let identity_bytes = serde_json::to_vec(&identity)?;
    let certificate = NodeCertificate {
        identity,
        root_signature: hex::encode(root_signing_key.sign(&identity_bytes).to_bytes()),
    };

    write_new(
        &root_key_path,
        format!("{}\n", hex::encode(root_signing_key.to_bytes())).as_bytes(),
        true,
    )?;
    write_new(
        &home.join("root.pub"),
        format!("{}\n", hex::encode(root_verifying_key.as_bytes())).as_bytes(),
        false,
    )?;
    write_new(
        &home.join("node.key"),
        format!("{}\n", hex::encode(signing_key.to_bytes())).as_bytes(),
        true,
    )?;
    write_new(
        &home.join("node.cert"),
        &serde_json::to_vec_pretty(&certificate)?,
        false,
    )?;
    write_new(&home.join("seed.toml"), config_bytes, true)?;
    write_new(
        &home.join("seed.sig"),
        format!("{}\n", hex::encode(seed_signature.to_bytes())).as_bytes(),
        true,
    )?;

    let seed = Seed {
        home: home.clone(),
        config,
        signing_key,
        verifying_key,
        root_verifying_key,
        cluster_id: cluster_id.clone(),
        node_id: "node-primary".into(),
        role: "control".into(),
    };
    crate::store::Store::initialize(&seed)?;
    println!(
        "Initialized root-signed MOLT seed and runtime node at {}",
        home.display()
    );
    println!(
        "Offline root private key written to: {}",
        root_key_path.display()
    );
    println!(
        "Root public-key fingerprint (SHA-256): {}",
        hex::encode(Sha256::digest(root_verifying_key.as_bytes()))
    );
    println!("Keep root.key offline. It is written outside MOLT_HOME and is only needed for peer signing.");
    println!("Cluster ID: {cluster_id}");
    println!("Set MOLT_TRUSTED_ROOT_SHA256 to pin the root fingerprint on every run.");
    Ok(())
}

pub fn home_dir() -> Result<PathBuf> {
    if let Some(path) = env::var_os("MOLT_HOME") {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path).join("molt-genesis"));
    }
    let home = env::var_os("HOME").context("Neither MOLT_HOME, XDG_DATA_HOME, nor HOME is set")?;
    Ok(PathBuf::from(home).join(".local/share/molt-genesis"))
}

fn validate_config(config: &SeedConfig) -> Result<()> {
    let i = &config.invariants;
    if config.seed.version != "1.0.0" {
        bail!("Unsupported seed version: {}", config.seed.version);
    }
    if i.allow_arbitrary_network_outbound
        || !i.require_cryptographic_signatures
        || !i.deny_unsafe_rust
    {
        bail!("Seed weakens a mandatory invariant; refusing to start");
    }
    if !(256..=16384).contains(&i.max_memory_mb)
        || !(1..=300).contains(&i.max_cpu_seconds)
        || !(5..=600).contains(&i.max_wall_seconds)
        || !(1024..=1_048_576).contains(&i.max_source_bytes)
        || !(1024..=1_048_576).contains(&i.max_test_bytes)
    {
        bail!("Seed resource limits are outside the supported safe ranges");
    }
    Ok(())
}

pub(crate) fn verify_node_identity(
    identity: &NodeIdentity,
    root_public: &[u8; 32],
    config: &[u8],
) -> Result<()> {
    if identity.version != "2"
        || identity.root_public_key != hex::encode(root_public)
        || identity.seed_sha256 != hex::encode(Sha256::digest(config))
        || uuid::Uuid::parse_str(&identity.cluster_id)?.to_string() != identity.cluster_id
    {
        bail!("Node certificate does not match the trusted root and signed seed");
    }
    validate_node_id(&identity.node_id)?;
    validate_role(&identity.role)?;
    Ok(())
}

pub(crate) fn validate_node_id(node_id: &str) -> Result<()> {
    if node_id.is_empty()
        || node_id.len() > 63
        || node_id.starts_with('-')
        || node_id.ends_with('-')
        || !node_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("Node IDs must be 1-63 lowercase ASCII letters, digits, or interior hyphens");
    }
    Ok(())
}

pub(crate) fn validate_role(role: &str) -> Result<()> {
    if !matches!(role, "control" | "validator" | "consensus") {
        bail!("Role must be control, validator, or consensus");
    }
    Ok(())
}

pub(crate) fn trusted_root_sha256() -> Result<[u8; 32]> {
    let expected = env::var("MOLT_TRUSTED_ROOT_SHA256")
        .context("MOLT_TRUSTED_ROOT_SHA256 is required; set it to the independently recorded fingerprint printed by `molt init`")?;
    decode_fixed::<32>(&expected, "MOLT_TRUSTED_ROOT_SHA256")
}

pub(crate) fn verify_trusted_root(public: &[u8; 32], expected: &[u8; 32]) -> Result<()> {
    let actual: [u8; 32] = Sha256::digest(public).into();
    let mut difference = 0u8;
    for (actual_byte, expected_byte) in actual.iter().zip(expected) {
        difference |= actual_byte ^ expected_byte;
    }
    if difference != 0 {
        bail!("Root public-key fingerprint does not match MOLT_TRUSTED_ROOT_SHA256");
    }
    Ok(())
}

pub(crate) fn decode_fixed<const N: usize>(text: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(text.trim()).with_context(|| format!("Malformed {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Unexpected length for {label}"))
}

pub(crate) fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("Cannot create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn verify_private_dir(path: &Path) -> Result<()> {
    reject_symlink_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::symlink_metadata(path)?;
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!(
                "Runtime directory {} is owned by another user",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("Runtime directory {} is accessible to group or other users; set permissions to 0700", path.display());
        }
    }
    Ok(())
}

pub(crate) fn prepare_private_dir(path: &Path) -> Result<()> {
    reject_symlink_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!("Refusing to change permissions on a directory owned by another user");
        }
    }
    set_private_dir(path)?;
    verify_private_dir(path)
}

pub(crate) fn reject_symlink_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Cannot inspect runtime directory {}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "Runtime path {} must be a real directory, not a symlink",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn set_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(crate) fn read_private_file(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let before = fs::symlink_metadata(path)
        .with_context(|| format!("Cannot inspect {label} {}", path.display()))?;
    if !before.file_type().is_file() || before.file_type().is_symlink() {
        bail!("{label} must be a regular, non-symlink file");
    }
    if before.len() > max_bytes as u64
        || before.mode() & 0o077 != 0
        || before.uid() != unsafe { libc::geteuid() }
    {
        bail!("{label} is oversized, accessible to group/other users, or owned by another user");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("Cannot securely open {label} {}", path.display()))?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file()
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.mode() & 0o077 != 0
    {
        bail!("{label} changed during secure open or has an untrusted owner/mode");
    }
    let mut bytes = Vec::with_capacity(max_bytes.min(4096));
    file.take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        bail!("{label} exceeds the {max_bytes}-byte limit");
    }
    Ok(bytes)
}
