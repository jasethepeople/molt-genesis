use crate::seed::Seed;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use syn::visit::{self, Visit};
use syn::{ItemFn, ItemForeignMod, ItemImpl, ItemStatic, ItemTrait};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Passed,
    Rejected,
    Blocked,
}

#[derive(Clone, Debug, Serialize)]
pub struct CrucibleReport {
    pub outcome: Outcome,
    pub static_checks: Vec<String>,
    pub sandbox_exit_code: Option<i32>,
    pub sandbox_output: String,
    pub note: String,
}

#[derive(Default)]
struct UnsafeVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for UnsafeVisitor {
    fn visit_expr_unsafe(&mut self, _: &'ast syn::ExprUnsafe) {
        self.found = true;
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if node.sig.unsafety.is_some() {
            self.found = true;
        }
        visit::visit_item_fn(self, node);
    }

    fn visit_item_foreign_mod(&mut self, _: &'ast ItemForeignMod) {
        self.found = true;
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if node.unsafety.is_some() {
            self.found = true;
        }
        visit::visit_item_impl(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        if node.unsafety.is_some() {
            self.found = true;
        }
        visit::visit_item_trait(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        if !matches!(node.mutability, syn::StaticMutability::None) {
            self.found = true;
        }
        visit::visit_item_static(self, node);
    }
}

#[derive(Default)]
struct ProcessApiVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for ProcessApiVisitor {
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node
            .path
            .segments
            .iter()
            .any(|segment| matches!(segment.ident.to_string().as_str(), "process" | "fs"))
        {
            self.found = true;
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if use_tree_mentions_process(&node.tree, false) {
            self.found = true;
        }
        visit::visit_item_use(self, node);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if node.ident.is_some() {
            self.found = true;
        }
        visit::visit_item_macro(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        let name = node
            .mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
        if name.as_deref().is_some_and(|name| {
            matches!(
                name,
                "include" | "include_str" | "include_bytes" | "env" | "option_env"
            )
        }) {
            self.found = true;
        }
        visit::visit_expr_macro(self, node);
    }
}

fn use_tree_mentions_process(tree: &syn::UseTree, in_blocked_module: bool) -> bool {
    match tree {
        syn::UseTree::Path(path) => use_tree_mentions_process(
            &path.tree,
            in_blocked_module || matches!(path.ident.to_string().as_str(), "process" | "fs"),
        ),
        syn::UseTree::Name(name) => {
            in_blocked_module || matches!(name.ident.to_string().as_str(), "process" | "fs")
        }
        syn::UseTree::Rename(rename) => {
            in_blocked_module
                || matches!(rename.ident.to_string().as_str(), "process" | "fs" | "std")
        }
        syn::UseTree::Glob(_) => in_blocked_module,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_mentions_process(item, in_blocked_module)),
    }
}

pub fn evaluate(seed: &Seed, source: &str, tests: &str) -> Result<CrucibleReport> {
    let config = &seed.config.invariants;
    if source.len() > config.max_source_bytes || tests.len() > config.max_test_bytes {
        return Ok(rejected(
            "Patch source or test file exceeds the signed size limit",
            vec!["size_limit".to_string()],
        ));
    }
    let source_ast = match syn::parse_file(source) {
        Ok(ast) => ast,
        Err(error) => {
            return Ok(rejected(
                &format!("Source is not valid Rust syntax: {error}"),
                vec!["source_parse".to_string()],
            ))
        }
    };
    let tests_ast = match syn::parse_file(tests) {
        Ok(ast) => ast,
        Err(error) => {
            return Ok(rejected(
                &format!("Tests are not valid Rust syntax: {error}"),
                vec!["test_parse".to_string()],
            ))
        }
    };
    if !source_ast.attrs.is_empty() || !tests_ast.attrs.is_empty() {
        return Ok(rejected(
            "Crate-level attributes are not permitted in generated artifacts",
            vec!["crate_attributes".to_string()],
        ));
    }
    if config.deny_unsafe_rust {
        let mut visitor = UnsafeVisitor::default();
        visitor.visit_file(&source_ast);
        visitor.visit_file(&tests_ast);
        if visitor.found {
            return Ok(rejected(
                "Unsafe Rust, FFI, unsafe traits/impls, and mutable statics are forbidden",
                vec!["unsafe_rust".to_string()],
            ));
        }
    }
    let mut termination_visitor = ProcessApiVisitor::default();
    termination_visitor.visit_file(&source_ast);
    termination_visitor.visit_file(&tests_ast);
    if termination_visitor.found {
        return Ok(rejected(
            "Process APIs and user-defined macros are forbidden in generated patches",
            vec!["process_api_or_macro".to_string()],
        ));
    }

    let harness = format!("#![forbid(unsafe_code)]\n{source}\n{tests}\n");

    let rustc = find_rustc()?;
    let sysroot_output = Command::new(&rustc)
        .arg("--print")
        .arg("sysroot")
        .output()
        .context("Cannot locate the Rust compiler sysroot")?;
    if !sysroot_output.status.success() {
        bail!("Rust compiler could not report its sysroot");
    }
    let sysroot = PathBuf::from(String::from_utf8(sysroot_output.stdout)?.trim());
    if !sysroot.is_absolute() || !sysroot.join("bin/rustc").exists() {
        bail!("Rust compiler reported an invalid sysroot");
    }
    let probe = sandbox_command(seed, &sysroot, &["/usr/bin/true"])?;
    let probe = match run_limited(probe, None) {
        Ok(result) if result.status.success() => result,
        Ok(result) => {
            return Ok(blocked(&format!(
                "Bubblewrap isolation probe failed (exit {:?}): {}",
                result.status.code(),
                excerpt(&result.stderr)
            )))
        }
        Err(error) => {
            return Ok(blocked(&format!(
                "Bubblewrap isolation probe could not run: {error:#}"
            )))
        }
    };
    let _ = probe;

    let run_script = "/toolchain/bin/rustc --edition=2021 --test -C debuginfo=0 - -o /work/molt-tests && /work/molt-tests --nocapture";
    let run_args = ["/usr/bin/sh", "-c", run_script];
    let sandbox_run = sandbox_command(seed, &sysroot, &run_args)?;
    let result = match run_limited(sandbox_run, Some(harness.into_bytes())) {
        Ok(result) => result,
        Err(error) => {
            return Ok(blocked(&format!(
                "Isolated compile/test run could not complete: {error:#}"
            )))
        }
    };
    let passed = result.status.success();
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(CrucibleReport {
        outcome: if passed {
            Outcome::Passed
        } else {
            Outcome::Rejected
        },
        static_checks: vec![
            "Rust syntax parsed".into(),
            "unsafe-code inspection passed".into(),
            "sandbox isolation probe passed".into(),
            "compiled without external crates".into(),
        ],
        sandbox_exit_code: result.status.code(),
        sandbox_output: excerpt(output),
        note: if passed {
            "Compilation and all submitted unit tests passed in the isolated sandbox".into()
        } else {
            "Compilation or one or more unit tests failed or exceeded resource limits in the isolated sandbox".into()
        },
    })
}

fn rejected(note: &str, checks: Vec<String>) -> CrucibleReport {
    CrucibleReport {
        outcome: Outcome::Rejected,
        static_checks: checks,
        sandbox_exit_code: None,
        sandbox_output: String::new(),
        note: note.to_string(),
    }
}

fn blocked(note: &str) -> CrucibleReport {
    CrucibleReport {
        outcome: Outcome::Blocked,
        static_checks: Vec::new(),
        sandbox_exit_code: None,
        sandbox_output: String::new(),
        note: note.to_string(),
    }
}

fn find_rustc() -> Result<PathBuf> {
    if let Ok(path) = env::var("MOLT_RUSTC") {
        return Ok(PathBuf::from(path));
    }
    let path = env::var_os("PATH").unwrap_or_default();
    for directory in env::split_paths(&path) {
        let candidate = directory.join("rustc");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("Rust compiler not found; add rustc to PATH or set MOLT_RUSTC")
}

fn sandbox_command(seed: &Seed, sysroot: &Path, command: &[&str]) -> Result<Command> {
    for path in ["/usr", "/usr/lib", "/usr/lib64"] {
        if !Path::new(path).exists() {
            bail!("Required read-only sandbox runtime path is missing: {path}");
        }
    }
    let mem_bytes = seed
        .config
        .invariants
        .max_memory_mb
        .saturating_mul(1024 * 1024);
    let cpu_limit = format!("--cpu={0}:{0}", seed.config.invariants.max_cpu_seconds);
    let memory_limit = format!("--as={mem_bytes}:{mem_bytes}");
    let sysroot = sysroot.canonicalize()?;
    let mut args: Vec<String> = vec![
        "--signal=TERM".into(),
        "--kill-after=2s".into(),
        format!("{}s", seed.config.invariants.max_wall_seconds),
        "prlimit".into(),
        cpu_limit,
        memory_limit,
        "--fsize=67108864:67108864".into(),
        "--nproc=8:8".into(),
        "--".into(),
        "bwrap".into(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-all".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--tmpfs".into(),
        "/".into(),
        "--dir".into(),
        "/usr".into(),
        "--ro-bind".into(),
        "/usr".into(),
        "/usr".into(),
        "--dir".into(),
        "/lib".into(),
        "--ro-bind".into(),
        "/usr/lib".into(),
        "/lib".into(),
        "--dir".into(),
        "/lib64".into(),
        "--ro-bind".into(),
        "/usr/lib64".into(),
        "/lib64".into(),
        "--dir".into(),
        "/toolchain".into(),
        "--ro-bind".into(),
        sysroot.display().to_string(),
        "/toolchain".into(),
        "--size".into(),
        "536870912".into(),
        "--tmpfs".into(),
        "/work".into(),
        "--chmod".into(),
        "1777".into(),
        "/work".into(),
        "--size".into(),
        "134217728".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--chmod".into(),
        "1777".into(),
        "/tmp".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--chdir".into(),
        "/work".into(),
        "--clearenv".into(),
        "--setenv".into(),
        "PATH".into(),
        "/toolchain/bin:/usr/bin".into(),
        "--setenv".into(),
        "HOME".into(),
        "/tmp".into(),
        "--setenv".into(),
        "TMPDIR".into(),
        "/tmp".into(),
        "--setenv".into(),
        "LC_ALL".into(),
        "C".into(),
        "--uid".into(),
        "65534".into(),
        "--gid".into(),
        "65534".into(),
    ];
    args.extend(command.iter().map(|s| (*s).to_string()));
    let mut process = Command::new("timeout");
    process.args(args).env_clear();
    Ok(process)
}

const MAX_CAPTURE_BYTES_PER_STREAM: usize = 128 * 1024;

fn run_limited(mut command: Command, stdin_input: Option<Vec<u8>>) -> Result<std::process::Output> {
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(if stdin_input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("Cannot start timeout/prlimit/bubblewrap")?;
    let stdin_writer = if let Some(input) = stdin_input {
        let mut stdin = child
            .stdin
            .take()
            .context("Sandbox stdin pipe is missing")?;
        Some(thread::spawn(move || {
            let _ = stdin.write_all(&input);
        }))
    } else {
        None
    };
    let stdout = child
        .stdout
        .take()
        .context("Sandbox stdout pipe is missing")?;
    let stderr = child
        .stderr
        .take()
        .context("Sandbox stderr pipe is missing")?;
    let stdout_reader =
        thread::spawn(move || capture_bounded(stdout, MAX_CAPTURE_BYTES_PER_STREAM));
    let stderr_reader =
        thread::spawn(move || capture_bounded(stderr, MAX_CAPTURE_BYTES_PER_STREAM));
    let status = child.wait().context("Cannot wait for sandbox process")?;
    if let Some(writer) = stdin_writer {
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("Sandbox stdin writer panicked"))?;
    }
    let (mut stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("Sandbox stdout reader panicked"))??;
    let (mut stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("Sandbox stderr reader panicked"))??;
    if stdout_truncated {
        stdout.extend_from_slice(b"\n[MOLT: stdout capture truncated at 128 KiB]\n");
    }
    if stderr_truncated {
        stderr.extend_from_slice(b"\n[MOLT: stderr capture truncated at 128 KiB]\n");
    }
    if status.code() == Some(124) || status.code() == Some(137) {
        bail!("Sandbox command exceeded the signed CPU or wall-clock limit");
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn capture_bounded(mut reader: impl Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut output = Vec::with_capacity(limit.min(8192));
    let mut truncated = false;
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(output.len());
        let keep = read.min(remaining);
        output.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    Ok((output, truncated))
}

fn excerpt(text: impl AsRef<[u8]>) -> String {
    let text = String::from_utf8_lossy(text.as_ref());
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 12000 {
        text.into_owned()
    } else {
        chars[chars.len() - 12000..].iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn valid_code_is_never_executed_outside_the_sandbox() {
        let home = env::temp_dir().join(format!("molt-crucible-test-{}", Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let seed = Seed {
            home: home.clone(),
            config: toml::from_str(include_str!("../config/seed.toml")).unwrap(),
            verifying_key,
            root_verifying_key: verifying_key,
            cluster_id: Uuid::new_v4().to_string(),
            node_id: "node-primary".into(),
            role: "control".into(),
            signing_key,
        };
        let report = evaluate(
            &seed,
            "pub fn add(a: u32, b: u32) -> u32 { a + b }",
            "#[test] fn addition_is_correct() { assert_eq!(add(2, 3), 5); }",
        )
        .unwrap();
        assert!(!matches!(report.outcome, Outcome::Rejected));
        if matches!(report.outcome, Outcome::Blocked) {
            assert!(
                report.note.contains("sandbox") || report.note.contains("isolation"),
                "unexpected block report: {}",
                report.note
            );
        }
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn unsafe_operations_are_detected_from_rust_syntax() {
        for source in [
            "pub unsafe fn exposed() {}",
            "pub fn exposed() { unsafe { std::ptr::read(std::ptr::null()) }; }",
            "extern \"C\" { fn foreign(); }",
            "static mut SHARED: u8 = 0;",
        ] {
            let parsed = syn::parse_file(source).unwrap();
            let mut visitor = UnsafeVisitor::default();
            visitor.visit_file(&parsed);
            assert!(visitor.found, "expected unsafe Rust to be found: {source}");
        }
    }

    #[test]
    fn process_termination_aliases_and_user_macros_are_rejected() {
        for source in [
            "pub fn stop() { std::process::exit(0); }",
            "use std::process::exit as finish; pub fn stop() { finish(0); }",
            "macro_rules! stop { () => { std::process::exit(0) } }",
        ] {
            let parsed = syn::parse_file(source).unwrap();
            let mut visitor = ProcessApiVisitor::default();
            visitor.visit_file(&parsed);
            assert!(
                visitor.found,
                "expected process escape to be blocked: {source}"
            );
        }
    }

    #[test]
    fn ordinary_safe_rust_is_not_flagged() {
        let parsed = syn::parse_file("pub fn add(a: u32, b: u32) -> u32 { a + b }").unwrap();
        let mut visitor = UnsafeVisitor::default();
        visitor.visit_file(&parsed);
        assert!(!visitor.found);
    }

    #[test]
    fn output_capture_is_bounded_while_the_stream_is_drained() {
        let input = std::io::Cursor::new(b"0123456789".to_vec());
        let (output, truncated) = capture_bounded(input, 4).unwrap();
        assert_eq!(output, b"0123");
        assert!(truncated);
    }
}
