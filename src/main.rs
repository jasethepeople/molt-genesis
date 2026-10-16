mod agents;
mod bench;
mod crucible;
mod molt;
mod peering;
mod seed;
mod store;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "molt",
    version,
    about = "Signed, fail-closed local agent runtime"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Initialize a runtime and write its root private key outside MOLT_HOME")]
    Init {
        #[arg(long)]
        root_key_out: PathBuf,
    },
    #[command(about = "Verify root pin, signatures, audit chain, and replayed state")]
    Verify,
    #[command(about = "Show signed runtime state and pending work")]
    Status,
    #[command(about = "Plan bounded tasks from an objective")]
    Plan { objective: String },
    #[command(about = "Generate an inert patch proposal for one task")]
    Work { task_id: String },
    #[command(about = "Run signed patch tests in fail-closed Crucible isolation")]
    Crucible { patch_id: String },
    #[command(about = "Stage a human-approved, passing patch; never hot-swaps code")]
    Approve { patch_id: String },
    #[command(about = "Sign benchmark suites, propose candidates, and record real scores")]
    Bench {
        #[command(subcommand)]
        command: BenchCommand,
    },
    #[command(about = "Provision root-signed peer identities; this does not create a network")]
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
}

#[derive(Subcommand)]
enum BenchCommand {
    #[command(about = "Sign a public task suite and held-out test digests")]
    SignSuite {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        held_out_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    #[command(about = "Generate and audit one inert candidate from public task data")]
    Propose {
        #[arg(long)]
        suite: PathBuf,
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        iteration: u64,
        #[arg(long = "context-patch")]
        context_patch_ids: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    #[command(about = "Score an audit-recorded candidate with the real Crucible")]
    Score {
        #[arg(long)]
        suite: PathBuf,
        #[arg(long)]
        held_out_dir: PathBuf,
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        iteration: u64,
        #[arg(long = "context-patch")]
        context_patch_ids: Vec<String>,
        #[arg(long)]
        source: PathBuf,
    },
    #[command(about = "Export signed benchmark scores to a new CSV file")]
    ExportCsv {
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum PeerCommand {
    #[command(about = "Create a local key and root-pinned proof-of-possession request")]
    Request {
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        root_fingerprint: String,
    },
    #[command(about = "Export the primary's public context for offline signing")]
    ExportRootContext {
        #[arg(long)]
        output: PathBuf,
    },
    #[command(about = "Verify a request and sign it using an external offline root key")]
    Sign {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        root_key: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
    },
    #[command(about = "Register a signed peer identity in the primary audit history")]
    Register {
        #[arg(long)]
        bundle: PathBuf,
    },
    #[command(about = "Verify and install a root-signed identity bundle locally")]
    Join {
        #[arg(long)]
        bundle: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { root_key_out } => seed::initialize(&root_key_out),
        Command::Verify => molt::Runtime::open()?.verify(),
        Command::Status => molt::Runtime::open()?.status(),
        Command::Plan { objective } => molt::Runtime::open()?.plan(&objective),
        Command::Work { task_id } => molt::Runtime::open()?.work(&task_id),
        Command::Crucible { patch_id } => molt::Runtime::open()?.crucible(&patch_id),
        Command::Approve { patch_id } => molt::Runtime::open()?.approve(&patch_id),
        Command::Bench { command } => {
            let mut runtime = molt::Runtime::open()?;
            match command {
                BenchCommand::SignSuite {
                    manifest,
                    held_out_dir,
                    output,
                } => runtime.bench_sign_suite(&manifest, &held_out_dir, &output),
                BenchCommand::Propose {
                    suite,
                    task_id,
                    iteration,
                    context_patch_ids,
                    output,
                } => {
                    runtime.bench_propose(&suite, &task_id, iteration, &context_patch_ids, &output)
                }
                BenchCommand::Score {
                    suite,
                    held_out_dir,
                    task_id,
                    iteration,
                    context_patch_ids,
                    source,
                } => runtime.bench_score(
                    &suite,
                    &held_out_dir,
                    &task_id,
                    iteration,
                    &context_patch_ids,
                    &source,
                ),
                BenchCommand::ExportCsv { output } => runtime.bench_export_csv(&output),
            }
        }
        Command::Peer { command } => match command {
            PeerCommand::Request {
                node_id,
                role,
                root_fingerprint,
            } => peering::request_identity(&node_id, &role, &root_fingerprint),
            PeerCommand::ExportRootContext { output } => {
                molt::Runtime::open()?.export_root_context(&output)
            }
            PeerCommand::Sign {
                request,
                root_key,
                bundle,
            } => {
                let context = seed::SeedTrust::load()?;
                let issued = peering::sign_request(&context, &request, &root_key, &bundle)?;
                println!(
                    "Signed peer identity {} ({}) into {}",
                    issued.request.body.node_id,
                    issued.request.body.role,
                    issued.bundle_path.display()
                );
                Ok(())
            }
            PeerCommand::Register { bundle } => molt::Runtime::open()?.register_peer(&bundle),
            PeerCommand::Join { bundle } => peering::join_bundle(&bundle),
        },
    }
}
