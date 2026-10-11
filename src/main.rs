use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use mcp_warden::audit::Audit;
use mcp_warden::extract::sanitize_string;
use mcp_warden::relay;
use mcp_warden::sanitize::{Policy, Sanitizer, Trust};
use mcp_warden::session::Session;

#[cfg(windows)]
mod process_job;

/// Exit code of `scan --fail-on-findings` when something was found.
const FINDINGS_EXIT_CODE: u8 = 3;

/// Stdio proxy that cleans untrusted MCP tool output before the agent reads it.
#[derive(Parser)]
#[command(
    name = "mcp-warden",
    version,
    args_conflicts_with_subcommands = true,
    override_usage = "mcp-warden [OPTIONS] -- <SERVER COMMAND>...\n       mcp-warden scan [OPTIONS] [FILE]"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    wrap: WrapArgs,
}

#[derive(Args)]
struct WrapArgs {
    /// Name of the wrapped server, used in logs and the audit log.
    #[arg(long, default_value = "server")]
    server_id: String,
    #[command(flatten)]
    filter: FilterArgs,
    /// Audit log directory [default: ~/.mcp-warden/audit, or $MCP_WARDEN_HOME/audit].
    #[arg(long)]
    audit_dir: Option<PathBuf>,
    /// Don't write an audit log (overrides --audit-dir).
    #[arg(long)]
    no_audit: bool,
    /// The real server command, after `--`.
    #[arg(last = true)]
    server: Vec<String>,
}

#[derive(Args)]
struct FilterArgs {
    /// Who can write this server's output: `untrusted` applies every rule,
    /// `trusted` only strips invisible characters.
    #[arg(long, value_enum, default_value_t = Trust::Untrusted)]
    trust: Trust,
    /// Extra image host to leave alone (a leading `.` matches subdomains). Repeatable.
    #[arg(long = "allow-image-host", value_name = "HOST")]
    allow_image_hosts: Vec<String>,
}

impl FilterArgs {
    fn sanitizer(&self) -> Result<Sanitizer> {
        let mut policy = Policy::default();
        policy.allowed_image_hosts.extend(
            self.allow_image_hosts
                .iter()
                .map(|h| h.to_ascii_lowercase()),
        );
        Sanitizer::new(policy).context("compiling sanitizer rules")
    }
}

#[derive(Subcommand)]
enum Command {
    /// Sanitize a file (or stdin) offline: clean text on stdout, findings as JSON lines on stderr.
    Scan {
        /// File to scan; reads stdin when omitted.
        file: Option<PathBuf>,
        #[command(flatten)]
        filter: FilterArgs,
        /// Exit with code 3 when anything was found.
        #[arg(long)]
        fail_on_findings: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Scan {
            file,
            filter,
            fail_on_findings,
        }) => scan(file, &filter, fail_on_findings),
        None => wrap(cli.wrap),
    };
    result.unwrap_or_else(|err| {
        eprintln!("mcp-warden: {err:#}");
        ExitCode::FAILURE
    })
}

fn wrap(args: WrapArgs) -> Result<ExitCode> {
    if args.server.is_empty() {
        bail!("no server command given\n\nusage: mcp-warden [OPTIONS] -- <SERVER COMMAND>...");
    }
    #[cfg(windows)]
    process_job::contain_process_tree().context("configuring server process cleanup")?;
    let audit = if args.no_audit {
        None
    } else {
        match args.audit_dir.or_else(Audit::default_dir) {
            Some(dir) => Some(
                Audit::open(dir.clone())
                    .with_context(|| format!("opening audit log in {}", dir.display()))?,
            ),
            None => {
                eprintln!(
                    "mcp-warden[{}]: no home directory, audit log disabled",
                    args.server_id
                );
                None
            }
        }
    };
    let session = Arc::new(Session::new(
        args.server_id,
        args.filter.trust,
        args.filter.sanitizer()?,
        audit,
    ));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let code = runtime.block_on(relay::run(session, &args.server))?;
    // The task reading our stdin blocks in a thread the runtime would wait for
    // on shutdown; the client may never close it, so exit right away.
    std::process::exit(code);
}

fn scan(file: Option<PathBuf>, filter: &FilterArgs, fail_on_findings: bool) -> Result<ExitCode> {
    let input = match &file {
        Some(path) => std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading stdin")?;
            buf
        }
    };
    let text = String::from_utf8(input).context("input is not UTF-8")?;
    let sanitizer = filter.sanitizer()?;
    let mut findings = Vec::new();
    let clean = sanitize_string(&sanitizer, &text, filter.trust, &mut findings);

    std::io::stdout().write_all(clean.as_deref().unwrap_or(&text).as_bytes())?;
    let mut stderr = std::io::stderr().lock();
    for finding in &findings {
        writeln!(stderr, "{}", serde_json::to_string(finding)?)?;
    }
    Ok(if fail_on_findings && !findings.is_empty() {
        ExitCode::from(FINDINGS_EXIT_CODE)
    } else {
        ExitCode::SUCCESS
    })
}
