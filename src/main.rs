use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use mcp_warden::audit::Audit;
use mcp_warden::extract::sanitize_string;
use mcp_warden::hook::{Client, Reply};
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
    override_usage = "mcp-warden [OPTIONS] -- <SERVER COMMAND>...\n       mcp-warden <COMMAND> [OPTIONS]"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    wrap: WrapArgs,
}

#[derive(Args)]
struct WrapArgs {
    /// Persist first-seen tool fingerprints and warn if definitions change.
    #[arg(long)]
    pin_tools: Option<PathBuf>,
    /// Enforce shared taint-based policy on outbound MCP calls.
    #[arg(long)]
    enforce: bool,
    #[command(flatten)]
    state: StateArgs,
    /// Add provenance boundaries around untrusted result text.
    #[arg(long)]
    label: bool,
    /// TOML trust map overriding global and project settings.
    #[arg(long)]
    config: Option<PathBuf>,
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
struct StateArgs {
    /// Shared taint state (default: ~/.mcp-warden/state.json).
    #[arg(long)]
    state_file: Option<PathBuf>,
}

#[derive(Args)]
struct FilterArgs {
    /// Annotate suspicious instructions and withhold critical fields using local heuristics.
    #[arg(long)]
    detect: bool,
    /// Who can write this server's output: `untrusted` applies every rule,
    /// `trusted` only strips invisible characters.
    #[arg(long, value_enum)]
    trust: Option<Trust>,
    /// Extra image host to leave alone (a leading `.` matches subdomains). Repeatable.
    #[arg(long = "allow-image-host", value_name = "HOST")]
    allow_image_hosts: Vec<String>,
}

impl FilterArgs {
    fn sanitizer(&self) -> Result<Sanitizer> {
        let mut policy = Policy {
            detect: self.detect,
            ..Policy::default()
        };
        policy.allowed_image_hosts.extend(
            self.allow_image_hosts
                .iter()
                .map(|h| h.to_ascii_lowercase()),
        );
        Sanitizer::new(policy).context("compiling sanitizer rules")
    }
}

#[derive(Args)]
struct ClientArgs {
    /// Agent client to configure [default: every supported client found].
    #[arg(value_enum)]
    client: Option<Client>,
    /// Hook settings file [default: ~/.claude/settings.json, ~/.codex/hooks.json, ~/.cursor/hooks.json, ~/.gemini/settings.json, ~/.copilot/hooks/mcp-warden.json, ~/.factory/hooks.json, ~/.qwen/settings.json, ~/.augment/settings.json or ~/.kiro/hooks/mcp-warden.json].
    #[arg(long, requires = "client")]
    settings: Option<PathBuf>,
    /// Home directory to look for clients in [default: your home directory].
    #[arg(long, conflicts_with = "settings")]
    home: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Wrap stdio entries in a JSON MCP client config, preserving an exact backup.
    Wrap { config: PathBuf },
    /// Display current shared taint and pending approvals as JSON.
    Status {
        #[command(flatten)]
        state: StateArgs,
    },
    /// Authorize one exact pending MCP call for one use (expires after ten minutes).
    Approve {
        token: String,
        #[command(flatten)]
        state: StateArgs,
    },
    /// Clear shared taint and all approvals after reviewing the session.
    Untaint {
        #[command(flatten)]
        state: StateArgs,
    },
    /// Register `mcp-warden hook` for every tool in an agent client (backs up the settings first).
    Install {
        #[command(flatten)]
        target: ClientArgs,
    },
    /// Remove warden's hooks from an agent client, keeping all other settings.
    Uninstall {
        #[command(flatten)]
        target: ClientArgs,
    },
    /// Agent hook: reads one hook event on stdin and checks tool results from any source.
    Hook {
        /// Agent client sending the event.
        #[arg(long, value_enum, default_value = "claude-code")]
        client: Client,
    },
    /// Show content the hook withheld from the agent (for you, not the agent).
    Show { id: String },
    /// Let the agent see withheld content after you reviewed it.
    Release { id: String },
    /// Treat a project the agent cloned as your own.
    Trust { dir: PathBuf },
    /// Check a project's files like outside content.
    Distrust { dir: PathBuf },
    /// Measure detection against malicious.json and benign.json in a corpus directory.
    Replay { directory: PathBuf },
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
        Some(Command::Wrap { config }) => std::env::current_exe()
            .map_err(anyhow::Error::from)
            .and_then(|exe| mcp_warden::wrap_config::rewrite(&config, &exe))
            .and_then(|report| {
                writeln!(std::io::stdout(), "{report}")?;
                Ok(ExitCode::SUCCESS)
            }),
        Some(Command::Status { state }) => state_command(state, None, false),
        Some(Command::Approve { token, state }) => state_command(state, Some(token), false),
        Some(Command::Untaint { state }) => state_command(state, None, true),
        Some(Command::Hook { client }) => hook(client),
        Some(Command::Show { id }) => show(&id, false),
        Some(Command::Release { id }) => show(&id, true),
        Some(Command::Trust { dir }) => trust(&dir, false),
        Some(Command::Distrust { dir }) => trust(&dir, true),
        Some(Command::Install { target }) => install(target, true),
        Some(Command::Uninstall { target }) => install(target, false),
        Some(Command::Replay { directory }) => {
            mcp_warden::replay::corpus(&directory).and_then(|report| {
                writeln!(std::io::stdout(), "{report}")?;
                Ok(ExitCode::SUCCESS)
            })
        }
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
    let mut map = mcp_warden::config::TrustMap::load(args.config.as_deref(), &args.server_id)?;
    let trust = args
        .filter
        .trust
        .or(map.default_trust)
        .unwrap_or(Trust::Untrusted);
    let gate = if args.enforce {
        Some(mcp_warden::policy::Gate {
            store: mcp_warden::taint::Store::open(args.state.state_file)?,
            allowed_hosts: map
                .allowed_egress_hosts
                .take()
                .unwrap_or_else(mcp_warden::policy::default_egress_hosts),
        })
    } else {
        None
    };
    let session = Arc::new(
        Session::new(args.server_id, trust, args.filter.sanitizer()?, audit)
            .with_labeler(
                (args.label || map.has_fields()).then_some(mcp_warden::label::Labeler {
                    map,
                    visible: args.label,
                }),
            )
            .with_gate(gate)
            .with_pins(args.pin_tools.map(|path| mcp_warden::pins::Pins { path })),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let outcome = runtime.block_on(relay::run(session, &args.server));
    runtime.shutdown_background();
    let code = outcome?;
    // The task reading our stdin blocks in a thread the runtime would wait for
    // on shutdown; the client may never close it, so exit right away.
    std::process::exit(code);
}

fn state_command(args: StateArgs, approval: Option<String>, clear: bool) -> Result<ExitCode> {
    let store = mcp_warden::taint::Store::open(args.state_file)?;
    if let Some(token) = approval {
        store.approve(&token)?;
    }
    let status = store.with_state(|state| {
        if clear {
            *state = mcp_warden::taint::State::default();
        }
        Ok(serde_json::to_value(state)?)
    })?;
    writeln!(std::io::stdout(), "{status}")?;
    Ok(ExitCode::SUCCESS)
}

fn install(target: ClientArgs, install: bool) -> Result<ExitCode> {
    let executable = std::env::current_exe().context("locating the mcp-warden executable")?;
    let home = || match &target.home {
        Some(home) => Ok(home.clone()),
        None => mcp_warden::install::home(),
    };
    let report = match (target.client, &target.settings) {
        (Some(client), Some(settings)) => {
            mcp_warden::install::hook_settings(settings, &executable, client, install)?
        }
        (Some(client), None) => mcp_warden::install::hook_settings(
            &mcp_warden::install::settings_in(&home()?, client),
            &executable,
            client,
            install,
        )?,
        (None, _) => mcp_warden::install::all_clients(&home()?, &executable, install)?,
    };
    writeln!(std::io::stdout(), "{report}")?;
    Ok(ExitCode::SUCCESS)
}

fn hook(client: Client) -> Result<ExitCode> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("reading hook input")?;
    match mcp_warden::hook::Hook::new(client)?.handle(&input)? {
        Some(Reply::Json(output)) => writeln!(std::io::stdout(), "{output}")?,
        Some(Reply::Context(text)) => writeln!(std::io::stdout(), "{text}")?,
        Some(Reply::Block(reason)) => {
            eprintln!("{reason}");
            return Ok(ExitCode::from(2));
        }
        None => {}
    }
    Ok(ExitCode::SUCCESS)
}

fn trust(dir: &std::path::Path, suspicious: bool) -> Result<ExitCode> {
    let dir = mcp_warden::projects::Projects::open()?.set(dir, suspicious)?;
    let state = if suspicious { "SUSPICIOUS" } else { "trusted" };
    writeln!(std::io::stdout(), "{}: {state}", dir.display())?;
    Ok(ExitCode::SUCCESS)
}

fn show(id: &str, release: bool) -> Result<ExitCode> {
    let quarantine = mcp_warden::quarantine::Quarantine::open()?;
    let record = if release {
        quarantine.release(id)?
    } else {
        quarantine.load(id)?
    };
    let mut out = std::io::stdout().lock();
    writeln!(out, "quarantine {} ({})", record.id, record.ts)?;
    writeln!(out, "tool: {}", record.tool)?;
    writeln!(out, "input: {}", record.input)?;
    writeln!(out, "rules: {}", record.rules.join(", "))?;
    for (n, text) in record.withheld.iter().enumerate() {
        writeln!(out, "--- withheld {} ---\n{text}", n + 1)?;
    }
    if release {
        writeln!(
            out,
            "--- released: the agent will see this content when it reads it again ---"
        )?;
    }
    Ok(ExitCode::SUCCESS)
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
    let clean = sanitize_string(
        &sanitizer,
        &text,
        filter.trust.unwrap_or(Trust::Untrusted),
        &mut findings,
    );

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
