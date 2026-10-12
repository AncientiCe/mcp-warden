//! Stdio relay: spawns the real server and pumps newline-delimited JSON-RPC
//! between it and the client.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::session::Session;

/// Runs the server until its stdout closes and returns its exit code.
pub async fn run(session: Arc<Session>, command: &[String]) -> Result<i32> {
    let (program, args) = command.split_first().context("no server command given")?;
    let mut child = Command::new(resolve_program(program))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start server `{program}`"))?;
    let mut server_in = child.stdin.take().context("server stdin not captured")?;
    let server_out = child.stdout.take().context("server stdout not captured")?;
    let client_out = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    let upstream_out = client_out.clone();

    let upstream_session = session.clone();
    // The client side's failure, recorded before the server's stdin closes so
    // the server exiting in response can never hide it.
    let failure = Arc::new(std::sync::Mutex::new(None::<anyhow::Error>));
    let upstream_failure = failure.clone();
    let upstream = tokio::spawn(async move {
        let result = async {
            let mut client = BufReader::new(tokio::io::stdin());
            let mut line = Vec::new();
            loop {
                line.clear();
                match client.read_until(b'\n', &mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let authorization = upstream_session.authorize_client_line(&line)?;
                if let Some(reply) = authorization.reply {
                    let mut client = upstream_out.lock().await;
                    client.write_all(&reply).await?;
                    client.flush().await?;
                }
                let Some(forwarded) = authorization.forwarded else {
                    continue;
                };
                upstream_session.on_client_line(&forwarded);
                if server_in.write_all(&forwarded).await.is_err()
                    || server_in.flush().await.is_err()
                {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(err) = result
            && let Ok(mut slot) = upstream_failure.lock()
        {
            *slot = Some(err);
        }
        // Dropping `server_in` closes the server's stdin: the MCP way to ask it to exit.
        drop(server_in);
    });

    let mut server = BufReader::new(server_out);
    let mut line = Vec::new();
    loop {
        line.clear();
        if server
            .read_until(b'\n', &mut line)
            .await
            .context("reading from server")?
            == 0
        {
            break;
        }
        let rewritten = session.on_server_line(&line)?;
        let mut client = client_out.lock().await;
        client
            .write_all(rewritten.as_deref().unwrap_or(&line))
            .await
            .context("writing to client")?;
        client.flush().await.context("writing to client")?;
    }

    let status = child.wait().await.context("waiting for server")?;
    // The client may still be open after the server exits; stop reading from it.
    upstream.abort();
    let failure = failure
        .lock()
        .map_err(|_| anyhow::anyhow!("client relay task panicked"))?
        .take();
    if let Some(err) = failure {
        return Err(err);
    }
    Ok(status.code().unwrap_or(1))
}

/// Resolves through PATH (and PATHEXT on Windows, so `npx` finds `npx.cmd`).
fn resolve_program(program: &str) -> PathBuf {
    which::which(program).unwrap_or_else(|_| PathBuf::from(program))
}
