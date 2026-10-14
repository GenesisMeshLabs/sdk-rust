//! `genesis-mesh-edge` (1.7.0, beta): the Genesis Mesh edge agent. It holds
//! a device's node and executor keys, asks the Network Authority (NA) for
//! decisions while connected, acts within pre-issued grants while not,
//! breaks the glass when it must, and uploads every record in order when the
//! NA is back. Local workloads ask it through a local API (docs/edge.md).
//!
//! Exit codes: 0 OK, 1 internal error, 2 usage or configuration, 3 not
//! enrolled, 4 enrolment refused, 5 NA unreachable during enrolment, 6
//! insecure permissions on the state directory or keys.

#![forbid(unsafe_code)]

mod agent;
mod api;
mod config;
mod db;
mod log;
mod state;

use std::{path::PathBuf, process::ExitCode, sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    agent::{Agent, Exit, VERSION},
    config::{process_env, Config},
    state::{StateDir, DATABASE, ENROLLMENT, SNAPSHOT},
};

const USAGE: &str = "usage: genesis-mesh-edge [--config <file>] <command>

commands:
  init [--json]
  enroll [--invite-token-file <file>] [--reset [--discard-pending]]
  run [--invite-token-file <file>]
  status [--json]
  token new --name <name>
  check-config
  --version";

struct Args {
    config: Option<PathBuf>,
    command: Vec<String>,
    invite_token_file: Option<PathBuf>,
    reset: bool,
    discard_pending: bool,
    json: bool,
    name: Option<String>,
}

fn parse(arguments: Vec<String>) -> Result<Args, Exit> {
    let mut args = Args {
        config: None,
        command: Vec::new(),
        invite_token_file: None,
        reset: false,
        discard_pending: false,
        json: false,
        name: None,
    };
    let mut iter = arguments.into_iter();
    let usage = |m: &str| Exit::Usage(format!("{m}\n{USAGE}"));
    while let Some(argument) = iter.next() {
        match argument.as_str() {
            "--config" => {
                args.config = Some(
                    iter.next()
                        .ok_or_else(|| usage("--config needs a file"))?
                        .into(),
                )
            }
            "--invite-token-file" => {
                args.invite_token_file = Some(
                    iter.next()
                        .ok_or_else(|| usage("--invite-token-file needs a file"))?
                        .into(),
                )
            }
            "--reset" => args.reset = true,
            "--discard-pending" => args.discard_pending = true,
            "--json" => args.json = true,
            "--name" => args.name = Some(iter.next().ok_or_else(|| usage("--name needs a name"))?),
            other if other.starts_with('-') && other != "--version" => {
                return Err(usage(&format!("unknown option {other}")))
            }
            other => args.command.push(other.to_owned()),
        }
    }
    Ok(args)
}

/// The invite token: `--invite-token-file`, `GM_EDGE_INVITE_TOKEN_FILE`,
/// `$CREDENTIALS_DIRECTORY/invite-token` (systemd), `GM_EDGE_INVITE_TOKEN`.
fn invite_token(args: &Args) -> Result<Option<String>, Exit> {
    let env = process_env();
    let file = args
        .invite_token_file
        .clone()
        .or_else(|| {
            env.get("GM_EDGE_INVITE_TOKEN_FILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| {
            env.get("CREDENTIALS_DIRECTORY")
                .map(|d| PathBuf::from(d).join("invite-token"))
                .filter(|p| p.exists())
        });
    if let Some(file) = file {
        let token = std::fs::read_to_string(&file).map_err(|e| {
            Exit::Usage(format!(
                "cannot read the invite token file {}: {e}",
                file.display()
            ))
        })?;
        let token = token.trim().to_owned();
        if token.is_empty() {
            return Err(Exit::Usage(format!(
                "the invite token file {} is empty",
                file.display()
            )));
        }
        return Ok(Some(token));
    }
    Ok(env
        .get("GM_EDGE_INVITE_TOKEN")
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty()))
}

fn load_config(args: &Args) -> Result<Config, Exit> {
    let config =
        Config::load(args.config.as_deref(), &process_env()).map_err(|e| Exit::Usage(e.0))?;
    log::set_level(config.log_level);
    Ok(config)
}

fn runtime() -> Result<tokio::runtime::Runtime, Exit> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Exit::Internal(e.to_string()))
}

async fn enroll(agent: &Arc<Agent>, token: &str) -> Result<(), Exit> {
    agent.enroll(token).await?;
    // A first sync; a failure here is not fatal.
    if let Err(err) = agent.sync().await {
        log::warn("first_sync_failed", json!({"code": err.code()}));
    }
    Ok(())
}

/// Create the state directory and the keys if absent, and print the node's
/// public key: an operator can then bind the edge invite to it
/// (`recipient_public_key`). `enroll` uses these keys.
fn command_init(args: &Args) -> Result<(), Exit> {
    let config = load_config(args)?;
    let dir = StateDir::open(&config.state_dir)?;
    let node = dir.key(state::NODE_KEY)?;
    let executor = dir.key(state::EXECUTOR_KEY)?;
    let public = |seed: &str| {
        genesis_mesh_sdk::public_key_from_seed(seed).map_err(|e| Exit::Internal(e.to_string()))
    };
    let (node, executor) = (public(&node)?, public(&executor)?);
    if args.json {
        println!(
            "{}",
            json!({"node_public_key": node, "executor_public_key": executor})
        );
    } else {
        println!("{node}");
    }
    Ok(())
}

fn command_enroll(args: &Args) -> Result<(), Exit> {
    let config = load_config(args)?;
    if args.reset {
        let dir = StateDir::open(&config.state_dir)?;
        if dir.path(DATABASE).exists() {
            let db =
                db::Db::open(&dir.path(DATABASE)).map_err(|e| Exit::Internal(e.to_string()))?;
            let (pending, dead) = db
                .outbox_counts()
                .map_err(|e| Exit::Internal(e.to_string()))?;
            if pending + dead > 0 && !args.discard_pending {
                return Err(Exit::Usage(format!(
                    "{pending} records are not uploaded yet ({dead} dead letters): run the agent until they are, or add --discard-pending"
                )));
            }
        }
        dir.reset()?;
        log::warn("state_reset", json!({}));
    }
    let token = invite_token(args)?.ok_or_else(|| {
        Exit::Usage("no invite token: --invite-token-file, GM_EDGE_INVITE_TOKEN_FILE, $CREDENTIALS_DIRECTORY/invite-token or GM_EDGE_INVITE_TOKEN".into())
    })?;
    let agent = Agent::load(config)?;
    if agent.enrolled() {
        return Err(Exit::Usage(
            "already enrolled; enroll --reset starts again".into(),
        ));
    }
    runtime()?.block_on(enroll(&agent, &token))
}

fn command_run(args: &Args) -> Result<(), Exit> {
    let config = load_config(args)?;
    let agent = Agent::load(config)?;
    let token = if agent.enrolled() {
        None
    } else {
        invite_token(args)?
    };
    if !agent.enrolled() && token.is_none() {
        return Err(Exit::NotEnrolled(
            "not enrolled and no invite token (docs/edge.md, \"Enrolment\")".into(),
        ));
    }
    runtime()?.block_on(async move {
        if let Some(token) = token {
            enroll(&agent, &token).await?;
        }
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(api::serve(Arc::clone(&agent), stop_rx.clone()));
        let schedule = {
            let agent = Arc::clone(&agent);
            let stop = stop_rx.clone();
            tokio::spawn(async move { agent.run(stop).await })
        };
        log::info("started", json!({"version": VERSION, "state": agent.state().name()}));
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| Exit::Internal(e.to_string()))?;
        let mut server = server;
        tokio::select! {
            _ = terminate.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
            served = &mut server => {
                return match served {
                    Ok(Err(err)) => Err(Exit::Usage(format!("the local API could not listen: {err}"))),
                    _ => Err(Exit::Internal("the local API stopped".into())),
                };
            }
        }
        log::info("stopping", json!({}));
        let _ = stop_tx.send(true);
        agent.shut_down(Duration::from_secs(10)).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), schedule).await;
        log::info("stopped", json!({}));
        Ok(())
    })
}

fn command_status(args: &Args) -> Result<(), Exit> {
    let config = load_config(args)?;
    let dir = StateDir::open(&config.state_dir)?;
    let enrollment = dir.read_json(ENROLLMENT)?;
    let snapshot = dir.read_json(SNAPSHOT)?.unwrap_or(json!({}));
    let (pending, dead) = if dir.path(DATABASE).exists() {
        db::Db::open(&dir.path(DATABASE))
            .and_then(|db| db.outbox_counts())
            .map_err(|e| Exit::Internal(e.to_string()))?
    } else {
        (0, 0)
    };
    let enrollment = enrollment.unwrap_or(serde_json::Value::Null);
    let status = json!({
        "agent_version": VERSION,
        "enrolled": !enrollment.is_null(),
        "node_public_key": enrollment["cert"]["node_public_key"],
        "node_sovereign_id": enrollment["node_sovereign_id"],
        "executor_key_id": enrollment["executor_key"]["key_id"],
        "resource_prefix": enrollment["executor_key"]["resource_prefix"],
        "cert_id": enrollment["cert"]["cert_id"],
        "cert_expires_at": enrollment["cert"]["expires_at"],
        "snapshot_synced_at": snapshot["synced_at"],
        "pending_uploads": pending,
        "dead_letters": dead,
    });
    if args.json {
        println!("{status}");
    } else if enrollment.is_null() {
        println!("not enrolled");
    } else {
        println!(
            "node {} ({}), certificate {} until {}",
            status["node_sovereign_id"].as_str().unwrap_or("?"),
            status["executor_key_id"].as_str().unwrap_or("?"),
            status["cert_id"].as_str().unwrap_or("?"),
            status["cert_expires_at"].as_str().unwrap_or("?"),
        );
        println!(
            "snapshot synced at {}; {pending} uploads pending, {dead} dead letters",
            status["snapshot_synced_at"].as_str().unwrap_or("never"),
        );
    }
    Ok(())
}

fn command_token(args: &Args) -> Result<(), Exit> {
    let name = args
        .name
        .clone()
        .filter(|n| !n.is_empty() && !n.contains([',', ':', '"']))
        .ok_or_else(|| Exit::Usage(format!("token new needs --name <name>\n{USAGE}")))?;
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| Exit::Internal(e.to_string()))?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let digest: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("{token}");
    eprintln!(
        "Give the token to the client; put its digest in edge.toml:\n\n[[local_api.tokens]]\nname = \"{name}\"\nsha256 = \"{digest}\"\n\nor GM_EDGE_TOKENS=\"{name}:{digest}\""
    );
    Ok(())
}

fn command_check(args: &Args) -> Result<(), Exit> {
    let config = load_config(args)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&config.summary()).unwrap_or_default()
    );
    Ok(())
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.iter().any(|a| a == "--version") {
        println!("genesis-mesh-edge {VERSION}");
        return ExitCode::SUCCESS;
    }
    let result = parse(arguments).and_then(|args| {
        let words: Vec<&str> = args.command.iter().map(String::as_str).collect();
        match words.as_slice() {
            ["init"] => command_init(&args),
            ["enroll"] => command_enroll(&args),
            ["run"] => command_run(&args),
            ["status"] => command_status(&args),
            ["token", "new"] => command_token(&args),
            ["check-config"] => command_check(&args),
            [] => Err(Exit::Usage(USAGE.into())),
            _ => Err(Exit::Usage(format!("unknown command\n{USAGE}"))),
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(exit) => {
            log::error(
                "exit",
                json!({"code": exit.code(), "message": exit.message()}),
            );
            if !matches!(exit, Exit::Internal(_)) {
                eprintln!("genesis-mesh-edge: {}", exit.message());
            }
            ExitCode::from(exit.code())
        }
    }
}
