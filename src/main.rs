use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use euthyna_signer::pair;
use euthyna_signer::server::{self, Config};
use euthyna_signer::store::{AgentRecord, ApiAccess, DEFAULT_METHODS, Store, valid_account_id};
use zeroize::Zeroize;

/// Where the installers put the config, Linux first.
const CONFIG_PATHS: &[&str] = &[
    "/etc/euthyna-signer/config.json",
    "/usr/local/etc/euthyna-signer/config.json",
];

#[derive(Parser)]
#[command(
    name = "euthyna-signer",
    version,
    about = "Keeps Euthyna agent keys away from the AI; signs only vault requests."
)]
struct Cli {
    /// Config file (default: /etc/euthyna-signer/config.json, then /usr/local/etc/…).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon.
    Serve,
    /// Hire an agent with the code the console shows: makes its key here, sends
    /// only the public key, and keeps the API key the console issues.
    Pair {
        /// The pairing code, EUT-….
        code: String,
        /// Euthyna API base URL (the console's command includes it).
        #[arg(long)]
        api_url: String,
    },
    /// Create an agent key, print its PUBLIC key, then take the API key the console gives after hiring.
    AddAgent {
        /// The agent's NEAR account, as shown by the console.
        account: String,
        /// The company vault: the only contract this key may call.
        #[arg(long)]
        vault: String,
        /// Euthyna API base URL; the signer keeps the agent's API key for it.
        #[arg(long)]
        api_url: Option<String>,
        #[arg(long, default_value = "testnet")]
        network: String,
        /// Vault methods the key may call (comma separated).
        #[arg(long, value_delimiter = ',')]
        methods: Option<Vec<String>>,
    },
    /// List agents.
    List,
    /// Show an agent's public data (never the secret).
    Show { account: String },
    /// Generate the next key; it signs only after `promote`.
    Rotate { account: String },
    /// Switch to the key made by `rotate` (once it is registered on chain).
    Promote { account: String },
    /// Give (or replace) the agent's Euthyna API key.
    SetApi {
        account: String,
        #[arg(long)]
        api_url: String,
    },
    /// Delete an agent's key.
    Remove { account: String },
}

fn config_path(given: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = given {
        return Ok(path);
    }
    CONFIG_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .context("euthyna-signer is not installed here (no config in /etc/euthyna-signer or /usr/local/etc/euthyna-signer)")
}

/// Admin commands run as the signer's own user, so the files they write stay
/// readable by the daemon and by nobody else. Started with sudo, they drop to
/// that user before touching anything.
fn become_owner(state_dir: &Path) -> Result<()> {
    let meta = std::fs::metadata(state_dir).with_context(|| {
        format!(
            "{} is missing: is euthyna-signer installed?",
            state_dir.display()
        )
    })?;
    let (owner, group) = (meta.uid(), meta.gid());
    let me = unsafe { libc::geteuid() };
    if me == owner {
        return Ok(());
    }
    if me != 0 {
        bail!("run it with sudo: `sudo euthyna-signer …`");
    }
    if owner == 0 {
        bail!(
            "{} belongs to root: reinstall euthyna-signer",
            state_dir.display()
        );
    }
    // Order matters: supplementary groups and gid while still root, uid last.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(group) != 0
            || libc::setuid(owner) != 0
        {
            bail!(
                "could not switch to the signer's user: {}",
                std::io::Error::last_os_error()
            );
        }
        if libc::setuid(0) == 0 {
            bail!("privileges were not dropped");
        }
    }
    Ok(())
}

fn open_store(config: &Config) -> Result<Store> {
    become_owner(&config.state_dir)?;
    Store::open(&config.state_dir)
}

fn check_api_url(url: &str) -> Result<()> {
    pair::check_api_url(url)
}

/// Reads one line from the terminal without echoing it.
fn read_secret_line() -> Result<String> {
    let stdin = std::io::stdin();
    let fd = libc::STDIN_FILENO;
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let tty = stdin.is_terminal() && unsafe { libc::tcgetattr(fd, &mut saved) } == 0;
    if tty {
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line);
    if tty {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        eprintln!();
    }
    read.context("read the API key")?;
    let key = line.trim().to_owned();
    line.zeroize();
    Ok(key)
}

fn ask_api_key(record: &mut AgentRecord, url: String) -> Result<bool> {
    eprint!("API key (input hidden; Enter alone to skip): ");
    std::io::stderr().flush().ok();
    let mut key = read_secret_line()?;
    if key.is_empty() {
        return Ok(false);
    }
    record.api = Some(ApiAccess {
        url,
        key: key.clone(),
    });
    key.zeroize();
    Ok(true)
}

fn show(record: &AgentRecord) -> Result<()> {
    println!("account     {}", record.account_id);
    println!("network     {}", record.network_id);
    println!("vault       {}", record.vault_id);
    println!("methods     {}", record.allowed_methods.join(", "));
    println!("public key  {}", record.public_key()?);
    if let Some(next) = record.next_public_key()? {
        println!("next key    {next}  (not signing yet: register it, then `promote`)");
    }
    println!(
        "api         {}",
        record
            .api
            .as_ref()
            .map(|a| a.url.as_str())
            .unwrap_or("none")
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("euthyna-signer: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let config = Config::load(&config_path(cli.config)?)?;
    match cli.command {
        Command::Serve => server::serve(config).await,
        Command::Pair { code, api_url } => {
            pair::check_api_url(&api_url)?;
            let http = pair::http_client()?;
            let store = open_store(&config)?;
            let mut record = pair::new_unpaired_record();
            let public_key = record.public_key()?;
            eprintln!("  Pairing with {api_url}…");
            let paired =
                pair::redeem(&http, &api_url, &code, &public_key, &pair::hostname()).await?;
            if store.exists(&paired.account_id) {
                bail!(
                    "{} already has a key on this machine; revoke the new hire in the console",
                    paired.account_id
                );
            }
            pair::apply(&mut record, &paired, &api_url);
            store.save(&record)?;
            println!(
                "\n  Hired: {} (role {}, vault {}).",
                record.account_id, paired.role, record.vault_id
            );
            println!(
                "  Its private key stays on this machine; the API key went straight to the signer."
            );
            println!("  The console now creates the agent's NEAR account; keep it open.\n");
            println!("  Then plug it into your AI (no secret in it):\n");
            println!(
                "      claude mcp add euthyna --env EUTHYNA_AGENT={} -- npx -y @euthyna/mcp\n",
                record.account_id
            );
            Ok(())
        }
        Command::AddAgent {
            account,
            vault,
            api_url,
            network,
            methods,
        } => {
            if !valid_account_id(&account) || !valid_account_id(&vault) {
                bail!("invalid NEAR account id");
            }
            if let Some(url) = &api_url {
                check_api_url(url)?;
            }
            let store = open_store(&config)?;
            if store.exists(&account) {
                bail!("{account} already exists: use `rotate` for a new key");
            }
            let methods =
                methods.unwrap_or_else(|| DEFAULT_METHODS.iter().map(|m| m.to_string()).collect());
            let mut record = AgentRecord::new(&account, &network, &vault, methods, None);
            store.save(&record)?;
            println!(
                "\n  Public key for {account}:\n\n      {}\n",
                record.public_key()?
            );
            println!("  1. Paste it in the Euthyna console and hire the agent.");
            println!("     The private key never leaves this machine; the AI cannot read it.");
            let Some(url) = api_url else {
                println!(
                    "  2. Then give the signer the agent's API key:\n     sudo euthyna-signer set-api {account} --api-url <Euthyna API URL>"
                );
                return Ok(());
            };
            if !std::io::stdin().is_terminal() {
                println!("  2. Then: sudo euthyna-signer set-api {account} --api-url {url}");
                return Ok(());
            }
            println!("  2. The console then shows the agent's API key once. Paste it here:\n");
            if ask_api_key(&mut record, url.clone())? {
                store.save(&record)?;
                println!(
                    "\n  Done. The signer holds the key and the API key; the MCP config needs no secret."
                );
            } else {
                println!(
                    "\n  Skipped. Later: sudo euthyna-signer set-api {account} --api-url {url}"
                );
            }
            Ok(())
        }
        Command::List => {
            for account in open_store(&config)?.list()? {
                println!("{account}");
            }
            Ok(())
        }
        Command::Show { account } => show(&open_store(&config)?.load(&account)?),
        Command::Rotate { account } => {
            let store = open_store(&config)?;
            let mut record = store.load(&account)?;
            record.rotate();
            store.save(&record)?;
            show(&record)
        }
        Command::Promote { account } => {
            let store = open_store(&config)?;
            let mut record = store.load(&account)?;
            record.promote()?;
            store.save(&record)?;
            show(&record)
        }
        Command::SetApi { account, api_url } => {
            check_api_url(&api_url)?;
            let store = open_store(&config)?;
            let mut record = store.load(&account)?;
            if !ask_api_key(&mut record, api_url)? {
                bail!("no API key given");
            }
            store.save(&record)?;
            show(&record)
        }
        Command::Remove { account } => {
            open_store(&config)?.remove(&account)?;
            println!("removed {account}; also remove its access key on chain by vote");
            Ok(())
        }
    }
}
