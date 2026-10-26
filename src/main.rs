use std::io::Read as _;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use euthyna_signer::server::{self, Config};
use euthyna_signer::store::{AgentRecord, ApiAccess, DEFAULT_METHODS, Store, valid_account_id};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "euthyna-signer",
    version,
    about = "Keeps Euthyna agent keys away from the AI; signs only vault requests."
)]
struct Cli {
    #[arg(long, global = true, default_value = "/etc/euthyna-signer/config.json")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon.
    Serve,
    /// Create an agent key. Prints the PUBLIC key to register by vote.
    AddAgent {
        #[arg(long)]
        account: String,
        #[arg(long)]
        vault: String,
        #[arg(long, default_value = "testnet")]
        network: String,
        /// Vault methods the key may call (comma separated).
        #[arg(long, value_delimiter = ',')]
        methods: Option<Vec<String>>,
        /// Euthyna API base URL; with --api-key-stdin the signer keeps the agent's API key too.
        #[arg(long)]
        api_url: Option<String>,
        /// Read the agent's API key from standard input (never from the command line).
        #[arg(long)]
        api_key_stdin: bool,
    },
    /// List agents.
    List,
    /// Show an agent's public data (never the secret).
    Show {
        #[arg(long)]
        account: String,
    },
    /// Generate the next key; it signs only after `promote`.
    Rotate {
        #[arg(long)]
        account: String,
    },
    /// Switch to the key made by `rotate` (once it is registered on chain).
    Promote {
        #[arg(long)]
        account: String,
    },
    /// Give the signer the agent's Euthyna API key (read from standard input).
    SetApi {
        #[arg(long)]
        account: String,
        #[arg(long)]
        api_url: String,
    },
    /// Delete an agent's key.
    Remove {
        #[arg(long)]
        account: String,
    },
}

/// Admin commands must run as the signer's own user, so the files they write
/// stay readable by the daemon and by nobody else.
fn open_store(config: &Config) -> Result<Store> {
    let store = Store::open(&config.state_dir)?;
    let owner = std::fs::metadata(&config.state_dir)?.uid();
    let me = unsafe { libc::geteuid() };
    if owner != me {
        bail!(
            "run this as the signer's user (uid {owner}), e.g. `sudo -u euthyna-signer euthyna-signer ...`; you are uid {me}"
        );
    }
    Ok(store)
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
    let config = Config::load(&cli.config)?;
    match cli.command {
        Command::Serve => server::serve(config).await,
        Command::AddAgent {
            account,
            vault,
            network,
            methods,
            api_url,
            api_key_stdin,
        } => {
            if !valid_account_id(&account) || !valid_account_id(&vault) {
                bail!("invalid NEAR account id");
            }
            let store = open_store(&config)?;
            if store.exists(&account) {
                bail!("{account} already exists: use `rotate` for a new key");
            }
            let api = match (api_url, api_key_stdin) {
                (Some(url), true) => {
                    let mut key = String::new();
                    std::io::stdin()
                        .read_to_string(&mut key)
                        .context("read API key from stdin")?;
                    let access = ApiAccess {
                        url,
                        key: key.trim().to_owned(),
                    };
                    key.zeroize();
                    Some(access)
                }
                (Some(_), false) => bail!("--api-url needs --api-key-stdin"),
                (None, true) => bail!("--api-key-stdin needs --api-url"),
                (None, false) => None,
            };
            let methods =
                methods.unwrap_or_else(|| DEFAULT_METHODS.iter().map(|m| m.to_string()).collect());
            let record = AgentRecord::new(&account, &network, &vault, methods, api);
            store.save(&record)?;
            show(&record)?;
            println!(
                "\nRegister this public key for {account} (agent onboarding vote); the key itself never leaves this machine."
            );
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
            if !api_url.starts_with("https://")
                && !api_url.starts_with("http://localhost")
                && !api_url.starts_with("http://127.0.0.1")
            {
                bail!("the API URL must be https (or localhost for development)");
            }
            let store = open_store(&config)?;
            let mut record = store.load(&account)?;
            eprintln!("Paste the agent's API key, then press Enter and Ctrl-D:");
            let mut key = String::new();
            std::io::stdin()
                .read_to_string(&mut key)
                .context("read API key from stdin")?;
            if key.trim().is_empty() {
                bail!("no API key given");
            }
            record.api = Some(ApiAccess {
                url: api_url,
                key: key.trim().to_owned(),
            });
            key.zeroize();
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
