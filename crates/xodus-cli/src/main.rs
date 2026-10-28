use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use xodus::tokens::{AccountRole, TokenManager};

mod commands;
mod license;
mod package;
mod package_plan;
#[cfg(feature = "native-webview")]
mod webview;
#[cfg(not(feature = "native-webview"))]
#[path = "webview_stdio.rs"]
mod webview;

#[derive(Clone, Copy, clap::ValueEnum)]
enum AccountArg {
    Store,
    Play,
}

impl From<AccountArg> for AccountRole {
    fn from(account: AccountArg) -> Self {
        match account {
            AccountArg::Store => AccountRole::Store,
            AccountArg::Play => AccountRole::Play,
        }
    }
}

#[derive(Subcommand)]
enum SubCommand {
    #[cfg(target_os = "linux")]
    #[command(about = "Gracefully stop only a Nexus-owned session keyring without accessing credentials")]
    KeyringSessionStop {
        #[arg(long)]
        provider_pid: u32,
    },
    #[cfg(target_os = "linux")]
    #[command(about = "Create the first default wallet using the provider's password dialog")]
    KeyringCreate {
        #[arg(long, default_value = "")]
        window_id: String,
    },
    #[cfg(target_os = "linux")]
    #[command(about = "Unlock the default system wallet without reading credentials or signing in")]
    KeyringUnlock {
        #[arg(long, default_value = "")]
        window_id: String,
    },
    #[command(about = "Resolve public Store packages without sign-in or downloading")]
    ResolvePackage {
        product: String,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value = "US")]
        market: String,
        #[arg(long, help = "Include parent-bound PC Durable packages for managed DLC installation")]
        include_dlc: bool,
    },
    #[command(about = "Download msixvc or xsp files fo given game")]
    Download {
        product: String,
        #[arg(short, long)]
        market: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Display download URLs instead of downloading"
        )]
        dry_run: bool,
    },
    #[command(about = "Dump CIKs for use with XvdTool")]
    License {
        #[clap(help = "Content Id of a license")]
        content_id: String,
        #[clap(help = "A path where to dump CIKs")]
        ciks: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(about = "Extract locally stored msixvc file")]
    Extract {
        path: String,
        destination: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(
        about = "Extract a locally stored EAppx/EMSIX package (research task, see issue #91)"
    )]
    ExtractEappx {
        path: String,
        destination: String,
        #[arg(short, long, help = "Path to a keyfile with content decryption keys")]
        key_file: Option<String>,
    },
    #[command(about = "Show whether Xodus has a stored Microsoft account")]
    Account {
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(
            long,
            value_enum,
            default_value_t = AccountArg::Store,
            help = "Account role: store (licenses) or play (in-game identity, falls back to store)"
        )]
        account: AccountArg,
    },
    #[command(about = "Read Xbox gamertag and gamerpic for the stored account")]
    Profile {
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(
            long,
            value_enum,
            default_value_t = AccountArg::Store,
            help = "Account role: store (licenses) or play (in-game identity, falls back to store)"
        )]
        account: AccountArg,
    },
    #[command(about = "Explicit Xbox friends and text chat, JSON request on standard input")]
    Social {
        #[arg(long, required = true)]
        json: bool,
        #[arg(
            long,
            value_enum,
            default_value_t = AccountArg::Store,
            help = "Account role: store (licenses) or play (in-game identity, falls back to store)"
        )]
        account: AccountArg,
    },
    #[command(about = "Read Xbox time played and last activity for one title without starting sign-in")]
    GameActivity {
        title_id: u32,
        #[arg(long)]
        json: bool,
        #[arg(
            long,
            value_enum,
            default_value_t = AccountArg::Store,
            help = "Account role: store (licenses) or play (in-game identity, falls back to store)"
        )]
        account: AccountArg,
    },
    #[command(about = "Read achievements for one Xbox title without signing in or unlocking anything")]
    Achievements {
        title_id: u32,
        #[arg(long)]
        json: bool,
        #[arg(
            long,
            value_enum,
            default_value_t = AccountArg::Store,
            help = "Account role: store (licenses) or play (in-game identity, falls back to store)"
        )]
        account: AccountArg,
    },
    #[command(about = "Read account product entitlements without starting sign-in")]
    Library {
        #[arg(long, default_value_t = false)]
        json: bool,
        #[arg(long, default_value = "US")]
        market: String,
    },
    Login {
        #[arg(
            long,
            value_enum,
            default_value_t = AccountArg::Store,
            help = "Account role to sign in: store (licenses) or play (in-game identity)"
        )]
        account: AccountArg,
    },
    Logout {
        #[arg(long, default_value_t = false, help = "Remove device license")]
        device: bool,
        #[arg(
            long,
            value_enum,
            default_value_t = AccountArg::Store,
            help = "Account role to remove; play removes only the play account"
        )]
        account: AccountArg,
    },
    #[command(about = "Download and extract the game through streaming algorithm")]
    Streaming {
        source: String,
        destination: String,
        #[arg(long, help = "Content ID explicitly selected from resolve-package for this Store product")]
        selected_content_id: Option<String>,
        #[arg(
            long,
            help = "Emit Nexus progress protocol v1 as newline-delimited JSON"
        )]
        progress_json: bool,
        #[arg(
            long,
            requires = "progress_json",
            help = "Accept pause/resume JSON commands on stdin"
        )]
        control_stdin: bool,
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u32).range(0..=1_048_576), help = "Aggregate download bandwidth in KiB/s, 0 for unlimited; accepts live set-download-limit stdin control")]
        download_limit_kib: u32,
        #[arg(
            long,
            default_value_t = false,
            help = "Attempt to skip downloading NTFS metadata to be faste while missing some files"
        )]
        try_skip_ntfs: bool,
        #[arg(short, long)]
        parallel: Option<usize>,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[cfg(unix)]
    #[command(about = "Run a Game with xodus wine")]
    Run {
        source: String,
        wine: String,
        #[arg(short, long)]
        exe: Option<String>,
        #[arg(long, default_value_t = false)]
        materialize_exe: bool,
        #[arg(long, default_value_t = false)]
        materialize_chain: bool,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(about = "Generate or decrypt base64-encoded CLEP challenge data")]
    Clep {
        #[command(subcommand)]
        action: ClepAction,
    },
    #[command(about = "Decode SPLicenseBlock")]
    SpLicense {
        block: String,
    },
}

#[derive(Subcommand)]
enum ClepAction {
    #[command(
        about = "Generate a base64-encoded CLEP challenge (V2 and V4) from SMBIOS/disk serial data"
    )]
    Generate {
        #[arg(
            long,
            help = "Base64-encoded SMBIOS data (up to 256 bytes, zero-padded)"
        )]
        smbios: Option<String>,
        #[arg(
            long,
            help = "Base64-encoded disk serial (up to 64 bytes, zero-padded)"
        )]
        disk_serial: Option<String>,
    },
    #[command(about = "Decrypt a base64-encoded CLEP challenge back into its plaintext fields")]
    Decrypt {
        #[clap(help = "Base64-encoded, obfuscated CLEP challenge data (2048 bytes)")]
        data: String,
    },
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    #[cfg(not(feature = "native-webview"))]
    #[arg(long, help = "Use Nexus external sign-in UI protocol version 1 on private stdio")]
    external_webview_stdio: bool,
    #[command(subcommand)]
    command: SubCommand,
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::from_env("XODUS_LOG");
    let registry =
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_filter(filter));

    #[cfg(feature = "tokio_console")]
    {
        use tracing::level_filters::LevelFilter;
        use tracing_subscriber::filter::Targets;

        let console_filter = Targets::new()
            .with_target("tokio", LevelFilter::TRACE)
            .with_target("runtime", LevelFilter::TRACE);
        let console_layer = console_subscriber::spawn().with_filter(console_filter);
        registry.with(console_layer).init();
    }
    #[cfg(not(feature = "tokio_console"))]
    {
        registry.init();
    }
    let client = reqwest::ClientBuilder::new()
        .user_agent(format!("xodus-cli/{}", env!("CARGO_PKG_VERSION")))
        .connection_verbose(true)
        .build()
        .unwrap();
    let args = CliArgs::parse();
    #[cfg(target_os = "linux")]
    if let SubCommand::KeyringSessionStop { provider_pid } = &args.command {
        let state = xodus::keyring_session::stop_session_provider(*provider_pid);
        println!("{}", serde_json::json!({"schema": 1, "state": state.as_str()}));
        return if state == xodus::keyring_session::StopState::Unavailable { ExitCode::FAILURE } else { ExitCode::SUCCESS };
    }
    #[cfg(target_os = "linux")]
    if let SubCommand::KeyringUnlock { window_id } | SubCommand::KeyringCreate { window_id } = &args.command {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = cancelled.clone();
        let state = if ctrlc::set_handler(move || { signal.store(true, Ordering::SeqCst); }).is_err() {
            xodus::keyring_unlock::UnlockState::Unavailable
        } else {
            if matches!(&args.command, SubCommand::KeyringCreate { .. }) {
                xodus::keyring_unlock::create_default(window_id, &cancelled)
            } else {
                xodus::keyring_unlock::unlock_default(window_id, &cancelled)
            }
        };
        println!("{}", serde_json::json!({"schema": 1, "state": state.as_str()}));
        return ExitCode::SUCCESS;
    }
    #[cfg(not(feature = "native-webview"))]
    if args.external_webview_stdio {
        webview::enable_stdio();
    }

    // Public preflight must not activate a keyring, provision a device or sign in.
    if let SubCommand::ResolvePackage { product, json: _, market, include_dlc } = &args.command {
        return match package_plan::resolve(&client, &product.to_uppercase(), &market.to_uppercase()).await {
            Ok(plan) => {
                let plan = if *include_dlc { plan } else { plan.without_durable_selection() };
                println!("{}", plan.json(&product.to_uppercase(), &market.to_uppercase())); ExitCode::SUCCESS
            },
            Err(error) => { eprintln!("{error}"); ExitCode::FAILURE },
        };
    }
    if let Err(error) = xodus::secrets::init_secrets() {
        xodus::tokens::store::TokenStoreError::from(error).report();
        return ExitCode::FAILURE;
    }
    let tokens = TokenManager::with_keychain_and_memory();

    // Clep/SpLicense are pure local data transforms and Logout only removes
    // stored credentials - none of them need a device identity, so don't
    // force provisioning (network + keychain access) just to run them. This
    // matters in practice: on a session with no usable secret-service
    // keychain, provisioning fails outright, which previously meant even
    // these fully offline commands were unusable.
    let needs_device_credentials = !matches!(
        args.command,
        SubCommand::Account { .. }
            | SubCommand::Profile { .. }
            | SubCommand::Social { .. }
            | SubCommand::GameActivity { .. }
            | SubCommand::Achievements { .. }
            | SubCommand::Library { .. }
            | SubCommand::Clep { .. }
            | SubCommand::SpLicense { .. }
            | SubCommand::Logout { .. }
    );
    if needs_device_credentials {
        if let Err(error) = xodus::tokens::device::ensure_device_credentials(&client, &tokens).await {
            error.report();
            return ExitCode::FAILURE;
        }
    }

    let code = match args.command {
        #[cfg(target_os = "linux")]
        SubCommand::KeyringSessionStop { .. } => unreachable!(),
        #[cfg(target_os = "linux")]
        SubCommand::KeyringUnlock { .. } => unreachable!(),
        #[cfg(target_os = "linux")]
        SubCommand::KeyringCreate { .. } => unreachable!(),
        SubCommand::ResolvePackage { .. } => unreachable!(),
        SubCommand::Download {
            product,
            market,
            dry_run,
        } => commands::download::run(&client, &tokens, product, market, dry_run).await,
        SubCommand::License {
            content_id,
            market,
            ciks,
        } => {
            commands::license::run(
                &client,
                &tokens,
                content_id,
                market.unwrap_or("neutral".to_string()),
                ciks,
            )
            .await
        }
        SubCommand::Library { json, market } => commands::library::run(&tokens, json, market).await,
        SubCommand::Account {
            json,
            account: AccountArg::Play,
        } => commands::account::play(&tokens, json),
        SubCommand::Account { json, .. } => match tokens.get_user() {
            Ok(user) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "stored": true,
                            "username": user.username,
                        })
                    );
                } else {
                    println!("{}", user.username);
                }
                ExitCode::SUCCESS
            }
            Err(xodus::tokens::store::TokenStoreError::NotFound) => {
                if json {
                    println!("{}", serde_json::json!({ "stored": false }));
                } else {
                    println!("No stored Microsoft account");
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("Unable to read the stored account: {error}");
                ExitCode::FAILURE
            }
        },
        SubCommand::Profile { json, account } => match tokens.resolve(account.into()) {
            Ok(tokens) => commands::profile::run(&tokens, json).await,
            Err(error) => {
                error.report();
                ExitCode::FAILURE
            }
        },
        SubCommand::Social { account, .. } => match tokens.resolve(account.into()) {
            Ok(tokens) => commands::social::run(&tokens).await,
            Err(error) => {
                error.report();
                ExitCode::FAILURE
            }
        },
        SubCommand::GameActivity {
            title_id,
            json,
            account,
        } => match tokens.resolve(account.into()) {
            Ok(tokens) => commands::game_activity::run(&tokens, title_id, json).await,
            Err(error) => {
                error.report();
                ExitCode::FAILURE
            }
        },
        SubCommand::Achievements {
            title_id,
            json,
            account,
        } => match tokens.resolve(account.into()) {
            Ok(tokens) => commands::achievements::run(&tokens, title_id, json).await,
            Err(error) => {
                error.report();
                ExitCode::FAILURE
            }
        },
        // Sign-in and sign-out target exactly the requested role, never a fallback.
        SubCommand::Login { account } => {
            commands::login::run(&client, &tokens.for_role(account.into())).await
        }
        SubCommand::Logout { device, account } => {
            commands::logout::run(&tokens.for_role(account.into()), device).await
        }
        SubCommand::Extract {
            path,
            destination,
            market,
        } => {
            commands::extract::run(
                &client,
                &tokens,
                path,
                destination,
                market.unwrap_or("neutral".to_string()),
            )
            .await
        }
        SubCommand::ExtractEappx {
            path,
            destination,
            key_file,
        } => commands::extract_eappx::run(path, destination, key_file).await,
        SubCommand::Streaming {
            source,
            destination,
            selected_content_id,
            progress_json,
            control_stdin,
            download_limit_kib,
            try_skip_ntfs,
            market,
            parallel,
        } => {
            msixvc::bandwidth::set_limit_kib(download_limit_kib);
            commands::streaming::run(
                &client,
                &tokens,
                source,
                destination,
                try_skip_ntfs,
                parallel,
                market,
                progress_json,
                control_stdin,
                selected_content_id,
            )
            .await
        }
        #[cfg(unix)]
        SubCommand::Run {
            source,
            wine,
            exe,
            materialize_exe,
            materialize_chain,
            market,
        } => {
            commands::run::run(
                &client,
                &tokens,
                source,
                wine,
                exe,
                materialize_exe,
                materialize_chain,
                market,
            )
            .await
        }
        SubCommand::Clep { action } => match action {
            ClepAction::Generate {
                smbios,
                disk_serial,
            } => commands::clep::generate(smbios, disk_serial),
            ClepAction::Decrypt { data } => commands::clep::decrypt(data),
        },
        SubCommand::SpLicense { block } => commands::splicense::run(block),
    };

    xodus::secrets::destroy_secrets();

    code
}
