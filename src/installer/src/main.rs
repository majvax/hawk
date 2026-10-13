//! hawk-setup: installs, updates and removes Hawk.
//!
//! One program for every part: the machine service and the desktop app on
//! Windows, the relay on Linux. Without arguments on Windows it opens a
//! window that walks through the same steps; with a command it's a plain
//! command-line tool that never opens a window, for scripts and servers.
//!
//! It's also the updater: the machine service and the relay's timer run
//! `hawk-setup update`, so an update is checked and applied the same way an
//! install is.

mod archive;
#[cfg_attr(not(windows), allow(dead_code))]
mod machine_config;
mod probe;
mod release;
mod report;

#[cfg(windows)]
mod app;
#[cfg(all(windows, feature = "gui"))]
mod gui;
#[cfg(windows)]
mod machine;
#[cfg(unix)]
mod relay;
#[cfg(windows)]
mod windows;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::release::Overrides;
use crate::report::Report;

/// What `update --check` exits with when a newer release is out (the
/// machine service reads it).
const EXIT_UPDATE_AVAILABLE: u8 = 10;

#[derive(Parser)]
#[command(name = "hawk-setup", version, about = "Install, update and remove Hawk", long_about = None)]
struct Cli {
    /// Print only warnings and errors.
    #[arg(long, short, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Install (or repair) a part of Hawk on this computer.
    Install {
        #[command(subcommand)]
        part: InstallPart,
    },
    /// Install a newer release, or with --check, only look for one.
    Update {
        part: Part,
        /// Look, don't install. Exits with 10 when one is available.
        #[arg(long)]
        check: bool,
        /// Run by the relay's timer: follow the policy in /etc/hawk/update.toml.
        #[arg(long, hide = true)]
        scheduled: bool,
        #[command(flatten)]
        source: SourceArgs,
    },
    /// Remove a part of Hawk from this computer.
    Uninstall {
        part: Part,
        /// Machine: keep the settings and the machine key, for a reinstall.
        #[arg(long)]
        keep_data: bool,
        /// Relay: also delete the database, settings and TLS key.
        #[arg(long)]
        delete_data: bool,
    },
    /// Show what's installed and how it's doing.
    Status {
        /// As JSON.
        #[arg(long)]
        json: bool,
    },
    /// certbot's deploy hook for a relay's certificate.
    #[command(hide = true)]
    RelayCertDeploy,
}

#[derive(Subcommand)]
enum InstallPart {
    /// The service that makes this Windows PC reachable from your relay.
    Machine {
        /// The relay's address, as the dashboard shows it with the code.
        #[arg(long)]
        relay: Option<String>,
        /// The relay's TLS key pin, shown with the code. Repeat for a backup key.
        #[arg(long = "pin")]
        pins: Vec<String>,
        /// One-time enrollment code from the dashboard (Machines > Add machine).
        #[arg(long)]
        code: Option<String>,
        /// What the machine may do about updates on its own.
        #[arg(long, value_enum)]
        updates: Option<Policy>,
        /// Seconds to watch the service connect and enroll.
        #[arg(long, default_value_t = 60)]
        wait: u64,
        /// Development builds only: install these binaries without a release.
        #[arg(long, hide = true)]
        unsigned_from: Option<PathBuf>,
        #[command(flatten)]
        source: SourceArgs,
    },
    /// The relay and dashboard, as a systemd service (Linux).
    Relay {
        /// Where people and machines reach it, e.g. https://relay.example.com.
        #[arg(long)]
        public_url: String,
        /// The port to listen on, when it isn't the public URL's (behind a
        /// proxy or port forward).
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, value_enum, default_value_t = TlsChoice::SelfSigned)]
        tls: TlsChoice,
        /// For --tls certbot: Let's Encrypt's contact address.
        #[arg(long)]
        email: Option<String>,
        /// For --tls existing.
        #[arg(long)]
        cert: Option<PathBuf>,
        /// For --tls existing.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Other origins allowed to use the relay (a separately hosted
        /// dashboard). The desktop app is always allowed.
        #[arg(long = "origin")]
        origins: Vec<String>,
        /// Mail server, to verify addresses and send security notices.
        #[arg(long, requires = "mail_from")]
        smtp_url: Option<String>,
        #[arg(long, requires = "smtp_url")]
        mail_from: Option<String>,
        #[arg(long, value_enum)]
        updates: Option<Policy>,
        #[command(flatten)]
        source: SourceArgs,
    },
    /// The desktop dashboard app (Windows).
    App {
        #[command(flatten)]
        source: SourceArgs,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Part {
    Machine,
    Relay,
    App,
}

#[derive(Clone, Copy, ValueEnum)]
enum Policy {
    /// Never look.
    Off,
    /// Look, and tell the owner; install when they say.
    Notify,
    /// Look, and install.
    Auto,
}

impl Policy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Notify => "notify",
            Self::Auto => "auto",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TlsChoice {
    SelfSigned,
    Certbot,
    Existing,
}

#[derive(Args, Clone, Default)]
struct SourceArgs {
    /// Install from a downloaded release in this folder instead of the feed.
    #[arg(long)]
    from: Option<PathBuf>,
    /// The release feed, with {channel} for the channel's name. Defaults to
    /// the feed this build came from.
    #[arg(long)]
    feed_url: Option<String>,
    /// The minisign public key releases are signed with. Defaults to the one
    /// this build trusts.
    #[arg(long)]
    public_key: Option<String>,
    #[arg(long, value_enum)]
    channel: Option<ChannelChoice>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ChannelChoice {
    Stable,
    Beta,
}

impl SourceArgs {
    fn overrides(&self) -> Overrides {
        Overrides {
            from: self.from.clone(),
            feed_url: self.feed_url.clone().unwrap_or_default(),
            public_key: self.public_key.clone().unwrap_or_default(),
            channel: self.channel.map(|channel| match channel {
                ChannelChoice::Stable => hawk_update::Channel::Stable,
                ChannelChoice::Beta => hawk_update::Channel::Beta,
            }),
        }
    }
}

fn main() -> ExitCode {
    let _ = rustls::crypto::ring::default_provider().install_default();

    #[cfg(all(windows, feature = "gui"))]
    if std::env::args_os().len() == 1 {
        return gui::run();
    }

    let cli = Cli::parse();
    let report = Report::terminal(cli.quiet);
    let Some(command) = cli.command else {
        use clap::CommandFactory;
        let _ = Cli::command().print_help();
        return ExitCode::from(2);
    };
    match run(command, &report) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command, report: &Report) -> Result<u8, String> {
    match command {
        Command::Install { part } => install(part, report).map(|()| 0),
        Command::Update { part, check, scheduled, source } => update(part, check, scheduled, &source.overrides(), report),
        Command::Uninstall { part, keep_data, delete_data } => uninstall(part, keep_data, delete_data, report).map(|()| 0),
        Command::Status { json } => status(json).map(|()| 0),
        Command::RelayCertDeploy => relay_cert_deploy().map(|()| 0),
    }
}

fn unsupported(what: &str) -> String {
    let os = if cfg!(windows) { "Windows" } else { "this system" };
    format!("the {what} isn't installed on {os} by this build of hawk-setup")
}

#[allow(unused_variables)]
fn install(part: InstallPart, report: &Report) -> Result<(), String> {
    match part {
        #[cfg(windows)]
        InstallPart::Machine { relay, pins, code, updates, wait, unsigned_from, source } => machine::install(
            machine::InstallOptions {
                relay,
                pins,
                code,
                policy: updates.map(|policy| policy.as_str().to_owned()),
                overrides: source.overrides(),
                unsigned_from,
                wait: std::time::Duration::from_secs(wait),
            },
            report,
        ),
        #[cfg(windows)]
        InstallPart::App { source } => app::install(&source.overrides(), report),
        #[cfg(unix)]
        InstallPart::Relay {
            public_url,
            port,
            tls,
            email,
            cert,
            key,
            origins,
            smtp_url,
            mail_from,
            updates,
            source,
        } => {
            let tls = match tls {
                TlsChoice::SelfSigned => relay::Tls::SelfSigned,
                TlsChoice::Certbot => relay::Tls::Certbot {
                    email: email.ok_or("--tls certbot needs --email for Let's Encrypt")?,
                },
                TlsChoice::Existing => relay::Tls::Existing {
                    cert: cert.ok_or("--tls existing needs --cert")?,
                    key: key.ok_or("--tls existing needs --key")?,
                },
            };
            relay::install(
                relay::InstallOptions {
                    public_url,
                    listen_port: port,
                    tls,
                    origins,
                    smtp_url,
                    mail_from,
                    policy: updates.map(|policy| policy.as_str().to_owned()),
                    overrides: source.overrides(),
                },
                report,
            )
        }
        #[allow(unreachable_patterns)]
        InstallPart::Machine { .. } => Err(unsupported("machine service")),
        #[allow(unreachable_patterns)]
        InstallPart::Relay { .. } => Err(unsupported("relay (it runs on Linux)")),
        #[allow(unreachable_patterns)]
        InstallPart::App { .. } => Err(unsupported("desktop app")),
    }
}

#[allow(unused_variables)]
fn update(part: Part, check: bool, scheduled: bool, overrides: &Overrides, report: &Report) -> Result<u8, String> {
    // The service reads the first line of a check: the version, or nothing.
    let available = |version: &str| {
        println!("{version}");
        EXIT_UPDATE_AVAILABLE
    };
    match part {
        #[cfg(windows)]
        Part::Machine => match machine::update(check, overrides, report)? {
            machine::UpdateOutcome::Available(version) => Ok(available(&version)),
            machine::UpdateOutcome::UpToDate | machine::UpdateOutcome::Updated => Ok(0),
        },
        #[cfg(unix)]
        Part::Relay => match relay::update(check, scheduled, overrides, report)? {
            relay::UpdateOutcome::Available(version) if check => Ok(available(&version)),
            _ => Ok(0),
        },
        #[cfg(windows)]
        Part::App => app::install(overrides, report).map(|()| 0),
        #[allow(unreachable_patterns)]
        _ => Err(unsupported("part")),
    }
}

#[allow(unused_variables)]
fn uninstall(part: Part, keep_data: bool, delete_data: bool, report: &Report) -> Result<(), String> {
    match part {
        #[cfg(windows)]
        Part::Machine => machine::uninstall(keep_data, report),
        #[cfg(windows)]
        Part::App => app::uninstall(report),
        #[cfg(unix)]
        Part::Relay => relay::uninstall(delete_data, report),
        #[allow(unreachable_patterns)]
        _ => Err(unsupported("part")),
    }
}

fn status(json: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        let machine = machine::summary();
        let app = app::installed_version();
        if json {
            let value = serde_json::json!({ "machine": machine, "app": app });
            println!("{}", serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?);
            return Ok(());
        }
        println!("Machine service");
        if machine.installed {
            println!("  version   {}", machine.version.as_deref().unwrap_or("unknown"));
            println!("  service   {}", machine.service.as_deref().unwrap_or("missing"));
            if let Some(status) = &machine.status {
                println!("  status    {}", machine::describe(status));
            }
            println!("  relay     {}", machine.relay.as_deref().unwrap_or("not set"));
            println!("  updates   {}", machine.update_policy.as_deref().unwrap_or("notify"));
        } else if let Some(service) = &machine.service {
            println!("  service   {service}, registered by an earlier install (install-service.ps1)");
            println!("            run hawk-setup install machine --relay <address> to take it over");
        } else {
            println!("  not installed");
        }
        println!("Desktop app");
        println!("  {}", app.map_or_else(|| "not installed".to_owned(), |version| format!("version   {version}")));
    }
    #[cfg(unix)]
    {
        let relay = relay::summary();
        if json {
            println!("{}", serde_json::to_string_pretty(&relay).map_err(|error| error.to_string())?);
            return Ok(());
        }
        println!("Relay");
        if relay.installed {
            println!("  version   {}", relay.version.as_deref().unwrap_or("unknown"));
            println!("  running   {}", if relay.active { "yes" } else { "no" });
            println!("  pin       {}", relay.pin.as_deref().unwrap_or("no certificate"));
            println!("  updates   {}", relay.update_policy);
        } else {
            println!("  not installed");
        }
    }
    Ok(())
}

fn relay_cert_deploy() -> Result<(), String> {
    #[cfg(unix)]
    return relay::deploy_hook();
    #[cfg(not(unix))]
    Err(unsupported("relay"))
}
