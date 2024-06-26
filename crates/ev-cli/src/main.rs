use atty::Stream;
use clap::Parser;
use commands::Command;
use env_logger::fmt::Formatter;
use env_logger::{Builder, Env};
use human_panic::setup_panic;
use log::Record;
use serde_json::Value;
use std::io::{IsTerminal, Write};

mod auth;
mod commands;
mod errors;
mod fs;
mod function;
mod relay;
mod theme;
mod version;

pub use auth::get_auth;

pub trait CmdOutput: std::fmt::Display {
    fn code(&self) -> String;

    fn exitcode(&self) -> crate::errors::ExitCode;

    fn data(&self) -> Option<Value>;
}

pub fn run_cmd(r: Result<impl CmdOutput, impl CmdOutput>) -> ! {
    match r {
        Ok(output) => crate::print_and_exit(output, false),
        Err(e) => crate::print_and_exit(e, true),
    }
}

pub fn print_and_exit<T>(output: T, is_error: bool) -> !
where
    T: CmdOutput,
{
    let base_args = BaseArgs::parse();

    let msg = if base_args.json {
        fmt_json(&output, is_error)
    } else {
        output.to_string()
    };

    // when a we have json data to display in a non-json output, print it to stdout and print
    // the message to stderr, so a user that doesn't pass the --json flag can still pipe the json
    if !base_args.json {
        if let Some(Ok(data)) = output.data().map(|d| serde_json::to_string_pretty(&d)) {
            eprintln!("{msg}");
            println!("{data}");
        } else {
            println!("{msg}");
        }
    } else {
        println!("{msg}");
    }

    std::process::exit(output.exitcode());
}

fn fmt_json<T>(output: &T, is_error: bool) -> String
where
    T: CmdOutput,
{
    let mut json = serde_json::json!({
        "message": output.to_string(),
        "code": output.code(),
        "is_error": is_error
    });

    if let Some(data) = output.data() {
        json.as_object_mut()
            .expect("infallible")
            .insert("data".into(), data);
    }

    if std::io::stdout().is_terminal() {
        serde_json::to_string_pretty(&json).unwrap_or(json.to_string())
    } else {
        json.to_string()
    }
}

#[derive(Debug, Parser)]
#[clap(name = "Evervault Enclave CLI", version)]
pub struct BaseArgs {
    /// Toggle verbose output
    #[clap(short, long, global = true, default_value_t = false)]
    pub verbose: bool,

    /// Toggle JSON output for stdout
    #[clap(long, global = true)]
    pub json: bool,

    #[clap(subcommand)]
    pub command: Command,
}

#[tokio::main]
async fn main() {
    // Use human panic to give nicer error logs in the case of a runtime panic
    setup_panic!(Metadata {
        name: env!("CARGO_PKG_NAME").into(),
        version: env!("CARGO_PKG_VERSION").into(),
        authors: "Engineering <engineering@evervault.com>".into(),
        homepage: "https://github.com/evervault/cages".into(),
    });

    let base_args: BaseArgs = BaseArgs::parse();
    setup_logger(base_args.verbose);
    setup_sentry();
    commands::run(base_args).await;
}

fn setup_logger(verbose_logging: bool) {
    let env = Env::new()
        .filter_or("EV_LOG", "INFO")
        .write_style("EV_LOG_STYLE");
    let mut builder = Builder::from_env(env);

    let log_formatter = |buf: &mut Formatter, record: &Record| {
        // If stderr is being piped elsewhere, add timestamps and remove colors
        if atty::isnt(Stream::Stderr) {
            let timestamp = buf.timestamp_millis();
            writeln!(
                buf,
                "[{} {}] {}",
                timestamp,
                record.metadata().level(),
                record.args()
            )
        } else {
            writeln!(
                buf,
                "[{}] {}",
                buf.default_styled_level(record.metadata().level()),
                record.args()
            )
        }
    };

    builder
        .format_timestamp(None)
        .format_module_path(false)
        .format_target(false);
    if verbose_logging {
        builder.filter(Some("ev-enclave"), log::LevelFilter::Debug);
    } else {
        builder.filter(Some("ev-enclave"), log::LevelFilter::Info);
    }
    builder.format(log_formatter).init();
}

fn setup_sentry() {
    if cfg!(not(debug_assertions)) {
        let _ = sentry::init((
            "https://7930c2e61c1642bca8518bdadf37b78b@o359326.ingest.sentry.io/5799012",
            sentry::ClientOptions {
                release: sentry::release_name!(),
                ..Default::default()
            },
        ));
    }
}
