use crate::api;
use crate::api::{client::ApiClient, AuthMode};
use crate::common::CliError;
use crate::config::{CageConfig, ValidatedCageBuildConfig};
use crate::get_api_key;

use chrono::TimeZone;
use clap::Parser;
use std::fmt::Write;

/// Pull the logs for a Cage
#[derive(Debug, Parser)]
#[clap(name = "logs", about)]
pub struct LogArgs {
    /// Uuid of the Cage show logs for. If not supplied, the CLI will look for a local cage.toml
    #[clap(long = "cage-uuid")]
    pub cage_uuid: Option<String>,

    /// Path to the toml file containing the Cage's config
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,
}

pub async fn run(log_args: LogArgs) -> i32 {
    let api_key = get_api_key!();
    let cages_client = api::cage::CagesClient::new(AuthMode::ApiKey(api_key));

    let cage_uuid = match log_args.cage_uuid.clone() {
        Some(cage_uuid) => cage_uuid,
        None => match CageConfig::try_from_filepath(&log_args.config)
            .and_then(|config| ValidatedCageBuildConfig::try_from(config.as_ref()))
        {
            Ok(config) => config.cage_uuid().to_string(),
            Err(e) => {
                eprintln!("An error occurred while resolving your Cage toml.\n\nPlease make sure you have a cage.toml file in the current directory, or have supplied a path with the --config flag.");
                return e.exitcode();
            }
        },
    };

    let now = std::time::SystemTime::now();
    let end_time = match now.duration_since(std::time::UNIX_EPOCH).ok() {
        Some(end_time) => end_time,
        None => {
            eprintln!("Failed to compute current time");
            return exitcode::OSERR;
        }
    };

    let start_time = match now
        .checked_sub(std::time::Duration::from_secs(60 * 60 * 3))
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
    {
        Some(start_time) => start_time,
        None => {
            eprintln!("Failed to compute start time.");
            return exitcode::SOFTWARE;
        }
    };

    let cage_logs = match cages_client
        .get_cage_logs(
            cage_uuid.as_str(),
            start_time.as_millis(),
            end_time.as_millis(),
        )
        .await
    {
        Ok(logs) => logs,
        Err(e) => {
            eprintln!("Failed to retrieve logs for Cage - {:?}", e);
            return e.exitcode();
        }
    };

    let start_time = i64::from_str_radix(cage_logs.start_time(), 10).unwrap();
    let logs_start = format_timestamp(start_time);
    let end_time = i64::from_str_radix(cage_logs.end_time(), 10).unwrap();
    let logs_end = format_timestamp(end_time);

    if cage_logs.log_events().is_empty() {
        println!("No logs found between {logs_start} and {logs_end}",);
        return exitcode::OK;
    }

    println!(
        "Retrieved {} logs from {logs_start} to {logs_end}",
        cage_logs.log_events().len()
    );

    let mut output = minus::Pager::new();

    // TODO: add support for loading more logs at end of page
    cage_logs
        .log_events()
        .iter()
        .map(serde_json::to_string_pretty)
        .filter_map(|serialized_log| serialized_log.ok())
        .for_each(|log_event| {
            writeln!(output, "{}", log_event).unwrap();
        });

    if let Err(e) = minus::page_all(output) {
        eprintln!("An error occurred while paginating your log data - {:?}", e);
        return exitcode::SOFTWARE;
    } else {
        return exitcode::OK;
    }
}

fn format_timestamp(epoch: i64) -> String {
    let epoch_secs = epoch / 1000;
    let epoch_nsecs = epoch % 1000;
    chrono::Utc
        .timestamp(epoch_secs, epoch_nsecs as u32)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}