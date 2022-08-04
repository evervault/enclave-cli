use atty::Stream;

use crate::describe::describe_eif;
use clap::Parser;

/// Get the PCRs of a built EIF
#[derive(Debug, Parser)]
#[clap(name = "describe", about)]
pub struct DescribeArgs {
    /// Path to the EIF to descibe.
    #[clap(default_value = "./enclave.eif")]
    pub eif_path: String,
}

pub async fn run(describe_args: DescribeArgs) {
    let measurements = match describe_eif(&describe_args.eif_path) {
        Ok(measurements) => measurements,
        Err(e) => {
            log::error!("Failed to describe eif — {}", e);
            return;
        }
    };

    if atty::is(Stream::Stdout) {
        // nicely format the JSON when printing to a TTY
        println!("{}", serde_json::to_string_pretty(&measurements).unwrap());
    } else {
        println!("{}", serde_json::to_string(&measurements).unwrap());
    }
}
