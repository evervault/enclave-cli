use crate::common::CliError;
use crate::delete::delete_enclave;
use crate::get_api_key;
use crate::version::check_version;
use clap::Parser;

/// Delete an Enclave from a toml file.
#[derive(Debug, Parser)]
#[clap(name = "delete", about)]
pub struct DeleteArgs {
    /// Path to enclave.toml config file
    #[clap(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,

    /// Uuid of the Enclave to delete
    #[clap(long = "enclave-uuid")]
    pub enclave_uuid: Option<String>,

    /// Disable verbose output
    #[clap(long)]
    pub quiet: bool,

    /// Perform the Enclave deletion in the background
    #[clap(long)]
    pub background: bool,

    #[clap(long)]
    pub force: bool,
}

pub async fn run(delete_args: DeleteArgs) -> exitcode::ExitCode {
    if let Err(e) = check_version().await {
        log::error!("{e}");
        return exitcode::SOFTWARE;
    };
    let should_del = match dialoguer::Confirm::new()
        .with_prompt("Are you sure you want to delete this Enclave?")
        .default(false)
        .interact()
    {
        Ok(should_delete) => should_delete,
        Err(_) => {
            log::error!("An error occurred while attempting to confirm this Enclave delete.");
            return exitcode::IOERR;
        }
    };

    if !should_del {
        log::info!("Phew! Exiting early...");
        return exitcode::OK;
    }

    let api_key = get_api_key!();
    match delete_enclave(
        delete_args.config.as_str(),
        delete_args.enclave_uuid.as_deref(),
        api_key.as_str(),
        delete_args.background,
    )
    .await
    {
        Ok(_) => {
            if delete_args.background {
                log::info!("Enclave successfully marked for deletion.");
            } else {
                log::info!("Deletion was successful");
            }
        }
        Err(e) => {
            log::error!("{e}");
            return e.exitcode();
        }
    };

    exitcode::OK
}
