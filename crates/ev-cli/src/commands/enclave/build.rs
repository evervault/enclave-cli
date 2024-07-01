use clap::Parser;
use common::CliError;
use ev_enclave::build::build_enclave_image_file;
use ev_enclave::common::prepare_build_args;
use ev_enclave::config::{read_and_validate_config, BuildTimeConfig};
use ev_enclave::docker::command::get_source_date_epoch;
use ev_enclave::version::EnclaveRuntime;

use crate::BaseArgs;

/// Build an Enclave from a Dockerfile
#[derive(Parser, Debug)]
#[command(name = "build", about)]
pub struct BuildArgs {
    /// Path to enclave.toml config file. This can be generated using the init command
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,

    /// Path to Dockerfile for Enclave. Will override any dockerfile specified in the .toml file.
    #[arg(short = 'f', long = "file")]
    pub dockerfile: Option<String>,

    /// Path to use for Docker context. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub context_path: String,

    /// Certificate used to sign the Enclave image file
    #[arg(long = "signing-cert")]
    pub certificate: Option<String>,

    /// Private key used to sign the Enclave image file
    #[arg(long = "private-key")]
    pub private_key: Option<String>,

    /// Path to directory where the processed dockerfile and Enclave will be saved
    #[arg(short = 'o', long = "output", default_value = ".")]
    pub output_dir: String,

    /// Build time arguments to provide to docker
    #[arg(long = "build-arg")]
    pub docker_build_args: Vec<String>,

    /// Path to an Enclave dockerfile to build from existing
    #[arg(long = "from-existing")]
    pub from_existing: Option<String>,

    /// Deterministic builds
    #[arg(long = "reproducible")]
    pub reproducible: bool,

    /// Enables forwarding proxy protocol when TLS Termination is disabled
    #[arg(long = "forward-proxy-protocol")]
    pub forward_proxy_protocol: bool,

    /// Disables the use of cache during the image builds
    #[arg(long = "no-cache")]
    pub no_cache: bool,
}

impl BuildTimeConfig for BuildArgs {
    fn certificate(&self) -> Option<&str> {
        self.certificate.as_deref()
    }

    fn dockerfile(&self) -> Option<&str> {
        self.dockerfile.as_deref()
    }

    fn private_key(&self) -> Option<&str> {
        self.private_key.as_deref()
    }
}

pub async fn run(build_args: BuildArgs) -> exitcode::ExitCode {
    let base_args = BaseArgs::parse();

    let (mut enclave_config, validated_config) =
        match read_and_validate_config(&build_args.config, &build_args) {
            Ok(config) => config,
            Err(e) => {
                log::error!("Failed to read Enclave config from file system — {e}");
                return e.exitcode();
            }
        };

    let formatted_args = prepare_build_args(&build_args.docker_build_args);
    let borrowed_args = formatted_args
        .as_ref()
        .map(|args| args.iter().map(AsRef::as_ref).collect());

    let enclave_runtime = match EnclaveRuntime::maybe_from_existing_dockerfile(
        build_args.from_existing.clone(),
    )
    .await
    {
        Ok(runtime) => runtime,
        Err(e) => {
            log::error!("Failed to retrieve the latest data plane and installer versions - {e:?}");
            return e.exitcode();
        }
    };

    let timestamp = get_source_date_epoch();

    let from_existing = build_args.from_existing;
    let built_enclave = match build_enclave_image_file(
        &validated_config,
        &build_args.context_path,
        Some(&build_args.output_dir),
        base_args.verbose,
        borrowed_args,
        &enclave_runtime,
        timestamp,
        from_existing,
        build_args.reproducible,
        build_args.no_cache,
    )
    .await
    {
        Ok((built_enclave, _)) => built_enclave,
        Err(e) => {
            log::error!("An error occurred while building your Enclave — {e}");
            return e.exitcode();
        }
    };

    enclave_config.set_attestation(built_enclave.measurements());
    ev_enclave::common::save_enclave_config(&enclave_config, &build_args.config);

    if enclave_config.debug {
        ev_enclave::common::log_debug_mode_attestation_warning();
    }

    // Write Enclave measures to stdout
    let success_msg = serde_json::json!({
        "status": "success",
        "message": "EIF built successfully",
        "enclaveMeasurements": built_enclave.measurements()
    });

    println!("{}", serde_json::to_string_pretty(&success_msg).unwrap());
    exitcode::OK
}
