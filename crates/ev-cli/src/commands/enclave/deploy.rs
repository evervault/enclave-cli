use atty::Stream;
use clap::Parser;
use common::api::AuthMode;
use common::api::{client::ApiErrorKind, BasicAuth};
use common::CliError;
use ev_enclave::version::EnclaveRuntime;
use ev_enclave::{
    api::enclave::EnclaveApi,
    build::build_enclave_image_file,
    common::prepare_build_args,
    common::OutputPath,
    config::{read_and_validate_config, BuildTimeConfig, ValidatedEnclaveBuildConfig},
    deploy::{deploy_eif, get_eif},
    docker::command::get_source_date_epoch,
    enclave::EIFMeasurements,
};

use crate::BaseArgs;

/// Deploy an Enclave from a toml file.
#[derive(Debug, Parser)]
#[command(name = "deploy", about)]
pub struct DeployArgs {
    /// Path to enclave.toml config file
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,

    /// Path to Dockerfile for Enclave. Will override any dockerfile specified in the .toml file.
    #[arg(short = 'f', long = "file")]
    pub dockerfile: Option<String>,

    /// Path to EIF for Enclave. Will not build if EIF is provided.
    #[arg(long = "eif-path")]
    pub eif_path: Option<String>,

    /// Path to use for docker context
    #[arg(default_value = ".")]
    pub context_path: String,

    /// Certificate used to sign the Enclave image file
    #[arg(long = "signing-cert")]
    pub certificate: Option<String>,

    /// Private key used to sign the Enclave image file
    #[arg(long = "private-key")]
    pub private_key: Option<String>,

    /// Build time arguments to provide to docker
    #[arg(long = "build-arg")]
    pub docker_build_args: Vec<String>,

    /// Path to an Enclave dockerfile to build from existing
    #[arg(long = "from-existing")]
    pub from_existing: Option<String>,

    /// Deterministic builds
    #[arg(long = "reproducible")]
    pub reproducible: bool,

    /// Healthcheck path exposed by your service
    #[arg(long = "healthcheck")]
    pub healthcheck: Option<String>,

    /// Disables the use of cache during the image builds
    #[arg(long = "no-cache")]
    pub no_cache: bool,
}

impl BuildTimeConfig for DeployArgs {
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

pub async fn run(deploy_args: DeployArgs, (_, api_key): BasicAuth) -> exitcode::ExitCode {
    let base_args = BaseArgs::parse();
    let (mut enclave_config, validated_config) =
        match read_and_validate_config(&deploy_args.config, &deploy_args) {
            Ok(configs) => configs,
            Err(e) => {
                log::error!("Failed to validate Enclave config - {e}");
                return e.exitcode();
            }
        };

    let enclave_api = ev_enclave::api::enclave::EnclaveClient::new(AuthMode::ApiKey(api_key));

    let enclave = match enclave_api
        .get_enclave(validated_config.enclave_uuid())
        .await
    {
        Ok(enclave) => enclave,
        Err(e) => {
            log::error!(
                "Failed to retrieve Enclave details from Evervault API – {}",
                e
            );
            return e.exitcode();
        }
    };

    let enclave_scaling_config = match enclave_api
        .get_scaling_config(validated_config.enclave_uuid())
        .await
    {
        Ok(scaling_config) => Some(scaling_config),
        Err(e) if matches!(e.kind, ApiErrorKind::NotFound) => None,
        Err(e) => {
            log::error!("Failed to load Enclave scaling config - {e}");
            return e.exitcode();
        }
    };

    let local_replicas = validated_config
        .scaling
        .as_ref()
        .map(|local_scaling_config| local_scaling_config.desired_replicas);

    // Warn if local scaling config differs from remote
    let has_scaling_config_drift = enclave_scaling_config.as_ref().is_some_and(|config| {
        local_replicas.is_some_and(|replicas| config.desired_replicas() != replicas)
    });

    // cage scaling config is None - has_scaling_config_drift: false
    // cage scaling config is Some - local scaling config is None : has_scaling_config_drift: false
    // cage scaling config is Some - local scaling config is Some - scaling config differs : has_scaling_config_drift: true

    if has_scaling_config_drift {
        let remote_replicas = enclave_scaling_config.as_ref().unwrap().desired_replicas();
        let local_replicas_count = local_replicas
            .map(|count| count.to_string())
            .expect("Infallible - checked above");

        log::warn!("Remote scaling config differs from local config. This deployment will apply the local config.\n\nCurrent remote replica count: {remote_replicas}\nLocal replica count: {local_replicas_count}\n");
    }

    let timestamp = get_source_date_epoch();

    let formatted_args = prepare_build_args(&deploy_args.docker_build_args);
    let build_args = formatted_args
        .as_ref()
        .map(|args| args.iter().map(AsRef::as_ref).collect());

    let enclave_runtime = match EnclaveRuntime::new().await {
        Ok(versions) => versions,
        Err(e) => {
            log::error!("Failed to get data plane and installer versions – {e}");
            return e.exitcode();
        }
    };

    let from_existing = deploy_args.from_existing;
    let (eif_measurements, output_path) = match resolve_eif(
        &validated_config,
        &deploy_args.context_path,
        deploy_args.eif_path.as_deref(),
        base_args.verbose,
        build_args,
        from_existing,
        timestamp,
        &enclave_runtime,
        deploy_args.reproducible,
        deploy_args.no_cache,
    )
    .await
    {
        Ok(eif_info) => eif_info,
        Err(e) => return e,
    };

    if enclave_config.debug {
        ev_enclave::common::log_debug_mode_attestation_warning();
    }

    log::info!(
        "Deploying Enclave with the following attestation measurements: {}",
        serde_json::to_string_pretty(&eif_measurements)
            .expect("Failed to serialize Enclave attestation measures.")
    );

    enclave_config.set_attestation(&eif_measurements);
    ev_enclave::common::save_enclave_config(&enclave_config, &deploy_args.config);

    if let Err(e) = deploy_eif(
        &validated_config,
        enclave_api,
        output_path,
        &eif_measurements,
        &enclave_runtime,
    )
    .await
    {
        log::error!("{e}");
        return e.exitcode();
    };

    if atty::is(Stream::Stdout) {
        log::info!(
            "Your Enclave is now available at https://{}",
            enclave.domain()
        );
    } else {
        let success_msg = serde_json::json!({
            "status": "success",
            "enclaveDomain": enclave.domain(),
            "measurements": &eif_measurements
        });
        println!("{}", serde_json::to_string(&success_msg).unwrap());
    };
    exitcode::OK
}

#[allow(clippy::too_many_arguments)]
async fn resolve_eif(
    validated_config: &ValidatedEnclaveBuildConfig,
    context_path: &str,
    eif_path: Option<&str>,
    verbose: bool,
    build_args: Option<Vec<&str>>,
    from_existing: Option<String>,
    timestamp: String,
    enclave_runtime: &EnclaveRuntime,
    reproducible: bool,
    no_cache: bool,
) -> Result<(EIFMeasurements, OutputPath), exitcode::ExitCode> {
    if let Some(path) = eif_path {
        let (mut measurements, output_path) = get_eif(path, verbose, no_cache).map_err(|e| {
            log::error!("{e}");
            e.exitcode()
        })?;

        /*
         * We cannot guarantee that the signing key pair of the provided EIF are present when it is being uploaded.
         * We compare the PCRs found in the toml to the PCRs of the EIF (returned by `nitro-cli describe-eif`).
         * If the PCRs match, then we know that the signature in the enclave.toml was generated using the key pair which signed this EIF
         * and can include the signature in our Deployment request.
         * Otherwise, upload the PCRs without the signature and warn the user.
         */
        let consistent_pcrs = validated_config
            .attestation
            .as_ref()
            .map(|existing_attestation| existing_attestation.pcrs() == measurements.pcrs())
            .unwrap_or(false);

        if consistent_pcrs {
            validated_config
                .attestation
                .as_ref()
                .unwrap()
                .signature()
                .map(|signature| {
                    measurements.set_signature(signature.to_string());
                });
        } else {
            log::warn!("The PCRs in the enclave.toml do not match the PCRs of the EIF provided. The deployment will continue using the PCRs from the EIF.");
            log::warn!(
                "The signature value in your enclave.toml will not be uploaded to Evervault."
            );
        }

        Ok((measurements, output_path))
    } else {
        let (built_enclave, output_path) = build_enclave_image_file(
            validated_config,
            context_path,
            None,
            verbose,
            build_args,
            enclave_runtime,
            timestamp,
            from_existing,
            reproducible,
            no_cache,
        )
        .await
        .map_err(|build_err| {
            log::error!("Failed to build EIF - {build_err}");
            build_err.exitcode()
        })?;
        Ok((built_enclave.measurements().to_owned(), output_path))
    }
}
