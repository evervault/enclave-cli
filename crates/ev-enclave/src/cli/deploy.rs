use crate::api::client::ApiErrorKind;
use crate::api::{self, assets::AssetsClient, enclave::EnclaveApi, AuthMode};
use crate::build::build_enclave_image_file;
use crate::common::prepare_build_args;
use crate::docker::command::get_source_date_epoch;
use crate::get_api_key;
use crate::version::check_version;
use crate::{
    common::{CliError, OutputPath},
    config::{read_and_validate_config, BuildTimeConfig, ValidatedEnclaveBuildConfig},
    deploy::{deploy_eif, get_eif},
    enclave::EIFMeasurements,
};
use atty::Stream;
use clap::Parser;
use exitcode::ExitCode;

/// Deploy an Enclave from a toml file.
#[derive(Debug, Parser)]
#[clap(name = "deploy", about)]
pub struct DeployArgs {
    /// Path to enclave.toml config file
    #[clap(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,

    /// Path to Dockerfile for Enclave. Will override any dockerfile specified in the .toml file.
    #[clap(short = 'f', long = "file")]
    pub dockerfile: Option<String>,

    /// Path to EIF for Enclave. Will not build if EIF is provided.
    #[clap(long = "eif-path")]
    pub eif_path: Option<String>,

    /// Path to use for docker context
    #[clap(default_value = ".")]
    pub context_path: String,

    /// Certificate used to sign the Enclave image file
    #[clap(long = "signing-cert")]
    pub certificate: Option<String>,

    /// Private key used to sign the Enclave image file
    #[clap(long = "private-key")]
    pub private_key: Option<String>,

    /// Disable verbose output
    #[clap(long)]
    pub quiet: bool,

    /// Build time arguments to provide to docker
    #[clap(long = "build-arg")]
    pub docker_build_args: Vec<String>,

    /// Path to an Enclave dockerfile to build from existing
    #[clap(long = "from-existing")]
    pub from_existing: Option<String>,

    /// Deterministic builds
    #[clap(long = "reproducible")]
    pub reproducible: bool,

    /// Healthcheck path exposed by your service
    #[clap(long = "healthcheck")]
    pub healthcheck: Option<String>,

    /// Disables the use of cache during the image builds
    #[clap(long = "no-cache")]
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

pub async fn run(deploy_args: DeployArgs) -> exitcode::ExitCode {
    if let Err(e) = check_version().await {
        log::error!("{e}");
        return exitcode::SOFTWARE;
    };
    let api_key = get_api_key!();
    let (mut enclave_config, validated_config) =
        match read_and_validate_config(&deploy_args.config, &deploy_args) {
            Ok(configs) => configs,
            Err(e) => {
                log::error!("Failed to validate Enclave config - {e}");
                return e.exitcode();
            }
        };

    let enclave_api = api::enclave::EnclaveClient::new(AuthMode::ApiKey(api_key));

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

    let (data_plane_version, installer_version) =
        match get_data_plane_and_installer_version(&validated_config).await {
            Ok(versions) => versions,
            Err(e) => {
                log::error!("Failed to get data plane and installer versions – {e}");
                return e;
            }
        };

    let from_existing = deploy_args.from_existing;
    let (eif_measurements, output_path) = match resolve_eif(
        &validated_config,
        &deploy_args.context_path,
        deploy_args.eif_path.as_deref(),
        !deploy_args.quiet,
        build_args,
        from_existing,
        timestamp,
        data_plane_version.clone(),
        installer_version.clone(),
        deploy_args.reproducible,
        deploy_args.no_cache,
    )
    .await
    {
        Ok(eif_info) => eif_info,
        Err(e) => return e,
    };

    if enclave_config.debug {
        crate::common::log_debug_mode_attestation_warning();
    }

    log::info!(
        "Deploying Enclave with the following attestation measurements: {}",
        serde_json::to_string_pretty(&eif_measurements)
            .expect("Failed to serialize Enclave attestation measures.")
    );

    enclave_config.set_attestation(&eif_measurements);
    crate::common::save_enclave_config(&enclave_config, &deploy_args.config);

    if let Err(e) = deploy_eif(
        &validated_config,
        enclave_api,
        output_path,
        &eif_measurements,
        data_plane_version,
        installer_version,
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
    data_plane_version: String,
    installer_version: String,
    reproducible: bool,
    no_cache: bool,
) -> Result<(EIFMeasurements, OutputPath), exitcode::ExitCode> {
    if let Some(path) = eif_path {
        let (mut measurements, output_path) = get_eif(path, verbose, no_cache).map_err(|e| {
            log::error!("{e}");
            e.exitcode()
        })?;

        let consistent_pcrs = validated_config.attestation.as_ref()
          .map(|existing_attestation| existing_attestation.pcrs() == measurements.pcrs())
          .unwrap_or(false);

        if consistent_pcrs {
          validated_config.attestation.as_ref().unwrap().signature().map(|signature| {
            measurements.set_signature(signature.to_string());
          });
        } else {
          log::warn!("The PCRs in the enclave.toml do not match the EIF to upload. The deployment will continue, but the signature stored in the enclave.toml will not be uploaded to Evervault.");
        }

        Ok((measurements, output_path))
    } else {
        let (built_enclave, output_path) = build_enclave_image_file(
            validated_config,
            context_path,
            None,
            verbose,
            build_args,
            data_plane_version,
            installer_version,
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

async fn get_data_plane_and_installer_version(
    validated_config: &ValidatedEnclaveBuildConfig,
) -> Result<(String, String), ExitCode> {
    let enclave_build_assets_client = AssetsClient::new();
    match validated_config.runtime.clone() {
        Some(config) => Ok((config.data_plane_version.clone(), config.installer_version)),
        None => {
            let data_plane_version =
                match enclave_build_assets_client.get_data_plane_version().await {
                    Ok(version) => version,
                    Err(e) => {
                        log::error!("Failed to retrieve the latest data plane version - {e:?}");
                        return Err(e.exitcode());
                    }
                };
            let installer_version = match enclave_build_assets_client.get_installer_version().await
            {
                Ok(version) => version,
                Err(e) => {
                    log::error!("Failed to retrieve the latest installer version - {e:?}");
                    return Err(e.exitcode());
                }
            };
            Ok((data_plane_version, installer_version))
        }
    }
}
