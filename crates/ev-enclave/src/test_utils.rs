use crate::api::enclave::{
    BuildStatus, DeployStatus, DeploymentsForGetEnclave, Enclave, EnclaveDeployment,
    EnclaveRegionalDeployment, EnclaveSigningCert, EnclaveState, EnclaveVersion,
    GetEnclaveDeploymentResponse, GetEnclaveResponse,
};
use crate::build::build_enclave_image_file;
use crate::build::error::BuildError;
use crate::common::OutputPath;
use crate::config::{read_and_validate_config, ValidatedEnclaveBuildConfig};
use crate::enclave::BuiltEnclave;
use crate::version::EnclaveRuntime;

pub async fn build_test_enclave(
    output_dir: Option<&str>,
    from_existing: Option<String>,
    reproducible: bool,
) -> Result<(BuiltEnclave, OutputPath), BuildError> {
    let dn_string = crate::cert::DistinguishedName::default();
    crate::cert::create_new_cert(
        std::path::Path::new("."),
        dn_string,
        crate::cert::DesiredLifetime::default(),
    )
    .expect("Failed to gen cert in tests");
    let build_args = get_test_build_args();

    let enclave_runtime = EnclaveRuntime::new().await.unwrap();
    let timestamp = "0".to_string();

    build_enclave_image_file(
        &build_args,
        ".",
        output_dir,
        false,
        None,
        &enclave_runtime,
        timestamp,
        from_existing,
        reproducible,
        true,
    )
    .await
}

fn get_test_build_args() -> ValidatedEnclaveBuildConfig {
    let (_enclave_config, validated_config) = read_and_validate_config("./test.enclave.toml", &())
        .expect("Testing config failed to validate");
    validated_config
}

pub fn build_get_enclave_response(
    state: EnclaveState,
    deployments: Vec<DeploymentsForGetEnclave>,
) -> GetEnclaveResponse {
    GetEnclaveResponse {
        enclaves: Enclave {
            uuid: "abc".into(),
            name: "def".into(),
            team_uuid: "team_123".into(),
            app_uuid: "app_456".into(),
            domain: "enclave.com".into(),
            state,
            created_at: "".into(),
            updated_at: "".into(),
        },
        deployments,
    }
}

pub fn build_get_enclave_deployment(
    build_status: BuildStatus,
    deploy_status: DeployStatus,
    started_at: Option<String>,
    completed_at: Option<String>,
) -> GetEnclaveDeploymentResponse {
    GetEnclaveDeploymentResponse {
        deployment: EnclaveDeployment {
            uuid: "".into(),
            enclave_uuid: "".into(),
            version_uuid: "".into(),
            signing_cert_uuid: "".into(),
            debug_mode: true,
            started_at: started_at.clone(),
            completed_at: completed_at.clone(),
        },
        enclave_version: EnclaveVersion {
            uuid: "".into(),
            version: 0,
            control_plane_img_url: Some("".into()),
            control_plane_version: Some("".into()),
            data_plane_version: None,
            build_status,
            failure_reason: None,
            started_at: started_at.clone(),
            healthcheck: None,
        },
        enclave_signing_cert: EnclaveSigningCert {
            name: Some("".into()),
            uuid: "".into(),
            app_uuid: "".into(),
            cert_hash: "".into(),
            not_before: None,
            not_after: None,
        },
        enclave_regional_deployments: vec![EnclaveRegionalDeployment {
            uuid: "".into(),
            deployment_uuid: "".into(),
            deployment_order: 0,
            region: "".into(),
            failure_reason: None,
            deploy_status,
            started_at,
            completed_at,
            detailed_status: Some("".into()),
        }],
    }
}
