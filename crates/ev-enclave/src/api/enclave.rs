use crate::config::ValidatedEnclaveBuildConfig;
use crate::version::EnclaveRuntime;

use common::api::client::{ApiClient, ApiClientError, ApiResult, GenericApiClient, HandleResponse};
use common::api::AuthMode;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use mockall::automock;

#[derive(Clone)]
pub struct EnclaveClient {
    inner: GenericApiClient,
}

impl ApiClient for EnclaveClient {
    fn auth(&self) -> &AuthMode {
        self.inner.auth()
    }

    fn update_auth(&mut self, auth: AuthMode) -> Result<(), ApiClientError> {
        self.inner.update_auth(auth)
    }

    fn client(&self) -> &Client {
        self.inner.client()
    }

    fn base_url(&self) -> String {
        let api_base = self.inner.base_url();
        format!("{}/enclaves", api_base)
    }

    fn accept(&self) -> String {
        format!("application/json;version={}", env!("CARGO_PKG_VERSION"))
    }
}

#[async_trait::async_trait]
#[cfg_attr(test, automock)]
pub trait EnclaveApi {
    async fn create_enclave(
        &self,
        enclave_create_payload: CreateEnclaveRequest,
    ) -> ApiResult<Enclave>;
    async fn create_enclave_deployment_intent(
        &self,
        enclave_uuid: &str,
        payload: CreateEnclaveDeploymentIntentRequest,
    ) -> ApiResult<CreateEnclaveDeploymentIntentResponse>;
    async fn create_enclave_signing_cert_ref(
        &self,
        payload: CreateEnclaveSigningCertRefRequest,
    ) -> ApiResult<CreateEnclaveSigningCertRefResponse>;
    async fn get_enclaves(&self) -> ApiResult<GetEnclavesResponse>;
    async fn get_enclave(&self, enclave_uuid: &str) -> ApiResult<GetEnclaveResponse>;
    async fn get_app_keys(&self, team_uuid: &str, app_uuid: &str) -> ApiResult<GetKeysResponse>;
    async fn add_env_var(&self, enclave_uuid: String, payload: AddSecretRequest) -> ApiResult<()>;
    async fn delete_env_var(&self, enclave_uuid: String, name: String) -> ApiResult<()>;
    async fn get_enclave_env(&self, enclave_uuid: String) -> ApiResult<EnclaveEnv>;
    async fn get_enclave_deployment_by_uuid(
        &self,
        enclave_uuid: &str,
        deployment_uuid: &str,
    ) -> ApiResult<GetEnclaveDeploymentResponse>;
    async fn get_signing_certs(&self) -> ApiResult<GetSigningCertsResponse>;
    async fn update_enclave_locked_signing_certs(
        &self,
        enclave_uuid: &str,
        payload: UpdateLockedEnclaveSigningCertRequest,
    ) -> ApiResult<Vec<EnclaveToSigningCert>>;
    async fn get_enclave_locked_signing_certs(
        &self,
        enclave_uuid: &str,
    ) -> ApiResult<Vec<EnclaveSigningCert>>;
    async fn get_enclave_cert_by_uuid(&self, cert_uuid: &str) -> ApiResult<EnclaveSigningCert>;
    async fn get_enclave_logs(
        &self,
        enclave_uuid: &str,
        start_time: u128,
        end_time: u128,
    ) -> ApiResult<EnclaveLogs>;
    async fn delete_enclave(&self, enclave_uuid: &str) -> ApiResult<DeleteEnclaveResponse>;
    async fn restart_enclave(&self, enclave_uuid: &str) -> ApiResult<EnclaveDeployment>;
    async fn get_scaling_config(&self, enclave_uuid: &str) -> ApiResult<EnclaveScalingConfig>;
    async fn update_scaling_config(
        &self,
        enclave_uuid: &str,
        update_scaling_config_request: UpdateEnclaveScalingConfigRequest,
    ) -> ApiResult<EnclaveScalingConfig>;
}

impl EnclaveClient {
    pub fn new(auth_mode: AuthMode) -> Self {
        Self {
            inner: GenericApiClient::from(auth_mode),
        }
    }
}

#[async_trait::async_trait]
impl EnclaveApi for EnclaveClient {
    async fn create_enclave(
        &self,
        enclave_create_payload: CreateEnclaveRequest,
    ) -> ApiResult<Enclave> {
        let create_enclave_url = format!("{}/", self.base_url());
        self.post(&create_enclave_url)
            .json(&enclave_create_payload)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn create_enclave_deployment_intent(
        &self,
        enclave_uuid: &str,
        payload: CreateEnclaveDeploymentIntentRequest,
    ) -> ApiResult<CreateEnclaveDeploymentIntentResponse> {
        let deployment_intent_url = format!("{}/{}/credentials", self.base_url(), enclave_uuid);
        self.post(&deployment_intent_url)
            .json(&payload)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn create_enclave_signing_cert_ref(
        &self,
        payload: CreateEnclaveSigningCertRefRequest,
    ) -> ApiResult<CreateEnclaveSigningCertRefResponse> {
        let signing_cert_url = format!("{}/signing/certs", self.base_url());
        self.post(&signing_cert_url)
            .json(&payload)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn get_enclaves(&self) -> ApiResult<GetEnclavesResponse> {
        let get_enclaves_url = format!("{}/", self.base_url());
        self.get(&get_enclaves_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn get_enclave(&self, enclave_uuid: &str) -> ApiResult<GetEnclaveResponse> {
        let get_enclave_url = format!("{}/{}", self.base_url(), enclave_uuid);
        self.get(&get_enclave_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn get_app_keys(&self, team_uuid: &str, app_uuid: &str) -> ApiResult<GetKeysResponse> {
        let get_enclave_url = format!("{}/{}/apps/{}", self.keys_url(), team_uuid, app_uuid);
        self.get(&get_enclave_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn add_env_var(&self, enclave_uuid: String, payload: AddSecretRequest) -> ApiResult<()> {
        let add_env_url = format!("{}/{}/secrets", self.base_url(), enclave_uuid);
        self.put(&add_env_url)
            .json(&payload)
            .send()
            .await
            .handle_no_op_response()
    }

    async fn delete_env_var(&self, enclave_uuid: String, name: String) -> ApiResult<()> {
        let delete_env_url = format!("{}/{}/secrets/{}", self.base_url(), enclave_uuid, name);
        self.delete(&delete_env_url)
            .send()
            .await
            .handle_no_op_response()
    }

    async fn get_enclave_env(&self, enclave_uuid: String) -> ApiResult<EnclaveEnv> {
        let get_env_url = format!("{}/{}/secrets", self.base_url(), enclave_uuid);
        self.get(&get_env_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn get_enclave_deployment_by_uuid(
        &self,
        enclave_uuid: &str,
        deployment_uuid: &str,
    ) -> ApiResult<GetEnclaveDeploymentResponse> {
        let get_enclave_url = format!(
            "{}/{}/deployments/{}",
            self.base_url(),
            enclave_uuid,
            deployment_uuid
        );
        self.get(&get_enclave_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn get_signing_certs(&self) -> ApiResult<GetSigningCertsResponse> {
        let get_certs_url = format!("{}/signing/certs", self.base_url(),);
        self.get(&get_certs_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn update_enclave_locked_signing_certs(
        &self,
        enclave_uuid: &str,
        payload: UpdateLockedEnclaveSigningCertRequest,
    ) -> ApiResult<Vec<EnclaveToSigningCert>> {
        let get_enclave_lock_certs_url =
            format!("{}/{}/signing/certs", self.base_url(), enclave_uuid);
        self.put(&get_enclave_lock_certs_url)
            .json(&payload)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn get_enclave_locked_signing_certs(
        &self,
        enclave_uuid: &str,
    ) -> ApiResult<Vec<EnclaveSigningCert>> {
        let get_enclave_lock_certs_url =
            format!("{}/{}/signing/certs", self.base_url(), enclave_uuid);
        self.get(&get_enclave_lock_certs_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn get_enclave_cert_by_uuid(&self, cert_uuid: &str) -> ApiResult<EnclaveSigningCert> {
        let get_cert_url = format!("{}/signing/certs/{}", self.base_url(), cert_uuid);
        self.get(&get_cert_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn get_enclave_logs(
        &self,
        enclave_uuid: &str,
        start_time: u128,
        end_time: u128,
    ) -> ApiResult<EnclaveLogs> {
        let get_logs_url = format!(
            "{}/{}/logs?startTime={start_time}&endTime={end_time}",
            self.base_url(),
            enclave_uuid
        );

        self.get(&get_logs_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn delete_enclave(&self, enclave_uuid: &str) -> ApiResult<DeleteEnclaveResponse> {
        let delete_enclave_url = format!("{}/{}", self.base_url(), enclave_uuid);
        self.delete(&delete_enclave_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn restart_enclave(&self, enclave_uuid: &str) -> ApiResult<EnclaveDeployment> {
        let patch_enclave_url = format!("{}/{}", self.base_url(), enclave_uuid);
        self.patch(&patch_enclave_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn get_scaling_config(&self, enclave_uuid: &str) -> ApiResult<EnclaveScalingConfig> {
        let enclave_scaling_url = format!("{}/{}/scale", self.base_url(), enclave_uuid);
        self.get(&enclave_scaling_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn update_scaling_config(
        &self,
        enclave_uuid: &str,
        update_scaling_config_request: UpdateEnclaveScalingConfigRequest,
    ) -> ApiResult<EnclaveScalingConfig> {
        let enclave_scaling_url = format!("{}/{}/scale", self.base_url(), enclave_uuid);
        self.put(&enclave_scaling_url)
            .json(&update_scaling_config_request)
            .send()
            .await
            .handle_json_response()
            .await
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionMetadata {
    installer_version: String,
    git_hash: String,
    data_plane_version: String,
    git_timestamp: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateEnclaveDeploymentIntentRequest {
    #[serde(flatten)]
    pcrs: crate::enclave::PCRs,
    debug_mode: bool,
    trusted_headers: Vec<String>,
    egress_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress_domains: Option<Vec<String>>,
    eif_size_bytes: u64,
    not_before: String,
    not_after: String,
    metadata: VersionMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    healthcheck: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    desired_replicas: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcrs_signature: Option<String>,
}

impl CreateEnclaveDeploymentIntentRequest {
    pub fn new(
        pcrs: &crate::enclave::PCRs,
        config: ValidatedEnclaveBuildConfig,
        eif_size_bytes: u64,
        enclave_runtime: &EnclaveRuntime,
        git_timestamp: String,
        git_hash: String,
        desired_replicas: Option<u32>,
        pcrs_signature: Option<String>,
    ) -> Self {
        Self {
            pcrs: pcrs.clone(),
            debug_mode: config.debug,
            egress_enabled: config.egress.enabled,
            egress_domains: config.egress.destinations.clone(),
            trusted_headers: config.trusted_headers().to_vec(),
            eif_size_bytes,
            not_before: config.signing.not_before(),
            not_after: config.signing.not_after(),
            metadata: VersionMetadata {
                git_hash,
                installer_version: enclave_runtime.installer_version.clone(),
                data_plane_version: enclave_runtime.data_plane_version.clone(),
                git_timestamp,
            },
            healthcheck: config.healthcheck().map(String::from),
            desired_replicas,
            pcrs_signature,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateEnclaveSigningCertRefRequest {
    cert_hash: String,
    name: String,
    not_before: String,
    not_after: String,
}

impl CreateEnclaveSigningCertRefRequest {
    pub fn new(cert_hash: String, name: String, not_before: String, not_after: String) -> Self {
        Self {
            cert_hash,
            name,
            not_before,
            not_after,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLockedEnclaveSigningCertRequest {
    cert_uuids: Vec<String>,
}

impl UpdateLockedEnclaveSigningCertRequest {
    pub fn new(cert_uuids: Vec<String>) -> Self {
        Self { cert_uuids }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateEnclaveRequest {
    name: String,
    is_time_bound: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddSecretRequest {
    pub name: String,
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveSecrets {
    pub name: String,
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnclaveEnv {
    pub secrets: Vec<Secret>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Secret {
    pub name: String,
    pub secret: String,
}

impl CreateEnclaveRequest {
    pub fn new(enclave_name: String, is_time_bound: bool) -> Self {
        Self {
            name: enclave_name,
            is_time_bound,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateEnclaveDeploymentIntentResponse {
    signed_url: String,
    enclave_uuid: String,
    deployment_uuid: String,
    version: u32,
}

impl CreateEnclaveDeploymentIntentResponse {
    pub fn signed_url(&self) -> &str {
        &self.signed_url
    }

    pub fn enclave_uuid(&self) -> &str {
        &self.enclave_uuid
    }

    pub fn deployment_uuid(&self) -> &str {
        &self.deployment_uuid
    }

    pub fn version(&self) -> u32 {
        self.version
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateEnclaveSigningCertRefResponse {
    cert_hash: String,
    not_before: String,
    not_after: String,
    name: String,
    uuid: String,
}

impl CreateEnclaveSigningCertRefResponse {
    pub fn cert_hash(&self) -> &str {
        &self.cert_hash
    }

    pub fn not_before(&self) -> &str {
        &self.not_before
    }

    pub fn not_after(&self) -> &str {
        &self.not_after
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveToSigningCert {
    pub enclave_uuid: String,
    pub signing_cert_uuid: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EnclaveState {
    Pending,
    Active,
    Deleting,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Enclave {
    pub uuid: String,
    pub name: String,
    pub team_uuid: String,
    pub app_uuid: String,
    pub domain: String,
    pub state: EnclaveState,
    pub created_at: String,
    pub updated_at: String,
}

impl Enclave {
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn app_uuid(&self) -> &str {
        &self.app_uuid
    }

    pub fn team_uuid(&self) -> &str {
        &self.team_uuid
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveDeployment {
    pub uuid: String,
    pub enclave_uuid: String,
    pub version_uuid: String,
    pub signing_cert_uuid: String,
    pub debug_mode: bool,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

impl EnclaveDeployment {
    pub fn is_finished(&self) -> bool {
        self.completed_at.is_some()
    }

    pub fn enclave_uuid(&self) -> &str {
        &self.enclave_uuid
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BuildStatus {
    Pending,
    Building,
    Ready,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveVersion {
    pub uuid: String,
    pub version: u16,
    pub control_plane_img_url: Option<String>,
    pub control_plane_version: Option<String>,
    pub data_plane_version: Option<String>,
    pub build_status: BuildStatus,
    pub failure_reason: Option<String>,
    pub started_at: Option<String>,
    pub healthcheck: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveSigningCert {
    pub name: Option<String>,
    pub uuid: String,
    pub app_uuid: String,
    pub cert_hash: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

impl EnclaveSigningCert {
    pub fn new(
        name: Option<String>,
        uuid: String,
        app_uuid: String,
        cert_hash: String,
        not_before: Option<String>,
        not_after: Option<String>,
    ) -> Self {
        Self {
            name,
            uuid,
            app_uuid,
            cert_hash,
            not_before,
            not_after,
        }
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn app_uuid(&self) -> &str {
        &self.app_uuid
    }

    pub fn cert_hash(&self) -> &str {
        &self.cert_hash
    }

    pub fn not_before(&self) -> Option<String> {
        self.not_before.clone()
    }

    pub fn not_after(&self) -> Option<String> {
        self.not_after.clone()
    }

    pub fn name(&self) -> Option<String> {
        self.name.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeployStatus {
    Pending,
    Deploying,
    Ready,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveRegionalDeployment {
    pub uuid: String,
    pub deployment_uuid: String,
    pub deployment_order: u16,
    pub region: String,
    pub failure_reason: Option<String>,
    pub deploy_status: DeployStatus,
    // started_at should be required, but is being returned as null sometimes
    // should revert this to just String after API fix
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub detailed_status: Option<String>,
}

impl EnclaveRegionalDeployment {
    pub fn is_failed(&self) -> bool {
        self.deploy_status == DeployStatus::Failed
    }

    pub fn get_failure_reason(&self) -> String {
        self.failure_reason
            .clone()
            .unwrap_or_else(|| String::from("An unknown error occurred during deployment."))
    }

    pub fn get_detailed_status(&self) -> String {
        self.detailed_status
            .clone()
            .unwrap_or_else(|| String::from("Starting deployment."))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetEnclavesResponse {
    enclaves: Vec<Enclave>,
}

impl GetEnclavesResponse {
    pub fn enclaves(&self) -> &Vec<Enclave> {
        self.enclaves.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentsForGetEnclave {
    #[serde(flatten)]
    pub deployment: EnclaveDeployment,
    #[serde(rename = "enclaveVersion")]
    pub version: EnclaveVersion,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetEnclaveResponse {
    #[serde(flatten)]
    pub enclaves: Enclave,
    #[serde(rename = "enclaveDeployments")]
    pub deployments: Vec<DeploymentsForGetEnclave>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeysResponse {
    pub ecdh_p256_key_uncompressed: String,
    pub ecdh_p256_key: String,
    pub ecdh_key: String,
}

impl GetEnclaveResponse {
    pub fn is_deleted(&self) -> bool {
        self.enclaves.state == EnclaveState::Deleted
    }

    pub fn domain(&self) -> &str {
        self.enclaves.domain.as_str()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetEnclaveDeploymentResponse {
    #[serde(flatten)]
    pub deployment: EnclaveDeployment,
    pub enclave_version: EnclaveVersion,
    pub enclave_signing_cert: EnclaveSigningCert,
    pub enclave_regional_deployments: Vec<EnclaveRegionalDeployment>,
}

impl GetEnclaveDeploymentResponse {
    pub fn is_built(&self) -> bool {
        matches!(self.enclave_version.build_status, BuildStatus::Ready)
    }

    pub fn is_finished(&self) -> bool {
        self.deployment.is_finished()
    }

    //TODO: Handle multi region deployment failures
    pub fn is_failed(&self) -> bool {
        let build_failed = matches!(self.enclave_version.build_status, BuildStatus::Failed);
        build_failed
            || self
                .enclave_regional_deployments
                .first()
                .map(|depl| depl.is_failed())
                .unwrap_or_default()
    }

    pub fn get_failure_reason(&self) -> Option<String> {
        self.enclave_version.failure_reason.clone().or_else(|| {
            self.enclave_regional_deployments
                .first()
                .map(|depl| depl.get_failure_reason())
        })
    }

    pub fn get_detailed_status(&self) -> Option<String> {
        self.enclave_regional_deployments
            .first()
            .map(|depl| depl.get_detailed_status())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSigningCertsResponse {
    pub certs: Vec<EnclaveSigningCert>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveLogs {
    log_events: Vec<LogEvent>,
    next_token: Option<String>,
    start_time: String,
    end_time: String,
}

impl EnclaveLogs {
    pub fn start_time(&self) -> &str {
        &self.start_time
    }

    pub fn end_time(&self) -> &str {
        &self.end_time
    }

    pub fn log_events(&self) -> &Vec<LogEvent> {
        &self.log_events
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    timestamp: i64,
    message: String,
    ingestion_time: i64,
    instance_id: String,
}

impl LogEvent {
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    pub fn instance_id(&self) -> &str {
        self.instance_id.as_str()
    }
}

pub type DeleteEnclaveResponse = Enclave;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnclaveScalingConfig {
    limits: ScalingLimits,
    config: ScalingConfig,
}

impl EnclaveScalingConfig {
    pub fn max_instances(&self) -> u32 {
        self.limits.max_instances
    }

    pub fn available_instances(&self) -> u32 {
        self.limits.available_instances
    }

    pub fn desired_replicas(&self) -> u32 {
        self.config.desired_replicas
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScalingLimits {
    max_instances: u32,
    available_instances: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScalingConfig {
    desired_replicas: u32,
}

impl std::convert::From<u32> for ScalingConfig {
    fn from(value: u32) -> Self {
        Self {
            desired_replicas: value,
        }
    }
}

pub type UpdateEnclaveScalingConfigRequest = ScalingConfig;

#[cfg(test)]
mod test {
    use super::*;

    fn get_testing_deployment() -> EnclaveDeployment {
        EnclaveDeployment {
            uuid: "abc".to_string(),
            enclave_uuid: "def".to_string(),
            version_uuid: "ghi".to_string(),
            signing_cert_uuid: "jkl".to_string(),
            debug_mode: false,
            started_at: None,
            completed_at: None,
        }
    }

    fn get_testing_version() -> EnclaveVersion {
        EnclaveVersion {
            uuid: "abc".to_string(),
            version: 1,
            control_plane_img_url: Some("control-plane.com".to_string()),
            control_plane_version: Some("1.0.0".to_string()),
            data_plane_version: Some("1.0.0".to_string()),
            build_status: BuildStatus::Ready,
            failure_reason: None,
            started_at: None,
            healthcheck: None,
        }
    }

    fn get_testing_cert() -> EnclaveSigningCert {
        EnclaveSigningCert {
            name: Some("abc".to_string()),
            uuid: "abc".to_string(),
            app_uuid: "def".to_string(),
            cert_hash: "ghi".to_string(),
            not_before: None,
            not_after: None,
        }
    }

    #[test]
    fn test_empty_regional_deployments() {
        let deployment = get_testing_deployment();
        let version = get_testing_version();
        let cert = get_testing_cert();
        let deployment_with_empty_regional = GetEnclaveDeploymentResponse {
            deployment,
            enclave_version: version,
            enclave_signing_cert: cert,
            enclave_regional_deployments: vec![],
        };

        assert!(deployment_with_empty_regional
            .get_detailed_status()
            .is_none());
        assert!(deployment_with_empty_regional
            .get_failure_reason()
            .is_none());
        assert_eq!(deployment_with_empty_regional.is_failed(), false);
    }

    #[test]
    fn test_populated_regional_deployments() {
        let deployment = get_testing_deployment();
        let version = get_testing_version();
        let cert = get_testing_cert();

        let failure_reason = "An error occurred provisioning your TEE".to_string();
        let detailed_failure_reason = "Insufficient capacity".to_string();
        let deployment_with_regional = GetEnclaveDeploymentResponse {
            deployment,
            enclave_version: version,
            enclave_signing_cert: cert,
            enclave_regional_deployments: vec![EnclaveRegionalDeployment {
                uuid: "abc".to_string(),
                deployment_uuid: "def".to_string(),
                deployment_order: 1,
                region: "us-east-1".to_string(),
                failure_reason: Some(failure_reason.clone()),
                deploy_status: DeployStatus::Failed,
                started_at: None,
                completed_at: None,
                detailed_status: Some(detailed_failure_reason.clone()),
            }],
        };

        assert_eq!(deployment_with_regional.is_failed(), true);
        assert_eq!(
            deployment_with_regional.get_failure_reason(),
            Some(failure_reason)
        );
        assert_eq!(
            deployment_with_regional.get_detailed_status(),
            Some(detailed_failure_reason)
        );
    }
}
