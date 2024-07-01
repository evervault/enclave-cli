use common::api::{
    client::{
        ApiClient, ApiClientError, ApiError, ApiErrorKind, ApiResult, GenericApiClient,
        HandleResponse,
    },
    AuthMode,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct RuntimeVersion {
    pub latest: String,
    pub versions: HashMap<String, RuntimeMajorVersion>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RuntimeMajorVersion {
    pub latest: String,
    pub installer: String,
}

pub struct EnclaveAssetsClient {
    inner: GenericApiClient,
}

impl ApiClient for EnclaveAssetsClient {
    fn client(&self) -> &reqwest::Client {
        self.inner.client()
    }

    fn base_url(&self) -> String {
        let domain = std::env::var("EV_DOMAIN").unwrap_or_else(|_| String::from("evervault.com"));
        format!("https://enclave-build-assets.{}", domain)
    }

    fn auth(&self) -> &AuthMode {
        self.inner.auth()
    }

    fn update_auth(&mut self, _: AuthMode) -> Result<(), ApiClientError> {
        Err(ApiClientError::AuthModeNotSupported)
    }

    fn accept(&self) -> String {
        format!(
            "application/json;version={}",
            env!("CARGO_PKG_VERSION_MAJOR")
        )
    }
}

impl Default for EnclaveAssetsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl EnclaveAssetsClient {
    pub fn new() -> Self {
        let generic_client = GenericApiClient::default();
        Self {
            inner: generic_client,
        }
    }

    pub async fn get_data_plane_version(&self) -> ApiResult<String> {
        self.get_runtime_versions()
            .await
            .map(|version| version.latest)
    }

    pub async fn get_runtime_installer_version(&self) -> ApiResult<String> {
        self.get_runtime_versions()
            .await
            .map(|version| version.installer)
    }

    pub async fn get_runtime_versions(&self) -> ApiResult<RuntimeMajorVersion> {
        let enclave_version = env!("CARGO_PKG_VERSION_MAJOR");
        let data_plane_version = format!("{}/runtime/versions", self.base_url());
        let result = self
            .get(&data_plane_version)
            .send()
            .await
            .handle_json_response::<RuntimeVersion>()
            .await?;
        match result.versions.get(enclave_version) {
            Some(versions) => Ok(versions.clone()),
            None => Err(ApiError::new(ApiErrorKind::NotFound)),
        }
    }
}
