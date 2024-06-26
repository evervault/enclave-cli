use super::AuthMode;
use async_trait::async_trait;
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use reqwest::{Error, Result as ReqwestResult};
use serde::de::DeserializeOwned;
use std::fmt::{Display, Formatter};
use std::time::Duration;
use thiserror::Error;

#[derive(Clone)]
pub struct GenericApiClient {
    client: Client,
    auth: AuthMode,
}

impl Default for GenericApiClient {
    fn default() -> Self {
        let client = Client::builder().timeout(Duration::from_secs(60)).build();
        Self {
            client: client.unwrap(),
            auth: AuthMode::NoAuth,
        }
    }
}

impl std::convert::From<AuthMode> for GenericApiClient {
    fn from(auth_mode: AuthMode) -> Self {
        let client = Client::builder().timeout(Duration::from_secs(60)).build();
        GenericApiClient {
            client: client.unwrap(),
            auth: auth_mode,
        }
    }
}

impl ApiClient for GenericApiClient {
    fn auth(&self) -> &AuthMode {
        &self.auth
    }

    fn update_auth(&mut self, auth: AuthMode) -> Result<(), ApiClientError> {
        self.auth = auth;
        Ok(())
    }

    fn client(&self) -> &Client {
        &self.client
    }
}

pub enum ApiClientError {
    AuthModeNotSupported,
}

pub trait ApiClient {
    fn auth(&self) -> &AuthMode;
    fn update_auth(&mut self, auth: AuthMode) -> Result<(), ApiClientError>;
    fn client(&self) -> &Client;

    fn base_url(&self) -> String {
        let domain = std::env::var("EV_DOMAIN").unwrap_or_else(|_| String::from("evervault.com"));
        format!("https://api.{}", domain)
    }

    fn keys_url(&self) -> String {
        if self.base_url().contains("evervault.com") {
            "https://keys.evervault.com".to_string()
        } else {
            "https://keys.evervault.io".to_string()
        }
    }

    fn user_agent(&self) -> String {
        format!("evervault-cli/{}", env!("CARGO_PKG_VERSION"))
    }

    fn accept(&self) -> String {
        "application/json".to_string()
    }

    fn is_authorised(&self) -> bool {
        !matches!(self.auth(), AuthMode::NoAuth)
    }

    fn get(&self, url: &str) -> RequestBuilder {
        self.prepare(self.client().get(url))
    }

    fn post(&self, url: &str) -> RequestBuilder {
        self.prepare(self.client().post(url))
    }

    fn put(&self, url: &str) -> RequestBuilder {
        self.prepare(self.client().put(url))
    }

    fn delete(&self, url: &str) -> RequestBuilder {
        self.prepare(self.client().delete(url))
    }

    fn patch(&self, url: &str) -> RequestBuilder {
        self.prepare(self.client().patch(url))
    }

    fn prepare(&self, mut request_builder: RequestBuilder) -> RequestBuilder {
        request_builder = request_builder
            .header(reqwest::header::USER_AGENT, self.user_agent())
            .header(reqwest::header::ACCEPT, self.accept());

        match &self.auth() {
            AuthMode::NoAuth => request_builder,
            AuthMode::ApiKey(api_key) => request_builder.header("api-key", api_key),
            AuthMode::BearerAuth(token) => request_builder.bearer_auth(token),
            AuthMode::BasicAuth((app_uuid, api_key)) => {
                request_builder.basic_auth(app_uuid, Some(api_key))
            }
        }
    }
}

#[async_trait]
pub trait HandleResponse {
    async fn handle_json_response<T: DeserializeOwned>(self) -> ApiResult<T>;
    async fn handle_text_response(self) -> ApiResult<String>;
    fn handle_no_op_response(self) -> ApiResult<()>;
}

#[async_trait]
impl HandleResponse for ReqwestResult<Response> {
    async fn handle_json_response<T: DeserializeOwned>(self) -> ApiResult<T> {
        match self {
            Ok(res) if res.status().is_success() => res
                .json()
                .await
                .map_err(|e| ApiError::new(ApiErrorKind::ParsingError(e.to_string()))),
            Ok(res) => Err(ApiError::get_error_detais_from_res(res).await),
            Err(e) => Err(e.into()),
        }
    }

    async fn handle_text_response(self) -> ApiResult<String> {
        match self {
            Ok(res) if res.status().is_success() => res
                .text()
                .await
                .map_err(|e| ApiError::new(ApiErrorKind::ParsingError(e.to_string()))),
            Ok(res) => Err(res.status().into()),
            Err(e) => Err(e.into()),
        }
    }

    fn handle_no_op_response(self) -> ApiResult<()> {
        match self {
            Ok(res) if res.status().is_success() => Ok(()),
            Ok(res) => Err(res.status().into()),
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(Error, Debug)]
pub enum ApiErrorKind {
    BadRequest,
    NotFound,
    Unauthorized,
    Internal,
    Forbidden,
    Conflict,
    Unknown(Option<Error>),
    ParsingError(String),
}

pub struct ApiError {
    pub kind: ApiErrorKind,
    pub details: Option<ApiErrorDetails>,
}

pub type ApiResult<T> = core::result::Result<T, ApiError>;

impl std::fmt::Display for ApiErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_msg())
    }
}

impl crate::CliError for ApiError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self.kind {
            ApiErrorKind::BadRequest | ApiErrorKind::NotFound => exitcode::DATAERR,
            ApiErrorKind::Unauthorized => exitcode::NOUSER,
            ApiErrorKind::Internal | ApiErrorKind::ParsingError(_) => exitcode::SOFTWARE,
            ApiErrorKind::Forbidden => exitcode::NOPERM,
            ApiErrorKind::Conflict => exitcode::DATAERR,
            ApiErrorKind::Unknown(_) => exitcode::UNAVAILABLE,
        }
    }
}

impl ApiErrorKind {
    pub fn to_msg(&self) -> String {
        match self {
            Self::BadRequest => "400: Bad Request".to_owned(),
            Self::Unauthorized => "401: Unauthorized".to_owned(),
            Self::Forbidden => "403: Forbidden".to_owned(),
            Self::NotFound => "404: Not Found".to_owned(),
            Self::Conflict => "409: Conflict".to_owned(),
            Self::Internal => "500: Internal Server Error".to_owned(),
            Self::Unknown(e) => format!("An unexpected error occured: {:?}", e),
            Self::ParsingError(e) => {
                format!("An error occurred while parsing the server's response: {e:?}")
            }
        }
    }
}

impl From<ApiErrorKind> for exitcode::ExitCode {
    fn from(value: ApiErrorKind) -> Self {
        match value {
            ApiErrorKind::BadRequest | ApiErrorKind::NotFound => exitcode::DATAERR,
            ApiErrorKind::Unauthorized => exitcode::NOUSER,
            ApiErrorKind::Internal | ApiErrorKind::ParsingError(_) => exitcode::SOFTWARE,
            ApiErrorKind::Forbidden => exitcode::NOPERM,
            ApiErrorKind::Conflict => exitcode::DATAERR,
            ApiErrorKind::Unknown(_) => exitcode::UNAVAILABLE,
        }
    }
}

impl From<StatusCode> for ApiError {
    fn from(status: StatusCode) -> Self {
        Self::new(Self::get_error_from_status(status.into()))
    }
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self::new(ApiErrorKind::Unknown(Some(e)))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.details {
            Some(details) => {
                write!(f, "{}", details.title)
            }
            None => self.kind.fmt(f),
        }
    }
}

impl std::fmt::Debug for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self::Display::fmt(&self, f)
    }
}

impl std::error::Error for ApiError {}

#[derive(serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct ApiErrorDetails {
    pub status: Option<u16>,
    pub title: String,
    pub detail: String,
    pub code: Option<String>,
}

impl ApiError {
    pub fn new(kind: ApiErrorKind) -> Self {
        Self {
            kind,
            details: None,
        }
    }

    pub fn get_error_from_status(code: u16) -> ApiErrorKind {
        match code {
            400 => ApiErrorKind::BadRequest,
            401 => ApiErrorKind::Unauthorized,
            403 => ApiErrorKind::Forbidden,
            404 => ApiErrorKind::NotFound,
            409 => ApiErrorKind::Conflict,
            500 => ApiErrorKind::Internal,
            _ => ApiErrorKind::Unknown(None),
        }
    }

    pub async fn get_error_detais_from_res(res: Response) -> ApiError {
        let mut api_error: ApiError = res.status().into();
        api_error.details = res.json::<ApiErrorDetails>().await.ok();

        api_error
    }
}
