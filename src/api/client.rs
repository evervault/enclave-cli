use super::AuthMode;
use crate::common::CliError;
use async_trait::async_trait;
use reqwest::{Client, RequestBuilder, Response};
use reqwest::{Error, Result};
use serde::de::DeserializeOwned;
use std::fmt::Formatter;
use std::time::Duration;
use thiserror::Error;

#[derive(Clone)]
pub struct GenericApiClient {
    client: Client,
}

impl Default for GenericApiClient {
    fn default() -> Self {
        let client = Client::builder().timeout(Duration::from_secs(60)).build();
        Self {
            client: client.unwrap(),
        }
    }
}

impl ApiClient for GenericApiClient {
    fn client(&self) -> &Client {
        &self.client
    }
}

pub trait ApiClient {
    fn client(&self) -> &Client;

    fn base_url(&self) -> String {
        std::env::var("EV_API_URL").unwrap_or(String::from("https://api.evervault.com"))
    }

    fn user_agent(&self) -> String {
        format!("evervault-cage-cli/{}", env!("CARGO_PKG_VERSION"))
    }

    fn get(&self, url: &String) -> RequestBuilder {
        self.prepare(self.client().get(url))
    }

    fn post(&self, url: &String) -> RequestBuilder {
        self.prepare(self.client().post(url))
    }

    fn put(&self, url: &String) -> RequestBuilder {
        self.prepare(self.client().put(url))
    }

    fn delete(&self, url: &String) -> RequestBuilder {
        self.prepare(self.client().delete(url))
    }

    fn prepare(&self, request_builder: RequestBuilder) -> RequestBuilder {
        request_builder.header("user-agent", self.user_agent())
    }
}

pub trait AuthenticatedClient: ApiClient {
    fn new(auth_mode: AuthMode) -> Self;
    fn auth(&self) -> &AuthMode;
    fn prepare(&self, request_builder: RequestBuilder) -> RequestBuilder {
        let request_builder = <Self as ApiClient>::prepare(self, request_builder);
        match self.auth() {
            AuthMode::ApiKey(api_key) => request_builder.header("api-key", api_key),
            AuthMode::BearerAuth(token) => request_builder.bearer_auth(token),
            AuthMode::NoAuth => request_builder,
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
impl HandleResponse for Result<Response> {
    async fn handle_json_response<T: DeserializeOwned>(self) -> ApiResult<T> {
        match self {
            Ok(res) if res.status().is_success() => res
                .json()
                .await
                .map_err(|e| ApiError::ParsingError(e.to_string())),
            Ok(res) => Err(ApiError::get_error_from_status(res.status().as_u16())),
            Err(e) => Err(ApiError::Unknown(Some(e))),
        }
    }

    async fn handle_text_response(self) -> ApiResult<String> {
        match self {
            Ok(res) if res.status().is_success() => res
                .text()
                .await
                .map_err(|e| ApiError::ParsingError(e.to_string())),
            Ok(res) => Err(ApiError::get_error_from_status(res.status().as_u16())),
            Err(e) => Err(ApiError::Unknown(Some(e))),
        }
    }

    fn handle_no_op_response(self) -> ApiResult<()> {
        match self {
            Ok(res) if res.status().is_success() => Ok(()),
            Ok(res) => Err(ApiError::get_error_from_status(res.status().as_u16())),
            Err(e) => Err(ApiError::Unknown(Some(e))),
        }
    }
}

#[derive(Error, Debug)]
pub enum ApiError {
    BadRequest,
    NotFound,
    Unauthorized,
    Internal,
    Forbidden,
    Conflict,
    Unknown(Option<Error>),
    ParsingError(String),
}

impl CliError for ApiError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::BadRequest | Self::NotFound => exitcode::DATAERR,
            Self::Unauthorized => exitcode::NOUSER,
            Self::Internal | Self::ParsingError(_) => exitcode::SOFTWARE,
            Self::Forbidden => exitcode::NOPERM,
            Self::Conflict => exitcode::DATAERR,
            Self::Unknown(_) => exitcode::UNAVAILABLE,
        }
    }
}

pub type ApiResult<T> = core::result::Result<T, ApiError>;

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_msg())
    }
}

impl ApiError {
    pub fn get_error_from_status(code: u16) -> Self {
        match code {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            500 => Self::Internal,
            _ => Self::Unknown(None),
        }
    }

    pub fn to_msg(&self) -> String {
        match self {
            Self::BadRequest => "400: Bad Request".to_owned(),
            Self::Unauthorized => "401: Unauthorized".to_owned(),
            Self::Forbidden => "403: Forbidden".to_owned(),
            Self::NotFound => "404: Not Found".to_owned(),
            Self::Conflict => "409: Conflict".to_owned(),
            Self::Internal => "500: Internal Server Error".to_owned(),
            Self::Unknown(e) => format!("An unexpected error occured: {:?}", e),
            Self::ParsingError(_) => {
                "An error occurred while parsing the server's response.to_owned()".to_owned()
            }
        }
    }
}
