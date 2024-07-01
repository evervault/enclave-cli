pub mod assets;
pub mod client;
pub mod function;
pub mod papi;
pub use reqwest::Client;

pub type BasicAuth = (String, String);

#[derive(Clone)]
pub enum AuthMode {
    NoAuth,
    ApiKey(String),
    BearerAuth(String),
    BasicAuth(BasicAuth),
}
