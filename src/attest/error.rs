use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestCommandError {
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
    #[error("The received certificate had no Subject Alt Name extension")]
    NoSubjectAltNames,
    #[error("Unable to parse  doc bytes from Subject Alt Name extension")]
    ParseError,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    Attestation(#[from] attestation_doc_validation::AttestationError),
    #[error(transparent)]
    InvalidHostname(#[from] tokio_rustls::rustls::client::InvalidDnsNameError),
    #[error(transparent)]
    DNSLookupFailure(#[from] tokio::time::error::Elapsed),
    #[error(transparent)]
    X509CertError(#[from] x509_parser::error::X509Error),
}
