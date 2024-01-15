use crate::common::CliError;

use super::parse::DecodeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("An error occurred while executing a docker command — {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to capture IO stream")]
    StdIoCaptureError,
    #[error("{0} not found. Please install {0} to use this feature.")]
    CommandNotFound(String),
    #[error("Error getting Git history — {0}")]
    GitError(#[from] git2::Error),
    #[error("Error parsing semver from buildx version string")]
    RegexError(#[from] regex::Error),
    #[error("Failed to parse semver versions")]
    SemverParseError,
}

impl CliError for CommandError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::IoError(io_err) => io_err.raw_os_error().unwrap_or(exitcode::IOERR),
            _ => exitcode::IOERR,
        }
    }
}

#[derive(Debug, Error)]
pub enum DockerError {
    #[error(transparent)]
    ParserDecodeError(#[from] DecodeError),
    #[error("Failed to access the docker daemon — {0:?}")]
    DaemonAccessError(#[from] std::io::Error),
    #[error("Docker daemon is not running")]
    DaemonNotRunning,
    #[error("Restricted port exposed. Cannot forward traffic to :{0}, address is already in use.")]
    RestrictedPortExposed(u16),
    #[error(transparent)]
    CommandError(#[from] CommandError),
}
