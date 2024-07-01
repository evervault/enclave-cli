use crate::api::enclave_assets::EnclaveAssetsClient;
use common::api::client::ApiError;
use common::CliError;
use regex::Regex;
use std::fs;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VersionError {
    #[error("An error occurred getting CLI versions — {0}")]
    ApiError(#[from] ApiError),
    #[error("Couldn't parse the semver version - {0}")]
    SemVerError(#[from] semver::Error),
    #[error("Couldn't parse env string as int - {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("This version is deprecated, please run ev-enclave update to continue")]
    DeprecatedVersion,
    #[error("Couldn't check version against latest")]
    FailedVersionCheck,
    #[error("IO error - {0}")]
    IoError(#[from] std::io::Error),
    #[error("Regex error - {0}")]
    RegexError(#[from] regex::Error),
    #[error("Couldn't find the runtime and installer version in the Dockerfile")]
    MissingVersion,
}

impl CliError for VersionError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::IoError(_) => exitcode::IOERR,
            _ => exitcode::SOFTWARE,
        }
    }
}

pub struct EnclaveRuntime {
    pub data_plane_version: String,
    pub installer_version: String,
}

impl EnclaveRuntime {
    pub async fn new() -> Result<EnclaveRuntime, VersionError> {
        let client = EnclaveAssetsClient::new();
        let versions = client.get_runtime_versions().await?;

        Ok(Self {
            data_plane_version: versions.latest,
            installer_version: versions.installer,
        })
    }

    pub async fn maybe_from_existing_dockerfile(
        dockerfile: Option<String>,
    ) -> Result<EnclaveRuntime, VersionError> {
        match dockerfile {
            None => Self::new().await,
            Some(dockerfile) => {
                let (data_plane_version, installer_version) =
                    parse_version_from_existing_dockerfile(dockerfile)?;

                Ok(Self {
                    data_plane_version,
                    installer_version,
                })
            }
        }
    }
}

pub fn parse_version_from_existing_dockerfile(
    from_existing: String,
) -> Result<(String, String), VersionError> {
    let content = fs::read_to_string(from_existing)?;
    get_versions_from_dockerfile(content)
}

fn get_versions_from_dockerfile(content: String) -> Result<(String, String), VersionError> {
    let installer_regex = Regex::new(r"installer\/([a-f0-9]+)\.tar\.gz")?;
    let runtime_regex = Regex::new(r"runtime\/(.*?)\/data-plane")?;
    let installer_version = installer_regex
        .captures(&content)
        .and_then(|mtch| mtch.get(1).map(|m| m.as_str()))
        .ok_or(VersionError::MissingVersion)?;
    let runtime_version = runtime_regex
        .captures(&content)
        .and_then(|mtch| mtch.get(1).map(|m| m.as_str()))
        .ok_or(VersionError::MissingVersion)?;

    Ok((runtime_version.to_string(), installer_version.to_string()))
}

#[cfg(test)]
mod versions_tests {
    use super::*;

    #[test]
    fn parse_version_from_existing_dockerfile() {
        let test_dockerfile = r##"FROM node:18-alpine AS builder
        # Do stuff
        FROM alpine AS lastlayer
        RUN touch /hello-script;\
        /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"
        USER root
        RUN mkdir -p /opt/evervault
        ADD https://enclave-build-assets.evervault.com/installer/abcdef.tar.gz /opt/evervault/runtime-dependencies.tar.gz
        RUN cd /opt/evervault ; tar -xzf runtime-dependencies.tar.gz ; sh ./installer.sh ; rm runtime-dependencies.tar.gz
        RUN echo {\"api_key_auth\":true,\"forward_proxy_protocol\":false,\"trusted_headers\":[\"X-Evervault-*\"],\"trx_logging_enabled\":true} > /etc/dataplane-config.json
        RUN mkdir -p /etc/service/user-entrypoint
        RUN printf "#!/bin/sh\nsleep 5\necho \"Checking status of data-plane\"\nSVDIR=/etc/service sv check data-plane || exit 1\necho \"Data-plane up and running\"\nwhile ! grep -q \"EV_INITIALIZED\" /etc/customer-env\n do echo \"Env not ready, sleeping user process for one second\"\n sleep 1\n done \n . /etc/customer-env\n\necho \"Booting user service...\"\ncd %s\nexec sh /hello-script\n" "$PWD"  > /etc/service/user-entrypoint/run && chmod +x /etc/service/user-entrypoint/run
        ADD https://enclave-build-assets.evervault.com/runtime/1.2.3/data-plane/egress-disabled/tls-termination-enabled /opt/evervault/data-plane
        RUN chmod +x /opt/evervault/data-plane
        RUN mkdir -p /etc/service/data-plane
        RUN printf "#!/bin/sh\necho \"Booting Evervault data plane...\"\nexec /opt/evervault/data-plane\n" > /etc/service/data-plane/run && chmod +x /etc/service/data-plane/run
        RUN printf "#!/bin/sh\nifconfig lo 127.0.0.1\n echo \"enclave.local\" > /etc/hostname \n echo \"127.0.0.1 enclave.local\" >> /etc/hosts \n hostname -F /etc/hostname \necho \"Booting enclave...\"\nexec runsvdir /etc/service\n" > /bootstrap && chmod +x /bootstrap
        RUN find $( ls / | grep -E -v "^(dev|mnt|proc|sys)$" ) -xdev | xargs touch --date="@0" --no-dereference || true
        FROM scratch
        COPY --from=lastlayer / /
        ENTRYPOINT ["/bootstrap", "1>&2"]
        "##.to_string();

        let result = get_versions_from_dockerfile(test_dockerfile).unwrap();
        assert_eq!(result, ("1.2.3".to_string(), "abcdef".to_string()));
    }

    #[test]
    fn parse_version_from_existing_dockerfile_staging() {
        let test_dockerfile = r##"FROM node:18-alpine AS builder
        # Do stuff
        FROM alpine AS lastlayer
        RUN touch /hello-script;\
        /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"
        USER root
        RUN mkdir -p /opt/evervault
        ADD https://enclave-build-assets.evervault.com/installer/abcdef.tar.gz /opt/evervault/runtime-dependencies.tar.gz
        RUN cd /opt/evervault ; tar -xzf runtime-dependencies.tar.gz ; sh ./installer.sh ; rm runtime-dependencies.tar.gz
        RUN echo {\"api_key_auth\":true,\"forward_proxy_protocol\":false,\"trusted_headers\":[\"X-Evervault-*\"],\"trx_logging_enabled\":true} > /etc/dataplane-config.json
        RUN mkdir -p /etc/service/user-entrypoint
        RUN printf "#!/bin/sh\nsleep 5\necho \"Checking status of data-plane\"\nSVDIR=/etc/service sv check data-plane || exit 1\necho \"Data-plane up and running\"\nwhile ! grep -q \"EV_INITIALIZED\" /etc/customer-env\n do echo \"Env not ready, sleeping user process for one second\"\n sleep 1\n done \n . /etc/customer-env\n\necho \"Booting user service...\"\ncd %s\nexec sh /hello-script\n" "$PWD"  > /etc/service/user-entrypoint/run && chmod +x /etc/service/user-entrypoint/run
        ADD https://enclave-build-assets.evervault.io/runtime/1.0.0-beta-daac60/data-plane/egress-disabled/tls-termination-enabled /opt/evervault/data-plane
        RUN chmod +x /opt/evervault/data-plane
        RUN mkdir -p /etc/service/data-plane
        RUN printf "#!/bin/sh\necho \"Booting Evervault data plane...\"\nexec /opt/evervault/data-plane\n" > /etc/service/data-plane/run && chmod +x /etc/service/data-plane/run
        RUN printf "#!/bin/sh\nifconfig lo 127.0.0.1\n echo \"enclave.local\" > /etc/hostname \n echo \"127.0.0.1 enclave.local\" >> /etc/hosts \n hostname -F /etc/hostname \necho \"Booting enclave...\"\nexec runsvdir /etc/service\n" > /bootstrap && chmod +x /bootstrap
        RUN find $( ls / | grep -E -v "^(dev|mnt|proc|sys)$" ) -xdev | xargs touch --date="@0" --no-dereference || true
        FROM scratch
        COPY --from=lastlayer / /
        ENTRYPOINT ["/bootstrap", "1>&2"]
        "##.to_string();

        let result = get_versions_from_dockerfile(test_dockerfile).unwrap();
        assert_eq!(
            result,
            ("1.0.0-beta-daac60".to_string(), "abcdef".to_string())
        );
    }

    #[test]
    fn parse_version_from_existing_dockerfile_error() {
        let test_dockerfile = r#"ENV Hello World Spaces"#.to_string();
        let result = get_versions_from_dockerfile(test_dockerfile);
        assert!(result.is_err())
    }
}
