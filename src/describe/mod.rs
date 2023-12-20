pub mod error;

use crate::common::resolve_output_path;
use crate::docker::{error::DockerError, utils::verify_docker_is_running};
use crate::enclave;
use crate::progress::get_tracker;
use error::DescribeError;

pub fn describe_eif(eif_path: &str, verbose: bool, no_cache: bool) -> Result<enclave::DescribeEif, DescribeError> {
    let eif_path = std::path::Path::new(eif_path);
    if !eif_path.exists() {
        return Err(DescribeError::EIFNotFound(eif_path.to_path_buf()));
    }
    let absolute_path = eif_path
        .canonicalize()
        .map_err(|_| DescribeError::EIFNotFound(eif_path.to_path_buf()))?;
    if !verify_docker_is_running()? {
        return Err(DockerError::DaemonNotRunning.into());
    }

    let describe_progress = get_tracker("Getting PCRs from existing EIF", None);

    let supplied_path: Option<&str> = None;
    let output_path = resolve_output_path(supplied_path).unwrap();
    enclave::build_nitro_cli_image(output_path.path(), None, verbose, no_cache)?;

    let description = enclave::describe_eif(&absolute_path, verbose)?;
    describe_progress.finish_with_message("PCRs retrieved.");

    Ok(description)
}
