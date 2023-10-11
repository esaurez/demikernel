// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub struct Config {}

/// IVSHMEM associated functions for Demikernel configuration object.
impl Config {
    /// Gets the "IS_HOST" parameter from environment variables.
    pub fn is_host() -> bool {
      ::std::env::var("IS_HOST").is_ok()
    }

		pub fn shmem_path() -> String {
			::std::env::var("SHMEM_PATH").unwrap_or_else(|_| "/ivshmem".to_string())
		}
}