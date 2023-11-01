// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::str::FromStr;

pub struct Config {}

pub struct ByteSized(pub u64);

#[derive(Debug)]
pub enum ByteSizedParseError {
    InvalidValue(String),
}

impl FromStr for ByteSized {
    type Err = ByteSizedParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(ByteSized({
            let s = s.trim();
            let shift = if s.ends_with('K') {
                10
            } else if s.ends_with('M') {
                20
            } else if s.ends_with('G') {
                30
            } else {
                0
            };

            let s = s.trim_end_matches(|c| c == 'K' || c == 'M' || c == 'G');
            s.parse::<u64>()
                .map_err(|_| ByteSizedParseError::InvalidValue(s.to_owned()))?
                << shift
        }))
    }
}

/// IVSHMEM associated functions for Demikernel configuration object.
impl Config {
    /// Gets the "IS_HOST" parameter from environment variables.
    pub fn is_host() -> bool {
        ::std::env::var("IS_HOST").is_ok()
    }

    // Gets the shmem size from environment variables.
    pub fn shmem_size() -> u64 {
        ::std::env::var("SHMEM_SIZE")
            .unwrap_or_else(|_| "512M".to_string())
            .parse::<ByteSized>()
            .unwrap()
            .0
    }

    // Get the socket address
    pub fn shmem_socket() -> String {
        ::std::env::var("SHMEM_SOCKET").unwrap_or_else(|_| "/tmp/nimble-sock".to_string())
    }
}
