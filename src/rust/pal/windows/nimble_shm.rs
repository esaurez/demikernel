// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// TODO: Remove allowances on this module.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    pal::windows::virtio_shmem_lib::base::{
        RegionLocation,
        RegionManager,
        RegionTrait,
    },
    runtime::fail::Fail,
};
use ::core::ops::{
    Deref,
    DerefMut,
};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        Mutex,
    },
};

//======================================================================================================================
// Structures
//======================================================================================================================

type RegionBox = Box<dyn RegionTrait<Target = [u8]>>;

lazy_static! {
    static ref MEM_MANAGERS: Arc<Mutex<HashMap<String, Arc<Mutex<Box<dyn RegionManager>>>>>> = Arc::new(Mutex::new(HashMap::new()));
}

/// A named shared memory region.
pub struct SharedMemory {
    region: RegionBox,
}

//======================================================================================================================
// Associated Functions
//======================================================================================================================

/// Associated functions.
impl SharedMemory {
    const SHM_NAME_PREFIX: &'static str = "demikernel-";

    pub fn add_manager(id: &str, manager: Arc<Mutex<Box<dyn RegionManager>>>) {
        let mut mem_manager = MEM_MANAGERS.lock().unwrap();
        mem_manager.insert(id.to_string(), manager);
    }

    /// Opens an existing named shared memory region.
    pub fn open(name: &str, _len: usize) -> Result<SharedMemory, Fail> {
        let mut mem_lock = MEM_MANAGERS.lock().map_err(|e| Fail {
            errno: 0,
            cause: e.to_string(),
        })?;
        let (id, segment_name) = Self::parse_name(name)?;

        let region_man_lock = match mem_lock.get_mut(&id) {
            Some(region) => region,
            None => {
                return Err(Fail::new(
                    libc::EINVAL,
                    &format!("failed to get region manager: {:?}", id),
                ))
            },
        };

        let mut region_man = region_man_lock.lock().map_err(|e|Fail {
            errno: 0,
            cause: e.to_string(),
        })?;

        let region_location: RegionLocation = match region_man.get_region(&segment_name) {
            Ok(region_location) => region_location,
            Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to get region: {:?}", e))),
        };
        let region: RegionBox = match region_man.mmap_region(&region_location) {
            Ok(region) => region,
            Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to mmap region: {:?}", e))),
        };
        Ok(Self { region })
    }

    /// Creates a named shared memory region.
    pub fn create(name: &str, size: usize) -> Result<SharedMemory, Fail> {
        let mut mem_lock = MEM_MANAGERS.lock().map_err(|e| Fail {
            errno: 0,
            cause: e.to_string(),
        })?;
        let (id, segment_name) = Self::parse_name(name)?;

        let region_man_lock = match mem_lock.get_mut(&id) {
            Some(region) => region,
            None => {
                return Err(Fail::new(
                    libc::EINVAL,
                    &format!("failed to get region manager: {:?}", id),
                ))
            },
        };

        let mut region_man = region_man_lock.lock().map_err(|e|Fail {
            errno: 0,
            cause: e.to_string(),
        })?;

        let region_location: RegionLocation = match region_man.create_region(&segment_name, size as u64) {
            Ok(region_location) => region_location,
            Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to get region: {:?}", e))),
        };
        let region: RegionBox = match region_man.mmap_region(&region_location) {
            Ok(region) => region,
            Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to mmap region: {:?}", e))),
        };
        Ok(Self { region })
    }

    fn parse_name(name: &str) -> Result<(String, String), Fail> {
        // The name send by the user would be in the format <id>-<ip:port>:<rx|tx>. The id may have '-' in it.
        // So we need to split the name into two parts. The first part is the id and the second part is the ip:port:<rx|tx>.
        // The first part could have multiple - in it, so we find the last - in the name and split the name into two parts.
        let mut parts = name.rsplitn(2, '-');
        // The first part is the id.
        let ip_port_rx_tx = parts.next().unwrap_or("");
        if ip_port_rx_tx.is_empty() {
            return Err(Fail::new(libc::EINVAL, "name of shared memory region cannot be empty"));
        }
        // The second part is the ip:port:<rx|tx>.
        let id = parts.next().unwrap_or("");
        if id.is_empty() {
            return Err(Fail::new(libc::EINVAL, "name of shared memory region cannot be empty"));
        }
        let prefix: String = String::from(Self::SHM_NAME_PREFIX);
        Ok((id.to_owned(), format!("{}{}", prefix, ip_port_rx_tx)))
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

/// Dereference trait implementation.
impl Deref for SharedMemory {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.region
    }
}

/// Mutable dereference trait implementation.
impl DerefMut for SharedMemory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.region
    }
}
