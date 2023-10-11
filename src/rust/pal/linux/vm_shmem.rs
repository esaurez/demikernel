// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// TODO: Remove allowances on this module.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::runtime::fail::Fail;
use crate::pal::linux::vm_shmem_lib::{
    base::{Region, IvshmemManager, RegionLocation},
    guest::CharDevice,
    host::SharedMemSegment,
    config::Config,
};

use ::core::ops::{
    Deref,
    DerefMut,
};
use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};


lazy_static! {
    static ref MEM_MANAGER: Arc<Mutex<Option<Box<dyn IvshmemManager>>>> = Arc::new(Mutex::new(Option::None));
}
//======================================================================================================================
// Structures
//======================================================================================================================

/// A named shared memory region.
pub struct SharedMemory {
	region: Region,
}

//======================================================================================================================
// Associated Functions
//======================================================================================================================

/// Associated functions.
impl SharedMemory {
    /// Prefix for shared memory region names.
    const SHM_NAME_PREFIX: &'static str = "demikernel-";

    fn initialize_static_mem_manager() {
        let mut mem_manager = MEM_MANAGER.lock().unwrap();
        if mem_manager.is_none() {
            if Config::is_host() {
                // The host runs directly on the shared memory segment, and handles it setup and management.
                mem_manager.replace(Box::new(SharedMemSegment::open(&Config::shmem_path(), true).unwrap()));
            } else {
                mem_manager.replace(Box::new(CharDevice::new()));
            }
        }
    }

    /// Opens an existing named shared memory region.
    pub fn open(name: &str, _len: usize) -> Result<SharedMemory, Fail> {
        Self::initialize_static_mem_manager();
        let mut mem_manager = MEM_MANAGER.lock().unwrap();
        let name: String = Self::build_name(name)?;
        let region_location: RegionLocation = 
            match mem_manager.as_mut().unwrap().get_region(&name) {
                Ok(region_location) => region_location,
                Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to get region: {:?}", e))),
            };
        let region: Region = match mem_manager.as_mut().unwrap().mmap_region(&region_location) {
            Ok(region) => region,
            Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to mmap region: {:?}", e))),
        };
        Ok(Self { region })
    }

    /// Creates a named shared memory region.
    pub fn create(name: &str, size: usize) -> Result<SharedMemory, Fail> {
        Self::initialize_static_mem_manager();
        let mut mem_manager = MEM_MANAGER.lock().unwrap();
        let name: String = Self::build_name(name)?;
        let region_location: RegionLocation = 
            match mem_manager.as_mut().unwrap().create_region(&name, size as u64) {
                Ok(region_location) => region_location,
                Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to get region: {:?}", e))),
            };
        let region: Region = match mem_manager.as_mut().unwrap().mmap_region(&region_location) {
            Ok(region) => region,
            Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to mmap region: {:?}", e))),
        };
        Ok(Self { region })
    }

    fn build_name(name: &str) -> Result<String, Fail> {
        // Check if provided name is valid.
        if name.is_empty() {
            return Err(Fail::new(libc::EINVAL, "name of shared memory region cannot be empty"));
        }
        let prefix: String = String::from(Self::SHM_NAME_PREFIX);
        Ok((prefix + name).to_string())
    }



}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

/// Dereference trait implementation.
impl Deref for SharedMemory {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.region[..self.region.size]
    }
}

/// Mutable dereference trait implementation.
impl DerefMut for SharedMemory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let size: usize = self.region.size;
        &mut self.region[..size]
    }
}