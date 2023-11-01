// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// TODO: Remove allowances on this module.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    pal::linux::virtio_shmem_lib::{
        base::{
            RegionLocation,
            RegionManager,
            RegionTrait,
        },
        config::Config,
        guest::CharDevice,
        host::VirtioNimbleRunner,
    },
    runtime::fail::Fail,
};

use ::core::ops::{
    Deref,
    DerefMut,
};
use lazy_static::lazy_static;
use std::sync::{
    Arc,
    Mutex,
    RwLock,
};

use crate::pal::linux::virtio_shmem_lib::host::{
    ShmemManager,
    VhostUserNimbleNetBackend,
};

lazy_static! {
    static ref MEM_MANAGER: Arc<Mutex<Option<Arc<Mutex<dyn RegionManager>>>>> = Arc::new(Mutex::new(Option::None));
    static ref VIRTIO_RUNNER: Arc<Mutex<Option<VirtioNimbleRunner>>> = Arc::new(Mutex::new(Option::None));
}
//======================================================================================================================
// Structures
//======================================================================================================================

type RegionBox = Box<dyn RegionTrait<Target = [u8]>>;

/// A named shared memory region.
pub struct SharedMemory {
    region: RegionBox,
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
                let runner: VirtioNimbleRunner =
                    VirtioNimbleRunner::new(Config::shmem_size(), 1, 2, Config::shmem_socket(), false).unwrap();
                let host_manager: Arc<RwLock<VhostUserNimbleNetBackend>> = runner.get_host_mem_manager();
                let shm_manager: Arc<Mutex<ShmemManager>> = host_manager.read().unwrap().get_shmem_manager();
                // \TODO there are many locks hold up to this point, check that this will not dead-lock
                // Get condition wait
                let cond_wait = shm_manager.lock().unwrap().get_init_wait();
                ShmemManager::wait(cond_wait).unwrap();
                // Finally replace the mem_manager with the shm_manager, once it is initialized
                mem_manager.replace(shm_manager);
                VIRTIO_RUNNER.lock().unwrap().replace(runner);
            } else {
                mem_manager.replace(Arc::new(Mutex::new(CharDevice::new())));
            }
        }
    }

    /// Opens an existing named shared memory region.
    pub fn open(name: &str, _len: usize) -> Result<SharedMemory, Fail> {
        Self::initialize_static_mem_manager();
        let mut mem_lock = MEM_MANAGER.lock().map_err(|e| Fail {
            errno: 0,
            cause: e.to_string(),
        })?;
        let mut mem_manager = mem_lock.as_mut().unwrap().lock().unwrap();
        let name: String = Self::build_name(name)?;
        let region_location: RegionLocation = match mem_manager.get_region(&name) {
            Ok(region_location) => region_location,
            Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to get region: {:?}", e))),
        };
        let region: RegionBox = match mem_manager.mmap_region(&region_location) {
            Ok(region) => region,
            Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to mmap region: {:?}", e))),
        };
        Ok(Self { region })
    }

    /// Creates a named shared memory region.
    pub fn create(name: &str, size: usize) -> Result<SharedMemory, Fail> {
        Self::initialize_static_mem_manager();
        let mut mem_lock = MEM_MANAGER.lock().map_err(|e| Fail {
            errno: 0,
            cause: e.to_string(),
        })?;
        let mut mem_manager = mem_lock.as_mut().unwrap().lock().unwrap();
        let name: String = Self::build_name(name)?;
        let region_location: RegionLocation = match mem_manager.create_region(&name, size as u64) {
            Ok(region_location) => region_location,
            Err(e) => return Err(Fail::new(libc::EINVAL, &format!("failed to get region: {:?}", e))),
        };
        let region: RegionBox = match mem_manager.mmap_region(&region_location) {
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
        &self.region
    }
}

/// Mutable dereference trait implementation.
impl DerefMut for SharedMemory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.region
    }
}
