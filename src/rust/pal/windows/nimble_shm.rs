// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// TODO: Remove allowances on this module.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::runtime::fail::Fail;
use ::core::{
    ops::{
        Deref,
        DerefMut,
    },
};
use ::std::ffi;

//======================================================================================================================
// Structures
//======================================================================================================================

/// A named shared memory region.
pub struct SharedMemory {
    /// Was this region created or opened?
    was_created: bool,
    /// Name.
    name: ffi::CString,
    // Size
    size: usize,
    // data - address
    data: Vec<u8>,
}

//======================================================================================================================
// Associated Functions
//======================================================================================================================

/// Associated functions.
impl SharedMemory {
    /// Prefix for shared memory region names.
    const SHM_NAME_PREFIX: &'static str = "demikernel-";

    /// Opens an existing named shared memory region.
    pub fn open(name: &str, len: usize) -> Result<SharedMemory, Fail> {
        let name: ffi::CString = Self::build_name(name)?;

        let shm: SharedMemory = SharedMemory {
            was_created: false,
            name,
            size: len,
            data: vec![0; len],
        };

        Ok(shm)
    }

    /// Creates a named shared memory region.
    pub fn create(name: &str, size: usize) -> Result<SharedMemory, Fail> {
        let name: ffi::CString = Self::build_name(name)?;

        let mut shm: SharedMemory = SharedMemory {
            was_created: true,
            name,
            size,
            data: vec![0; size],
        };

        shm.truncate(size)?;
        shm.map(size)?;

        Ok(shm)
    }

    /// Closes the target shared memory region.
    fn close(&mut self) -> Result<(), Fail> {
        Ok(())
    }

    /// Unlinks the target shared memory region.
    fn unlink(&mut self) -> Result<(), Fail> {
        Ok(())
    }

    /// Truncates the target shared memory region.
    fn truncate(&mut self, size: usize) -> Result<(), Fail> {
        self.size = size;

        Ok(())
    }

    /// Maps the target shared memory region to the address space of the calling process.
    fn map(&mut self, size: usize) -> Result<(), Fail> {
        self.size = size;
        Ok(())
    }

    // Unmaps the target shared memory region from the address space of the calling process.
    fn unmap(&mut self) -> Result<(), Fail> {
        Ok(())
    }

    /// Constructs the name of shared memory region.
    fn build_name(name: &str) -> Result<ffi::CString, Fail> {
        // Check if provided name is valid.
        if name.is_empty() {
            return Err(Fail::new(libc::EINVAL, "name of shared memory region cannot be empty"));
        }
        let prefix: String = String::from(Self::SHM_NAME_PREFIX);
        match ffi::CString::new((prefix + name).to_string()) {
            Ok(name) => Ok(name),
            Err(_) => Err(Fail::new(libc::EINVAL, "could not parse name of shared memory region")),
        }
    }

    /// Returns the size of the target shared memory region.
    #[allow(unused)]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Writes a value to the target shared memory region at a given offset.
    #[allow(unused)]
    pub fn write<T>(&mut self, index: usize, val: &T) {
    }

    /// Reads a value from the target shared memory region at a given offset.
    #[allow(unused)]
    pub fn read<T>(&mut self, index: usize, val: &mut T) {
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

/// Dereference trait implementation.
impl Deref for SharedMemory {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data.as_slice()
    }
}

/// Mutable dereference trait implementation.
impl DerefMut for SharedMemory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.as_mut_slice()
    }
}

/// Drop trait implementation.
impl Drop for SharedMemory {
    fn drop(&mut self) {
        // 1) Unmap the underlying shared memory region from the address space of the calling process.
        match self.unmap() {
            Ok(_) => {},
            Err(e) => eprintln!("{}", e),
        };
        // 2) Close the underlying shared memory region.
        match self.close() {
            Ok(_) => {},
            Err(e) => eprintln!("{}", e),
        }
        // 3) Remove the underlying shared memory region name link.
        if self.was_created {
            match self.unlink() {
                Ok(_) => {},
                Err(e) => eprintln!("{}", e),
            }
        }
    }
}