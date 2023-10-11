use std::{
    ffi::CString,
    ptr,
};

use crate::pal::linux::vm_shmem_lib::base::{
    IvshmemError,
    IvshmemManager,
    Region,
    RegionLocation,
};
use core::slice;
use std::collections::HashMap;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};
 
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, Clone, FromZeroes)]
pub struct InMemoryRegion {
    name_offset: u16,
    name_size: u16,
    reserved: u32, // padding
    offset: u64,
    size: u64,
}

pub struct ManagerMetadata {
    num_regions: u64,
    next_name_offset: u16,
    next_region_offset: u64,
}

pub struct SharedMemSegment {
    shmem_fd: libc::c_int,
    region_descriptors: *mut libc::c_void,
    region_dict: HashMap<u64, (*mut libc::c_void, usize)>,
    page_size: libc::c_long,
    memory_manager: bool,
    segment_size: u64,
    manager_metadata: Option<ManagerMetadata>,
}

// Check if this is safe
unsafe impl Send for SharedMemSegment {}

impl SharedMemSegment {
    pub fn open(shmem_path: &str, is_memory_manager: bool) -> Result<SharedMemSegment, IvshmemError> {
        // Path to the shared memory region
        let shmem_path = CString::new(shmem_path).expect("CString::new failed");

        let shmem_fd: libc::c_int = unsafe {
            // Forward request to underlying POSIX OS.
            let ret: libc::c_int = libc::shm_open(shmem_path.as_ptr(), libc::O_RDWR, 0o644);

            // Check for failure return value.
            if ret == -1 {
                let errno: libc::c_int = *libc::__errno_location();
                let cause: String = format!(
                    "failed to open shared memory region (name={:?}, errno={})",
                    shmem_path, errno
                );
                eprintln!("open(): {}", cause);
                return Err(IvshmemError::ShMemOpenFailed);
            }

            ret
        };
        // Get the total size of the shared memory region
        let segment_size: u64 = unsafe {
            let mut stat: libc::stat = std::mem::zeroed();
            let ret: libc::c_int = libc::fstat(shmem_fd, &mut stat);

            // Check for failure return value.
            if ret == -1 {
                let errno: libc::c_int = *libc::__errno_location();
                let cause: String = format!(
                    "failed to get size of shared memory region (name={:?}, errno={})",
                    shmem_path, errno
                );
                eprintln!("fstat(): {}", cause);
                return Err(IvshmemError::ShMemOpenFailed);
            }

            stat.st_size as u64
        };

        let page_size: libc::c_long = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };

        let flags = match is_memory_manager {
            true => libc::PROT_READ | libc::PROT_WRITE,
            false => libc::PROT_READ,
        };

        let region_descriptors: *mut libc::c_void = unsafe {
            let ret: *mut libc::c_void = libc::mmap(
                ptr::null_mut(),
                2 * page_size as usize,
                flags,
                libc::MAP_SHARED,
                shmem_fd,
                0,
            );

            // Check for failure return value.
            if ret == libc::MAP_FAILED {
                return Err(IvshmemError::MmapFailed);
            }
            ret
        };

        let manager_metadata = match is_memory_manager {
            true => Some(ManagerMetadata {
                num_regions: 0_u64,
                next_name_offset: 0_u16,
                next_region_offset: 0_u64,
            }),
            false => None,
        };

        Ok(SharedMemSegment {
            shmem_fd,
            region_descriptors,
            region_dict: HashMap::new(),
            page_size,
            memory_manager: is_memory_manager,
            segment_size,
            manager_metadata,
        })
    }

    fn internal_get_region(&mut self, region_name: &str) -> Result<RegionLocation, IvshmemError> {
        // Read the number of regions as u64 from the first 8 bytes of the region descriptors
        let num_regions: u64 = unsafe { *(self.region_descriptors as *mut u64) };
        println!("Number of regions: {}", num_regions);
        // Iterate over the regions and find the one with the given name
        for idx in 0..num_regions {
            let region: *mut InMemoryRegion = unsafe {
                self.region_descriptors
                    .add(8 + idx as usize * std::mem::size_of::<InMemoryRegion>())
                    as *mut InMemoryRegion
            };
            let region_name_ptr: *const u8 = unsafe {
                self.region_descriptors
                    .add((*region).name_offset as usize + self.page_size as usize) as *const u8
            };
            let region_name_slice: &[u8] =
                unsafe { slice::from_raw_parts(region_name_ptr, (*region).name_size as usize) };
            let region_name_str: &str = std::str::from_utf8(region_name_slice).unwrap();
            println!("Next region name to compare: {}", region_name_str);
            if region_name_str == region_name {
                let found_region = RegionLocation {
                    offset: unsafe { (*region).offset },
                    size: unsafe { (*region).size },
                };
                println!(
                    "Found region at offset {} and size {}",
                    found_region.offset, found_region.size
                );
                return Ok(found_region);
            }
        }
        Err(IvshmemError::RegionNotFound)
    }

    fn write_descriptor(&mut self, region_len: u64, region_name_len: u16) {
        let metadata = self.manager_metadata.as_mut().unwrap();
        let region_descriptor: *mut InMemoryRegion = unsafe {
            self.region_descriptors
                .add(8 + metadata.num_regions as usize * std::mem::size_of::<InMemoryRegion>())
                as *mut InMemoryRegion
        };
        unsafe {
            (*region_descriptor).name_offset = metadata.next_name_offset;
            (*region_descriptor).name_size = region_name_len;
            (*region_descriptor).offset = metadata.next_region_offset;
            (*region_descriptor).size = region_len;
            (*region_descriptor).reserved = 0;
        };
    }

    fn write_name(&mut self, region_name: &str) {
        let metadata = self.manager_metadata.as_mut().unwrap();
        let region_name_ptr: *mut u8 = unsafe {
            self.region_descriptors
                .add(metadata.next_name_offset as usize + self.page_size as usize) as *mut u8
        };
        unsafe {
            ptr::copy_nonoverlapping(region_name.as_ptr(), region_name_ptr, region_name.len());
        };
    }

    fn internal_create_region(&mut self, region_name: &str, len: u64) -> Result<RegionLocation, IvshmemError> {
        if !self.memory_manager {
            return Err(IvshmemError::NotPermittedOperation);
        }
        let region_offset;
        {
            // metadata borrow scope
            let metadata = self.manager_metadata.as_mut().unwrap();
            // Enough space for region
            if metadata.next_region_offset + len as u64 > self.segment_size {
                return Err(IvshmemError::NotEnoughCapacity);
            }
            // Enough space for string
            if metadata.next_name_offset + region_name.len() as u16 > self.page_size as u16 {
                return Err(IvshmemError::NotEnoughCapacity);
            }
            // Enough space for region descriptor
            if (metadata.num_regions as usize + 1) * std::mem::size_of::<InMemoryRegion>() + std::mem::size_of::<u64>()
                > self.page_size as usize
            {
                return Err(IvshmemError::NotEnoughCapacity);
            }

            region_offset = metadata.next_region_offset;
        }

        // Write region descriptor
        self.write_descriptor(len as u64, region_name.len() as u16);

        // Write name to shared memory
        self.write_name(region_name);

        // Update metadata
        {
            // metadata borrow scope
            let metadata = self.manager_metadata.as_mut().unwrap();
            metadata.num_regions += 1;
            metadata.next_name_offset += region_name.len() as u16;
            metadata.next_region_offset += len as u64;
        }

        // Update number of regions in shared memory
        unsafe {
            *(self.region_descriptors as *mut u64) = self.manager_metadata.as_ref().unwrap().num_regions;
        }

        Ok(RegionLocation {
            offset: region_offset,
            size: len as u64,
        })
    }

    pub fn mmap_region_location(&mut self, region_location: &RegionLocation) -> Result<Region, IvshmemError> {
        // Check if the region is already mapped
        if self.region_dict.contains_key(&region_location.offset) {
            let (region_addr, region_size) = self.region_dict.get(&region_location.offset).unwrap();
            return Ok(Region {
                addr: *region_addr,
                size: *region_size,
            });
        }

        let region_addr: *mut libc::c_void = unsafe {
            let ret: *mut libc::c_void = libc::mmap(
                ptr::null_mut(),
                region_location.size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.shmem_fd,
                // Offset is from the third page onwards
                2 * self.page_size as i64 + region_location.offset as i64,
            );

            // Check for failure return value.
            if ret == libc::MAP_FAILED {
                return Err(IvshmemError::MmapFailed);
            }
            ret
        };
        self.region_dict
            .insert(region_location.offset, (region_addr, region_location.size as usize));
        Ok(Region {
            addr: region_addr,
            size: region_location.size as usize,
        })
    }

    #[allow(unused)]
    pub fn mmap_region_by_name(&mut self, region_name: &str, len: u64) -> Result<Region, IvshmemError> {
        let region_location_result = self.internal_get_region(region_name);

        let region_location;
        if region_location_result.is_err() {
            match region_location_result.unwrap_err() {
                IvshmemError::RegionNotFound => {
                    // If the region is not found, create it
                    if !self.memory_manager {
                        return Err(IvshmemError::RegionNotFound);
                    }
                    region_location = self.internal_create_region(region_name, len)?;
                },
                _ => {
                    return Err(IvshmemError::RegionNotFound);
                },
            }
        } else {
            region_location = region_location_result.unwrap();
        }

        if region_location.size < len as u64 {
            return Err(IvshmemError::RegionTooSmall);
        }

        self.mmap_region_location(&region_location)
    }
}

impl IvshmemManager for SharedMemSegment {
    fn create_region(&mut self, region_name: &str, region_size: u64) -> Result<RegionLocation, IvshmemError> {
        if !self.memory_manager {
            return Err(IvshmemError::NotPermittedOperation);
        }
        self.internal_create_region(region_name, region_size)
    }

    fn get_region(&mut self, region_name: &str) -> Result<RegionLocation, IvshmemError> {
        self.internal_get_region(region_name)
    }

    fn mmap_region(&mut self, region_location: &RegionLocation) -> Result<Region, IvshmemError> {
        self.mmap_region_location(&region_location)
    }
}

impl Drop for SharedMemSegment {
    fn drop(&mut self) {
        unsafe {
            let ret: libc::c_int = libc::munmap(self.region_descriptors, 2 * self.page_size as usize);

            // Check for failure return value.
            if ret == -1 {
                eprintln!("munmap() failed");
            }
        }
        // Unmap other regions in the hashmap
        for (region_addr, region_size) in self.region_dict.values() {
            unsafe {
                let ret: libc::c_int = libc::munmap(*region_addr, *region_size);

                // Check for failure return value.
                if ret == -1 {
                    eprintln!("munmap() failed");
                }
            }
        }

        // Close the shared memory region.
        unsafe {
            let ret: libc::c_int = libc::close(self.shmem_fd);
            if ret == -1 {
                eprintln!("failed to close shared memory region");
            }
        }
    }
}
