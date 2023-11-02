use crate::pal::linux::virtio_shmem_lib::base::{
    NimbleResult,
    RegionLocation,
    RegionManager,
    RegionTrait,
    VirtioNimbleError,
};

use std::{
    collections::HashMap,
    ffi::CString,
    fs::OpenOptions,
    ops::{
        Deref,
        DerefMut,
    },
    os::{
        raw::c_char,
        unix::io::AsRawFd,
    },
    slice,
};

const DEVICE_PATH: &str = "/dev/virtio_nimblenet_dev";

#[repr(C)]
pub struct CreateRegion {
    // Request
    region_name: *const c_char,
    region_name_size: u16,
    region_size: u64,
    // Response
    region_offset: u64,
}

#[repr(C)]
pub struct GetRegion {
    // Request
    region_name: *const c_char,
    region_name_size: u16,
    // Response
    region_offset: u64,
    region_size: u64,
}

// The following is the equivalent of the following C code:
// #define SHVM_CREATE_REGION _IOWR(SHVM_IOC_MAGIC, 2, struct CreateRegion)
// #define SHVM_GET_REGION _IOWR(SHVM_IOC_MAGIC, 3, struct GetRegion)

// The magic  number used by the driver is lower-case s (0x73)
const IOCTL_MAGIC_NUMBER: u8 = 's' as u8;
const SHVM_CREATE_REGION: u8 = 1;
const SHVM_GET_REGION: u8 = 2;
ioctl_readwrite!(create_region, IOCTL_MAGIC_NUMBER, SHVM_CREATE_REGION, CreateRegion);
ioctl_readwrite!(get_region, IOCTL_MAGIC_NUMBER, SHVM_GET_REGION, GetRegion);

pub struct Region {
    /// Base address.
    pub addr: *mut libc::c_void,
    /// Size in bytes.
    pub size: libc::size_t,
    //\TODO Region should share the same lifetime as SharedMemSegment
}

impl Deref for Region {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let data: *const u8 = self.addr as *const u8;
        let len: usize = self.size;
        unsafe { slice::from_raw_parts(data, len) }
    }
}

impl DerefMut for Region {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let data: *mut u8 = self.addr as *mut u8;
        let len: usize = self.size;
        unsafe { slice::from_raw_parts_mut(data, len) }
    }
}

impl RegionTrait for Region {}

pub struct CharDevice {
    file: std::fs::File,
    region_dict: HashMap<u64, (*mut libc::c_void, usize)>,
}

// \TODO check that this is actually safe
unsafe impl Send for CharDevice {}
unsafe impl Sync for CharDevice {}

impl CharDevice {
    pub fn new() -> CharDevice {
        let device_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEVICE_PATH)
            .expect("Failed to open device file");
        CharDevice {
            file: device_file,
            region_dict: HashMap::new(),
        }
    }
}

impl RegionManager for CharDevice {
    fn create_region(&mut self, region_name: &str, region_size: u64) -> Result<RegionLocation, VirtioNimbleError> {
        if region_size % 4096 != 0 {
            eprintln!("Region size must be a multiple of a page");
            return Err(VirtioNimbleError::IoctlFailed);
        }

        let region_name = CString::new(region_name).expect("CString::new failed");
        let mut create_region_struct = CreateRegion {
            region_name: region_name.as_ptr(),
            region_name_size: region_name.as_bytes().len() as u16,
            region_size,
            region_offset: 0,
        };

        match unsafe { create_region(self.file.as_raw_fd() as _, &mut create_region_struct) } {
            Ok(_) => {
                println!("Region offset: {}", create_region_struct.region_offset);
                Ok(RegionLocation {
                    offset: create_region_struct.region_offset,
                    size: region_size,
                })
            },
            Err(_) => {
                eprintln!("Ioctl operation failed");
                Err(VirtioNimbleError::IoctlFailed)
            },
        }
    }

    fn get_region(&mut self, region_name: &str) -> Result<RegionLocation, VirtioNimbleError> {
        let region_name = CString::new(region_name).expect("CString::new failed");
        let mut get_region_struct = GetRegion {
            region_name: region_name.as_ptr(),
            region_name_size: region_name.as_bytes().len() as u16,
            region_size: 0,
            region_offset: 0,
        };

        match unsafe { get_region(self.file.as_raw_fd() as _, &mut get_region_struct) } {
            Ok(_) => {
                println!(
                    "Region offset: {} and size {}",
                    get_region_struct.region_offset, get_region_struct.region_size
                );
                // Check if the size is multiple of a page
                if get_region_struct.region_size % 4096 != 0 {
                    eprintln!("Invalid region: region size must be a multiple of a page");
                    return Err(VirtioNimbleError::IoctlFailed);
                }
                Ok(RegionLocation {
                    offset: get_region_struct.region_offset,
                    size: get_region_struct.region_size,
                })
            },
            Err(_) => {
                eprintln!("Ioctl operation failed");
                Err(VirtioNimbleError::IoctlFailed)
            },
        }
    }

    fn mmap_region(&mut self, region_location: &RegionLocation) -> NimbleResult<Box<dyn RegionTrait<Target = [u8]>>> {
        let mmap_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                region_location.size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.file.as_raw_fd(),
                // The offset is relative to the beginning of the file is handled by the driver
                region_location.offset as libc::off_t,
            )
        };

        if mmap_ptr == libc::MAP_FAILED {
            eprintln!("Failed to mmap region");
            Err(VirtioNimbleError::IoctlFailed)
        } else {
            self.region_dict
                .insert(region_location.offset, (mmap_ptr, region_location.size as usize));
            Ok(Box::new(Region {
                addr: mmap_ptr,
                size: region_location.size as usize,
            }))
        }
    }
}

impl Drop for CharDevice {
    fn drop(&mut self) {
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

        // File self.file is automatically closed when it goes out of scope
    }
}
