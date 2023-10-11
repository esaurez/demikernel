use ::core::{
    ops::{
        Deref,
        DerefMut,
    },
    slice,
};

// Create an error enum to handle errors
#[derive(Debug)]
pub enum IvshmemError {
    IoctlFailed,
    MmapFailed,
    ShMemOpenFailed,
    #[allow(unused)]
    UnmapFailed,
    RegionNotFound,
    RegionTooSmall,
    NotPermittedOperation,
    NotEnoughCapacity,
}

#[derive(Debug)]
pub struct RegionLocation {
    pub offset: u64,
    pub size: u64,
}

pub struct Region {
    /// Base address.
    pub addr: *mut libc::c_void,
    /// Size in bytes.
    pub size: libc::size_t,
    //\TODO Region should share the same lifetime as SharedMemSegment
}

pub trait IvshmemManager : Send {
    fn create_region(&mut self, region_name: &str, region_size: u64) -> Result<RegionLocation, IvshmemError>;
    fn get_region(&mut self, region_name: &str) -> Result<RegionLocation, IvshmemError>;
    fn mmap_region(&mut self, region: &RegionLocation) -> Result<Region, IvshmemError>;
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
