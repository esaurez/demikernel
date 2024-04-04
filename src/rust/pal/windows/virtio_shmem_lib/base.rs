use ::core::ops::{
    Deref,
    DerefMut,
};

use crate::runtime::fail::Fail;

pub type NimbleResult<T> = std::result::Result<T, Fail>;

pub struct RegionLocation {
    pub offset: u64,
    pub size: u64,
}

impl Clone for RegionLocation {
    fn clone(&self) -> Self {
        RegionLocation {
            offset: self.offset,
            size: self.size,
        }
    }
}

pub trait RegionTrait: Deref + DerefMut {}

pub trait RegionManager: Send + Sync {
    fn create_region(&mut self, segment_name: &str, segment_size: u64) -> NimbleResult<RegionLocation>;
    fn get_region(&mut self, segment_name: &str) -> NimbleResult<RegionLocation>;
    fn mmap_region(&mut self, region_location: &RegionLocation) -> NimbleResult<Box<dyn RegionTrait<Target = [u8]>>>;
}
