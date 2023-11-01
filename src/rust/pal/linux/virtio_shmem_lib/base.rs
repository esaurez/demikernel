use ::core::ops::{
    Deref,
    DerefMut,
};

use std::io;

use vhost::vhost_user;
use vm_memory::{
    bitmap::AtomicBitmap,
    GuestMemoryError,
};

pub type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;

#[derive(thiserror::Error, Debug)]
pub enum VirtioNimbleError {
    #[error("Failed to create kill eventfd: {0}")]
    CreateKillEventFd(io::Error),

    #[error("Failed to signal used queue: {0}")]
    FailedSignalingUsedQueue(io::Error),
    #[error("Failed to handle event other than input event")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknownEvent,
    #[error("No socket provided")]
    SocketParameterMissing,
    #[error("Missing size")]
    SizeParameterMissing,
    #[error("Guest gave us too few descriptors in a descriptor chain")]
    DescriptorChainTooShort,
    #[error("Read type of request was invalid")]
    UnexpectedWriteOnlyDescriptor,
    #[error("Format of the request was invalid")]
    InvalidRequest,
    #[error("Failed to read from guest memory: {0}")]
    GuestMemory(GuestMemoryError),
    #[error("Failed getting memory guard")]
    MemoryGuard,
    #[error("Region not found")]
    RegionNotFound,
    #[error("Region size is not correct {0}, expected {1}")]
    RegionSizeInvalid(u64, u64),
    #[error("Region start address is not correct {0}, expected {1}")]
    RegionAddressInvalid(u64, u64),
    #[error("Address was not found in region")]
    InvalidRegionAddr,
    #[error("Segment is too large for the region in which it is being created")]
    SegmentTooLarge,
    #[error("Error locking the backend {error:?}")]
    BackendLock { error: String },
    #[error("Error retrieving the segment")]
    SegmentRetrieval,
    #[error("Segment manager is not initialized")]
    SegmentManagerInitialization,
    #[error("Error converting a C string into a rust string")]
    StringConversion(std::str::Utf8Error),
    #[error("Integer conversion (downgrade) failed")]
    IntegerConversion(std::num::TryFromIntError),
    #[error("Ioctl operation failed")]
    IoctlFailed,
    #[error("Operation is not permitted")]
    NotPermittedOperation,
    #[error("Failed to start the vhost user daemon {0:?}")]
    VhostUserDaemon(vhost_user_backend::Error),
    #[error("Number of vring workers must be identical to the number of backend threads")]
    InvalidVringConfiguration,
    #[error("Error shutting down worker thread {0:?}")]
    WorkerShutDown(io::Error),
    #[error("Failed to start the vhost user daemon {0:?}")]
    VhostUser(vhost_user::Error),
    #[error("Error starting daemon thread {0:?}")]
    SpawnVhostUserDaemonThread(io::Error),
}

// Check if these two are safe
unsafe impl Send for VirtioNimbleError {}
unsafe impl Sync for VirtioNimbleError {}

pub type NimbleResult<T> = std::result::Result<T, VirtioNimbleError>;
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
