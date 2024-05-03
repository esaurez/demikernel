// Copyright 2023 Microsoft Corporation. All Rights Reserved.

use libc::EFD_NONBLOCK;
use log::*;
use std::{
    collections::HashMap,
    io,
    mem::size_of,
    ops::{
        Deref,
        DerefMut,
    },
    os::raw::c_char,
    slice,
    sync::{
        Arc,
        Condvar,
        Mutex,
        RwLock,
        RwLockWriteGuard,
    },
};
use vhost::vhost_user::{
    message::*,
    Listener,
};
use vhost_user_backend::{
    VhostUserBackendMut,
    VhostUserDaemon,
    VringRwLock,
    VringState,
    VringT,
};
use virtio_bindings::virtio_config::{
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VIRTIO_F_VERSION_1,
};
use virtio_queue::{
    DescriptorChain,
    QueueT,
};
use vm_memory::{
    bitmap::AtomicBitmap,
    Address,
    ByteValued,
    Bytes,
    GuestAddress,
    GuestAddressSpace,
    GuestMemory,
    GuestMemoryAtomic,
    GuestMemoryLoadGuard,
    GuestMemoryRegion,
};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::EventFd,
};

use crate::pal::linux::virtio_shmem_lib::base::{
    GuestMemoryMmap,
    NimbleResult,
    RegionLocation,
    RegionManager,
    RegionTrait,
    VirtioNimbleError,
};

type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;
type VhostNimbleUserDaemon = VhostUserDaemon<
    Arc<RwLock<VhostUserNimbleNetBackend>>,
    VringRwLock<GuestMemoryAtomic<vm_memory::GuestMemoryMmap<AtomicBitmap>>>,
    AtomicBitmap,
>;

// \TODO consider using zero copy for the objects in the shared memory

#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct VirtioNimbleReqHeader {
    type_: u8,
    _reserved: [u8; 7],
}

/// Set address request
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct VirtioNimbleReqSetAddr {
    addr: u64,
}

const NAME_LENGTH: usize = 128;

/// Get segment request
#[derive(Copy, Clone, Debug)]
#[repr(packed)]
struct VirtioNimbleReqGetSegment {
    name: [c_char; NAME_LENGTH],
}

impl Default for VirtioNimbleReqGetSegment {
    fn default() -> Self {
        Self { name: [0; NAME_LENGTH] }
    }
}

// Create segment request
#[derive(Copy, Clone, Debug)]
#[repr(packed)]
struct VirtioNimbleReqCreateSegment {
    name: [c_char; NAME_LENGTH],
    size: u64,
}

impl Default for VirtioNimbleReqCreateSegment {
    fn default() -> Self {
        Self {
            name: [0; NAME_LENGTH],
            size: 0,
        }
    }
}

// Get segment response
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioNimbleRespGet {
    size: u64,
    offset: u64,
}

// Create segment response
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioNimbleRespCreate {
    offset: u64,
}

// Set address response
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
#[allow(dead_code)]
struct VirtioNimbleRespSetAddr {
    status: u8,
    _reserved: [u8; 7],
}

const VIRTIO_NIMBLE_REQ_TYPE_SET_ADDR: u8 = 0;
const VIRTIO_NIMBLE_REQ_TYPE_GET_SEGMENT: u8 = 1;
const VIRTIO_NIMBLE_REQ_TYPE_CREATE_SEGMENT: u8 = 2;

const VIRTIO_NIMBLE_RESP_OK: u8 = 0;

unsafe impl ByteValued for VirtioNimbleReqHeader {}
unsafe impl ByteValued for VirtioNimbleReqSetAddr {}
unsafe impl ByteValued for VirtioNimbleReqGetSegment {}
unsafe impl ByteValued for VirtioNimbleReqCreateSegment {}
unsafe impl ByteValued for VirtioNimbleRespGet {}
unsafe impl ByteValued for VirtioNimbleRespCreate {}
unsafe impl ByteValued for VirtioNimbleRespSetAddr {}

pub struct MemGuard {
    addr: *mut u8,
    size: u64,
}

impl MemGuard {
    pub fn new(mem_guard: &GuestMemoryLoadGuard<GuestMemoryMmap>, gpa: GuestAddress) -> NimbleResult<MemGuard> {
        let region = mem_guard.find_region(gpa).ok_or(VirtioNimbleError::RegionNotFound)?;
        Ok(MemGuard {
            addr: region.as_ptr(),
            size: region.len(),
        })
    }
}

pub struct Region {
    // Mem and mem_snapshot contain the backing data for mem_guard
    _mem: GuestMemoryAtomic<GuestMemoryMmap>,
    _mem_snapshot: GuestMemoryLoadGuard<GuestMemoryMmap>,
    // mem_guard should never be copied out from Shared Memory, as it depends on the data of _mem_snapshot
    mem_guard: MemGuard,
    offset: usize,
    size: usize,
}

impl Region {
    pub fn new(
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        gpa: GuestAddress,
        offset: usize,
        size: usize,
    ) -> NimbleResult<Region> {
        //\TODO update the region ref, when address are changed (e.g., after migration)
        let mem_snapshot = mem.memory();
        let mem_guard = MemGuard::new(&mem_snapshot, gpa)?;
        Ok(Region {
            _mem: mem,
            _mem_snapshot: mem_snapshot,
            mem_guard,
            offset,
            size,
        })
    }
}

impl Deref for Region {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let slice = unsafe { slice::from_raw_parts(self.mem_guard.addr, self.mem_guard.size as usize) };
        &slice[self.offset..self.offset + self.size]
    }
}

impl DerefMut for Region {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let slice = unsafe { slice::from_raw_parts_mut(self.mem_guard.addr, self.mem_guard.size as usize) };
        &mut slice[self.offset..self.offset + self.size]
    }
}

impl RegionTrait for Region {}

pub struct ShmemManager {
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    region_addr: Option<GuestAddress>,
    segment_map: HashMap<String, RegionLocation>,
    pub size: u64,
    current_offset: u64,
    init_wait: Arc<(Mutex<bool>, Condvar)>,
}

impl ShmemManager {
    pub fn new(mem: GuestMemoryAtomic<GuestMemoryMmap>, region_size: u64) -> Self {
        ShmemManager {
            mem,
            region_addr: None,
            segment_map: HashMap::new(),
            size: region_size,
            current_offset: 0,
            init_wait: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    pub fn get_init_wait(&self) -> Arc<(Mutex<bool>, Condvar)> {
        self.init_wait.clone()
    }

    pub fn wait(cond_wait: Arc<(Mutex<bool>, Condvar)>) -> NimbleResult<()> {
        let (lock, cvar) = &*cond_wait;
        let mut initialized = lock
            .lock()
            .map_err(|e| VirtioNimbleError::BackendLock { error: e.to_string() })?;
        while !*initialized {
            initialized = cvar.wait(initialized).unwrap();
        }
        Ok(())
    }

    pub fn initialized(&self) -> bool {
        let (lock, _) = &*self.init_wait;
        let initialized = lock.lock().unwrap();
        *initialized
    }

    pub fn init(&mut self, gpa: GuestAddress) -> NimbleResult<()> {
        let mem_guard = self.mem.memory();
        let region = mem_guard.find_region(gpa).ok_or(VirtioNimbleError::RegionNotFound)?;
        // The regions used by the shared memory where explicitly created to match
        // Check that both size and starting address match
        if region.start_addr() != gpa {
            return Err(VirtioNimbleError::RegionAddressInvalid(region.start_addr().0, gpa.0));
        }
        if region.len() != self.size {
            return Err(VirtioNimbleError::RegionSizeInvalid(region.len(), self.size));
        }
        self.region_addr.replace(gpa);

        // Notify the waiting threads
        let (lock, cvar) = &*self.init_wait;
        let mut initialized = lock
            .lock()
            .map_err(|e| VirtioNimbleError::BackendLock { error: e.to_string() })?;
        *initialized = true;
        cvar.notify_all();
        Ok(())
    }
}

impl RegionManager for ShmemManager {
    fn create_region(&mut self, segment_name: &str, segment_size: u64) -> NimbleResult<RegionLocation> {
        if self.segment_map.contains_key(segment_name) {
            return Ok(self
                .segment_map
                .get(segment_name)
                .ok_or(VirtioNimbleError::SegmentRetrieval)?
                .clone());
        }

        if self.current_offset + segment_size > self.size {
            return Err(VirtioNimbleError::SegmentTooLarge);
        }

        let offset = self.current_offset;
        self.current_offset += segment_size;

        let segment = RegionLocation {
            offset,
            size: segment_size,
        };
        self.segment_map.insert(segment_name.to_string(), segment.clone());
        Ok(segment)
    }

    fn get_region(&mut self, segment_name: &str) -> NimbleResult<RegionLocation> {
        match self.segment_map.get(segment_name) {
            Some(segment) => Ok(segment.clone()),
            None => Err(VirtioNimbleError::RegionNotFound),
        }
    }

    fn mmap_region(&mut self, segment: &RegionLocation) -> NimbleResult<Box<dyn RegionTrait<Target = [u8]>>> {
        let offset = segment.offset as usize;
        let size = segment.size as usize;
        let region_addr = match self.region_addr {
            Some(addr) => addr,
            None => {
                return Err(VirtioNimbleError::SegmentManagerInitialization);
            },
        };
        if offset + size > (self.size as usize) {
            return Err(VirtioNimbleError::SegmentTooLarge);
        }
        let mem = self.mem.clone();
        Ok(Box::new(Region::new(mem, region_addr, offset, size)?))
    }
}

impl std::convert::From<VirtioNimbleError> for std::io::Error {
    fn from(e: VirtioNimbleError) -> Self {
        std::io::Error::new(io::ErrorKind::Other, e)
    }
}

struct VhostUserNimbleNetThread {
    event_idx: bool,
    kill_evt: EventFd,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    segment_manager: Arc<Mutex<ShmemManager>>,
}

impl VhostUserNimbleNetThread {
    /// Create a new virtio nimble net device
    fn new(mem: GuestMemoryAtomic<GuestMemoryMmap>, shmem_manager: Arc<Mutex<ShmemManager>>) -> NimbleResult<Self> {
        Ok(VhostUserNimbleNetThread {
            event_idx: false,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(VirtioNimbleError::CreateKillEventFd)?,
            mem,
            segment_manager: shmem_manager,
        })
    }

    fn handle(
        &mut self,
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
    ) -> NimbleResult<usize> {
        let desc = desc_chain
            .next()
            .ok_or(VirtioNimbleError::DescriptorChainTooShort)
            .map_err(|e| {
                error!("Missing head descriptor");
                e
            })?;
        // The descriptor contains the request type which MUST be readable.
        if desc.is_write_only() {
            return Err(VirtioNimbleError::UnexpectedWriteOnlyDescriptor);
        }

        if (desc.len() as usize) < size_of::<VirtioNimbleReqHeader>() {
            return Err(VirtioNimbleError::InvalidRequest);
        }

        let req_head: VirtioNimbleReqHeader = desc_chain
            .memory()
            .read_obj(desc.addr())
            .map_err(VirtioNimbleError::GuestMemory)?;

        let req_offset = size_of::<VirtioNimbleReqHeader>();
        let desc_size_left = (desc.len() as usize) - req_offset;
        let req_addr = if let Some(addr) = desc.addr().checked_add(req_offset as u64) {
            addr
        } else {
            return Err(VirtioNimbleError::InvalidRequest);
        };

        let reply: NimbleResult<Vec<u8>> = match req_head.type_ {
            VIRTIO_NIMBLE_REQ_TYPE_SET_ADDR => self.process_set_address(desc_chain, req_addr, desc_size_left),
            VIRTIO_NIMBLE_REQ_TYPE_GET_SEGMENT => self.process_get_segment(desc_chain, req_addr, desc_size_left),
            VIRTIO_NIMBLE_REQ_TYPE_CREATE_SEGMENT => self.process_create_segment(desc_chain, req_addr, desc_size_left),
            _ => Err(VirtioNimbleError::InvalidRequest),
        };

        let reply_vec = reply?;

        let resp_desc = desc_chain.next().ok_or(VirtioNimbleError::DescriptorChainTooShort)?;

        desc_chain
            .memory()
            .write_slice(reply_vec.as_slice(), resp_desc.addr())
            .map_err(VirtioNimbleError::GuestMemory)?;

        Ok(reply_vec.len())
    }

    fn process_set_address(
        &mut self,
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
        req_addr: GuestAddress,
        remaining_space: usize,
    ) -> NimbleResult<Vec<u8>> {
        let mut response: Vec<u8> = Vec::new();
        if remaining_space != size_of::<VirtioNimbleReqSetAddr>() {
            return Err(VirtioNimbleError::InvalidRequest);
        }

        let req: VirtioNimbleReqSetAddr = desc_chain
            .memory()
            .read_obj(req_addr as GuestAddress)
            .map_err(VirtioNimbleError::GuestMemory)?;

        let mut sm = self
            .segment_manager
            .lock()
            .map_err(|e| VirtioNimbleError::BackendLock { error: e.to_string() })?;
        if sm.initialized() {
            return Err(VirtioNimbleError::InvalidRequest);
        }

        sm.init(GuestAddress::new(req.addr))?;

        let resp = VirtioNimbleRespSetAddr {
            status: VIRTIO_NIMBLE_RESP_OK,
            ..Default::default()
        };
        response.extend_from_slice(resp.as_slice());
        Ok(response)
    }

    fn process_get_segment(
        &mut self,
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
        req_addr: GuestAddress,
        remaining_space: usize,
    ) -> NimbleResult<Vec<u8>> {
        let mut response: Vec<u8> = Vec::new();
        if remaining_space != size_of::<VirtioNimbleReqGetSegment>() {
            return Err(VirtioNimbleError::InvalidRequest);
        }

        let req: VirtioNimbleReqGetSegment = desc_chain
            .memory()
            .read_obj(req_addr as GuestAddress)
            .map_err(VirtioNimbleError::GuestMemory)?;

        // Cast name to &str
        let name_cstr = unsafe { std::ffi::CStr::from_ptr(req.name.as_ptr()) };
        let str_slice = name_cstr.to_str().map_err(VirtioNimbleError::StringConversion)?;

        let mut sm = self
            .segment_manager
            .lock()
            .map_err(|e| VirtioNimbleError::BackendLock { error: e.to_string() })?;
        if !sm.initialized() {
            return Err(VirtioNimbleError::SegmentManagerInitialization);
        }
        let region = sm.get_region(str_slice)?;
        let resp = VirtioNimbleRespGet {
            size: region.size,
            offset: region.offset,
        };
        response.extend_from_slice(resp.as_slice());

        Ok(response)
    }

    fn process_create_segment(
        &mut self,
        desc_chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
        req_addr: GuestAddress,
        remaining_space: usize,
    ) -> NimbleResult<Vec<u8>> {
        let mut response: Vec<u8> = Vec::new();
        if remaining_space != size_of::<VirtioNimbleReqCreateSegment>() {
            return Err(VirtioNimbleError::InvalidRequest);
        }

        let req: VirtioNimbleReqCreateSegment = desc_chain
            .memory()
            .read_obj(req_addr as GuestAddress)
            .map_err(VirtioNimbleError::GuestMemory)?;

        let name_cstr = unsafe { std::ffi::CStr::from_ptr(req.name.as_ptr()) };
        let str_slice = name_cstr.to_str().map_err(VirtioNimbleError::StringConversion)?;

        let mut sm = self
            .segment_manager
            .lock()
            .map_err(|e| VirtioNimbleError::BackendLock { error: e.to_string() })?;
        if !sm.initialized() {
            return Err(VirtioNimbleError::SegmentManagerInitialization);
        }
        let region = sm.create_region(str_slice, req.size)?;
        if region.size != req.size {
            return Err(VirtioNimbleError::SegmentTooLarge);
        }
        let resp = VirtioNimbleRespCreate { offset: region.offset };
        response.extend_from_slice(resp.as_slice());

        Ok(response)
    }

    fn process_queue(&mut self, vring: &mut RwLockWriteGuard<VringState<GuestMemoryAtomic<GuestMemoryMmap>>>) -> bool {
        let mut used_descs = false;

        while let Some(mut desc_chain) = vring.get_queue_mut().pop_descriptor_chain(self.mem.memory()) {
            debug!("got an element in the queue");
            let len: usize = match self.handle(&mut desc_chain) {
                Ok(written) => written,
                Err(err) => {
                    error!("failed to parse available descriptor chain: {:?}", err);
                    0
                },
            };

            let len32: u32 = len.try_into().unwrap();

            vring
                .get_queue_mut()
                .add_used(desc_chain.memory(), desc_chain.head_index(), len32)
                .unwrap();
            used_descs = true;
        }

        let mut needs_signalling = false;
        if self.event_idx {
            if vring
                .get_queue_mut()
                .needs_notification(self.mem.memory().deref())
                .unwrap()
            {
                debug!("signalling queue");
                needs_signalling = true;
            } else {
                debug!("omitting signal (event_idx)");
            }
        } else {
            debug!("signalling queue");
            needs_signalling = true;
        }

        if needs_signalling {
            vring.signal_used_queue().unwrap();
        }

        used_descs
    }
}

pub struct VhostUserNimbleNetBackend {
    threads: Vec<Mutex<VhostUserNimbleNetThread>>,
    num_queues: usize,
    queue_size: u16,
    queues_per_thread: Vec<u64>,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    segment_manager: Arc<Mutex<ShmemManager>>,
}

impl VhostUserNimbleNetBackend {
    #[allow(clippy::too_many_arguments)]
    fn new(
        size: u64,
        num_queues: usize,
        queue_size: u16,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> NimbleResult<Self> {
        let mut queues_per_thread = Vec::new();
        let mut threads = Vec::new();
        let segment_manager = Arc::new(Mutex::new(ShmemManager::new(mem.clone(), size)));
        let thread = Mutex::new(VhostUserNimbleNetThread::new(mem.clone(), segment_manager.clone())?);
        threads.push(thread);
        queues_per_thread.push(0b1);

        Ok(VhostUserNimbleNetBackend {
            threads,
            num_queues,
            queue_size,
            queues_per_thread,
            mem,
            segment_manager,
        })
    }

    pub fn get_shmem_manager(&self) -> Arc<Mutex<ShmemManager>> {
        self.segment_manager.clone()
    }
}

impl VhostUserBackendMut<VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>, AtomicBitmap> for VhostUserNimbleNetBackend {
    fn num_queues(&self) -> usize {
        self.num_queues
    }

    fn max_queue_size(&self) -> usize {
        self.queue_size as usize
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_NOTIFY_ON_EMPTY | 1 << VIRTIO_F_VERSION_1 | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock<GuestMemoryAtomic<GuestMemoryMmap>>],
        thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != EventSet::IN {
            return Err(VirtioNimbleError::HandleEventNotEpollIn.into());
        }

        let mut thread = self.threads[thread_id].lock().unwrap();
        match device_event {
            0 => {
                let mut vring = vrings[0].get_mut();
                // \TODO consider polling the queue
                if thread.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring
                            .get_queue_mut()
                            .enable_notification(self.mem.memory().deref())
                            .unwrap();
                        if !thread.process_queue(&mut vring) {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    thread.process_queue(&mut vring);
                }

                Ok(false)
            },
            _ => return Err(VirtioNimbleError::HandleEventUnknownEvent.into()),
        }
    }

    fn exit_event(&self, thread_index: usize) -> Option<EventFd> {
        Some(self.threads[thread_index].lock().unwrap().kill_evt.try_clone().unwrap())
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.queues_per_thread.clone()
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> VhostUserBackendResult<()> {
        self.mem = mem;
        Ok(())
    }

    fn set_event_idx(&mut self, _enabled: bool) {}
}

pub struct VirtioNimbleRunner {
    nimble_net_backend: Arc<RwLock<VhostUserNimbleNetBackend>>,
    runner_thread: Option<std::thread::JoinHandle<NimbleResult<()>>>,
}

impl VirtioNimbleRunner {
    pub fn new(
        size: u64,
        num_queues: usize,
        queue_size: u16,
        socket: String,
        client: bool,
    ) -> NimbleResult<VirtioNimbleRunner> {
        let mem = GuestMemoryAtomic::new(GuestMemoryMmap::new());

        let nimble_net_backend = Arc::new(RwLock::new(VhostUserNimbleNetBackend::new(
            size,
            num_queues,
            queue_size,
            mem.clone(),
        )?));

        let nimble_net_daemon = VhostUserDaemon::new(
            "vhost-user-nimble-net-backend".to_string(),
            nimble_net_backend.clone(),
            mem,
        )
        .map_err(VirtioNimbleError::VhostUserDaemon)?;

        let epoll_handlers = nimble_net_daemon.get_epoll_handlers();
        if epoll_handlers.len() != nimble_net_backend.read().unwrap().threads.len() {
            return Err(VirtioNimbleError::InvalidVringConfiguration);
        }

        let nimble_net_backend_clone = nimble_net_backend.clone();
        // Create the thread with the daemon
        let runner_thread = std::thread::Builder::new()
            .name("vhost-user-nimble-net-backend".to_string())
            .spawn(move || -> NimbleResult<()> {
                Self::thread_run(nimble_net_daemon, nimble_net_backend_clone, client, socket)?;
                Ok(())
            })
            .map_err(VirtioNimbleError::SpawnVhostUserDaemonThread)?;

        Ok(VirtioNimbleRunner {
            nimble_net_backend,
            runner_thread: Some(runner_thread),
        })
    }

    pub fn get_host_mem_manager(&self) -> Arc<RwLock<VhostUserNimbleNetBackend>> {
        self.nimble_net_backend.clone()
    }

    fn thread_run(
        mut nimble_net_daemon: VhostNimbleUserDaemon,
        nimble_net_backend: Arc<RwLock<VhostUserNimbleNetBackend>>,
        client: bool,
        socket: String,
    ) -> NimbleResult<()> {
        if let Err(e) = if client {
            nimble_net_daemon.start_client(&socket)
        } else {
            nimble_net_daemon.start(Listener::new(&socket, true).map_err(VirtioNimbleError::VhostUser)?)
        } {
            return Err(VirtioNimbleError::VhostUserDaemon(e));
        }

        if let Err(e) = nimble_net_daemon.wait() {
            return Err(VirtioNimbleError::VhostUserDaemon(e));
        }
        for thread in nimble_net_backend
            .read()
            .map_err(|e| VirtioNimbleError::BackendLock { error: e.to_string() })?
            .threads
            .iter()
        {
            if let Err(e) = thread.lock().unwrap().kill_evt.write(1) {
                return Err(VirtioNimbleError::WorkerShutDown(e));
            }
        }
        Ok(())
    }
}

impl Drop for VirtioNimbleRunner {
    fn drop(&mut self) {
        if let Some(runner_thread) = self.runner_thread.take() {
            if let Err(e) = runner_thread.join() {
                error!("Error joining on virtio-nimble-net backend thread: {:?}", e);
            }
        }
    }
}
