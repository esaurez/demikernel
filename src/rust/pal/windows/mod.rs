// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Exports
//======================================================================================================================

#[cfg(all(feature = "catmem-libos", feature = "nimble-shmem"))]
pub mod nimble_shm;
#[cfg(all(feature = "catmem-libos", feature = "nimble-shmem"))]
pub mod virtio_shmem_lib;
