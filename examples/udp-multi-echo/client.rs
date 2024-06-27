// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use anyhow::Result;
use demikernel::{
    demi_sgarray_t,
    runtime::types::{
        demi_opcode_t,
        demi_qresult_t,
    },
    LibOS,
    QDesc,
    QToken,
};
use histogram::Histogram;
use std::{
    collections::HashMap,
    net::SocketAddr,
    slice,
    str::FromStr,
    time::{
        Duration,
        Instant,
    },
};

#[cfg(target_os = "windows")]
pub const AF_INET: windows::Win32::Networking::WinSock::ADDRESS_FAMILY = windows::Win32::Networking::WinSock::AF_INET;

#[cfg(target_os = "windows")]
pub const AF_INET_VALUE: i32 = AF_INET.0 as i32;

#[cfg(target_os = "linux")]
pub const AF_INET_VALUE: i32 = libc::AF_INET;

#[cfg(target_os = "windows")]
pub const SOCK_DGRAM: i32 = windows::Win32::Networking::WinSock::SOCK_DGRAM.0 as i32;

#[cfg(target_os = "linux")]
pub const SOCK_DGRAM: i32 = libc::SOCK_DGRAM;

//======================================================================================================================
// Structures
//======================================================================================================================

/// A Udp echo client.
pub struct UdpEchoClient {
    /// Underlying libOS.
    libos: LibOS,
    /// Buffer size.
    bufsize: usize,
    /// Number of packets echoed back.
    nechoed: usize,
    /// Number of bytes transferred.
    nbytes: usize,
    /// Number of packets pushed to server.
    npushed: usize,
    /// Number of packets that had to be retried.
    retried: usize,
    /// Set of connected clients. Each client has a buffer and an index into the buffer. Plus time the first message was received, the number of messages received, and the time the last messaged was sent.
    clients: HashMap<QDesc, (Vec<u8>, usize, Instant, usize, u64)>,
    /// Address of remote peer.
    remote: SocketAddr,
    /// Local ip address
    local_ip: String,
    /// Base port
    base_port: u16,
    /// List of pending operations.
    qts: Vec<QToken>,
    /// Start time.
    start: Instant,
    /// Statistics.
    stats: Histogram,
}

//======================================================================================================================
// Associated Functions
//======================================================================================================================

impl UdpEchoClient {
    /// Instantiates a new TCP echo client.
    pub fn new(libos: LibOS, bufsize: usize, remote: SocketAddr, local_ip: String, base_port: u16) -> Result<Self> {
        return Ok(Self {
            libos,
            bufsize,
            nechoed: 0,
            nbytes: 0,
            npushed: 0,
            retried: 0,
            clients: HashMap::default(),
            remote,
            local_ip,
            base_port,
            qts: Vec::default(),
            start: Instant::now(),
            stats: Histogram::new(7, 64)?,
        });
    }

    fn print_stats(&mut self, time_elapsed: f64) -> Result<()> {
        let nrequests: f64 = (self.nbytes / self.bufsize) as f64;
        let rps: f64 = nrequests / time_elapsed;
        println!(
            "INFO: {:?} requests, {:2?} rps, p50 {:?} ns, p99 {:?} ns",
            nrequests,
            rps,
            self.stats.percentile(0.50)?.start(),
            self.stats.percentile(0.99)?.start()
        );
        Ok(())
    }

    /// Runs the target UDP echo client.
    pub fn run_sequential(
        &mut self,
        log_interval: Option<u64>,
        nclients: usize,
        nrequests: Option<usize>,
        niterations: usize,
    ) -> Result<()> {
        let udp_wait_timeout = Duration::from_micros(1000);

        for iter in 0..niterations {
            println!("INFO: Starting iteration {}", iter);
            self.nechoed = 0;
            self.npushed = 0;
            self.nbytes = 0;
            self.retried = 0;
            let mut last_log: Instant = Instant::now();
            self.start = Instant::now();
            self.stats = Histogram::new(7, 64)?;

            // Open all connections.
            for client_id in 0..nclients {
                let client_local_address = format!("{}:{}", self.local_ip, self.base_port + client_id as u16);
                let client_socket_address = SocketAddr::from_str(&client_local_address)?;
                let sockqd: QDesc = self.libos.socket(AF_INET_VALUE, SOCK_DGRAM, 1)?;
                self.clients
                    .insert(sockqd.clone(), (vec![0; self.bufsize], 0, Instant::now(), 0, 0));
                match self.libos.bind(sockqd.clone(), client_socket_address) {
                    Ok(_) => {},
                    Err(e) => {
                        anyhow::bail!("failed to bind socket: {:?}", e);
                    },
                }
                self.issue_push(sockqd, None)?;
            }

            loop {
                // Stop: enough packets were echoed.
                if let Some(nrequests) = nrequests {
                    if self.nechoed >= nrequests {
                        println!("INFO: {} requests completed", self.nechoed);
                        break;
                    }
                }

                // Dump statistics.
                if let Some(log_interval) = log_interval {
                    if last_log.elapsed() > Duration::from_secs(log_interval) {
                        let time_elapsed: f64 = (Instant::now() - last_log).as_secs() as f64;
                        self.print_stats(time_elapsed)?;
                        last_log = Instant::now();
                        self.nbytes = 0;
                    }
                }

                let qr: demi_qresult_t = match self.libos.wait_any(&self.qts, Some(udp_wait_timeout)) {
                    Ok((index, qr)) => {
                        self.unregister_operation(index)?;
                        qr
                    },
                    Err(e) => {
                        if e.errno == libc::ETIMEDOUT {
                            // 250 us timeout expired.
                            self.retried += 1;
                            // Push a message to all clients.
                            let clients = self.clients.clone();
                            for (sockqd, _) in clients.iter() {
                                self.issue_push(sockqd.clone(), None)?;
                            }
                            continue;
                        } else {
                            anyhow::bail!("failed to wait for any operation: {:?}", e);
                        }
                    },
                };

                // Parse result.
                match qr.qr_opcode {
                    demi_opcode_t::DEMI_OPC_PUSH => self.handle_push(&qr)?,
                    demi_opcode_t::DEMI_OPC_POP => self.handle_pop(&qr)?,
                    demi_opcode_t::DEMI_OPC_FAILED => self.handle_fail(&qr)?,
                    demi_opcode_t::DEMI_OPC_INVALID => self.handle_unexpected("invalid", &qr)?,
                    demi_opcode_t::DEMI_OPC_CLOSE => self.handle_unexpected("close", &qr)?,
                    demi_opcode_t::DEMI_OPC_CONNECT => self.handle_unexpected("connect", &qr)?,
                    demi_opcode_t::DEMI_OPC_ACCEPT => self.handle_unexpected("accept", &qr)?,
                }
            }

            if let Some(nrequests) = nrequests {
                let time_now = Instant::now();
                let time_elapsed: f64 = (time_now - last_log).as_secs() as f64;

                println!("INFO: Printing for {} requests", nrequests);

                self.print_stats(time_elapsed)?;

                // For each client print the average latency, using the start time in start_time
                for (_qd, (_buf, _index, start, num_messages, _last_message_time)) in &self.clients {
                    let time_elapsed: u64 = (time_now - *start).as_nanos() as u64;
                    let average: u64 = time_elapsed / *num_messages as u64;
                    println!("INFO: Average latency {:?} ns with time elapsed {} for {} messages with end at {} and begin at {}", average, time_elapsed, num_messages, time_now.duration_since(self.start).as_nanos(), start.duration_since(self.start).as_nanos());
                }
            }

            println!(
                "INFO: done (nechoed={}, nbytes={}, npushed={}, retried={})",
                self.nechoed, self.nbytes, self.npushed, self.retried
            );

            // Close all connections.
            for (qd, _) in self.clients.drain().collect::<Vec<_>>() {
                self.close_socket(qd)?;
            }

            // Drop all pending operations.
            self.qts.clear();
        }

        Ok(())
    }

    fn close_socket(&mut self, qd: QDesc) -> Result<()> {
        // Send a message with size 1 to signal the server to close the connection
        let sga: demi_sgarray_t = self.mksga(1, 0, true)?;
        let qt: QToken = match self.libos.pushto(qd, &sga, self.remote) {
            Ok(qt) => qt,
            Err(e) => anyhow::bail!("failed to send close message: {:?}", e),
        };
        match self.libos.wait(qt, None) {
            Ok(qr) if qr.qr_opcode == demi_opcode_t::DEMI_OPC_PUSH => (),
            Ok(_) => anyhow::bail!("unexpected result"),
            Err(e) => anyhow::bail!("operation failed: {:?}", e),
        };
        match self.libos.sgafree(sga) {
            Ok(_) => {},
            Err(e) => anyhow::bail!("failed to release scatter-gather array: {:?}", e),
        }
        // Close the socket
        self.libos.close(qd)?;
        Ok(())
    }

    // Makes a scatter-gather array.
    fn mksga(&mut self, size: usize, message_time: u64, close_connection: bool) -> Result<demi_sgarray_t> {
        if !close_connection {
            debug_assert!(size > std::mem::size_of::<u64>());
            let sga: demi_sgarray_t = self.libos.sgaalloc(size)?;
            let ptr: *mut u8 = sga.sga_segs[0].sgaseg_buf as *mut u8;
            let len: usize = sga.sga_segs[0].sgaseg_len as usize;
            let slice: &mut [u8] = unsafe { slice::from_raw_parts_mut(ptr, len) };
            slice[0..8].copy_from_slice(&message_time.to_le_bytes());
            Ok(sga)
        } else {
            // Allocate scatter-gather array.
            let sga: demi_sgarray_t = match self.libos.sgaalloc(size) {
                Ok(sga) => sga,
                Err(e) => anyhow::bail!("failed to allocate scatter-gather array: {:?}", e),
            };

            // Ensure that scatter-gather array has the requested size.
            // If error, free scatter-gather array.
            if sga.sga_segs[0].sgaseg_len as usize != size {
                Self::freesga(&mut self.libos, sga);
                let seglen: usize = sga.sga_segs[0].sgaseg_len as usize;
                anyhow::bail!(
                    "failed to allocate scatter-gather array: expected size={:?} allocated size={:?}",
                    size,
                    seglen
                );
            }

            // Fill in scatter-gather array.
            let ptr: *mut u8 = sga.sga_segs[0].sgaseg_buf as *mut u8;
            let len: usize = sga.sga_segs[0].sgaseg_len as usize;
            let slice: &mut [u8] = unsafe { slice::from_raw_parts_mut(ptr, len) };
            slice.fill(0);
            Ok(sga)
        }
    }

    /// Free scatter-gather array and warn on error.
    fn freesga(libos: &mut LibOS, sga: demi_sgarray_t) {
        if let Err(e) = libos.sgafree(sga) {
            println!("ERROR: sgafree() failed (error={:?})", e);
            println!("WARN: leaking sga");
        }
    }

    /// Handles the completion of a pop operation.
    fn handle_pop(&mut self, qr: &demi_qresult_t) -> Result<()> {
        let qd: QDesc = qr.qr_qd.into();
        let sga: demi_sgarray_t = unsafe { qr.qr_value.sga };

        // Retrieve client buffer.
        let (recvbuf, index, _, count, _last_msg_time): &mut (Vec<u8>, usize, Instant, usize, u64) = self
            .clients
            .get_mut(&qd)
            .ok_or(anyhow::anyhow!("unregistered socket"))?;

        // Copy data.
        let ptr: *mut u8 = sga.sga_segs[0].sgaseg_buf as *mut u8;
        let len: usize = sga.sga_segs[0].sgaseg_len as usize;
        let slice: &mut [u8] = unsafe { slice::from_raw_parts_mut(ptr, len) };
        recvbuf[*index..(*index + len)].copy_from_slice(slice);

        // TODO: Sanity check packet.

        *index += len;
        self.nbytes += len;

        // Check if there are more bytes to read from this packet.
        if *index < recvbuf.capacity() {
            self.libos.sgafree(sga)?;

            // There are, thus issue a partial pop.
            let size: usize = recvbuf.capacity() - *index;
            self.issue_pop(qd, Some(size))?;
        }
        // Push another packet.
        else {
            // Read timestamp from recvbuf.
            let timestamp: u64 = u64::from_le_bytes([
                recvbuf[0], recvbuf[1], recvbuf[2], recvbuf[3], recvbuf[4], recvbuf[5], recvbuf[6], recvbuf[7],
            ]);
            let now: u64 = Instant::now().duration_since(self.start).as_nanos() as u64;
            let elapsed: u64 = now - timestamp;
            // println!("Current: {}, prev: {}, elapsed: {}", now, timestamp, elapsed);
            self.stats.increment(elapsed)?;

            self.libos.sgafree(sga)?;

            // There aren't, so push another packet.
            *count += 1;
            *index = 0;
            self.nechoed += 1;
            self.issue_push(qd, None)?;
        }
        Ok(())
    }

    /// Handles the completion of a push operation.
    fn handle_push(&mut self, qr: &demi_qresult_t) -> Result<()> {
        let qd: QDesc = qr.qr_qd.into();
        self.npushed += 1;

        // Pop another packet
        self.issue_pop(qd, None)?;
        Ok(())
    }

    /// Handles the completion of an unexpected operation.
    fn handle_unexpected(&mut self, op_name: &str, qr: &demi_qresult_t) -> Result<()> {
        let qd: QDesc = qr.qr_qd.into();
        let qt: QToken = qr.qr_qt.into();

        println!(
            "WARN: unexpected {} operation completed, ignoring (qd={:?}, qt={:?})",
            op_name, qd, qt
        );

        Ok(())
    }

    /// Handles an operation that failed.
    fn handle_fail(&mut self, qr: &demi_qresult_t) -> Result<()> {
        let qd: QDesc = qr.qr_qd.into();
        let qt: QToken = qr.qr_qt.into();
        let errno: i64 = qr.qr_ret;

        println!(
            "WARN: operation failed, ignoring (qd={:?}, qt={:?}, errno={:?})",
            qd, qt, errno
        );

        Ok(())
    }

    /// Issues a pop operation.
    fn issue_pop(&mut self, qd: QDesc, size: Option<usize>) -> Result<()> {
        let qt: QToken = self.libos.pop(qd, size)?;
        self.register_operation(qt);
        Ok(())
    }

    /// Issues a push operation
    fn issue_push(&mut self, qd: QDesc, time: Option<u64>) -> Result<()> {
        let message_time = if let Some(t) = time {
            t
        } else {
            Instant::now().duration_since(self.start).as_nanos() as u64
        };
        // println!("Sending message with time {}", message_time);
        let sga: demi_sgarray_t = self.mksga(self.bufsize, message_time, false)?;
        let qt: QToken = self.libos.pushto(qd, &sga, self.remote)?;
        self.register_operation(qt);
        Ok(())
    }

    // Registers an asynchronous I/O operation.
    fn register_operation(&mut self, qt: QToken) {
        self.qts.push(qt);
    }

    // Unregisters an asynchronous I/O operation.
    fn unregister_operation(&mut self, index: usize) -> Result<()> {
        let _: QToken = self.qts.swap_remove(index);
        Ok(())
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl Drop for UdpEchoClient {
    // Releases all resources allocated to a pipe client.
    fn drop(&mut self) {
        // Close all connections.
        for (qd, _) in self.clients.drain().collect::<Vec<_>>() {
            if let Err(e) = self.close_socket(qd) {
                println!("ERROR: close() failed (error={:?}", e);
                println!("WARN: leaking qd={:?}", qd);
            }
        }
    }
}
