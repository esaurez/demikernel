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
use std::{
    net::{
        Ipv4Addr,
        SocketAddr,
        SocketAddrV4,
    },
    str::FromStr,
};

#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::SOCKADDR;

#[cfg(target_os = "windows")]
pub const AF_INET: windows::Win32::Networking::WinSock::ADDRESS_FAMILY = windows::Win32::Networking::WinSock::AF_INET;

#[cfg(target_os = "windows")]
pub const AF_INET_VALUE: i32 = AF_INET.0 as i32;

#[cfg(target_os = "windows")]
pub const SOCK_DGRAM: i32 = windows::Win32::Networking::WinSock::SOCK_DGRAM.0 as i32;

#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::SOCKADDR_IN;

#[cfg(target_os = "linux")]
pub const AF_INET_VALUE: i32 = libc::AF_INET;

#[cfg(target_os = "linux")]
pub const SOCK_DGRAM: i32 = libc::SOCK_DGRAM;

//======================================================================================================================
// Structures
//======================================================================================================================

/// A UDP echo server.
pub struct UdpEchoServer {
    /// IP of the client
    remote: String,
    /// Underlying libOS.
    libos: LibOS,
    /// Local socket descriptor.
    sockqd: QDesc,
    /// List of pending operations.
    qts: Vec<QToken>,
}

//======================================================================================================================
// Associated Functions
//======================================================================================================================

impl UdpEchoServer {
    /// Instantiates a new TCP echo server.
    pub fn new(mut libos: LibOS, local: SocketAddr, remote: String) -> Result<Self> {
        // Create a TCP socket.
        let sockqd: QDesc = libos.socket(AF_INET_VALUE, SOCK_DGRAM, 0)?;

        // Bind the socket to a local address.
        if let Err(e) = libos.bind(sockqd, local) {
            println!("ERROR: {:?}", e);
            libos.close(sockqd)?;
            anyhow::bail!("failed to bind socket: {:?}", e);
        }

        println!("INFO: listening on {:?}", local);

        return Ok(Self {
            remote,
            libos,
            sockqd,
            qts: Vec::default(),
        });
    }

    /// Runs the target TCP echo server.
    pub fn run(&mut self, _log_interval: Option<u64>, niterations: usize) -> Result<()> {
        for iter in 0..niterations {
            // Initialize the server with a pop operation.
            self.issue_pop(self.sockqd)?;
            loop {
                // Wait for any operation to complete.
                let qr: demi_qresult_t = {
                    let (index, qr): (usize, demi_qresult_t) = match self.libos.wait_any(&self.qts, None) {
                        Ok((index, qr)) => (index, qr),
                        Err(e) => {
                            if e.errno == libc::ETIMEDOUT {
                                println!("Wait timed out: {:?}", e);
                                return Ok(());
                            }
                            println!("ERROR: {:?}", e);
                            return Err(e.into());
                        },
                    };
                    self.unregister_operation(index)?;
                    qr
                };

                // Parse result.
                match qr.qr_opcode {
                    demi_opcode_t::DEMI_OPC_POP => {
                        if self.handle_pop(&qr)? {
                            break;
                        }
                    },
                    demi_opcode_t::DEMI_OPC_PUSH => self.handle_push()?,
                    demi_opcode_t::DEMI_OPC_FAILED => self.handle_fail(&qr)?,
                    demi_opcode_t::DEMI_OPC_INVALID => self.handle_unexpected("invalid", &qr)?,
                    demi_opcode_t::DEMI_OPC_CLOSE => self.handle_unexpected("close", &qr)?,
                    demi_opcode_t::DEMI_OPC_CONNECT => self.handle_unexpected("connect", &qr)?,
                    demi_opcode_t::DEMI_OPC_ACCEPT => self.handle_unexpected("accept", &qr)?,
                }
            }

            // Clean up any pending operations.
            self.qts.clear();

            println!("INFO: iteration {} completed", iter);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    /// Converts a [sockaddr] into a [SocketAddrV4].
    pub fn sockaddr_to_port(saddr: libc::sockaddr) -> Result<u16> {
        // TODO: Change the logic below and rename this function once we support V6 addresses as well.
        let sin: libc::sockaddr_in = unsafe { mem::transmute(saddr) };
        if sin.sin_family != libc::AF_INET as u16 {
            anyhow::bail!("communication domain not supported");
        };
        // let addr: Ipv4Addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let port: u16 = u16::from_be(sin.sin_port);
        Ok(port)
    }

    #[cfg(target_os = "windows")]
    /// Converts a [sockaddr] into a [SocketAddrV4].
    pub fn sockaddr_to_port(saddr: SOCKADDR) -> Result<SocketAddrV4> {
        // Casting to SOCKADDR_IN
        let addr_in: SOCKADDR_IN = unsafe { std::mem::transmute(saddr) };

        if addr_in.sin_family != AF_INET {
            anyhow::bail!("communication domain not supported");
        };
        // Extracting IPv4 address and port
        // let ipv4_addr: Ipv4Addr = Ipv4Addr::from(u32::from_be(unsafe {addr_in.sin_addr.S_un.S_addr }));
        let port: u16 = u16::from_be(addr_in.sin_port);

        // Creating SocketAddrV4
        Ok(port)
    }

    /// Issues a push operation.
    fn issue_push(&mut self, qr: &demi_qresult_t, sga: &demi_sgarray_t) -> Result<()> {
        let qd: QDesc = qr.qr_qd.into();
        let port = Self::sockaddr_to_port(unsafe { qr.qr_value.sga.sga_addr })?;
        let saddr: SocketAddr = SocketAddr::from_str(&format!("{}:{}", self.remote, port))?;

        // Push packet back.
        let qt: QToken = match self.libos.pushto(qd, sga, saddr) {
            Ok(qt) => qt,
            Err(e) => {
                anyhow::bail!("failed to push data to socket: {:?}", e)
            },
        };

        self.register_operation(qt);
        Ok(())
    }

    /// Issues a pop operation.
    fn issue_pop(&mut self, qd: QDesc) -> Result<()> {
        let qt: QToken = self.libos.pop(qd, None)?;
        self.register_operation(qt);
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

    /// Handles the completion of a push operation.
    fn handle_push(&mut self) -> Result<()> {
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

    /// Handles the completion of a pop() operation.
    fn handle_pop(&mut self, qr: &demi_qresult_t) -> Result<bool> {
        let qd: QDesc = qr.qr_qd.into();
        let sga: demi_sgarray_t = unsafe { qr.qr_value.sga };
        let len: u32 = sga.sga_segs[0].sgaseg_len;

        // Check if we received any data.
        if len == 1 {
            // Chose message size equal 1 to mean end of iteration for the evaluation
            return Ok(true);
        } else {
            // Push packet back.
            self.issue_push(qr, &sga)?;
            // Pop next packet.
            self.issue_pop(qd)?;
        }

        // Free scatter-gather array.
        self.libos.sgafree(sga)?;

        Ok(false)
    }

    /// Registers an asynchronous I/O operation.
    fn register_operation(&mut self, qt: QToken) {
        self.qts.push(qt);
    }

    /// Unregisters an asynchronous I/O operation.
    fn unregister_operation(&mut self, index: usize) -> Result<()> {
        let _: QToken = self.qts.swap_remove(index);
        Ok(())
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl Drop for UdpEchoServer {
    fn drop(&mut self) {
        // Close local socket
        if let Err(e) = self.libos.close(self.sockqd) {
            println!("ERROR: {:?}", e);
        }
    }
}
