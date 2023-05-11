// SPDX-License-Identifier: GPL-2.0

//! Networking.
//!
//! C headers: [`include/linux/net.h`](../../../../include/linux/net.h),
//! [`include/linux/socket.h`](../../../../include/linux/socket.h),

use crate::{
    bindings,
    error::{to_result, Result},
};
use alloc::vec::Vec;

/// Represents `struct socket *`.
///
/// # Invariants
///
/// The pointer is valid.
pub struct Socket {
    /// temporary hack.
    pub sock: *mut bindings::socket,
}

impl Drop for Socket {
    fn drop(&mut self) {
        // SAFETY: The type invariant guarantees that the pointer is valid.
        unsafe { bindings::sock_release(self.sock) }
    }
}

/// Address families. Defines AF_* here.
pub enum Family {
    /// Internet IP Protocol.
    Ip = bindings::AF_INET as isize,
}

/// Communication type.
pub enum SocketType {
    /// Stream (connection).
    Stream = bindings::sock_type_SOCK_STREAM as isize,
}

/// Protocols.
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp = bindings::IPPROTO_TCP as isize,
}

impl Socket {
    /// Creates a [`Socket`] object.
    pub fn new(family: Family, sf: SocketType, proto: Protocol) -> Result<Self> {
        let mut sock = core::ptr::null_mut();

        // SAFETY: FFI call.
        to_result(unsafe {
            bindings::sock_create_kern(
                &mut bindings::init_net,
                family as _,
                sf as _,
                proto as _,
                &mut sock,
            )
        })
        .map(|_| Socket { sock })
    }

    /// Moves a socket to listening state.
    pub fn listen(&mut self, backlog: i32) -> Result {
        // SAFETY: The type invariant guarantees that the pointer is valid.
        to_result(unsafe { bindings::kernel_listen(self.sock, backlog) })
    }

    /// Binds an address to a socket.
    pub fn bind(&mut self, addr: &SocketAddr) -> Result {
        let (addr, addrlen) = match addr {
            SocketAddr::V4(addr) => (
                addr as *const _ as _,
                core::mem::size_of::<bindings::sockaddr>() as i32,
            ),
        };
        // SAFETY: The type invariant guarantees that the pointer is valid.
        to_result(unsafe { bindings::kernel_bind(self.sock, addr, addrlen) })
    }

    /// Accepts a connection
    pub fn accept(&mut self) -> Result<Self> {
        let mut client = core::ptr::null_mut();
        // SAFETY: The type invariant guarantees that the pointer is valid.
        to_result(unsafe { bindings::kernel_accept(self.sock, &mut client, 0) })
            .map(|_| Socket { sock: client })
    }

    /// Receives a message from a socket.
    pub fn recvmsg(&mut self, bufs: &mut [&mut [u8]], flags: i32) -> Result<usize> {
        let mut msg = bindings::msghdr::default();
        let mut kvec = Vec::try_with_capacity(bufs.len())?;
        let mut len = 0;
        for i in 0..bufs.len() {
            len += bufs[i].len();
            kvec.try_push(bindings::kvec {
                iov_base: bufs[i].as_mut_ptr().cast(),
                iov_len: bufs[i].len(),
            })?;
        }
        // SAFETY: The type invariant guarantees that the pointer is valid.
        let r = unsafe {
            bindings::kernel_recvmsg(
                self.sock,
                &mut msg,
                kvec.as_mut_ptr(),
                bufs.len(),
                len,
                flags,
            )
        };
        to_result(r).map(|_| r as usize)
    }

    /// Sends a message through a socket.
    pub fn sendmsg(&mut self, bufs: &[&[u8]]) -> Result<usize> {
        let mut msg = bindings::msghdr::default();
        let mut kvec = Vec::try_with_capacity(bufs.len())?;
        let mut len = 0;
        for i in 0..bufs.len() {
            len += bufs[i].len();
            kvec.try_push(bindings::kvec {
                iov_base: bufs[i].as_ptr() as *mut u8 as _,
                iov_len: bufs[i].len(),
            })?;
        }
        // SAFETY: The type invariant guarantees that the pointer is valid.
        let r = unsafe {
            bindings::kernel_sendmsg(self.sock, &mut msg, kvec.as_mut_ptr(), bufs.len(), len)
        };
        to_result(r).map(|_| r as usize)
    }
}

/// A socket address.
pub enum SocketAddr {
    /// An IPv4 socket address.
    V4(SocketAddrV4),
}

/// Represents `struct in_addr`.
#[repr(transparent)]
pub struct Ipv4Addr(bindings::in_addr);

impl Ipv4Addr {
    /// Creates a new IPv4 address from four eight-bit octets.
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(bindings::in_addr {
            s_addr: u32::from_be_bytes([a, b, c, d]).to_be(),
        })
    }
}

/// Prepresents `struct sockaddr_in`.
#[repr(transparent)]
pub struct SocketAddrV4(bindings::sockaddr_in);

impl SocketAddrV4 {
    /// Creates a new IPv4 socket address.
    pub const fn new(addr: Ipv4Addr, port: u16) -> Self {
        Self(bindings::sockaddr_in {
            sin_family: Family::Ip as _,
            sin_port: port.to_be(),
            sin_addr: addr.0,
            __pad: [0; 8],
        })
    }
}

/// Waits for a full request
pub const MSG_WAITALL: i32 = bindings::MSG_WAITALL as i32;
