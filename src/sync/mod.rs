// Derived from the mio-afpacket crate by Alexander Polakov <plhk@sdf.org>,
// licensed under the MIT license. https://github.com/polachok/mio-afpacket

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
mod linux;

use std::io::{Error, ErrorKind, Read, Result, Write};
#[cfg(any(target_family = "unix", doc))]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

/// Packet sockets are used to receive or send raw packets at OSI 2 level.
#[cfg(any(target_family = "unix", doc))]
#[derive(Debug, Clone)]
pub struct RawPacketStream(RawFd);

pub type Filter = (u16, u8, u8, u32);
pub type FilterProgram = Vec<Filter>;

#[derive(Debug, Clone)]
#[repr(C)]
struct sock_filter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[derive(Debug, Clone)]
#[repr(C)]
struct sock_fprog {
    len: u16,
    filter: *const sock_filter,
}

impl From<Filter> for sock_filter {
    fn from(f: Filter) -> sock_filter {
        sock_filter {
            code: f.0,
            jt: f.1,
            jf: f.2,
            k: f.3,
        }
    }
}

impl RawPacketStream {
    /// Bind socket to an interface (by name).
    pub fn bind(&mut self, name: &str) -> Result<()> {
        self.bind_internal(name)
    }

    // TODO: more oses
    #[cfg(any(target_os = "linux", doc))]
    pub fn set_promisc(&mut self, name: &str, state: bool) -> Result<()> {
        self.set_promisc_internal(name, state)
    }

    #[cfg(any(target_os = "macos", doc))]
    pub fn set_promisc(&mut self, state: bool) -> Result<()> {
        self.set_promisc_internal(state)
    }

    // TODO: more oses
    #[cfg(any(target_os = "linux", doc))]
    pub fn set_bpf_filter(&mut self, filter: FilterProgram) -> Result<()> {
        self.set_bpf_filter_internal(filter)
    }
}

#[cfg(any(target_family = "unix", doc))]
impl IntoRawFd for RawPacketStream {
    fn into_raw_fd(self) -> RawFd {
        self.0
    }
}

#[cfg(any(target_family = "unix", doc))]
impl AsRawFd for RawPacketStream {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(any(target_family = "unix", doc))]
impl FromRawFd for RawPacketStream {
    unsafe fn from_raw_fd(fd: RawFd) -> RawPacketStream {
        RawPacketStream(fd)
    }
}
