// Derived from the mio-afpacket crate by Alexander Polakov <plhk@sdf.org>,
// licensed under the MIT license. https://github.com/polachok/mio-afpacket

use std::io::{Error, ErrorKind, Read, Result, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use libc::{sockaddr_ll, sockaddr_storage, socket, packet_mreq, setsockopt};
use libc::{AF_PACKET, ETH_P_ALL, SOCK_RAW, SOL_PACKET, SOL_SOCKET, PACKET_MR_PROMISC,
        SO_ATTACH_FILTER, PACKET_ADD_MEMBERSHIP, PACKET_DROP_MEMBERSHIP, MSG_DONTWAIT};

/// Packet sockets are used to receive or send raw packets at OSI 2 level.
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
    /// Create new raw packet stream binding to all interfaces
    pub fn new() -> Result<Self> {
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, i32::from((ETH_P_ALL as u16).to_be())) };
        if fd == -1 {
            return Err(Error::last_os_error());
        }
        Ok(RawPacketStream(fd as RawFd))
    }

    /// Bind socket to an interface (by name).
    pub fn bind(&mut self, name: &str) -> Result<()> {
        self.bind_internal(name)
    }

    // should take an &mut to unsure not just anyone can call it,
    // but async wrapper needs this variant
    pub(crate) fn bind_internal(&self, name: &str) -> Result<()> {
        let idx = index_by_name(name)?;
        self.bind_by_index(idx)
    }

    fn bind_by_index(&self, ifindex: i32) -> Result<()> {
        unsafe {
            let mut ss: sockaddr_storage = std::mem::zeroed();
            let sll: *mut sockaddr_ll = &mut ss as *mut sockaddr_storage as *mut sockaddr_ll;
            (*sll).sll_family = AF_PACKET as u16;
            (*sll).sll_protocol = (ETH_P_ALL as u16).to_be();
            (*sll).sll_ifindex = ifindex;

            let sa = (&ss as *const libc::sockaddr_storage) as *const libc::sockaddr;
            let res = libc::bind(self.0, sa, std::mem::size_of::<sockaddr_ll>() as u32);
            if res == -1 {
                return Err(Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn set_promisc(&mut self, name: &str, state: bool) -> Result<()> {
        self.set_promisc_internal(name, state)
    }

    // should take an &mut to unsure not just anyone can call it,
    // but async wrapper needs this variant
    pub(crate) fn set_promisc_internal(&self, name: &str, state: bool) -> Result<()> {
        let packet_membership = if state {
            PACKET_ADD_MEMBERSHIP
        } else {
            PACKET_DROP_MEMBERSHIP
        };

        let idx = index_by_name(name)?;

        unsafe {
            let mut mreq: packet_mreq = std::mem::zeroed();

            mreq.mr_ifindex = idx;
            mreq.mr_type = PACKET_MR_PROMISC as u16;

            let res = setsockopt(self.0, SOL_PACKET, packet_membership, (&mreq as *const packet_mreq) as *const libc::c_void, std::mem::size_of::<packet_mreq>() as u32);
            if res == -1 {
                return Err(Error::last_os_error());
            }
        }

        Ok(())
    }

    pub fn set_bpf_filter(&mut self, filter: FilterProgram) -> Result<()> {
        self.set_bpf_filter_internal(filter)
    }

    pub(crate) fn set_bpf_filter_internal(&self, filter: FilterProgram) -> Result<()> {
        let filters: Vec<sock_filter> = filter.into_iter().map(|x| x.into()).collect();
        let program = sock_fprog {
            len: filters.len() as u16,
            filter: filters.as_ptr(),
        };

        unsafe {
            let res = setsockopt(self.0, SOL_SOCKET, SO_ATTACH_FILTER, &program as *const _ as *const libc::c_void, std::mem::size_of::<sock_fprog>() as u32);
            if res == -1 {
                return Err(Error::last_os_error());
            }
        }

        Ok(())
    }

    pub fn drain(&mut self) {
        let mut buf = [0u8; 1];
        loop {
            let rv = unsafe { libc::recv(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), MSG_DONTWAIT) };
            if rv == -1 { break; }
        }
    }
}

fn index_by_name(name: &str) -> Result<i32> {
    if name.len() > libc::IFNAMSIZ {
        return Err(ErrorKind::InvalidInput.into());
    }
    let mut buf = [0u8; libc::IFNAMSIZ];
        buf[..name.len()].copy_from_slice(name.as_bytes());
    let idx = unsafe { libc::if_nametoindex(buf.as_ptr() as *const libc::c_char) };
    if idx == 0 {
        return Err(Error::last_os_error());
    }

    Ok(idx as i32)
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> Result<usize> {
    let rv = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if rv < 0 {
        return Err(Error::last_os_error());
    }

    Ok(rv as usize)
}

impl Read for RawPacketStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        read_fd(self.0, buf)
    }
}

impl<'a> Read for &'a RawPacketStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        read_fd(self.0, buf)
    }
}

fn write_fd(fd: RawFd, buf: &[u8]) -> Result<usize> {
    let rv = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if rv < 0 {
        return Err(Error::last_os_error());
    }

    Ok(rv as usize)
}

impl Write for RawPacketStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        write_fd(self.0, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<'a> Write for &'a RawPacketStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        write_fd(self.0, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl IntoRawFd for RawPacketStream {
    fn into_raw_fd(self) -> RawFd {
        self.0
    }
}

impl AsRawFd for RawPacketStream {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl FromRawFd for RawPacketStream {
    unsafe fn from_raw_fd(fd: RawFd) -> RawPacketStream {
        RawPacketStream(fd)
    }
}

impl Drop for RawPacketStream {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}
