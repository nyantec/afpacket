use std::io::{Error, ErrorKind, Read, Result, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use libc::*;

use super::*;
use std::fmt::Arguments;

impl RawPacketStream {
    pub fn new() -> Result<Self> {
        let mut i = 0;
        let fd = loop {
            let path = format!("/dev/bpf{}\0", i);
            let fd = unsafe { open(path.as_ptr() as *const _, O_RDWR) };
            if fd != -1 {
                break fd;
            }
            i += 1;
            if i >= 100 {
                return Err(Error::last_os_error());
            }
        };

        // buffer length has to be retrieved to make the socket active
        let mut length = 0u32;
        if unsafe { ioctl(fd, BIOCGBLEN as _, &mut length as *mut _) } == -1 {
            return Err(Error::last_os_error());
        }

        Ok(RawPacketStream(fd as RawFd))
    }

    pub(crate) fn bind_internal(&self, if_name: &str) -> Result<()> {
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };

        ifr.ifr_name[..if_name.len()].copy_from_slice(if_name.as_ref());

        if unsafe { ioctl(self.0, BIOCSETIF as _, &ifr) } == -1 {
            return Err(Error::last_os_error());
        }

        // set imidiat mode
        let value = 1;
        if unsafe { ioctl(self.0, BIOCIMMEDIATE as _, &value) } == -1 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }

    pub(crate) fn set_promisc_internal(&self, state: bool) -> Result<()> {
        let value = if state { 1 } else { 0 };
        if unsafe { ioctl(self.0, BIOCPROMISC as _, &value) } == -1 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn get_buffer_size(&self) -> Result<u32> {
        let mut length = 0u32;
        if unsafe { ioctl(self.0, BIOCGBLEN as _, &mut length as *mut _) } == -1 {
            return Err(Error::last_os_error());
        }
        Ok(length)
    }
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> Result<usize> {
    let rv = unsafe { read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
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
    let rv = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
    if rv < 0 {
        return Err(Error::last_os_error());
    }

    Ok(rv as usize)
}

fn flush_fd(fd: RawFd) -> Result<()> {
    if unsafe { ioctl(fd, BIOCFLUSH as _) } == -1 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

impl Write for RawPacketStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        write_fd(self.0, buf)
    }

    fn flush(&mut self) -> Result<()> {
        flush_fd(self.0)
    }
}

impl<'a> Write for &'a RawPacketStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        write_fd(self.0, buf)
    }

    fn flush(&mut self) -> Result<()> {
        flush_fd(self.0)
    }
}

impl Drop for RawPacketStream {
    fn drop(&mut self) {
        unsafe { close(self.0) };
    }
}

#[repr(C)]
union IfrIfru {
    ifru_addr: sockaddr,
    ifru_addr_v4: sockaddr_in,
    ifru_addr_v6: sockaddr_in,
    ifru_dstaddr: sockaddr,
    ifru_broadaddr: sockaddr,
    ifru_flags: c_short,
    ifru_metric: c_int,
    ifru_mtu: c_int,
    ifru_phys: c_int,
    ifru_media: c_int,
    ifru_intval: c_int,
    //ifru_data: caddr_t,
    //ifru_devmtu: ifdevmtu,
    //ifru_kpi: ifkpi,
    ifru_wake_flags: u32,
    ifru_route_refcnt: u32,
    ifru_cap: [c_int; 2],
    ifru_functional_type: u32,
}

#[repr(C)]
pub struct ifreq {
    ifr_name: [c_uchar; IF_NAMESIZE],
    ifr_ifru: IfrIfru,
}
