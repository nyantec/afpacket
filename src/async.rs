use super::sync::RawPacketStream as SyncRawPacketStream;
pub use super::sync::{Filter, FilterProgram};
use async_io::Async;
use futures_lite::io::{AsyncRead, AsyncWrite};
use std::io::Result;
use std::os::unix::prelude::{AsRawFd, FromRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Debug, Clone)]
pub struct RawPacketStream(Arc<Async<SyncRawPacketStream>>);

#[cfg(any(target_family = "unix", doc))]
impl RawPacketStream {
    pub fn new() -> Result<RawPacketStream> {
        Ok(SyncRawPacketStream::new()?.into())
    }

    pub fn bind(&mut self, name: &str) -> Result<()> {
        (&*self.0).as_ref().bind_internal(name)
    }

    // TODO: add darwin
    #[cfg(any(target_os = "linux", doc))]
    pub fn set_promisc(&mut self, name: &str, state: bool) -> Result<()> {
        (&*self.0).as_ref().set_promisc_internal(name, state)
    }

    // TODO: add darwin
    #[cfg(any(target_os = "linux", doc))]
    pub fn set_bpf_filter(&mut self, filter: FilterProgram) -> Result<()> {
        (&*self.0).as_ref().set_bpf_filter_internal(filter)
    }
}

#[cfg(any(target_family = "unix", doc))]
impl AsyncRead for RawPacketStream {
    fn poll_read(self: Pin<&mut Self>, ctx: &mut Context, buf: &mut [u8]) -> Poll<Result<usize>> {
        Pin::new(&mut &*self.0).poll_read(ctx, buf)
    }
}

#[cfg(any(target_family = "unix", doc))]
impl AsyncWrite for RawPacketStream {
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context, buf: &[u8]) -> Poll<Result<usize>> {
        Pin::new(&mut &*self.0).poll_write(ctx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Result<()>> {
        Pin::new(&mut &*self.0).poll_flush(ctx)
    }
    fn poll_close(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Result<()>> {
        Pin::new(&mut &*self.0).poll_close(ctx)
    }
}

#[cfg(any(target_family = "unix", doc))]
impl From<SyncRawPacketStream> for RawPacketStream {
    fn from(sync: SyncRawPacketStream) -> RawPacketStream {
        RawPacketStream(Arc::new(Async::new(sync).expect("oopsie whoopsie")))
    }
}

#[cfg(any(target_family = "unix", doc))]
impl AsRawFd for RawPacketStream {
    fn as_raw_fd(&self) -> RawFd {
        (&*self.0).get_ref().as_raw_fd()
    }
}

#[cfg(any(target_family = "unix", doc))]
impl FromRawFd for RawPacketStream {
    unsafe fn from_raw_fd(fd: RawFd) -> RawPacketStream {
        SyncRawPacketStream::from_raw_fd(fd).into()
    }
}
