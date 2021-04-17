//! Rust bindings for Linux AF_PACKET (raw) sockets
//! > Packet sockets are used to receive or send raw packets at the device
//! > driver (OSI Layer 2) level.  They allow the user to implement
//! > protocol modules in user space on top of the physical layer.
//!   -- [packet(7)](http://man7.org/linux/man-pages/man7/packet.7.html)

#[cfg(feature = "async")]
/// Async wrapper for use with `futures` or `async-std`
///
/// Example usage:
/// ```
/// use afpacket::r#async::RawPacketStream;
/// use futures_lite::{future, AsyncReadExt};
/// use nom::HexDisplay;
///
/// fn main() {
///     future::block_on(async {
///         let mut ps = RawPacketStream::new().unwrap();
///         loop {
///             let mut buf = [0u8; 1500];
///             ps.read(&mut buf).await.unwrap();
///             println!("{}", buf.to_hex(24));
///         }
///     })
/// }
/// ```
pub mod r#async;

/// The bindings
///
/// Example usage:
/// ```
/// use afpacket::sync::RawPacketStream;
/// use nom::HexDisplay;
///
/// fn main() {
///     let mut ps = RawPacketStream::new().unwrap();
///     loop {
///         let mut buf = [0u8; 1500];
///         ps.read(&mut buf).unwrap();
///         println!("{}", buf.to_hex(24));
///     }
/// }
/// ```
pub mod sync;
