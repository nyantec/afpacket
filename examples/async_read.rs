use afpacket::r#async::RawPacketStream;
use futures_lite::{future, AsyncReadExt};
use nom::HexDisplay;

fn main() {
    future::block_on(async {
        let mut ps = RawPacketStream::new().unwrap();
        loop {
            #[cfg(target_os = "linux")]
            let mut buf = [0u8; 1500];
            #[cfg(target_os = "macos")]
            let mut buf = [0u8; 4096];

            #[cfg(target_os = "linux")]
            ps.bind("lo");
            #[cfg(target_os = "macos")]
            ps.bind("lo0");

            let read = ps.read(&mut buf).await.unwrap();
            println!("{}", (&buf[..read]).to_hex(24));
        }
    })
}
