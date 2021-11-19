use afpacket::async_std::RawPacketStream;
use futures_lite::{future, AsyncReadExt};
use nom::HexDisplay;

fn main() {
    future::block_on(async {
        let mut ps = RawPacketStream::new().unwrap();
        loop {
            let mut buf = [0u8; 1500];
            ps.read(&mut buf).await.unwrap();
            println!("{}", buf.to_hex(24));
        }
    })
}
