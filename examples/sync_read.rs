use std::io::Read;

use afpacket::sync::RawPacketStream;
use nom::HexDisplay;

fn main() {
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

        let read = ps.read(&mut buf).unwrap();
        println!("{}", (&buf[..read]).to_hex(24));
    }
}
