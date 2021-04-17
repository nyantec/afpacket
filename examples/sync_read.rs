use afpacket::sync::RawPacketStream;
use nom::HexDisplay;

fn main() {
    let mut ps = RawPacketStream::new().unwrap();
    loop {
        let mut buf = [0u8; 1500];
        ps.read(&mut buf).unwrap();
        println!("{}", buf.to_hex(24));
    }
}
