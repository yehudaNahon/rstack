use pnet::packet::{ip::IpNextHeaderProtocol, PacketSize};
use pnet_macros::Packet;
use pnet_macros_support::types::{u16be, u32be};

#[derive(Packet)]
pub struct Ah {
    #[construct_with(u8)]
    pub next_header: IpNextHeaderProtocol,
    pub payload_len: u8,
    pub reserved: u16be,
    pub spi: u32be, // security parameter index
    pub sequence_number: u32be,

    #[length_fn = "icv_length_calculation"]
    pub icv: Vec<u8>, // integrity check value

    #[payload]
    pub payload: Vec<u8>,
}

pub fn icv_length_calculation<'a>(packet: &AhPacket<'a>) -> usize {
    let payload_len = packet.get_payload_len() as usize;
    // payload length holds the lengh of the header - 2. then we reduce the fixed fields size which is 3 32 bit values
    (payload_len + 2 - 3) * 4
}
