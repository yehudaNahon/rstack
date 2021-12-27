use pnet::packet::{ip::IpNextHeaderProtocol, PacketSize};
use pnet_macros::Packet;
use pnet_macros_support::types::{u16be, u32be};

/// the public representation of the esp packet
/// all the encrypted data is saved as payload and should be parsed to a EspPrivate struct after-word
/// there is no current support for the optional icv field because there isn't static metadata to inticate wether this filed exists
#[derive(Packet)]
pub struct EspPublic {
    pub spi: u32be, // security parameter index
    pub sequence_number: u32be,

    #[payload]
    pub payload: Vec<u8>,
    // icv is optional and depends on the SA configuration so we cannot know it out of context of the model
}

#[derive(Packet)]
pub struct EspPrivate {
    #[payload]
    #[length_fn = "payload_length_calculation"]
    pub payload: Vec<u8>,

    #[length_fn = "padding_length_calculation"]
    pub padding: Vec<u8>,

    pub pad_length: u8,

    #[construct_with(u8)]
    pub next_header: IpNextHeaderProtocol,
}

pub fn padding_length_calculation<'a>(packet: &EspPrivatePacket<'a>) -> usize {
    packet.get_pad_length() as usize
}

pub fn payload_length_calculation<'a>(packet: &EspPrivatePacket<'a>) -> usize {
    // the payload can be deduced as the left-over of the packet
    packet.packet_size() - 2 - packet.get_pad_length() as usize
}
