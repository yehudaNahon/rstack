use pcap::Capture;
use pnet::packet::{
    arp::ArpPacket,
    ethernet::{EtherTypes, EthernetPacket},
    icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes},
    icmpv6::Icmpv6Packet,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};
use rstack::packets::{ah::AhPacket, esp::EspPublicPacket};
use std::{fs::File, net::IpAddr, path::PathBuf};
use structopt::StructOpt;

macro_rules! parse_packet {
    ($packet:ident, $data: expr) => {
        if let Some(p) = $packet::new($data) {
            p.parse()
        } else {
            format!("Invalid {} packet", stringify!($packet))
        }
    };
}

trait Parser {
    fn parse(&self) -> String;
}

impl Parser for EthernetPacket<'_> {
    fn parse(&self) -> String {
        let next_leyer = match self.get_ethertype() {
            EtherTypes::Ipv4 => parse_packet!(Ipv4Packet, self.payload()),
            EtherTypes::Ipv6 => parse_packet!(Ipv6Packet, self.payload()),
            EtherTypes::Arp => parse_packet!(ArpPacket, self.payload()),
            _ => format!("Unknown Protocol ({})", self.get_ethertype()),
        };

        format!(
            "Ethernet (src:{}, dst:{}) :: {}",
            self.get_source(),
            self.get_destination(),
            next_leyer
        )
    }
}

impl Parser for Ipv4Packet<'_> {
    fn parse(&self) -> String {
        format!(
            "Ipv4 (src:{}, dst:{}, ttl:{}) :: {}",
            self.get_source(),
            self.get_destination(),
            self.get_ttl(),
            parse_transport_protocol(self.get_next_level_protocol(), self.payload())
        )
    }
}

impl Parser for Ipv6Packet<'_> {
    fn parse(&self) -> String {
        format!(
            "Ipv6 (src:{}, dst:{}, hop limit:{}) :: {}",
            self.get_source(),
            self.get_destination(),
            self.get_hop_limit(),
            parse_transport_protocol(self.get_next_header(), self.payload())
        )
    }
}

impl Parser for ArpPacket<'_> {
    fn parse(&self) -> String {
        format!(
            "ARP( sender proto: {}, target proto: {}, operation: {:?})",
            self.get_sender_proto_addr(),
            self.get_target_proto_addr(),
            self.get_operation()
        )
    }
}

impl Parser for UdpPacket<'_> {
    fn parse(&self) -> String {
        format!(
            " UDP (src:{}, dst:{}, length: {}) :: {:?}",
            self.get_source(),
            self.get_destination(),
            self.get_length(),
            self.payload()
        )
    }
}

impl Parser for TcpPacket<'_> {
    fn parse(&self) -> String {
        format!(
            " TCP (src:{}, dst:{}, window: {}, sequence: {:?}) :: {:?}",
            self.get_source(),
            self.get_destination(),
            self.get_window(),
            self.get_sequence(),
            self.payload()
        )
    }
}

impl Parser for IcmpPacket<'_> {
    fn parse(&self) -> String {
        match self.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(self.payload()).unwrap();
                format!(
                    "ICMP echo reply (seq={:?}, id={:?})",
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                )
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet =
                    echo_request::EchoRequestPacket::new(self.payload()).unwrap();
                format!(
                    "ICMP echo request (seq={:?}, id={:?})",
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                )
            }
            _ => format!("ICMP (type: {:?})", self.get_icmp_type()),
        }
    }
}

impl Parser for Icmpv6Packet<'_> {
    fn parse(&self) -> String {
        format!(" ICMPv6 (type={:?})", self.get_icmpv6_type())
    }
}

impl Parser for EspPublicPacket<'_> {
    fn parse(&self) -> String {
        format!(
            "Esp (spi: {:#10x}, seq: {}) :: {} bytes of encrypted data",
            self.get_spi(),
            self.get_sequence_number(),
            self.payload().len()
        )
    }
}

impl Parser for AhPacket<'_> {
    fn parse(&self) -> String {
        format!(
            "Ah (payload_len: {}, reserved: {}, spi: {:#10x}, seq: {}, icv: {:x?}) :: {}",
            self.get_payload_len(),
            self.get_reserved(),
            self.get_spi(),
            self.get_sequence_number(),
            self.get_icv_raw(),
            parse_transport_protocol(self.get_next_header(), self.payload())
        )
    }
}

fn parse_transport_protocol(protocol: IpNextHeaderProtocol, packet: &[u8]) -> String {
    match protocol {
        IpNextHeaderProtocols::Udp => parse_packet!(UdpPacket, packet),
        IpNextHeaderProtocols::Tcp => parse_packet!(TcpPacket, packet),
        IpNextHeaderProtocols::Icmp => parse_packet!(IcmpPacket, packet),
        IpNextHeaderProtocols::Icmpv6 => parse_packet!(Icmpv6Packet, packet),
        IpNextHeaderProtocols::Ah => parse_packet!(AhPacket, packet),
        IpNextHeaderProtocols::Esp => parse_packet!(EspPublicPacket, packet),
        _ => format!("Unknown Protocol"),
    }
}

#[derive(Debug, StructOpt)]
struct Args {
    /// the file to read
    file: PathBuf,
}

fn main() {
    let args = Args::from_args();

    let mut cap = Capture::from_file(args.file).expect("failed to open file");

    // Read test.pcap
    while let Ok(packet) = cap.next() {
        let ethernet = EthernetPacket::new(packet.data).unwrap();
        println!("{}", ethernet.parse());
    }
}
