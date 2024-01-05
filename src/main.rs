mod config;

use env_logger;
use log::{debug, error, info};
use pnet::datalink;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use std::net::{Ipv4Addr, Shutdown, TcpStream};
use std::vec;

fn main() {
    env_logger::init();

    let flags = config::Flags::init();
    debug!("{:?}", flags);
    let config: config::Config = flags.into();
    debug!("{:?}", config);

    let (mut datalink_sender, _) =
        match datalink::channel(&config.network_interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

    for port in config.clone().ports {
        // TODO: Understand each packet method. Probably, we need make each method configurable.
        let mut ipv4_packet_buf = vec![0u8; 40];
        let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_packet_buf)
            .map(|mut p| {
                p.set_version(4);
                p.set_header_length(5);
                p.set_total_length(40);
                p.set_ttl(64);
                p.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                p.set_source(Ipv4Addr::new(192, 168, 1, 1));
                p.set_destination(config.ipv4_addr());
                p
            })
            .unwrap();
        let tcp_packet = MutableTcpPacket::owned(vec![0u8; 20])
            .map(|mut p| {
                p.set_destination(port);
                p.set_sequence(0);
                p.set_flags(TcpFlags::SYN);
                p.set_checksum(pnet::packet::tcp::ipv4_checksum(
                    &p.to_immutable(),
                    &ipv4_packet.get_source(),
                    &ipv4_packet.get_destination(),
                ));
                p
            })
            .unwrap();
        ipv4_packet.set_payload(tcp_packet.packet());

        // TODO: We should not send TCP SYN packet and establish TCP connection both. Add a flag to control this behavior.
        match datalink_sender.send_to(ipv4_packet.packet(), Some(config.network_interface.clone()))
        {
            Some(Ok(_)) => info!("Packet sent"),
            Some(Err(e)) => error!("Failed to send packet: {}", e),
            None => error!("Failed to send packet"),
        }
        match TcpStream::connect((config.ipv4_addr(), port)) {
            Ok(s) => {
                s.peer_addr()
                    .map(|addr| info!("Connection established: {}", addr))
                    .expect("peer_addr call failed");
                s.shutdown(Shutdown::Both).expect("shutdown call failed");
            }
            Err(e) => error!("{}: {}:{}", e, config.ipv4_addr(), port),
        }
    }
}
