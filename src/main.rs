use env_logger;
use log::{debug, error, info};
use pnet::datalink;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use std::net::{Ipv4Addr, Shutdown, TcpStream};
use std::str::FromStr;
use std::{env, vec};

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        error!("Usage: {} <host> <port>", args[0]);
        return;
    }
    let target_host = &args[1];
    let target_port = args[2]
        .parse::<u16>()
        .expect("Please enter a valid port number");

    // TODO: User can specify network interface
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
        .expect("Failed to find a valid interface");

    // TODO: Consider improving this log message.
    debug!("Using interface: {:?}", interface);

    let (mut datalink_sender, _) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

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
            p.set_destination(Ipv4Addr::from_str(&target_host.as_str()).unwrap());
            p
        })
        .unwrap();
    let tcp_packet = MutableTcpPacket::owned(vec![0u8; 20])
        .map(|mut p| {
            p.set_destination(target_port);
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
    match datalink_sender.send_to(ipv4_packet.packet(), Some(interface)) {
        Some(Ok(_)) => info!("Packet sent"),
        Some(Err(e)) => error!("Failed to send packet: {}", e),
        None => error!("Failed to send packet"),
    }
    match TcpStream::connect((target_host.as_str(), target_port)) {
        Ok(s) => {
            s.peer_addr()
                .map(|addr| info!("Connection established: {}", addr))
                .expect("peer_addr call failed");
            s.shutdown(Shutdown::Both).expect("shutdown call failed");
        }
        Err(e) => error!("{}: {}:{}", e, target_host, target_port),
    }
}
