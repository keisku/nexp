use crate::config;

use log::{debug, error, info};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, ipv6_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, TcpStream};
use std::str::FromStr;
use std::vec;

pub fn run(config: config::Config) {
    if config.tcp_syn_scan && !config.tcp_connect_scan {
        tcp_syn_scan(config);
        return;
    }
    tcp_connect_scan(config);
}

fn tcp_syn_scan(config: config::Config) {
    for port in config.clone().ports {
        let (mut ts, mut tr) = match transport_channel(
            65475,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        ) {
            Ok((ts, tr)) => (ts, tr),
            Err(e) => {
                error!("Error creating the transport channel: {}", e);
                return;
            }
        };
        let tcp_packet = build_tcp_packet(config.ip_addr, port, TcpFlags::SYN);
        debug!("Sending packet: {:?}", tcp_packet);

        match ts.send_to(tcp_packet, config.ip_addr) {
            Ok(s) => debug!("Packet sent: {:?} bytes", s),
            Err(e) => {
                error!("Error sending packet: {}", e);
                continue;
            }
        }

        let mut iter = tcp_packet_iter(&mut tr);
        match iter.next() {
            Ok((packet, addr)) => {
                info!("Response from {}: {:?}", addr, packet);
                if packet.get_flags() == (TcpFlags::SYN | TcpFlags::ACK) {
                    let ack_packet = build_tcp_packet(config.ip_addr, port, TcpFlags::ACK);
                    match ts.send_to(ack_packet, config.ip_addr) {
                        Ok(_) => debug!("ACK packet sent"),
                        Err(e) => error!("Error sending the ACK packet: {}", e),
                    }

                    // TCP port is open, here you could continue the handshake or other processing
                    info!("TCP port {} is open", port);

                    // Send FIN packet to close the connection gracefully
                    let fin_packet = build_tcp_packet(config.ip_addr, port, TcpFlags::FIN);
                    match ts.send_to(fin_packet, config.ip_addr) {
                        Ok(_) => debug!("FIN packet sent"),
                        Err(e) => error!("Error sending the FIN packet: {}", e),
                    }
                } else {
                    info!("TCP port {} is closed or filtered", port);
                }
            }
            // Ok(None) => info!("No response received within timeout"),
            Err(e) => error!("An error occurred while listening for responses: {}", e),
        }
    }
}

fn tcp_connect_scan(config: config::Config) {
    for port in config.clone().ports {
        match TcpStream::connect((config.ip_addr, port)) {
            Ok(s) => {
                s.peer_addr()
                    .map(|addr| info!("Connection established: {}", addr))
                    .expect("peer_addr call failed");
                s.shutdown(Shutdown::Both).expect("shutdown call failed");
            }
            Err(e) => error!("{}: {}:{}", e, config.ip_addr, port),
        }
    }
}

fn build_tcp_packet<'a>(
    target_ip_addr: IpAddr,
    target_port: u16,
    flags: u8,
) -> MutableTcpPacket<'a> {
    let mut tcp_packet = MutableTcpPacket::owned(vec![0u8; 20]).unwrap();
    tcp_packet.set_destination(target_port);
    tcp_packet.set_sequence(0);
    tcp_packet.set_flags(flags);
    if target_ip_addr.is_ipv4() {
        tcp_packet.set_checksum(ipv4_checksum(
            &tcp_packet.to_immutable(),
            &Ipv4Addr::new(192, 168, 1, 1),
            &Ipv4Addr::from_str(target_ip_addr.to_string().as_str()).unwrap(),
        ));
    } else {
        tcp_packet.set_checksum(ipv6_checksum(
            &tcp_packet.to_immutable(),
            &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            &Ipv6Addr::from_str(target_ip_addr.to_string().as_str()).unwrap(),
        ));
    }
    tcp_packet
}
