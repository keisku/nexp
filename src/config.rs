use clap::Parser;
use log::debug;
use log::error;
use pnet::datalink::{self, NetworkInterface};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Parser, Default)]
#[command(author = "Keisuke Umegaki", about = "A nexp alternative")]
pub struct Flags {
    #[arg(short = 'e', value_name = "iface", help = "Use specified interface.")]
    interface: Option<String>,

    #[arg(
        short = 'p',
        value_name = "port ranges",
        help = "\
Only scan specified ports.
Ex: -p22; -p1-65535; -p22,80,443; -p-;
You can specify -p- to scan ports from 1 through 65535. 
NOTE: We will support https://nmap.org/book/man-port-specification.html
"
    )]
    port: Option<String>,

    #[arg(
        long = "sS",
        default_value_t = true,
        help = "SYN scan is the default and most popular scan option for good reasons."
    )]
    tcp_syn_scan: bool,

    #[arg(
        long = "sT",
        default_value_t = false,
        help = "TCP connect scan is the default TCP scan type when SYN scan is not an option."
    )]
    tcp_syn_connect: bool,

    #[arg(required = true, help = "The host address to scan.")]
    host_addr: String,
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("flags")
            .field("-e", &self.interface)
            .field("-p", &self.port)
            .field("--sS", &self.tcp_syn_scan)
            .field("--sT", &self.tcp_syn_connect)
            .finish()
    }
}

impl Flags {
    pub fn init() -> Self {
        Self::parse()
    }

    // single port config could be "80", "80-81"
    fn parse_single_port_config(&self, port: &str) -> Vec<u16> {
        let parts: Vec<&str> = port.split('-').collect();
        match parts.len() {
            1 => parts[0].parse().map_or(vec![], |num| vec![num]),
            2 => {
                let start = match parts[0].parse::<u16>().map(|p| p) {
                    Ok(p) => p,
                    Err(e) => {
                        error!("{}", e);
                        return vec![];
                    }
                };
                let end = match parts[1].parse::<u16>().map(|p| p) {
                    Ok(p) => p,
                    Err(e) => {
                        error!("{}", e);
                        return vec![];
                    }
                };
                {
                    if start < end {
                        return (start..end + 1).collect();
                    }
                    if start == end {
                        return vec![start];
                    }
                }
                vec![]
            }
            _ => vec![],
        }
    }

    fn parse_ports(&self) -> Vec<u16> {
        return match self.port.clone() {
            Some(port) => {
                if port.eq("-") {
                    return (1..65535).collect();
                } else if port.contains(",") {
                    let mut ports = Vec::new();
                    for p in port.split(',') {
                        ports.append(&mut self.parse_single_port_config(p));
                    }
                    ports
                } else {
                    return self.parse_single_port_config(&port);
                }
            }
            None => vec![],
        };
    }

    fn parse_interface(&self) -> NetworkInterface {
        let mut if_iter = datalink::interfaces().into_iter();
        let mut cloned_if_iter = if_iter.clone();
        let fallback = cloned_if_iter
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .unwrap();
        if self.interface.is_none() {
            return fallback;
        }
        let iface = if_iter.find(|iface| {
            iface.is_up()
                && !iface.is_loopback()
                && !iface.ips.is_empty()
                && iface.name.eq(self.interface.as_ref().unwrap())
        });
        if iface.is_none() {
            debug!(
                "Failed to find a valid network interface by {}, fallback to {}",
                self.interface.as_ref().unwrap(),
                fallback.name
            );
            return fallback;
        }
        return iface.unwrap();
    }
}

pub struct Config {
    pub ip_addr: IpAddr,
    pub network_interface: NetworkInterface,
    pub ports: Vec<u16>,
    pub tcp_syn_scan: bool,
    pub tcp_connect_scan: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("config")
            .field("ip address", &self.ip_addr)
            .field("network_interface", &self.network_interface)
            .field("ports", &self.ports)
            .field("TCP SYN scan", &self.tcp_syn_scan)
            .field("TCP connect scan", &self.tcp_connect_scan)
            .finish()
    }
}

impl Clone for Config {
    fn clone(&self) -> Self {
        Config {
            ip_addr: self.ip_addr.clone(),
            network_interface: self.network_interface.clone(),
            ports: self.ports.clone(),
            tcp_syn_scan: self.tcp_syn_scan,
            tcp_connect_scan: self.tcp_connect_scan,
        }
    }
}

impl From<Flags> for Config {
    fn from(flags: Flags) -> Self {
        let ip_addr: IpAddr = match flags.host_addr.parse::<Ipv4Addr>() {
            Ok(addr) => IpAddr::V4(addr),
            Err(_) => IpAddr::V6(
                flags
                    .host_addr
                    .parse::<Ipv6Addr>()
                    .expect("Failed to parse IP address"),
            ),
        };
        let config = Config {
            ip_addr: ip_addr,
            network_interface: flags.parse_interface(),
            ports: flags.parse_ports(),
            tcp_syn_scan: flags.tcp_syn_scan,
            tcp_connect_scan: flags.tcp_syn_connect,
        };
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ports_single() {
        let flags = Flags {
            interface: None,
            port: Some("80".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![80]);
    }

    #[test]
    fn test_ports_single_range() {
        let flags = Flags {
            interface: None,
            port: Some("80-81".to_string()),
            host_addr: "2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![80, 81]);
    }

    #[test]
    fn test_ports_single_full_range() {
        let flags = Flags {
            interface: None,
            port: Some("-".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        let result: Vec<u16> = (1..65535).collect();
        assert_eq!(config.ports, result);
    }

    #[test]
    fn test_ports_complex() {
        let flags = Flags {
            interface: None,
            port: Some("80,443,8000-8002".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn test_ports_complex_2() {
        let flags = Flags {
            interface: None,
            port: Some("80,443,,8000-8002".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn test_ports_complex_with_invalid() {
        let flags = Flags {
            interface: None,
            port: Some("80,443,8000-8002,invalid".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn test_ports_complex_with_invalid_2() {
        let flags = Flags {
            interface: None,
            port: Some("80,443,8000-8002,invalid-9000".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn test_ports_complex_with_invalid_3() {
        let flags = Flags {
            interface: None,
            port: Some("80,443,8000-8002,9000-invalid".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn test_ports_multiple_full_range() {
        let flags = Flags {
            interface: None,
            port: Some("-,-,-".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, Vec::<u16>::new());
    }

    #[test]
    fn test_ports_single_range_but_same_number() {
        let flags = Flags {
            interface: None,
            port: Some("8000-8000".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![8000]);
    }

    #[test]
    fn test_ports_double_hyphen() {
        let flags = Flags {
            interface: None,
            port: Some("8000--8001".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![]);
    }

    #[test]
    fn test_ports_invalid_to_number() {
        let flags = Flags {
            interface: None,
            port: Some("invalid-80".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![]);
    }

    #[test]
    fn test_ports_number_to_invalid() {
        let flags = Flags {
            interface: None,
            port: Some("80-invalid".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, vec![]);
    }

    #[test]
    fn test_ports_single_invalid() {
        let flags = Flags {
            interface: None,
            port: Some("invalid".to_string()),
            host_addr: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let config = Config::from(flags);
        assert_eq!(config.ports, Vec::<u16>::new());
    }

    // More tests could be added here to cover different scenarios
}
