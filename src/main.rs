use std::env;
use std::net::{TcpStream, Shutdown};
use log::{info, error};
use env_logger;

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <host> <port>", args[0]);
        return;
    }
    let target_host = &args[1];
    let target_port = args[2].parse::<u16>().expect("Please enter a valid port number");

    match TcpStream::connect((target_host.as_str(), target_port)) {
        Ok(s) => {
            s.peer_addr().map(|addr| info!("Connection established: {}", addr)).expect("peer_addr call failed");
            s.shutdown(Shutdown::Both).expect("shutdown call failed");
        },
        Err(e) => error!("{}: {}:{}", e, target_host, target_port),
    }
}
