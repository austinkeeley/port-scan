use std::net;
use std::sync::mpsc::channel;

use clap::Clap;
use threadpool::ThreadPool;
use crossbeam::queue;

mod values;
use crate::values::constants::TCP_PORT_RANGE;

#[derive(Clap)]
struct Opts {
    target_ip: net::Ipv4Addr,
}

/// Results from a scan.
struct ScanResult {
    /// Ports that complete the TCP handshake
    open_ports: Vec<u16>,
    /// Ports that do **not** complete the TCP handshake. Because we aren't doing raw 
    /// IP packets, we can't distinguish between ports that don't respond at all (filtered)
    /// and ports that send a TCP RST (closed).
    non_open_ports: Vec<u16>,
}

fn main() {
    let opts: Opts = Opts::parse();
    println!("[*] Scanning host {}", opts.target_ip);
    let result = scan_host(&opts.target_ip).unwrap();

    println!("Open TCP ports:");
    for p in result.open_ports {
        println!("  {}", p);
    }

}

/// Scans a single host using the top 1000 most common TCP ports.
fn scan_host(host_ip: &net::Ipv4Addr) -> Result<ScanResult, String> {

    let jobs_queue: queue::MsQueue<u16> = queue::MsQueue::new();
    let pool = ThreadPool::new(10);

    for port_num in TCP_PORT_RANGE.iter() {
        jobs_queue.push(*port_num);
    }

    let (open_tx, open_rx) = channel();
    let (non_open_tx, non_open_rx) = channel();
    while !jobs_queue.is_empty() {
        let host_ip = host_ip.clone();
        let open_tx = open_tx.clone();
        let non_open_tx = non_open_tx.clone();
        let port_num = jobs_queue.pop();
        pool.execute(move|| { 
            println!("[*] Scanning port {}", port_num);
            match tcp_scan(&host_ip, port_num) {
                Ok(_) => open_tx.send(port_num),
                Err(_) => non_open_tx.send(port_num),
            };
        });
    }
    pool.join();

    drop(open_tx);
    drop(non_open_tx);
    let result = ScanResult {
        open_ports: open_rx.iter().collect(),
        non_open_ports: non_open_rx.iter().collect(),
    };

    Ok(result)
}

/// Performs the actual TCP scan. 
fn tcp_scan(host_ip: &net::Ipv4Addr, host_port: u16) -> std::io::Result<()> {
    let socket_addr = format!("{}:{}", host_ip, host_port);
    net::TcpStream::connect(socket_addr)?;
    Ok(())
}
