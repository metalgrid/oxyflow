mod http;
mod listeners;
mod metrics;
mod sflow;

use crate::metrics::Collector;
use crate::sflow::Datagram;
use http::start_http_server;
use listeners::{PCapReceiver, Receiver, UdpReceiver};
use metrics::{Counter, FlowCounter};
use std::collections::HashMap;
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::{io::Cursor, net::IpAddr};

fn main() {
    let mut socket = PCapReceiver::new("any", "udp dst port 6343", 9000, true);
    let mut buf = [0; 9000];
    let (tx, rx) = mpsc::channel::<[u8; 9000]>();

    let statmap: HashMap<IpAddr, Counter> = HashMap::new();
    let smarc: Arc<RwLock<HashMap<IpAddr, Counter>>> = Arc::new(RwLock::new(statmap));
    let sc = smarc.clone();
    let flowstats = FlowCounter::new();
    let fsarc: Arc<RwLock<FlowCounter>> = Arc::new(RwLock::new(flowstats));
    let fsc = fsarc.clone();

    thread::spawn(move || loop {
        let mut c = Cursor::new(rx.recv().unwrap());
        let datagram = Datagram::parse(&mut c);
        println!("{}: {}\n", datagram.agent_address, datagram.num_samples);

        for sample in datagram.samples {
            fsarc.write().unwrap().collect(sample.into());
        }
    });

    thread::spawn(move || start_http_server(sc, fsc));
    loop {
        match socket.receive(&mut buf) {
            Ok((amt, src)) => {
                tx.send(buf.clone()).unwrap();
                let mut kys = smarc.write().unwrap();
                let metric = kys.entry(src.ip()).or_insert(Counter {
                    packets: 0,
                    bytes: 0,
                });
                metric.packets += 1;
                metric.bytes += amt as u64;
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}
