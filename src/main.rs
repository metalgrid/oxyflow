mod http;
mod listeners;
mod metrics;
mod sflow5;

use crate::{http::start_http_server, metrics::Collector, sflow5::*};
use listeners::{PCapReceiver, Receiver};
use metrics::{Counter, FlowCounter};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{mpsc, Arc, RwLock};
use std::thread;

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
    let flow_agent_stats: Arc<RwLock<HashMap<IpAddr, HashMap<String, Counter>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let fas = flow_agent_stats.clone();

    thread::spawn(move || loop {
        let flow_agent_stats = flow_agent_stats.clone();
        let boffer = rx.recv().unwrap();
        let datagram = SFlowPacket::new(&boffer).unwrap();

        for sample in datagram.get_samples() {
            let agent_stats = &mut flow_agent_stats.write().unwrap();
            let agent_stats = agent_stats
                .entry(IpAddr::V4(datagram.get_agent_address()))
                .or_insert(HashMap::new())
                .entry(sample.get_sample_type().to_string())
                .or_insert(Counter::default());
            agent_stats.packets += 1;
            agent_stats.bytes += sample.get_sample_length() as u64;

            if let Err(e) = fsarc.write().unwrap().collect(sample) {
                println!("Error: {:?}", e);
            }
        }
    });

    thread::spawn(move || start_http_server(sc, fas, fsc));
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
