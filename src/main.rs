mod http;
mod listeners;
mod metrics;
mod sflow;

use crate::sflow::{Datagram, RecordType, SampleType};
use http::start_http_server;
use listeners::{PCapReceiver, Receiver, UdpReceiver};
use metrics::Counter;
use std::collections::HashMap;
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::{io::Cursor, net::IpAddr};

fn main() {
    let mut socket = PCapReceiver::new("any", "udp dst port 6343", 9000, true);
    let mut buf = [0; 9000];
    let (tx, rx) = mpsc::channel::<[u8; 9000]>();

    thread::spawn(move || loop {
        let mut c = Cursor::new(rx.recv().unwrap());
        let datagram = Datagram::parse(&mut c);
        println!("{}: {}\n", datagram.agent_address, datagram.num_samples);

        for sample in datagram.samples {
            match SampleType::from(sample) {
                SampleType::ExpandedFlowSample(sample) | SampleType::ExpandedFlowSample(sample) => {
                    println!("Expanded Flow Sample: {:?}", sample);
                    for record in sample.records {
                        match RecordType::from(record) {
                            RecordType::RawPacket(record) => {
                                println!("Raw Packet Header: {:?}", record);
                            }
                            RecordType::EthernetFrame(record) => {
                                println!("Ethernet Frame: {:?}", record);
                            }
                            RecordType::Ipv4(record) => {
                                println!("IPv4: {:?}", record);
                            }
                            RecordType::Ipv6(record) => {
                                println!("IPv6: {:?}", record);
                            }
                            RecordType::ExtendedSwitch(record) => {
                                println!("Extended Switch: {:?}", record);
                            }
                            _ => {
                                println!("Unknown record type");
                            }
                        }
                    }
                }
                _ => println!("Unknown sample type"),
            }
        }
    });

    let statmap: HashMap<IpAddr, Counter> = HashMap::new();
    let smarc: Arc<RwLock<HashMap<IpAddr, Counter>>> = Arc::new(RwLock::new(statmap));
    let sc = smarc.clone();
    thread::spawn(move || start_http_server(sc));
    loop {
        let (amt, src) = socket.receive(&mut buf).expect("didn't receive data");
        tx.send(buf.clone()).unwrap();
        let mut kys = smarc.write().unwrap();
        let metric = kys.entry(src.ip()).or_insert(Counter {
            packets: 0,
            bytes: 0,
        });
        metric.packets += 1;
        metric.bytes += amt as u128;
    }
}
