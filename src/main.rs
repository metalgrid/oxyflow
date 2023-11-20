mod http;
mod listeners;

use byteorder::{BigEndian, ReadBytesExt};

use http::start_http_server;
use listeners::{PCapReceiver, Receiver, UdpReceiver};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Error, Formatter};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::{io::Cursor, io::Read, io::Seek, net::IpAddr, time::Duration};
#[derive(Debug)]
#[allow(dead_code)]
struct SFlowRecord {
    record_type: u32,
    length: u32,
    data: Vec<u8>,
}

impl SFlowRecord {
    fn parse<T: Read + Seek>(buf: &mut T) -> SFlowRecord {
        let record_type = buf.read_u32::<BigEndian>().unwrap();
        let length = buf.read_u32::<BigEndian>().unwrap();
        let mut data = vec![0; length as usize];
        buf.read_exact(&mut data).unwrap();
        SFlowRecord {
            record_type,
            length,
            data,
        }
    }
}

// allow unused fields
#[allow(dead_code)]
#[derive(Debug)]
struct SFlowRawPacketHeader {
    protocol: u32,
    frame_length: u32,
    stripped: u32,
    header_size: u32,
    header: Vec<u8>,
}
impl From<SFlowRecord> for SFlowRawPacketHeader {
    fn from(record: SFlowRecord) -> Self {
        let mut buf = Cursor::new(record.data);
        let protocol = buf.read_u32::<BigEndian>().unwrap();
        let frame_length = buf.read_u32::<BigEndian>().unwrap();
        let stripped = buf.read_u32::<BigEndian>().unwrap();
        let header_size = buf.read_u32::<BigEndian>().unwrap();
        let mut header = vec![0; header_size as usize];
        buf.read_exact(&mut header).unwrap();
        SFlowRawPacketHeader {
            protocol,
            frame_length,
            stripped,
            header_size,
            header,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct SFlowEthernetFrame {
    frame_length: u32,
    source_mac: MacAddress,
    destination_mac: MacAddress,
    ethertype: u16,
}
impl From<SFlowRecord> for SFlowEthernetFrame {
    fn from(record: SFlowRecord) -> Self {
        let mut buf = Cursor::new(record.data);
        let frame_length = buf.read_u32::<BigEndian>().unwrap();
        let mut mac_buf = [0; 6];
        buf.read_exact(&mut mac_buf).unwrap();
        let source_mac = MacAddress::new(mac_buf);
        buf.read_exact(&mut mac_buf).unwrap();
        let destination_mac = MacAddress::new(mac_buf);
        let ethertype = buf.read_u16::<BigEndian>().unwrap();
        SFlowEthernetFrame {
            frame_length,
            source_mac,
            destination_mac,
            ethertype,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct SFlowIpv4 {
    length: u32,
    protocol: u32,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u32,
    dst_port: u32,
    tcp_flags: u32,
    tos: u32,
}
impl From<SFlowRecord> for SFlowIpv4 {
    fn from(record: SFlowRecord) -> Self {
        let mut buf = Cursor::new(record.data);
        let length = buf.read_u32::<BigEndian>().unwrap();
        let protocol = buf.read_u32::<BigEndian>().unwrap();
        let src_ip = IpAddr::V4(buf.read_u32::<BigEndian>().unwrap().into());
        let dst_ip = IpAddr::V4(buf.read_u32::<BigEndian>().unwrap().into());
        let src_port = buf.read_u32::<BigEndian>().unwrap();
        let dst_port = buf.read_u32::<BigEndian>().unwrap();
        let tcp_flags = buf.read_u32::<BigEndian>().unwrap();
        let tos = buf.read_u32::<BigEndian>().unwrap();
        SFlowIpv4 {
            length,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_flags,
            tos,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct SFlowIpv6 {
    length: u32,
    protocol: u32,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u32,
    dst_port: u32,
    tcp_flags: u32,
    priority: u32,
}
impl From<SFlowRecord> for SFlowIpv6 {
    fn from(record: SFlowRecord) -> Self {
        let mut ipv6_buf: [u8; 16] = [0; 16];
        let mut buf = Cursor::new(record.data);
        let length = buf.read_u32::<BigEndian>().unwrap();
        let protocol = buf.read_u32::<BigEndian>().unwrap();
        buf.read_exact(&mut ipv6_buf).unwrap();
        let src_ip = IpAddr::V6(ipv6_buf.into());
        buf.read_exact(&mut ipv6_buf).unwrap();
        let dst_ip = IpAddr::V6(ipv6_buf.into());
        let src_port = buf.read_u32::<BigEndian>().unwrap();
        let dst_port = buf.read_u32::<BigEndian>().unwrap();
        let tcp_flags = buf.read_u32::<BigEndian>().unwrap();
        let priority = buf.read_u32::<BigEndian>().unwrap();
        SFlowIpv6 {
            length,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_flags,
            priority,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct SFlowExtendedSwitch {
    src_vlan: u32,
    src_priority: u32,
    dst_vlan: u32,
    dst_priority: u32,
}
impl From<SFlowRecord> for SFlowExtendedSwitch {
    fn from(record: SFlowRecord) -> Self {
        let mut buf = Cursor::new(record.data);
        let src_vlan = buf.read_u32::<BigEndian>().unwrap();
        let src_priority = buf.read_u32::<BigEndian>().unwrap();
        let dst_vlan = buf.read_u32::<BigEndian>().unwrap();
        let dst_priority = buf.read_u32::<BigEndian>().unwrap();
        SFlowExtendedSwitch {
            src_vlan,
            src_priority,
            dst_vlan,
            dst_priority,
        }
    }
}

// TODO: Implement
#[derive(Debug)]
#[allow(dead_code)]
struct SFlowExtendedRouter {
    nexthop: IpAddr,
    src_mask: u32,
    dst_mask: u32,
}
impl From<SFlowRecord> for SFlowExtendedRouter {
    fn from(record: SFlowRecord) -> Self {
        let mut buf = Cursor::new(record.data);
        let mut nexthop_buf: [u8; 16] = [0; 16];
        buf.read_exact(&mut nexthop_buf).unwrap();
        let nexthop = IpAddr::V6(nexthop_buf.into());
        let src_mask = buf.read_u32::<BigEndian>().unwrap();
        let dst_mask = buf.read_u32::<BigEndian>().unwrap();
        SFlowExtendedRouter {
            nexthop,
            src_mask,
            dst_mask,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct SFlowSample {
    sample_type: u32,
    sample_length: u32,
    sequence_number: u32,
    source_id_type: u32,
    source_id_index: u32,
    sampling_rate: u32,
    sample_pool: u32,
    drops: u32,
    in_interface_format: u32,
    in_interface_value: u32,
    out_interface_format: u32,
    out_interface_value: u32,
    num_records: u32,
    records: Vec<SFlowRecord>,
}

impl SFlowSample {
    fn parse<T: Read + Seek>(buf: &mut T) -> SFlowSample {
        let sample_type = buf.read_u32::<BigEndian>().unwrap();
        let sample_length = buf.read_u32::<BigEndian>().unwrap();
        let sequence_number = buf.read_u32::<BigEndian>().unwrap();
        let source_id_type = buf.read_u32::<BigEndian>().unwrap();
        let source_id_index = buf.read_u32::<BigEndian>().unwrap();
        let sampling_rate = buf.read_u32::<BigEndian>().unwrap();
        let sample_pool = buf.read_u32::<BigEndian>().unwrap();
        let drops = buf.read_u32::<BigEndian>().unwrap();
        let in_interface_format = buf.read_u32::<BigEndian>().unwrap();
        let in_interface_value = buf.read_u32::<BigEndian>().unwrap();
        let out_interface_format = buf.read_u32::<BigEndian>().unwrap();
        let out_interface_value = buf.read_u32::<BigEndian>().unwrap();
        let num_records = buf.read_u32::<BigEndian>().unwrap();
        let mut records = Vec::new();

        for _ in 0..num_records {
            match sample_type {
                3 => {
                    records.push(SFlowRecord::parse(buf));
                }
                _ => println!("Unknown sample type"),
            }
        }

        SFlowSample {
            sample_type,
            sample_length,
            sequence_number,
            source_id_type,
            source_id_index,
            sampling_rate,
            sample_pool,
            drops,
            in_interface_format,
            in_interface_value,
            out_interface_format,
            out_interface_value,
            num_records,
            records,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct SFlowDatagram {
    version: u32,
    agent_address_type: u32,
    agent_address: IpAddr,
    sub_agent_id: u32,
    sequence_number: u32,
    uptime: Duration,
    num_samples: u32,
    samples: Vec<SFlowSample>,
}

impl SFlowDatagram {
    fn parse<T: Read + Seek>(buf: &mut T) -> SFlowDatagram {
        let version = buf.read_u32::<BigEndian>().unwrap();
        let agent_address_type = buf.read_u32::<BigEndian>().unwrap();
        let agent_address: IpAddr;
        if agent_address_type == 1 {
            let mut buffer = [0; 4];
            buf.read_exact(&mut buffer).unwrap();
            agent_address = IpAddr::V4(buffer.into());
        } else if agent_address_type == 2 {
            let mut buffer = [0; 16];
            buf.read_exact(&mut buffer).unwrap();
            agent_address = IpAddr::V6(buffer.into());
        } else {
            panic!("agent_address_type not supported");
        }
        let sub_agent_id = buf.read_u32::<BigEndian>().unwrap();
        let sequence_number = buf.read_u32::<BigEndian>().unwrap();
        let uptime = Duration::from_millis(buf.read_u32::<BigEndian>().unwrap().into());
        let num_samples = buf.read_u32::<BigEndian>().unwrap();
        let mut samples = Vec::new();

        for _ in 0..num_samples {
            samples.push(SFlowSample::parse(buf));
        }
        SFlowDatagram {
            version,
            agent_address_type,
            agent_address,
            sub_agent_id,
            sequence_number,
            uptime,
            num_samples,
            samples,
        }
    }
}
fn main() {
    let mut socket = PCapReceiver::new("any", "udp dst port 6343", 9000, false);
    let mut buf = [0; 9000];
    let (tx, rx) = mpsc::channel::<[u8; 9000]>();

    thread::spawn(move || loop {
        let mut c = Cursor::new(rx.recv().unwrap());
        let datagram = SFlowDatagram::parse(&mut c);
        println!("{}: {}\n", datagram.agent_address, datagram.num_samples);
        for sample in datagram.samples {
            for record in sample.records {
                match record.record_type {
                    1 => {
                        // let raw_packet_header = SFlowRawPacketHeader::from(record);
                        // println!("Raw Packet Header: {:?}\n", raw_packet_header);
                    }
                    2 => {
                        let ethernet_frame = SFlowEthernetFrame::from(record);
                        println!(
                            "Ethernet Frame: length: {}, source: {}, destination: {}\n",
                            ethernet_frame.frame_length,
                            ethernet_frame.source_mac,
                            ethernet_frame.destination_mac,
                        );
                    }
                    3 => {
                        let ipv4 = SFlowIpv4::from(record);
                        println!("IPv4: {:?}\n", ipv4);
                    }
                    4 => {
                        let ipv6 = SFlowIpv6::from(record);
                        println!("IPv6: {:?}\n", ipv6);
                    }
                    1001 => {
                        let extended_switch = SFlowExtendedSwitch::from(record);
                        println!("Extended Switch: {:?}\n", extended_switch);
                    }
                    1002 => {
                        let extended_router = SFlowExtendedRouter::from(record);
                        println!("Extended Router: {:?}\n", extended_router);
                    }
                    _ => println!("Unknown record type"),
                }
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
        println!("hammer time");
        let mut kys = smarc.write().unwrap();
        let metric = kys.entry(src.ip()).or_insert(Counter {
            packets: 0,
            bytes: 0,
        });
        metric.packets += 1;
        metric.bytes += amt as u128;
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Counter {
    packets: u128,
    bytes: u128,
}

impl Display for Counter {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "packets={},bytes={}", self.packets, self.bytes)
    }
}
