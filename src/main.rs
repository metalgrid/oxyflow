use byteorder::{BigEndian, ReadBytesExt};
use std::{io::Cursor, io::Read, io::Seek, net::IpAddr, net::UdpSocket, time::Duration};

#[derive(Debug)]
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

struct SFlowRawPacketHeader {
    protocol: u32,
    frame_length: u32,
    stripped: u32,
    header_size: u32,
    header: Vec<u8>,
}

struct SFlowEthernetFrame {
    frame_length: u32,
    payload: Vec<u8>,
}

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

struct SFlowExtendedSwitch {
    src_vlan: u32,
    src_priority: u32,
    dst_vlan: u32,
    dst_priority: u32,
}

struct SFlowExtendedRouter {
    nexthop: IpAddr,
    src_mask: u32,
    dst_mask: u32,
}

#[derive(Debug)]
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
    let socket = UdpSocket::bind("0.0.0.0:6344").expect("couldn't bind to address");
    let mut buf = [0; 9000];

    let mut counter = 0;
    loop {
        counter += 1;
        let (amt, src) = socket.recv_from(&mut buf).expect("didn't receive data");
        let mut c = Cursor::new(buf.clone());
        let datagram = SFlowDatagram::parse(&mut c);
    }
}
