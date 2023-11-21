use std::{
    io::{Cursor, Read, Seek},
    net::IpAddr,
    time::Duration,
};

use byteorder::{BigEndian, ReadBytesExt};
use mac_address::MacAddress;
use serde::Serialize;

pub enum SampleType {
    FlowSample(Sample),
    CounterSample,
    ExpandedFlowSample(Sample),
    ExpandedCounterSample,
}

impl From<Sample> for SampleType {
    fn from(sample: Sample) -> Self {
        match sample.sample_type {
            1 => SampleType::FlowSample(sample),
            2 => SampleType::CounterSample,
            3 => SampleType::ExpandedFlowSample(sample),
            4 => SampleType::ExpandedCounterSample,
            _ => panic!("Unknown sample type"),
        }
    }
}

#[derive(Debug)]
pub enum RecordType {
    RawPacket(RawPacket),
    EthernetFrame(EthernetFrame),
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    ExtendedSwitch(ExtendedSwitch),
    ExtendedRouter(ExtendedRouter),
}

impl From<Record> for RecordType {
    fn from(record: Record) -> Self {
        match record.record_type {
            1 => RecordType::RawPacket(RawPacket::from(record)),
            2 => RecordType::EthernetFrame(EthernetFrame::from(record)),
            3 => RecordType::Ipv4(Ipv4::from(record)),
            4 => RecordType::Ipv6(Ipv6::from(record)),
            1001 => RecordType::ExtendedSwitch(ExtendedSwitch::from(record)),
            1002 => RecordType::ExtendedRouter(ExtendedRouter::from(record)),
            _ => panic!("Unknown record type"),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Datagram {
    pub version: u32,
    pub agent_address_type: u32,
    pub agent_address: IpAddr,
    pub sub_agent_id: u32,
    pub sequence_number: u32,
    pub uptime: Duration,
    pub num_samples: u32,
    pub samples: Vec<Sample>,
}

impl Datagram {
    pub fn parse<T: Read + Seek>(buf: &mut T) -> Datagram {
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
            samples.push(Sample::parse(buf));
        }
        Datagram {
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

#[derive(Debug)]
#[allow(dead_code)]
pub struct Sample {
    pub sample_type: u32,
    pub sample_length: u32,
    pub sequence_number: u32,
    pub source_id_type: u32,
    pub source_id_index: u32,
    pub sampling_rate: u32,
    pub sample_pool: u32,
    pub drops: u32,
    pub in_interface_format: u32,
    pub in_interface_value: u32,
    pub out_interface_format: u32,
    pub out_interface_value: u32,
    pub num_records: u32,
    pub records: Vec<RecordType>,
}

impl Sample {
    pub fn parse<T: Read + Seek>(buf: &mut T) -> Sample {
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
                    records.push(Record::parse(buf).into());
                }
                _ => println!("Unknown sample type"),
            }
        }

        Sample {
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

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct Record {
    pub record_type: u32,
    pub length: u32,
    pub data: Vec<u8>,
}

impl Record {
    pub fn parse<T: Read + Seek>(buf: &mut T) -> Record {
        let record_type = buf.read_u32::<BigEndian>().unwrap();
        let length = buf.read_u32::<BigEndian>().unwrap();
        let mut data = vec![0; length as usize];
        buf.read_exact(&mut data).unwrap();
        Record {
            record_type,
            length,
            data,
        }
    }
}

// allow unused fields
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct RawPacket {
    pub protocol: u32,
    pub frame_length: u32,
    pub stripped: u32,
    pub header_size: u32,
    pub header: Vec<u8>,
}
impl From<Record> for RawPacket {
    fn from(record: Record) -> Self {
        let mut buf = Cursor::new(record.data);
        let protocol = buf.read_u32::<BigEndian>().unwrap();
        let frame_length = buf.read_u32::<BigEndian>().unwrap();
        let stripped = buf.read_u32::<BigEndian>().unwrap();
        let header_size = buf.read_u32::<BigEndian>().unwrap();
        let mut header = vec![0; header_size as usize];
        buf.read_exact(&mut header).unwrap();
        RawPacket {
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
pub struct EthernetFrame {
    pub frame_length: u32,
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub ethertype: u16,
}
impl From<Record> for EthernetFrame {
    fn from(record: Record) -> Self {
        let mut buf = Cursor::new(record.data);
        let frame_length = buf.read_u32::<BigEndian>().unwrap();
        let mut mac_buf = [0; 6];
        buf.read_exact(&mut mac_buf).unwrap();
        let src_mac = MacAddress::new(mac_buf);
        buf.read_exact(&mut mac_buf).unwrap();
        let dst_mac = MacAddress::new(mac_buf);
        let ethertype = buf.read_u16::<BigEndian>().unwrap();
        EthernetFrame {
            frame_length,
            src_mac,
            dst_mac,
            ethertype,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Ipv4 {
    pub length: u32,
    pub protocol: u32,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u32,
    pub dst_port: u32,
    pub tcp_flags: u32,
    pub tos: u32,
}
impl From<Record> for Ipv4 {
    fn from(record: Record) -> Self {
        let mut buf = Cursor::new(record.data);
        let length = buf.read_u32::<BigEndian>().unwrap();
        let protocol = buf.read_u32::<BigEndian>().unwrap();
        let src_ip = IpAddr::V4(buf.read_u32::<BigEndian>().unwrap().into());
        let dst_ip = IpAddr::V4(buf.read_u32::<BigEndian>().unwrap().into());
        let src_port = buf.read_u32::<BigEndian>().unwrap();
        let dst_port = buf.read_u32::<BigEndian>().unwrap();
        let tcp_flags = buf.read_u32::<BigEndian>().unwrap();
        let tos = buf.read_u32::<BigEndian>().unwrap();
        Ipv4 {
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
pub struct Ipv6 {
    pub length: u32,
    pub protocol: u32,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u32,
    pub dst_port: u32,
    pub tcp_flags: u32,
    pub priority: u32,
}
impl From<Record> for Ipv6 {
    fn from(record: Record) -> Self {
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
        Ipv6 {
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
pub struct ExtendedSwitch {
    pub src_vlan: u32,
    pub src_priority: u32,
    pub dst_vlan: u32,
    pub dst_priority: u32,
}
impl From<Record> for ExtendedSwitch {
    fn from(record: Record) -> Self {
        let mut buf = Cursor::new(record.data);
        let src_vlan = buf.read_u32::<BigEndian>().unwrap();
        let src_priority = buf.read_u32::<BigEndian>().unwrap();
        let dst_vlan = buf.read_u32::<BigEndian>().unwrap();
        let dst_priority = buf.read_u32::<BigEndian>().unwrap();
        ExtendedSwitch {
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
pub struct ExtendedRouter {
    pub nexthop: IpAddr,
    pub src_mask: u32,
    pub dst_mask: u32,
}
impl From<Record> for ExtendedRouter {
    fn from(record: Record) -> Self {
        let mut buf = Cursor::new(record.data);
        let mut nexthop_buf: [u8; 16] = [0; 16];
        buf.read_exact(&mut nexthop_buf).unwrap();
        let nexthop = IpAddr::V6(nexthop_buf.into());
        let src_mask = buf.read_u32::<BigEndian>().unwrap();
        let dst_mask = buf.read_u32::<BigEndian>().unwrap();
        ExtendedRouter {
            nexthop,
            src_mask,
            dst_mask,
        }
    }
}
