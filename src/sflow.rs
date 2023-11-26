use std::{
    fmt::{Display, Error, Formatter},
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
        match agent_address_type {
            1 => {
                let mut buffer = [0; 4];
                buf.read_exact(&mut buffer).unwrap();
                agent_address = IpAddr::V4(buffer.into());
            }
            2 => {
                let mut buffer = [0; 16];
                buf.read_exact(&mut buffer).unwrap();
                agent_address = IpAddr::V6(buffer.into());
            }
            _ => panic!("agent_address_type not supported"),
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
impl RawPacket {
    pub fn header(self) -> PacketHeader {
        PacketHeader::from(self)
    }
}

// https://sflow.org/SFLOW-STRUCTS5.txt /* Packet Header Data */
pub struct PacketHeader {
    pub dst_mac: MacAddress,
    pub src_mac: MacAddress,
    pub ethertype: u16,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
}

impl From<RawPacket> for PacketHeader {
    fn from(raw_packet: RawPacket) -> Self {
        let mut buf =
            Cursor::new(raw_packet.header[..(raw_packet.header_size - 1) as usize].to_vec());
        let mut mac_buf = [0; 6];
        buf.read_exact(&mut mac_buf).unwrap();
        let dst_mac = MacAddress::new(mac_buf);
        buf.read_exact(&mut mac_buf).unwrap();
        let src_mac = MacAddress::new(mac_buf);
        let ethertype = buf.read_u16::<BigEndian>().unwrap();
        let src_addr: IpAddr;
        let dst_addr: IpAddr;
        match ethertype {
            0x0800 => {
                let ip_ver_hdr = buf.read_u8().unwrap();
                let ip_tos = buf.read_u8().unwrap();
                let ip_total_len = buf.read_u16::<BigEndian>().unwrap();
                let id = buf.read_u16::<BigEndian>().unwrap();
                let flags = buf.read_u16::<BigEndian>().unwrap();
                let ttl = buf.read_u8().unwrap();
                let ip_proto = buf.read_u8().unwrap();
                let _ck_sum = buf.read_u16::<BigEndian>().unwrap();
                // IPv4
                let mut addr_buf = [0; 4];
                buf.read_exact(&mut addr_buf).unwrap();
                src_addr = IpAddr::V4(addr_buf.into());
                dst_addr = IpAddr::V4(addr_buf.into());
            }
            0x86DD => {
                let _kys = buf.read_u64::<BigEndian>().unwrap(); // version, traffic class, flow label
                let plen = buf.read_u16::<BigEndian>().unwrap(); // payload length
                let _nh_hl = buf.read_u16::<BigEndian>().unwrap(); // next header, hop limit

                // IPv6
                let mut addr_buf = [0; 16];
                buf.read_exact(&mut addr_buf).unwrap();
                src_addr = IpAddr::V6(addr_buf.into());
                dst_addr = IpAddr::V6(addr_buf.into());
            }
            0x8100 => {
                // VLAN
                let _vlan = buf.read_u16::<BigEndian>().unwrap();
                println!(
                    "Priority: {}, DEI: {}, VLAN ID: {}",
                    _vlan >> 13 & 0x7,
                    _vlan >> 12 & 0x1,
                    _vlan & 0xfff,
                );
                let vlan_etype = buf.read_u16::<BigEndian>().unwrap();
                match vlan_etype {
                    0x0800 => {
                        let ip_ver_hdr = buf.read_u8().unwrap();
                        let ip_tos = buf.read_u8().unwrap();
                        let ip_total_len = buf.read_u16::<BigEndian>().unwrap();
                        let id = buf.read_u16::<BigEndian>().unwrap();
                        let flags = buf.read_u16::<BigEndian>().unwrap();
                        let ttl = buf.read_u8().unwrap();
                        let ip_proto = buf.read_u8().unwrap();
                        let _ck_sum = buf.read_u16::<BigEndian>().unwrap();
                        // IPv4
                        let mut addr_buf = [0; 4];
                        buf.read_exact(&mut addr_buf).unwrap();
                        src_addr = IpAddr::V4(addr_buf.into());
                        dst_addr = IpAddr::V4(addr_buf.into());
                    }
                    0x86DD => {
                        let _kys = buf.read_u64::<BigEndian>().unwrap(); // version, traffic class, flow label
                        let plen = buf.read_u16::<BigEndian>().unwrap(); // payload length
                        let _nh_hl = buf.read_u16::<BigEndian>().unwrap(); // next header, hop limit

                        // IPv6
                        let mut addr_buf = [0; 16];
                        buf.read_exact(&mut addr_buf).unwrap();
                        src_addr = IpAddr::V6(addr_buf.into());
                        dst_addr = IpAddr::V6(addr_buf.into());
                    }
                    _ => {
                        println!("[Warning] Unknown ethertype in VLAN packet: {}", ethertype);
                        // write the entire packet in a file for later analysis
                        src_addr = IpAddr::V4([0; 4].into());
                        dst_addr = IpAddr::V4([0; 4].into());
                    }
                }
            }
            _ => {
                println!("[Warning] Unknown ethertype in Raw header: {}", ethertype);
                // write the entire packet in a file for later analysis
                src_addr = IpAddr::V4([0; 4].into());
                dst_addr = IpAddr::V4([0; 4].into());
            }
        }
        PacketHeader {
            dst_mac,
            src_mac,
            ethertype,
            src_addr,
            dst_addr,
        }
    }
}

#[derive(Debug)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Unknown,
}

impl From<u32> for EtherType {
    fn from(ethertype: u32) -> Self {
        match ethertype {
            0x0800 => EtherType::Ipv4,
            0x86DD => EtherType::Ipv6,
            _ => EtherType::Unknown,
        }
    }
}

impl Into<u32> for EtherType {
    fn into(self) -> u32 {
        match self {
            EtherType::Ipv4 => 0x0800,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Unknown => 0x0000,
        }
    }
}

impl Display for EtherType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            EtherType::Ipv4 => write!(f, "IPv4"),
            EtherType::Ipv6 => write!(f, "IPv6"),
            EtherType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Serialize for EtherType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            EtherType::Ipv4 => serializer.serialize_str("IPv4"),
            EtherType::Ipv6 => serializer.serialize_str("IPv6"),
            EtherType::Unknown => serializer.serialize_str("Unknown"),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct EthernetFrame {
    pub length: u32,
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub ethertype: EtherType,
}
impl From<Record> for EthernetFrame {
    fn from(record: Record) -> Self {
        let mut buf = Cursor::new(record.data);
        let length = buf.read_u32::<BigEndian>().unwrap();
        let mut mac_buf = [0; 6];
        buf.read_exact(&mut mac_buf).unwrap();
        // MAC addresses in the ethernet record are stored in a padded u8, so we need to skip the padding
        buf.set_position(buf.position() + 2);
        let src_mac = MacAddress::new(mac_buf);
        buf.read_exact(&mut mac_buf).unwrap();
        let dst_mac = MacAddress::new(mac_buf);
        // MAC addresses in the ethernet record are stored in a padded u8, so we need to skip the padding
        buf.set_position(buf.position() + 2);
        let ethertype: EtherType = buf.read_u32::<BigEndian>().unwrap().into();
        EthernetFrame {
            length,
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
