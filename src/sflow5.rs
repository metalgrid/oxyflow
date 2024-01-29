use byteorder::{BigEndian, ReadBytesExt};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use pnet_macros::packet;
use pnet_macros_support::types::*;
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};
#[packet]
pub struct SFlow {
    pub version: u32be,
    pub agent_address_type: u32be,
    #[construct_with(u8, u8, u8, u8)]
    pub agent_address: Ipv4Addr,
    pub sub_agent_id: u32be,
    pub sequence_number: u32be,
    pub uptime: u32be,
    pub num_samples: u32be,
    #[payload]
    pub payload: Vec<u8>,
}
impl SFlowPacket<'_> {
    pub fn get_samples(&self) -> Vec<SFlowSamplePacket> {
        let mut samples = Vec::new();
        let mut offset = 0;
        for _ in 0..self.get_num_samples() {
            let sample = SFlowSamplePacket::new(&self.payload()[offset..]).unwrap();
            offset += sample.get_sample_length() as usize + 8;
            samples.push(sample);
        }
        samples
    }
}

#[packet]
pub struct SFlowSample {
    pub sample_type: u32be,
    pub sample_length: u32be,
    pub sequence_number: u32be,
    pub source_id_type: u32be,
    pub source_id_index: u32be,
    pub sampling_rate: u32be,
    pub sample_pool: u32be,
    pub drops: u32be,
    pub input_interface_format: u32be,
    pub input_interface_value: u32be,
    pub output_interface_format: u32be,
    pub output_interface_value: u32be,
    pub num_sampled_records: u32be,
    #[length = "sample_length"]
    #[payload]
    pub payload: Vec<u8>,
}

impl SFlowSamplePacket<'_> {
    pub fn get_records(&self) -> Vec<SFlowRecordPacket> {
        let mut records = Vec::new();
        let mut offset = 0;
        for _ in 0..self.get_num_sampled_records() {
            let record = SFlowRecordPacket::new(&self.payload()[offset..]).unwrap();
            offset += record.get_length() as usize + 8; // add the header length
            records.push(record);
        }
        records
    }
}

#[packet]
pub struct SFlowRecord {
    pub record_type: u32be,
    pub length: u32be,
    #[length = "length"]
    #[payload]
    pub payload: Vec<u8>,
}

#[packet]
pub struct SFlowRawHeader {
    pub protocol: u32be,
    pub frame_length: u32be,
    pub stripped: u32be,
    pub header_size: u32be,
    #[length = "header_size"]
    #[payload]
    pub payload: Vec<u8>,
}

impl SFlowRawHeaderPacket<'_> {
    pub fn get_src_mac(&self) -> MacAddr {
        let ethernet_packet = EthernetPacket::new(self.payload()).unwrap();
        return ethernet_packet.get_source();
    }

    pub fn get_dst_mac(&self) -> MacAddr {
        let ethernet_packet = EthernetPacket::new(self.payload()).unwrap();
        return ethernet_packet.get_destination();
    }

    pub fn get_vlan(&self) -> Result<u32, String> {
        let ethernet_packet = EthernetPacket::new(self.payload()).unwrap();
        if ethernet_packet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Vlan {
            let vlan_packet =
                pnet::packet::vlan::VlanPacket::new(ethernet_packet.payload()).unwrap();
            return Ok(vlan_packet.get_vlan_identifier() as u32);
        }
        return Err(format!(
            "Ethernet packet does not contain a VLAN (ethertype) {}",
            ethernet_packet.get_ethertype()
        )
        .into());
    }
}

#[derive(Debug)]
// SFlowEthernetFrame is 24 bytes with padding
pub struct SFlowEthernetFrame {
    pub length: u32be,    // 4 bytes
    pub src_mac: MacAddr, // 6 bytes + 2 bytes of padding
    pub dst_mac: MacAddr, // 6 bytes + 2 bytes of padding
    pub ethertype: u32be, // 4 bytes
}

impl From<&[u8]> for SFlowEthernetFrame {
    fn from(bytes: &[u8]) -> Self {
        let mut payload = Cursor::new(bytes);
        let length = payload.read_u32::<BigEndian>().unwrap();
        let src_mac = MacAddr::new(
            payload.read_u8().unwrap(),
            payload.read_u8().unwrap(),
            payload.read_u8().unwrap(),
            payload.read_u8().unwrap(),
            payload.read_u8().unwrap(),
            payload.read_u8().unwrap(),
        );
        payload.set_position(payload.position() + 2);
        let dst_mac = MacAddr::new(
            payload.read_u8().unwrap(),
            payload.read_u8().unwrap(),
            payload.read_u8().unwrap(),
            payload.read_u8().unwrap(),
            payload.read_u8().unwrap(),
            payload.read_u8().unwrap(),
        );
        payload.set_position(payload.position() + 2);

        let ethertype = payload.read_u32::<BigEndian>().unwrap();
        SFlowEthernetFrame {
            length,
            src_mac,
            dst_mac,
            ethertype,
        }
    }
}

#[packet]
pub struct SFlowIpv4 {
    pub length: u32be,
    pub protocol: u32be,
    #[construct_with(u8, u8, u8, u8)]
    pub src_ip: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub dst_ip: Ipv4Addr,
    pub src_port: u32be,
    pub dst_port: u32be,
    pub tcp_flags: u32be,
    #[length = "length"]
    #[payload]
    pub payload: Vec<u8>,
}

#[packet]
pub struct SFlowIpv6 {
    pub length: u32be,
    pub protocol: u32be,
    #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
    pub src_ip: Ipv6Addr,
    #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
    pub dst_ip: Ipv6Addr,
    pub src_port: u32be,
    pub dst_port: u32be,
    pub tcp_flags: u32be,
    pub priority: u32be,
    #[length = "length"]
    #[payload]
    pub payload: Vec<u8>,
}

#[packet]
pub struct SFlowExtendedSwitch {
    pub src_vlan: u32be,
    pub src_priority: u32be,
    pub dst_vlan: u32be,
    pub dst_priority: u32be,
    #[payload]
    pub payload: Vec<u8>,
}
