use pnet::{packet::vlan, util::MacAddr};
use pnet_macros_support::packet::Packet;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{Display, Error, Formatter},
};

use crate::sflow5::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

impl Display for Counter {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "packets={},bytes={}", self.packets, self.bytes)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Counter {
            packets: 0,
            bytes: 0,
        }
    }
}

pub trait Collector {
    fn collect(&mut self, sample: SFlowSamplePacket) -> &mut Self;
}

#[derive(Eq, Hash, PartialEq, Serialize, Debug)]
pub struct FlowCounterKey {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub vlan: u32,
    pub protocol: u32,
}

pub type FlowCounter = HashMap<FlowCounterKey, Counter>;

impl Collector for FlowCounter {
    fn collect(&mut self, sample: SFlowSamplePacket) -> &mut Self {
        match sample.get_sample_type() {
            1 | 3 => {
                //sFlow sample or an expanded sFlow sample
                let mut key = FlowCounterKey {
                    src_mac: MacAddr::zero(),
                    dst_mac: MacAddr::zero(),
                    vlan: 0,
                    protocol: 0,
                };
                let pkts = sample.get_sampling_rate() as u64;
                let mut bytes: u64 = 0;

                for record in sample.get_records() {
                    match record.get_record_type() {
                        //TODO: enumerate these
                        1 => {
                            let raw_packet_header =
                                SFlowRawHeaderPacket::new(record.payload()).unwrap();
                            bytes = raw_packet_header.get_frame_length() as u64 * pkts as u64;
                            key.protocol = raw_packet_header.get_protocol();
                            key.src_mac = raw_packet_header.get_src_mac();
                            key.dst_mac = raw_packet_header.get_dst_mac();
                            match raw_packet_header.get_vlan() {
                                Ok(vlan) => {
                                    key.vlan = vlan;
                                }
                                Err(_) => {} // Do nothing, we can't expect every packet to have a VLAN
                            }
                        }
                        2 => {
                            let ethernet_frame: SFlowEthernetFrame = record.payload().into();
                            key.src_mac = ethernet_frame.src_mac;
                            key.dst_mac = ethernet_frame.dst_mac;
                            key.protocol = ethernet_frame.ethertype;
                        }
                        1001 => {
                            let extended_switch =
                                SFlowExtendedSwitchPacket::new(record.payload()).unwrap();
                            key.vlan = extended_switch.get_src_vlan();
                        }
                        1002 => {
                            let ipv4 = SFlowIpv4Packet::new(record.payload()).unwrap();
                            key.protocol = ipv4.get_protocol();
                            bytes = ipv4.get_length() as u64 * pkts as u64;
                        }
                        1003 => {
                            let ipv6 = SFlowIpv6Packet::new(record.payload()).unwrap();
                            key.protocol = ipv6.get_protocol();
                            bytes = ipv6.get_length() as u64 * pkts as u64;
                        }
                        _ => {}
                    }
                }
                let counter = self.entry(key).or_insert(Counter::default());
                counter.packets += pkts;
                counter.bytes += bytes;
            }
            _ => {}
        }

        self
    }
}
