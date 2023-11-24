use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{Display, Error, Formatter},
};

use crate::sflow::{self, SampleType};

#[derive(Serialize, Deserialize, Debug)]
pub struct Counter {
    pub packets: u128,
    pub bytes: u128,
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
    fn collect(&mut self, sample: sflow::SampleType) -> &mut Self;
}

#[derive(Eq, Hash, PartialEq, Serialize, Debug)]
pub struct FlowCounterKey {
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub vlan: u32,
    pub protocol: u32,
}

pub type FlowCounter = HashMap<FlowCounterKey, Counter>;

impl Collector for FlowCounter {
    fn collect(&mut self, sample: sflow::SampleType) -> &mut Self {
        match sample {
            SampleType::ExpandedFlowSample(sample) => {
                let mut key = FlowCounterKey {
                    src_mac: MacAddress::default(),
                    dst_mac: MacAddress::default(),
                    vlan: 0,
                    protocol: 0,
                };
                let pkts = sample.sampling_rate;
                let mut bytes: u128 = 0;

                for record in sample.records {
                    match record {
                        sflow::RecordType::RawPacket(record) => {
                            bytes = record.frame_length as u128 * sample.sampling_rate as u128;
                            let hdr = record.header();
                            key.src_mac = hdr.src_mac;
                            key.dst_mac = hdr.dst_mac;
                            key.protocol = hdr.ethertype.into();
                        }
                        sflow::RecordType::EthernetFrame(record) => {
                            key.src_mac = record.src_mac;
                            key.dst_mac = record.dst_mac;
                            key.protocol = record.ethertype.into();
                        }
                        sflow::RecordType::ExtendedSwitch(record) => {
                            key.vlan = record.src_vlan;
                        }
                        sflow::RecordType::Ipv4(record) => {
                            bytes = record.length as u128 * sample.sampling_rate as u128;
                        }
                        sflow::RecordType::Ipv6(record) => {
                            bytes = record.length as u128 * sample.sampling_rate as u128;
                        }
                        _ => {}
                    }
                }
                let counter = self.entry(key).or_insert_with(Counter::default);
                counter.packets += pkts as u128;
                counter.bytes += bytes as u128;
            }
            _ => {}
        }
        self
    }
}
