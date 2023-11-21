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

#[derive(Eq, Hash, PartialEq)]
struct FlowCounterKey {
    src_mac: MacAddress,
    dst_mac: MacAddress,
    vlan: u32,
    protocol: u32,
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
                let mut bytes = 0;

                for record in sample.records {
                    match record {
                        sflow::RecordType::EthernetFrame(record) => {
                            key.src_mac = record.src_mac;
                            key.dst_mac = record.dst_mac;
                        }
                        sflow::RecordType::ExtendedSwitch(record) => {
                            key.vlan = record.src_vlan;
                        }
                        sflow::RecordType::Ipv4(record) => {
                            key.protocol = record.protocol;
                            bytes = record.length * sample.sampling_rate;
                        }
                        sflow::RecordType::Ipv6(record) => {
                            key.protocol = record.protocol;
                            bytes = record.length * sample.sampling_rate;
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
