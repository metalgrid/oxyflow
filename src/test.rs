fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 == 0 {
        (0..s.len())
            .step_by(2)
            .map(|i| {
                s.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
            })
            .collect()
    } else {
        None
    }
}

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;

mod sflow5;
use sflow5::*;

fn main() {
    let sflow_bytes = "0000000500000001ac10011300000001058de11f8e7bb50c0000000400000003000001240000063b00000000000000260008000031d80000000000000000000000000026000000000000003d00000004000000010000009000000001000005f2000005720000008034efb6832f0040deade1eefc81000c8a0800450005dc83c340003f068a4468473c2a173f6c6401bb8d140b245952f84d83a4801024815a7d00000101080a89d4c736dc92367fd6196de87133be1b843f988e5c65800b31d2d2198d0499e1614debe7798e27f658d58140c0848e1797e8fd044c547f362ca6287a661e0978ca480000000200000018000005f240deade1eefc000034efb6832f00000000000800000003e90000001000000c8a0000000000000000000000000000000300000020000005dc0000000668473c2a173f6c64000001bb00008d140000001000000000000000030000012400001065000000000000000a000800008328000000000000000000000000000a000000000000003d0000000400000001000000900000000100000502000004820000008020ab48f41d47d404ffd833fb81000c8a0800450004ec000f40005d110a409df0c6ca672f42c801bb87d104d887f84753458eb31e5791cf6e901f2aa50bcaeba05dee1324e5f9c933d18add40b071a6a4a7682252b595763d31f3cc1e0f7c75ff043a9533249fd6bacb1aaaf1252fcc331f3d838a5194559909394f21822b8098000000020000001800000502d404ffd833fb000020ab48f41d47000000000800000003e90000001000000c8a0000000000000000000000000000000300000020000004ec000000119df0c6ca672f42c8000001bb000087d1000000000000000000000003000000ec000003690000000000000009000800001b480000000000000000000000000009000000000000003d000000040000000100000058000000010000004a000000020000004848a98a98c72dd404ffd833fb81000c8a080045000034391c40005d0689c79df0c63c67a08f1301bbac1a8dbe3f1c81a9743e8010010db86300000101080a02dbfa5206feeda7000000000002000000180000004ad404ffd833fb000048a98a98c72d000000000800000003e90000001000000c8a000000000000000000000000000000030000002000000034000000069df0c63c67a08f13000001bb0000ac1a0000001000000000000000030000013c0000063c00000000000000260008000031e00000000000000000000000000026000000000000003d00000004000000010000009000000001000005d60000055600000080807ff873db0c40deade1eefc81000c8a86dd600caa580598063f2600140f2e00000000000000685a06522402e280222e027ba42b7d16838d162b01bbf1859189b1dbf9bfab6b801004d14f8000000101080a5e41abf21b856280b61a1c9983de28b5be1adde9a0b472e9b5654ab35b175776b4dec3b39be5d490c076c0e06e430000000200000018000005d640deade1eefc0000807ff873db0c0000000086dd000003e90000001000000c8a0000000000000000000000000000000400000038000005c0000000062600140f2e00000000000000685a06522402e280222e027ba42b7d16838d162b000001bb0000f1850000001000000000";

    let bytes = hex_to_bytes(sflow_bytes).unwrap();
    let packet = SFlowPacket::new(&bytes).unwrap();

    println!("{:?}", packet);
    for sample in packet.get_samples() {
        println!("\t{:?}", sample);

        for record in sample.get_records() {
            println!("\t\t{:?}", record);

            match record.get_record_type() {
                1 => {
                    let raw_packet_header = SFlowRawHeaderPacket::new(record.payload()).unwrap();
                    println!("\t\t\t{:?}", raw_packet_header);
                    raw_packet_header.get_header_size();
                    match raw_packet_header.get_protocol() {
                        1 => {
                            let ethernet_packet =
                                EthernetPacket::new(raw_packet_header.payload()).unwrap();
                            println!("\t\t\t\t{:?}", ethernet_packet);
                            match ethernet_packet.get_ethertype() {
                                pnet::packet::ethernet::EtherTypes::Vlan => {
                                    let vlan_packet = pnet::packet::vlan::VlanPacket::new(
                                        ethernet_packet.payload(),
                                    )
                                    .unwrap();
                                    println!("\t\t\t\t{:?}", vlan_packet);
                                    match vlan_packet.get_ethertype() {
                                        pnet::packet::ethernet::EtherTypes::Ipv4 => {
                                            let ipv4_packet = pnet::packet::ipv4::Ipv4Packet::new(
                                                vlan_packet.payload(),
                                            )
                                            .unwrap();
                                            println!("\t\t\t\t{:?}", ipv4_packet);
                                        }
                                        pnet::packet::ethernet::EtherTypes::Ipv6 => {
                                            let ipv6_packet = pnet::packet::ipv6::Ipv6Packet::new(
                                                vlan_packet.payload(),
                                            )
                                            .unwrap();
                                            println!("\t\t\t\t{:?}", ipv6_packet);
                                        }
                                        _ => {}
                                    }
                                }
                                pnet::packet::ethernet::EtherTypes::Ipv4 => {
                                    let ipv4_packet = pnet::packet::ipv4::Ipv4Packet::new(
                                        ethernet_packet.payload(),
                                    )
                                    .unwrap();
                                    println!("\t\t\t\t\t{:?}", ipv4_packet);
                                }
                                pnet::packet::ethernet::EtherTypes::Ipv6 => {
                                    let ipv6_packet = pnet::packet::ipv6::Ipv6Packet::new(
                                        ethernet_packet.payload(),
                                    )
                                    .unwrap();
                                    println!("\t\t\t\t\t{:?}", ipv6_packet);
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                2 => {
                    let ethernet_frame: SFlowEthernetFrame = record.payload().into();
                    println!("\t\t\t{:?}", ethernet_frame);
                }
                3 => {
                    let ipv4 = SFlowIpv4Packet::new(record.payload()).unwrap();
                    println!("\t\t\t{:?}", ipv4);
                }
                1001 => {
                    let extended_switch = SFlowExtendedSwitchPacket::new(record.payload()).unwrap();
                    println!("\t\t\t{:?}", extended_switch);
                }
                _ => {}
            }
        }
    }
}
