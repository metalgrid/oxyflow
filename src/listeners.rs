use pcap::{Active, Capture};
use pnet::packet::{ipv4::Ipv4Packet, sll::SLLPacket, udp::UdpPacket, Packet};
use std::{
    io::Error,
    net::{IpAddr, SocketAddr, UdpSocket},
};

pub trait Receiver {
    fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Error>;
}

pub struct UdpReceiver {
    socket: UdpSocket,
}
impl UdpReceiver {
    pub fn new(addr: &str) -> Self {
        let socket = UdpSocket::bind(addr).expect("couldn't bind to address");
        Self { socket }
    }
}

impl Receiver for UdpReceiver {
    fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        self.socket.recv_from(buffer)
    }
}

pub struct PCapReceiver {
    cap: Capture<Active>,
}

impl PCapReceiver {
    pub fn new(iface: &str, filter: &str, snaplen: i32, immediate_mode: bool) -> Self {
        let mut cap = Capture::from_device(iface)
            .unwrap()
            .promisc(true)
            .immediate_mode(immediate_mode)
            .snaplen(snaplen)
            .open()
            .unwrap();
        cap.filter(filter, true).unwrap();
        Self { cap }
    }
}

impl Receiver for PCapReceiver {
    fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        match self.cap.next_packet() {
            Ok(packet) => {
                let sllp = SLLPacket::new(packet.data).unwrap();
                let ip = Ipv4Packet::new(sllp.payload()).unwrap();
                let udp = UdpPacket::new(ip.payload()).unwrap();
                let addr = SocketAddr::new(IpAddr::V4(ip.get_source()), udp.get_source());

                let len = udp.payload().len();

                buffer[..len].copy_from_slice(udp.payload());
                Ok((len, addr))
            }
            Err(e) => Err(Error::new(std::io::ErrorKind::Other, e)),
        }
    }
}
