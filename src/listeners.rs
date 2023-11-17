use pcap::{Active, Capture};
use std::{
    io::Error,
    net::{SocketAddr, UdpSocket},
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
    pub fn new(iface: &str, filter: &str, snaplen: i32) -> Self {
        let mut cap = Capture::from_device(iface)
            .unwrap()
            .promisc(true)
            .snaplen(snaplen)
            .open()
            .unwrap();
        cap.filter(filter, true).unwrap();
        Self { cap }
    }
}

impl Receiver for PCapReceiver {
    fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        let packet = self.cap.next_packet().unwrap();
        let data = packet.data;
        let addr = SocketAddr::from(([0, 0, 0, 0], 0));
        buffer[..data.len()].copy_from_slice(&data);
        Ok((data.len(), addr))
    }
}
