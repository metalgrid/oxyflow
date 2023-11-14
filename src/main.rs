use byteorder::{BigEndian, ReadBytesExt};
use std::{io::Cursor, io::Read, net::IpAddr, net::UdpSocket, time::Duration};

#[derive(Debug)]
struct SFlowRecord {
    record_type: u32,
    length: u32,
    data: Vec<u8>,
}

impl SFlowRecord {
    fn parse(buf: &mut Cursor<&[u8; 9000]>) -> SFlowRecord {
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
    fn parse(buf: &mut Cursor<&[u8; 9000]>) -> SFlowSample {
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
            let record_type = buf.read_u32::<BigEndian>().unwrap();
            let length = buf.read_u32::<BigEndian>().unwrap();
            let mut data = vec![0; length as usize];
            buf.read_exact(&mut data).unwrap();
            records.push(SFlowRecord::parse(buf));
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
    fn parse(buf: &mut Cursor<&[u8; 9000]>) -> SFlowDatagram {
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

    loop {
        let (amt, src) = socket.recv_from(&mut buf).expect("didn't receive data");
        let mut c = Cursor::new(&buf);
        dbg!(SFlowDatagram::parse(&mut c));
    }
}
