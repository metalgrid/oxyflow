use pnet_macros::packet;

#[packet]
pub struct SFlow {
    pub version: u32,
    pub agent_address_type: u32,
    pub agent_address: IpAddr,
    pub sub_agent_id: u32,
    pub sequence_number: u32,
    pub uptime: Duration,
    pub num_samples: u32,
    #[payload]
    pub samples: Vec<Sample>,
}
