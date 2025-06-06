use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
};

use crate::{metrics::FlowCounter, Counter};
use serde_json::{self, json};
use tokio;
use warp::{reply::Reply, Filter};

#[tokio::main]
pub async fn start_http_server(
    statmap: Arc<RwLock<HashMap<IpAddr, Counter>>>,
    flow_agent_stats: Arc<RwLock<HashMap<IpAddr, HashMap<String, Counter>>>>,
    flowstat: Arc<RwLock<FlowCounter>>,
) {
    let net = warp::path("net").map(move || metrics(&statmap.read().unwrap()));
    let agent = warp::path("agent").map(move || get_agent_stats(&flow_agent_stats.read().unwrap()));
    let flow = warp::path("flow").map(move || flowstats(&flowstat.read().unwrap()));

    let routes = warp::path("metrics").and(net.or(flow).or(agent));
    warp::serve(routes).run(([0, 0, 0, 0], 3030)).await
}

fn metrics(counters: &HashMap<IpAddr, Counter>) -> impl Reply {
    warp::reply::json(&counters)
}

fn get_agent_stats(counters: &HashMap<IpAddr, HashMap<String, Counter>>) -> impl Reply {
    warp::reply::json(&counters)
}

fn flowstats(counters: &FlowCounter) -> impl Reply {
    let mut res = Vec::new();
    for (k, v) in counters {
        res.push(json!({
            "src_mac": k.src_mac,
            "dst_mac": k.dst_mac,
            "vlan": k.vlan,
            "protocol": k.protocol,
            "packets": v.packets,
            "bytes": v.bytes
        }));
    }
    warp::reply::json(&res)
}
