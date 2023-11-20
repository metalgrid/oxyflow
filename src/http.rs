use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
};

use tokio;
use warp::{reply::Reply, Filter};

use crate::Counter;

#[tokio::main]
pub async fn start_http_server(statmap: Arc<RwLock<HashMap<IpAddr, Counter>>>) {
    let net = warp::path("net").map(move || metrics(&statmap.read().unwrap()));
    let flow = warp::path("flow").map(|| "Flow statistics");

    let routes = warp::path("metrics").and(net.or(flow));
    warp::serve(routes).run(([0, 0, 0, 0], 3030)).await
}

fn metrics(counters: &HashMap<IpAddr, Counter>) -> impl Reply {
    warp::reply::json(&counters)
}
