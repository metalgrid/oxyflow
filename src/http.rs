use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use tokio;
use warp::Filter;

use crate::Counter;

#[tokio::main]
pub async fn start_http_server(statmap: Arc<Mutex<HashMap<IpAddr, Counter>>>) {
    let routes = warp::path!("metrics").map(move || metrics(&statmap.lock().unwrap()));

    warp::serve(routes).run(([0, 0, 0, 0], 3030)).await
}

fn metrics(counters: &HashMap<IpAddr, Counter>) -> String {
    let mut ret = String::new();
    for (ip, c) in counters {
        ret.push_str(&format!("host={},{}\n", ip, c));
    }
    ret
}
