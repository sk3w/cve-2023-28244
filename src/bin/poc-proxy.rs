use std::net::SocketAddr;

use clap::Parser;
use cve_2023_28244::Proxy;

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long)]
    listen: SocketAddr,

    #[arg(short, long)]
    remote: SocketAddr,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    tracing_subscriber::fmt::init();
    Proxy::listen(args.listen, args.remote).await.unwrap();
}
