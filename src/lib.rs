mod client;
mod codec;
mod constants;
mod messages;
mod nthash;
mod parser;
mod proxy;

pub use client::Client;
pub use codec::KdcFrame;
pub use constants::*;
pub use messages::{AsReqExt, EncryptedTimestamp, Keystream};
pub use nthash::NtHash;
pub use proxy::Proxy;
use rc4::{KeyInit, Rc4, StreamCipher};

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(i, j)| i ^ j).collect()
}

pub fn decrypt(nthash: &[u8; 16], buf: &mut Vec<u8>) -> () {
    let mut key = [0u8; 8];
    key.copy_from_slice(&nthash[..8]);
    let mut rc4 = Rc4::new(&key.into());
    rc4.apply_keystream(buf);
}

#[cfg(test)]
mod tests {
    use pretty_hex::PrettyHex;
    use rasn::der;
    use rasn_kerberos::AsRep;

    use super::*;
    
    #[test]
    fn decrypt_as_rep() {
        let as_rep: AsRep = der::decode(VAGRANT_AS_REP).unwrap();
        let mut buf = as_rep.0.enc_part.cipher.as_ref().to_vec();
        decrypt(&VAGRANT_NTHASH, &mut buf);
        dbg!(buf.hex_dump());
        todo!()
    }
}