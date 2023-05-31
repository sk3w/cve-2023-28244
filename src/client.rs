use std::{io, net::SocketAddr};

use futures::{SinkExt, StreamExt};
use rasn_kerberos::AsReq;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::codec::{KdcCodec, KdcFrame};

pub struct Client {
    framed: Framed<TcpStream, KdcCodec>,
}

impl Client {
    pub async fn connect(kdc_addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(&kdc_addr).await?;
        let framed = Framed::new(stream, KdcCodec);
        Ok(Self { framed })
    }

    pub async fn send_as_req(&mut self, as_req: AsReq) -> io::Result<KdcFrame> {
        self.framed.send(as_req).await?;
        let kdc_rep = self
            .framed
            .next()
            .await
            .unwrap()?;
        Ok(kdc_rep)
    }
}
