use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls_acme::futures_rustls::server::TlsStream;

/// This transport either contains a valid TLS stream, or represents a closed connection after
/// performing an ACME tls-alpn-01 challenge.
#[derive(Debug)]
pub struct Transport<Input>(pub(crate) Option<TlsStream<Input>>);

impl<Input> trillium_server_common::AsyncRead for Transport<Input>
where
    Input: trillium_server_common::Transport,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.0 {
            None => Poll::Ready(Ok(0)),
            Some(ref mut tls) => Pin::new(tls).poll_read(cx, buf),
        }
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.0 {
            None => Poll::Ready(Ok(0)),
            Some(ref mut tls) => Pin::new(tls).poll_read_vectored(cx, bufs),
        }
    }
}

impl<Input> trillium_server_common::AsyncWrite for Transport<Input>
where
    Input: trillium_server_common::Transport,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.0 {
            None => Poll::Ready(Ok(0)),
            Some(ref mut tls) => Pin::new(tls).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0 {
            None => Poll::Ready(Ok(())),
            Some(ref mut tls) => Pin::new(tls).poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.0 {
            None => Poll::Ready(Ok(())),
            Some(ref mut tls) => Pin::new(tls).poll_close(cx),
        }
    }

    // Provided method
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.0 {
            None => Poll::Ready(Ok(0)),
            Some(ref mut tls) => Pin::new(tls).poll_write_vectored(cx, bufs),
        }
    }
}

impl<Input> trillium_server_common::Transport for Transport<Input>
where
    Input: trillium_server_common::Transport,
{
    fn set_ip_ttl(&mut self, ttl: u32) -> std::io::Result<()> {
        match self.0 {
            None => Ok(()),
            Some(ref mut tls) => Ok(tls.get_mut().0.set_ip_ttl(ttl)?),
        }
    }

    fn set_linger(&mut self, linger: Option<std::time::Duration>) -> std::io::Result<()> {
        match self.0 {
            None => Ok(()),
            Some(ref mut tls) => Ok(tls.get_mut().0.set_linger(linger)?),
        }
    }

    fn set_nodelay(&mut self, nodelay: bool) -> std::io::Result<()> {
        match self.0 {
            None => Ok(()),
            Some(ref mut tls) => Ok(tls.get_mut().0.set_nodelay(nodelay)?),
        }
    }

    fn peer_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
        match self.0 {
            None => Ok(None),
            Some(ref tls) => Ok(tls.get_ref().0.peer_addr()?),
        }
    }
}
