//! trillium-acme helps you serve HTTPS with [Trillium](https://trillium.rs) using automatic
//! certificates, via Let’s Encrypt and ACME tls-alpn-01 challenges.
//!
//! To use `trillium-acme`, create an [`AcmeConfig`] to configure the certificate you want, then
//! call [`trillium_acme::new`] to create an [`Acceptor`] and a future. Spawn the future using the
//! same stopper as the server, then pass the [`Acceptor`] to the server configuration:
//!
//! ```rust,no_run
//! use trillium_acme::AcmeConfig;
//! use trillium_acme::rustls_acme::caches::DirCache;
//!
//! let config = AcmeConfig::new(["domain.example"])
//!     .contact_push("mailto:admin@example.org")
//!     .cache(DirCache::new("/srv/example/acme-cache-dir"));
//!
//! let (acceptor, future) = trillium_acme::new(config);
//! let stopper = trillium_smol::Stopper::new();
//! let future = stopper.stop_future(future);
//! trillium_smol::spawn(async {
//!     future.await;
//! });
//! trillium_smol::config()
//!     .with_port(443)
//!     .with_host("0.0.0.0")
//!     .with_nodelay()
//!     .with_acceptor(acceptor)
//!     .with_stopper(stopper)
//!     .run(|conn: trillium::Conn| async move {
//!        conn.ok("Hello TLS!")
//!     });
//! ```
//!
//! This will configure the TLS stack to obtain a certificate for the domain `domain.example`,
//! which must be a domain for which your Trillium server handles HTTPS traffic.
//!
//! On initial startup, your server will register a certificate via Let's Encrypt. Let's Encrypt
//! will verify your server's control of the domain via an
//! [ACME tls-alpn-01 challenge](https://tools.ietf.org/html/rfc8737), which the TLS listener
//! configured by `trillium-acme` will respond to.
//!
//! You must supply a cache via [`AcmeConfig::cache`] or one of the other cache methods. This cache
//! will keep the ACME account key and registered certificates between runs, needed to avoid
//! hitting rate limits. You can use [`rustls_acme::caches::DirCache`] for a simple filesystem
//! cache, or implement your own caching using the `rustls_acme` cache traits.
//!
//! By default, `trillium-acme` will use the Let's Encrypt staging environment, which is suitable
//! for testing purposes; it produces certificates signed by a staging root so that you can verify
//! your stack is working, but those certificates will not be trusted in browsers or other HTTPS
//! clients. The staging environment has more generous rate limits for use while testing.
//!
//! When you're ready to deploy to production, you can call `.directory_lets_encrypt(true)` to
//! switch to the production Let's Encrypt environment, which produces certificates trusted in
//! browsers and other HTTPS clients. The production environment has
//! [stricter rate limits](https://letsencrypt.org/docs/rate-limits/).
//!
//! `trillium-acme` builds upon the [`rustls-acme`](https://crates.io/crates/rustls-acme) crate.

#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    missing_copy_implementations,
    rustdoc::missing_crate_level_docs,
    missing_debug_implementations,
    missing_docs,
    nonstandard_style,
    unused_qualifications
)]

use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;

use futures_lite::{AsyncWriteExt, StreamExt};
use rustls_acme::futures_rustls::{rustls::ServerConfig, LazyConfigAcceptor};
use trillium::log::{error, info};
use trillium_server_common::async_trait;

pub use rustls_acme::{self, AcmeConfig};

mod transport;
pub use transport::Transport;

/// An acceptor that handles ACME tls-alpn-01 challenges.
///
/// After processing a challenge, this acceptor will return a Transport representing a closed
/// connection.
#[derive(Clone, Debug)]
pub struct Acceptor {
    challenge_server_config: Arc<ServerConfig>,
    default_server_config: Arc<ServerConfig>,
}

/// Create a new [`Acceptor`] to pass to [`trillium_server_common::Config::with_acceptor`], and a
/// new future that must be spawned detached in the background.
pub fn new<EC: 'static + Debug, EA: 'static + Debug>(
    config: AcmeConfig<EC, EA>,
) -> (Acceptor, impl Future) {
    let mut state = config.state();
    let challenge_server_config = state.challenge_rustls_config();
    let default_server_config = state.default_rustls_config();

    let future = async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => info!("ACME event: {:?}", ok),
                Err(err) => error!("ACME error: {:?}", err),
            }
        }
    };

    (
        Acceptor {
            challenge_server_config,
            default_server_config,
        },
        future,
    )
}

#[async_trait]
impl<Input> trillium_server_common::Acceptor<Input> for Acceptor
where
    Input: trillium_server_common::Transport,
{
    type Output = Transport<Input>;
    type Error = std::io::Error;
    async fn accept(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let start_handshake = LazyConfigAcceptor::new(Default::default(), input).await?;
        if rustls_acme::is_tls_alpn_challenge(&start_handshake.client_hello()) {
            let mut tls = start_handshake
                .into_stream(self.challenge_server_config.clone())
                .await?;
            tls.close().await?;
            Ok(Transport(None))
        } else {
            Ok(Transport(Some(
                start_handshake
                    .into_stream(self.default_server_config.clone())
                    .await?,
            )))
        }
    }
}
