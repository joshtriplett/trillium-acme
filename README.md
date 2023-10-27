trillium-acme helps you serve HTTPS with [Trillium](https://trillium.rs) using automatic
certificates, via Let’s Encrypt and ACME tls-alpn-01 challenges.

To use `trillium-acme`, create an `AcmeConfig` to configure the certificate you want, then
call `trillium_acme::new` to create an `Acceptor` and a future. Spawn the future using the
same stopper as the server, then pass the `Acceptor` to the server configuration:

```rust,no_run
use trillium_acme::AcmeConfig;
use trillium_acme::rustls_acme::caches::DirCache;

let config = AcmeConfig::new(["domain.example"])
    .contact_push("mailto:admin@example.org")
    .cache(DirCache::new("/srv/example/acme-cache-dir"));

let (acceptor, future) = trillium_acme::new(config);
let stopper = trillium_smol::Stopper::new();
let future = stopper.stop_future(future);
trillium_smol::spawn(async {
    future.await;
});
trillium_smol::config()
    .with_port(443)
    .with_host("0.0.0.0")
    .with_nodelay()
    .with_acceptor(acceptor)
    .with_stopper(stopper)
    .run(|conn: trillium::Conn| async move {
       conn.ok("Hello TLS!")
    });
```

This will configure the TLS stack to obtain a certificate for the domain `domain.example`,
which must be a domain for which your Trillium server handles HTTPS traffic.

On initial startup, your server will register a certificate via Let's Encrypt. Let's Encrypt
will verify your server's control of the domain via an
[ACME tls-alpn-01 challenge](https://tools.ietf.org/html/rfc8737), which the TLS listener
configured by `trillium-acme` will respond to.

You must supply a cache via `AcmeConfig::cache` or one of the other cache methods. This cache
will keep the ACME account key and registered certificates between runs, needed to avoid
hitting rate limits. You can use `rustls_acme::caches::DirCache` for a simple filesystem
cache, or implement your own caching using the `rustls_acme` cache traits.

By default, `trillium-acme` will use the Let's Encrypt staging environment, which is suitable
for testing purposes; it produces certificates signed by a staging root so that you can verify
your stack is working, but those certificates will not be trusted in browsers or other HTTPS
clients. The staging environment has more generous rate limits for use while testing.

When you're ready to deploy to production, you can call `.directory_lets_encrypt(true)` to
switch to the production Let's Encrypt environment, which produces certificates trusted in
browsers and other HTTPS clients. The production environment has
[stricter rate limits](https://letsencrypt.org/docs/rate-limits/).

`trillium-acme` builds upon the [`rustls-acme`](https://crates.io/crates/rustls-acme) crate.
