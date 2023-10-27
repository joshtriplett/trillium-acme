use trillium_acme::rustls_acme::caches::DirCache;
use trillium_acme::AcmeConfig;

fn main() {
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
        .run(|conn: trillium::Conn| async move { conn.ok("Hello TLS!") });
}
