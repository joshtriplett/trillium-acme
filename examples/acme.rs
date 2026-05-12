use trillium_acme::rustls_acme::caches::DirCache;
use trillium_acme::AcmeConfig;

fn main() {
    let config = AcmeConfig::new(["domain.example"])
        .contact_push("mailto:admin@example.org")
        .cache(DirCache::new("/srv/example/acme-cache-dir"));

    let (acceptor, future) = trillium_acme::new(config);
    let server_handle = trillium_smol::config()
        .with_port(443)
        .with_host("0.0.0.0")
        .with_nodelay()
        .with_acceptor(acceptor)
        .spawn(|conn: trillium::Conn| async move { conn.ok("Hello TLS!") });

    let future = server_handle.swansong().interrupt(future);
    server_handle.runtime().spawn(future);
    server_handle.block();
}
