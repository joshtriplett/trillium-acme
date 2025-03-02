#![allow(clippy::needless_question_mark)]

use std::fs::File;
use std::future::IntoFuture;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use trillium_acme::rustls_acme::caches::DirCache;
use trillium_acme::rustls_acme::futures_rustls::rustls::{self, ClientConfig, RootCertStore};
use trillium_acme::AcmeConfig;

// Retry the provided function until it returns true or 15 seconds have passed. If the latter,
// return an error.
fn retry_loop(f: impl Fn() -> anyhow::Result<bool>) -> anyhow::Result<()> {
    let time = Instant::now();
    while time.elapsed() <= Duration::from_secs(15) {
        match f() {
            Ok(true) => return Ok(()),
            Ok(false) => (),
            Err(e) => return Err(e),
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    bail!("timeout");
}

struct OnDrop(Option<Box<dyn FnOnce()>>);
impl Drop for OnDrop {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}
fn on_drop(f: impl FnOnce() + 'static) -> OnDrop {
    OnDrop(Some(Box::new(f)))
}

fn pem_to_client_config(pem: Vec<u8>) -> anyhow::Result<ClientConfig> {
    let mut roots = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("root certificate parsing")?;
    let root = roots.pop().context("root certificate")?;
    assert!(roots.is_empty());

    let mut root_store = RootCertStore::empty();
    root_store.add(root).context("root certificate")?;
    Ok(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

/// A TCP connector that always connects to the same place, for testing
struct TestTcpConnector(String, u16);

#[trillium::async_trait]
impl trillium_client::Connector for TestTcpConnector {
    type Transport = <trillium_smol::ClientConfig as trillium_client::Connector>::Transport;
    async fn connect(&self, url: &trillium_server_common::Url) -> std::io::Result<Self::Transport> {
        let mut url = url.clone();
        url.set_host(Some(self.0.as_str()))
            .expect("Url::set_host should not fail");
        url.set_port(Some(self.1))
            .expect("Url::set_port should not fail");
        trillium_smol::ClientConfig::new()
            .with_nodelay(true)
            .connect(&url)
            .await
    }
    fn spawn<Fut: std::future::Future<Output = ()> + Send + 'static>(&self, fut: Fut) {
        trillium_smol::ClientConfig::new()
            .with_nodelay(true)
            .spawn(fut)
    }
}

#[test]
fn test_with_pebble() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install default crypto provider"))?;

    let tempdir = tempfile::tempdir()?;

    let log_path = tempdir.path().join("pebble-challtestsrv.log");
    let mut child = Command::new("pebble-challtestsrv")
        .args([
            "-http01",
            "",
            "-https01",
            "",
            "-tlsalpn01",
            "",
            "-doh",
            "",
            "-dns01",
            "127.0.0.1:8053",
            "-management",
            "127.0.0.1:8055",
        ])
        .stdout(File::create(&log_path)?)
        .spawn()?;
    retry_loop(|| {
        Ok(std::fs::read_to_string(&log_path)
            .context("reading pebble-challtestsrv log")?
            .contains("Creating TCP and UDP DNS-01 challenge server on 127.0.0.1:8053"))
    })
    .context("waiting for pebble-challtestsrv")?;
    let _exit_challtestsrv = on_drop(move || child.kill().expect("kill pebble-challtestsrv"));
    println!("pebble-challtestsrv started");

    let log_path = tempdir.path().join("pebble.log");
    let mut child = Command::new("pebble")
        .args([
            "-dnsserver",
            "127.0.0.1:8053",
            "-config",
            "tests/test-with-pebble/pebble-config.json",
        ])
        .env("PEBBLE_VA_NOSLEEP", "1")
        .stdout(File::create(&log_path)?)
        .spawn()?;
    retry_loop(|| {
        Ok(std::fs::read_to_string(&log_path)
            .context("reading pebble log")?
            .contains("ACME directory available at: https://127.0.0.1:14000/dir"))
    })
    .context("waiting for pebble")?;
    let _exit_pebble = on_drop(move || child.kill().expect("kill pebble"));
    println!("pebble started");

    let pebble_client_config = pem_to_client_config(
        std::fs::read("tests/test-with-pebble/pebble.minica.pem")
            .context("reading pebble dir root certificate file")?,
    )
    .context("creating client config for pebble")?;

    let pebble_client = trillium_client::client(trillium_rustls::RustlsConfig::new(
        pebble_client_config.clone(),
        trillium_smol::ClientConfig::new().with_nodelay(true),
    ));
    let pebble_root = smol::block_on(async {
        anyhow::Result::<_>::Ok(
            pebble_client
                .get("https://localhost:15000/roots/0")
                .into_future()
                .await
                .context("pebble root request")?
                .response_body()
                .read_bytes()
                .await
                .context("pebble root response")?,
        )
    })?;
    println!("Got pebble root certificate");

    let acme_cache_path = tempdir.path().join("acme-cache-dir");
    let config = AcmeConfig::new(["domain.example"])
        .contact_push("mailto:admin@example.org")
        .client_tls_config(Arc::new(pebble_client_config))
        .directory("https://127.0.0.1:14000/dir")
        .cache(DirCache::new(acme_cache_path.clone()));

    let (acceptor, future) = trillium_acme::new(config);
    let stopper = trillium_smol::Stopper::new();
    let future = stopper.stop_future(future);
    trillium_smol::spawn(async {
        future.await;
    });
    const HELLO: &str = "Hello TLS!";
    trillium_smol::config()
        .with_port(5001)
        .with_nodelay()
        .with_acceptor(acceptor)
        .with_stopper(stopper)
        .spawn(|conn: trillium::Conn| async move { conn.ok(HELLO) });

    retry_loop(|| match std::fs::read_dir(&acme_cache_path) {
        Ok(dir) => Ok(dir
            .into_iter()
            .collect::<std::io::Result<Vec<std::fs::DirEntry>>>()
            .context("acme cache dir read")?
            .into_iter()
            .any(|entry| {
                entry
                    .file_name()
                    .into_string()
                    .expect("acme cache dir entries must be UTF-8")
                    .starts_with("cached_cert_")
            })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).context("acme cache dir open"),
    })
    .context("waiting for rustls-acme to store signed certificate in cache")?;
    println!("Certificate challenge complete");

    let client_config = pem_to_client_config(pebble_root)
        .context("creating client config for trillium-acme server")?;
    let client = trillium_client::client(trillium_rustls::RustlsConfig::new(
        client_config,
        TestTcpConnector("localhost".to_string(), 5001),
    ));
    let response = smol::block_on(async {
        anyhow::Result::<_>::Ok(
            client
                .get("https://domain.example/")
                .into_future()
                .await
                .context("request / from trillium-acme server")?
                .response_body()
                .read_string()
                .await
                .context("response to / from trillium-acme server")?,
        )
    })?;

    assert_eq!(response, HELLO);
    println!("Got expected response from trillium-acme server");

    Ok(())
}
