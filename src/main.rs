use std::fs::{File, OpenOptions};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, io};

use clap::Parser;
use color_eyre::eyre::{bail, eyre, OptionExt, WrapErr};
use color_eyre::{eyre, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::pki_types::PrivateKeyDer;
use quinn::{rustls, Connecting, Incoming};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, instrument};

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short, default_value = "[::]:4433")]
    listen: SocketAddr,
    #[clap(long, short)]
    peers: Vec<SocketAddr>,
    #[clap(long)]
    key: Option<PathBuf>,
    #[clap(long)]
    cert: Option<PathBuf>,
    #[clap(long = "ca")]
    ca: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let args = Args::parse();
    debug!(?args);

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("Cound not install default crypto provider"))?;

    run(args).await
}

#[instrument(skip_all, err)]
async fn run(args: Args) -> Result<()> {
    let (certs, key) = if let (Some(key_path), Some(cert_path)) = (&args.key, &args.cert) {
        let key = fs::read(key_path).context("failed to read private key")?;
        let key = if key_path.extension().map_or(false, |x| x == "der") {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
        } else {
            rustls_pemfile::private_key(&mut &*key)
                .context("malformed PKCS #1 private key")?
                .ok_or_eyre("no private keys found")?
        };
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
            vec![CertificateDer::from(cert_chain)]
        } else {
            rustls_pemfile::certs(&mut &*cert_chain)
                .collect::<Result<_, _>>()
                .context("invalid PEM-encoded certificate")?
        };

        (cert_chain, key)
    } else {
        let dirs = directories_next::ProjectDirs::from("nl", "tweedegolf", "qcksnc").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok((cert, key)) => (
                CertificateDer::from(cert),
                PrivateKeyDer::try_from(key).map_err(eyre::Error::msg)?,
            ),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
                let cert = cert.cert.into();
                fs::create_dir_all(path).context("failed to create certificate directory")?;
                fs::write(&cert_path, &cert).context("failed to write certificate")?;
                fs::write(&key_path, key.secret_pkcs8_der())
                    .context("failed to write private key")?;
                (cert, key.into())
            }
            Err(e) => {
                bail!("failed to read certificate: {}", e);
            }
        };

        (vec![cert], key)
    };

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    let mut endpoint = quinn::Endpoint::server(server_config, args.listen)?;
    info!("listening on {}", endpoint.local_addr()?);

    endpoint.set_default_client_config(setup_client(&args)?);
    for peer in args.peers {
        let connecting = endpoint.connect(peer, "localhost")?;
        tokio::spawn(handle_outgoing(connecting));
    }

    while let Some(conn) = endpoint.accept().await {
        if !conn.remote_address_validated() {
            info!("requiring connection to validate its address");
            conn.retry().unwrap();
        } else {
            tokio::spawn(handle_incoming(conn));
        }
    }

    Ok(())
}

#[instrument(err, skip_all)]
async fn handle_incoming(conn: Incoming) -> Result<()> {
    info!("accepting connection");
    let connection = conn.await?;
    let (mut tx, mut rx) = connection.accept_bi().await?;
    debug!("accepted connection");

    let mut file_name = String::new();
    rx.read_to_string(&mut file_name).await?;
    debug!(file_name, "requested file");
    let mut file = tokio::fs::File::open(file_name).await?;

    tokio::io::copy(&mut file, &mut tx).await?;

    debug!("written response");

    tx.finish()?;
    debug!("finished");
    tx.stopped().await?;
    debug!("flushed");

    Ok(())
}

#[instrument(err, skip_all)]
async fn handle_outgoing(conn: Connecting) -> Result<()> {
    let conn = conn.await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    debug!("established connection");

    tx.write_all(b"/etc/passwd").await?;
    debug!("written request");
    tx.finish()?;
    debug!("finished");
    tx.stopped().await?;
    debug!("flushed");

    let dest_file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open("temp.sync")?;
    dest_file.set_len(10_000)?;
    let mut map = unsafe { memmap2::MmapMut::map_mut(&dest_file)? };
    while let Some(chunk) = rx.read_chunk(10, false).await? {
        let offset = chunk.offset as usize;
        map[offset..][..chunk.bytes.len()].copy_from_slice(&chunk.bytes);
    }

    Ok(())
}

fn setup_client(args: &Args) -> Result<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca_path) = args.ca.as_ref() {
        roots.add(CertificateDer::from(fs::read(ca_path)?))?;
    } else {
        let dirs = directories_next::ProjectDirs::from("nl", "tweedegolf", "qcksnc").unwrap();
        match fs::read(dirs.data_local_dir().join("cert.der")) {
            Ok(cert) => {
                roots.add(CertificateDer::from(cert))?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("local server certificate not found");
            }
            Err(e) => {
                error!("failed to open local server certificate: {}", e);
            }
        }
    }
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto)?,
    )))
}
