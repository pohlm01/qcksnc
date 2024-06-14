use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use color_eyre::eyre::WrapErr;
use color_eyre::Result;
use rcgen::{generate_simple_self_signed, CertifiedKey, Certificate};

pub fn get_or_generate_certificate_and_keys(
    subject_alt_names: Vec<String>,
) -> Result<CertifiedKey> {
    let certificate_file = PathBuf::from(format!("{}.cert", subject_alt_names[0]));
    let key_file = PathBuf::from(format!("{}.key", subject_alt_names[0]));

    if let Ok(certified_key) = read_cert_and_key(certificate_file.as_path(), key_file.as_path()) {
        Ok(certified_key)
    } else {
        let certified_key = generate_simple_self_signed(subject_alt_names)
            .wrap_err("Failed to generate certificate")?;
        fs::write(certificate_file, certified_key.cert.pem())
            .wrap_err("Failed to write certificate")?;
        fs::write(key_file, certified_key.key_pair.serialize_pem())
            .wrap_err("Failed to write key")?;
        Ok(certified_key)
    }
}

fn read_cert_and_key(path_cert: &Path, path_key: &Path) -> Result<CertifiedKey> {
    let mut reader = BufReader::new(path_cert);

    CertificateDer:: fs::read_to_string(path_cert)
    fs::read_to_string(path_key)

}

fn load_certificates_from_pem(path: &str) -> std::io::Result<Vec<Certificate>> {
    let file = File::open(path)?;
    let certs = rustls_pemfile::certs(&mut reader)?;

    Ok(certs.into_iter().map(Certificate).collect())
}