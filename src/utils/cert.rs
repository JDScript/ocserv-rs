use tracing::{debug, info, warn};

/// Certificate key type for cipher selection
#[derive(Debug, Clone, PartialEq)]
pub enum CertKeyType {
    Ec,
    Rsa,
    Unknown,
}

/// Detect the public key type of a certificate file
pub fn detect_cert_key_type(cert_path: &str) -> CertKeyType {
    use openssl::pkey::Id;
    use openssl::x509::X509;

    let cert_pem = match std::fs::read(cert_path) {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to read certificate for key type detection: {}", e);
            return CertKeyType::Unknown;
        }
    };

    let cert = match X509::from_pem(&cert_pem) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to parse certificate PEM: {}", e);
            return CertKeyType::Unknown;
        }
    };

    let pubkey = match cert.public_key() {
        Ok(pk) => pk,
        Err(e) => {
            warn!("Failed to extract public key: {}", e);
            return CertKeyType::Unknown;
        }
    };

    match pubkey.id() {
        Id::EC => {
            debug!("Certificate uses EC (ECDSA) key");
            CertKeyType::Ec
        }
        Id::RSA => {
            debug!("Certificate uses RSA key");
            CertKeyType::Rsa
        }
        other => {
            warn!("Unknown certificate key type: {:?}", other);
            CertKeyType::Unknown
        }
    }
}

/// Select a cipher from the client's list that is compatible with our certificate type
pub fn select_compatible_cipher(client_ciphers: &str, cert_type: &CertKeyType) -> String {
    let ciphers: Vec<&str> = client_ciphers.split(':').collect();

    // Define preferred cipher order based on certificate type
    let preferred_prefixes = match cert_type {
        CertKeyType::Ec => vec!["ECDHE-ECDSA-"],
        CertKeyType::Rsa => vec!["ECDHE-RSA-", "DHE-RSA-"],
        CertKeyType::Unknown => vec!["ECDHE-ECDSA-", "ECDHE-RSA-", "DHE-RSA-", "AES"],
    };

    // Find first matching cipher
    for prefix in &preferred_prefixes {
        for cipher in &ciphers {
            if cipher.starts_with(prefix) {
                info!(
                    "Selected compatible DTLS cipher: {} (cert type: {:?})",
                    cipher, cert_type
                );
                return cipher.to_string();
            }
        }
    }

    // Fallback: return first cipher from list (may not work, but better than nothing)
    let fallback = ciphers.first().unwrap_or(&"AES256-GCM-SHA384").to_string();
    warn!(
        "No compatible cipher found for {:?} cert, using fallback: {}",
        cert_type, fallback
    );
    fallback
}
