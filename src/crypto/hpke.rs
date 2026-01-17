use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    pkcs8::{DecodePublicKey, EncodePublicKey},
    PublicKey,
};
use sha2::Sha256;

// ... (omitted code)

// Helper for random bytes using OsRng via getrandom directly or via rand_core
mod getrandom {
    pub fn getrandom(dest: &mut [u8]) -> Result<(), Error> {
        use aes_gcm::aead::rand_core::RngCore;
        aes_gcm::aead::OsRng.fill_bytes(dest);
        Ok(())
    }
    // Simple mock error to satisfy Result type from old usage
    #[derive(Debug)]
    pub struct Error;
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "Random Error")
        }
    }
    impl std::error::Error for Error {}
}

/// HPKE Context for AnyConnect SSO Token Encryption
///
/// Implements the specific variation of HPKE used by Cisco AnyConnect:
/// 1. ECDH P-256 Key Agreement
/// 2. HKDF-SHA256 Key Derivation with info="AC_ECIES"
/// 3. AES-256-GCM Encryption with 12-byte Tag (truncated from 16)
/// 4. Specific TLV Output Format
#[derive(Debug, Clone)]
pub struct HpkeContext {
    client_pubkey: Option<PublicKey>,
}

impl HpkeContext {
    pub fn new() -> Self {
        Self {
            client_pubkey: None,
        }
    }

    /// Parse Client's ECDH Public Key (from X-AnyConnect-STRAP-DH-Pubkey header)
    /// Expects Base64-encoded SPKI (SubjectPublicKeyInfo) format
    pub fn set_client_dh_pubkey(&mut self, base64_pubkey: &str) -> Result<(), String> {
        let pubkey_bytes = BASE64
            .decode(base64_pubkey)
            .map_err(|e| format!("Base64 decode failed: {}", e))?;

        let pubkey = PublicKey::from_public_key_der(&pubkey_bytes)
            .map_err(|e| format!("Invalid P-256 SPKI public key: {}", e))?;

        self.client_pubkey = Some(pubkey);
        Ok(())
    }

    /// Encrypt token using HPKE flow
    /// Returns Base64-encoded specific TLV structure expected by AnyConnect
    pub fn encrypt_token(&self, plain_token: &str) -> Result<String, String> {
        // ... (existing code up to encryption) ...
        let client_pubkey = self
            .client_pubkey
            .as_ref()
            .ok_or("Client public key not set")?;

        // 1. Generate Ephemeral Server Key Pair
        let server_secret = EphemeralSecret::random(&mut OsRng);
        let server_public_key = server_secret.public_key();

        // 2. ECDH: Derive Shared Secret
        let shared_secret = server_secret.diffie_hellman(client_pubkey);
        let shared_secret_bytes = shared_secret.raw_secret_bytes();

        // 3. HKDF: Derive AES Key
        // info = "AC_ECIES"
        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret_bytes);
        let mut aes_key = [0u8; 32]; // AES-256
        hkdf.expand(b"AC_ECIES", &mut aes_key)
            .map_err(|e| format!("HKDF expansion failed: {}", e))?;

        // 4. Encrypt with AES-256-GCM
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);

        // Generate Random IV (12 bytes)
        let mut iv_bytes = [0u8; 12];
        getrandom::getrandom(&mut iv_bytes).map_err(|e| format!("RNG failed: {}", e))?;
        let nonce = Nonce::from_slice(&iv_bytes);

        // Encrypt
        let ciphertext_with_tag = cipher
            .encrypt(nonce, plain_token.as_bytes())
            .map_err(|e| format!("AES encryption failed: {}", e))?;

        // Split Ciphertext and Tag
        let ct_len = ciphertext_with_tag.len() - 16;
        let ciphertext = &ciphertext_with_tag[..ct_len];
        let full_tag = &ciphertext_with_tag[ct_len..];
        let tag_12 = &full_tag[..12];

        // 5. Construct TLV Blob
        let mut tlv = Vec::new();

        // Header (Magic 0x00 0x01)
        tlv.extend_from_slice(&[0x00, 0x01]);

        // Tag 1: Server Public Key (SPKI DER)
        let spki_bytes = server_public_key
            .to_public_key_der()
            .map_err(|e| format!("SPKI encode failed: {}", e))?;

        write_tlv(&mut tlv, 1, spki_bytes.as_ref());

        // Tag 2: AEAD Tag (12 bytes)
        write_tlv(&mut tlv, 2, tag_12);

        // Tag 3: Ciphertext
        write_tlv(&mut tlv, 3, ciphertext);

        // Tag 4: IV (12 bytes)
        write_tlv(&mut tlv, 4, &iv_bytes);

        // 6. Base64 Encode
        Ok(BASE64.encode(tlv))
    }
}

/// Helper to write TLV (Type-Length-Value)
/// Type is 2 bytes big-endian
/// Length is 2 bytes big-endian
fn write_tlv(buf: &mut Vec<u8>, tag: u16, value: &[u8]) {
    buf.extend_from_slice(&tag.to_be_bytes());
    let len = value.len() as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(value);
}
