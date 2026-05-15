use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as GcmSivNonce};
use rand::rngs::OsRng;
use rand::RngCore;

pub const TAG_LEN: usize = 16;

/// Algoritma AEAD yang didukung simulasi.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    AesGcmSiv,
    AesGcm,
}

impl Algorithm {
    /// Mengembalikan label algoritma untuk output terminal dan CSV.
    pub fn label(self) -> &'static str {
        match self {
            Algorithm::AesGcmSiv => "AES-GCM-SIV",
            Algorithm::AesGcm => "AES-GCM",
        }
    }
}

/// Hasil enkripsi AEAD berisi nonce dan ciphertext yang sudah mencakup authentication tag.
#[derive(Clone, Debug)]
pub struct EncryptionResult {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Membangkitkan nonce 96-bit menggunakan CSPRNG untuk satu proses enkripsi.
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Mengenkripsi plaintext menggunakan AES-GCM-SIV dengan nonce acak 12-byte.
pub fn encrypt_aes_gcm_siv(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptionResult, String> {
    let nonce = generate_nonce();
    encrypt_aes_gcm_siv_with_nonce_and_aad(key, &nonce, plaintext, &[])
        .map(|ciphertext| EncryptionResult { nonce, ciphertext })
}

/// Mengenkripsi plaintext menggunakan AES-GCM dengan nonce acak 12-byte.
pub fn encrypt_aes_gcm(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptionResult, String> {
    let nonce = generate_nonce();
    encrypt_aes_gcm_with_nonce_and_aad(key, &nonce, plaintext, &[])
        .map(|ciphertext| EncryptionResult { nonce, ciphertext })
}

/// Mengenkripsi plaintext menggunakan AES-GCM-SIV dengan nonce dan associated data eksplisit.
pub fn encrypt_aes_gcm_siv_with_nonce_and_aad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| "Kunci AES-GCM-SIV tidak valid".to_string())?;
    cipher
        .encrypt(
            GcmSivNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "Enkripsi AES-GCM-SIV gagal".to_string())
}

/// Mengenkripsi plaintext menggunakan AES-GCM dengan nonce dan associated data eksplisit.
pub fn encrypt_aes_gcm_with_nonce_and_aad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| "Kunci AES-GCM tidak valid".to_string())?;
    cipher
        .encrypt(
            GcmNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "Enkripsi AES-GCM gagal".to_string())
}

/// Mengenkripsi plaintext menggunakan algoritma AEAD yang dipilih dengan nonce acak.
pub fn encrypt_with_algorithm(
    algorithm: Algorithm,
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptionResult, String> {
    match algorithm {
        Algorithm::AesGcmSiv => encrypt_aes_gcm_siv(key, plaintext),
        Algorithm::AesGcm => encrypt_aes_gcm(key, plaintext),
    }
}

/// Mengenkripsi plaintext menggunakan algoritma AEAD yang dipilih, nonce, dan AAD eksplisit.
pub fn encrypt_with_algorithm_nonce_aad(
    algorithm: Algorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    match algorithm {
        Algorithm::AesGcmSiv => encrypt_aes_gcm_siv_with_nonce_and_aad(key, nonce, plaintext, aad),
        Algorithm::AesGcm => encrypt_aes_gcm_with_nonce_and_aad(key, nonce, plaintext, aad),
    }
}

/// Memisahkan bagian ciphertext murni tanpa tag untuk demonstrasi XOR pada nonce reuse.
pub fn ciphertext_body(ciphertext_with_tag: &[u8]) -> &[u8] {
    if ciphertext_with_tag.len() <= TAG_LEN {
        ciphertext_with_tag
    } else {
        &ciphertext_with_tag[..ciphertext_with_tag.len() - TAG_LEN]
    }
}
