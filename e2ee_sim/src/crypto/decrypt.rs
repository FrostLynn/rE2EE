use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as GcmSivNonce};

use super::encrypt::Algorithm;

/// Mendekripsi ciphertext AES-GCM-SIV dan memverifikasi authentication tag.
pub fn decrypt_aes_gcm_siv(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    decrypt_aes_gcm_siv_with_aad(key, nonce, ciphertext, &[])
}

/// Mendekripsi ciphertext AES-GCM dan memverifikasi authentication tag.
pub fn decrypt_aes_gcm(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    decrypt_aes_gcm_with_aad(key, nonce, ciphertext, &[])
}

/// Mendekripsi AES-GCM-SIV dengan associated data eksplisit.
pub fn decrypt_aes_gcm_siv_with_aad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| "Kunci AES-GCM-SIV tidak valid".to_string())?;
    cipher
        .decrypt(
            GcmSivNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "authentication failed".to_string())
}

/// Mendekripsi AES-GCM dengan associated data eksplisit.
pub fn decrypt_aes_gcm_with_aad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| "Kunci AES-GCM tidak valid".to_string())?;
    cipher
        .decrypt(
            GcmNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "authentication failed".to_string())
}

/// Mendekripsi ciphertext menggunakan algoritma AEAD yang dipilih.
pub fn decrypt_with_algorithm(
    algorithm: Algorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    match algorithm {
        Algorithm::AesGcmSiv => decrypt_aes_gcm_siv(key, nonce, ciphertext),
        Algorithm::AesGcm => decrypt_aes_gcm(key, nonce, ciphertext),
    }
}

/// Mendekripsi ciphertext menggunakan algoritma AEAD yang dipilih dan AAD eksplisit.
pub fn decrypt_with_algorithm_aad(
    algorithm: Algorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    match algorithm {
        Algorithm::AesGcmSiv => decrypt_aes_gcm_siv_with_aad(key, nonce, ciphertext, aad),
        Algorithm::AesGcm => decrypt_aes_gcm_with_aad(key, nonce, ciphertext, aad),
    }
}
