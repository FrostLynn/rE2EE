use hkdf::Hkdf;
use sha2::Sha256;

pub const SESSION_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Material kunci hasil HKDF yang dipakai untuk AES-256 dan nonce dasar.
#[derive(Clone, Debug)]
pub struct SessionMaterial {
    pub session_key: [u8; SESSION_KEY_LEN],
    pub base_nonce: [u8; NONCE_LEN],
}

/// Menurunkan shared secret ECDH menjadi session key AES-256 dan nonce dasar menggunakan HKDF-SHA256.
pub fn derive_session_material(shared_secret: &[u8; 32]) -> Result<SessionMaterial, String> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; SESSION_KEY_LEN + NONCE_LEN];
    hk.expand(b"e2ee-sim session material", &mut okm)
        .map_err(|_| "HKDF gagal menghasilkan material kunci".to_string())?;

    let mut session_key = [0u8; SESSION_KEY_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    session_key.copy_from_slice(&okm[..SESSION_KEY_LEN]);
    base_nonce.copy_from_slice(&okm[SESSION_KEY_LEN..]);

    Ok(SessionMaterial {
        session_key,
        base_nonce,
    })
}

/// Menggunakan shared secret ECDH langsung sebagai AES-256 key untuk konfigurasi ablation tanpa HKDF.
pub fn direct_session_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    *shared_secret
}
