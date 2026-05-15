use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// Merepresentasikan pasangan kunci ECDH X25519 milik satu entitas E2EE.
pub struct KeyPair {
    private_key: StaticSecret,
    public_key: PublicKey,
}

impl KeyPair {
    /// Membangkitkan pasangan kunci privat-publik Curve25519 untuk simulasi E2EE.
    pub fn generate() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    /// Mengembalikan public key yang boleh dipertukarkan melalui kanal simulasi.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Menghitung shared secret ECDH menggunakan private key lokal dan public key lawan.
    pub fn diffie_hellman(&self, peer_public_key: &PublicKey) -> [u8; 32] {
        self.private_key.diffie_hellman(peer_public_key).to_bytes()
    }
}

/// Mengubah public key ke representasi hex agar mudah ditampilkan pada output verbose.
pub fn public_key_hex(public_key: &PublicKey) -> String {
    hex::encode(public_key.as_bytes())
}
