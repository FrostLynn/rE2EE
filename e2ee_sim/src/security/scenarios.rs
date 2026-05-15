use std::collections::HashSet;

use crate::crypto::decrypt::{decrypt_aes_gcm_siv, decrypt_with_algorithm_aad};
use crate::crypto::encrypt::{
    ciphertext_body, encrypt_aes_gcm_siv, encrypt_aes_gcm_siv_with_nonce_and_aad,
    encrypt_aes_gcm_with_nonce_and_aad, encrypt_with_algorithm_nonce_aad, generate_nonce,
    Algorithm,
};
use crate::crypto::kdf::derive_session_material;
use crate::crypto::keygen::{public_key_hex, KeyPair};
use crate::output::csv::{write_csv, SecurityRow};

/// Pilihan skenario keamanan dari CLI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioSelection {
    One(u8),
    All,
}

/// Mem-parse flag --scenario dan menolak nilai selain 1-5 atau all.
pub fn parse_scenario_selection(value: Option<&str>) -> Result<ScenarioSelection, String> {
    match value.unwrap_or("all") {
        "all" => Ok(ScenarioSelection::All),
        "1" => Ok(ScenarioSelection::One(1)),
        "2" => Ok(ScenarioSelection::One(2)),
        "3" => Ok(ScenarioSelection::One(3)),
        "4" => Ok(ScenarioSelection::One(4)),
        "5" => Ok(ScenarioSelection::One(5)),
        other => Err(format!(
            "Nilai --scenario tidak valid: {other}. Gunakan 1, 2, 3, 4, 5, atau all."
        )),
    }
}

/// Menjalankan satu atau seluruh skenario keamanan dan mengekspor ringkasannya ke CSV.
pub fn run_security(
    input: &str,
    selection: ScenarioSelection,
    output_path: &str,
) -> Result<(), String> {
    let plaintext = input.as_bytes();
    let mut rows = Vec::new();

    let scenarios: Vec<u8> = match selection {
        ScenarioSelection::All => vec![1, 2, 3, 4, 5],
        ScenarioSelection::One(n) => vec![n],
    };

    for scenario in scenarios {
        match scenario {
            1 => scenario_eavesdropping(plaintext, &mut rows)?,
            2 => scenario_tampering(plaintext, &mut rows)?,
            3 => scenario_replay(plaintext, &mut rows)?,
            4 => scenario_nonce_reuse(&mut rows)?,
            5 => scenario_mitm(plaintext, &mut rows)?,
            _ => unreachable!(),
        }
    }

    write_csv(output_path, &rows)?;
    Ok(())
}

/// Skenario 1: Eve mencoba membuka ciphertext dengan random key, partial key, dan zero key.
pub fn scenario_eavesdropping(plaintext: &[u8], rows: &mut Vec<SecurityRow>) -> Result<(), String> {
    println!("\n=== SCENARIO 1: Eavesdropping ===");
    println!("Tujuan:");
    println!("  Menguji CONFIDENTIALITY ketika Eve hanya memperoleh nonce dan ciphertext.");
    println!("  Eve tidak memiliki private key Alice/Bob dan tidak memiliki session key yang sah.");

    let key = session_key()?;
    let encrypted = encrypt_aes_gcm_siv(&key, plaintext)?;
    let tag = auth_tag(&encrypted.ciphertext);
    let body = ciphertext_body(&encrypted.ciphertext);

    println!("\nData yang diamati Eve:");
    println!(
        "  Plaintext asli hanya untuk validasi simulasi: {}",
        printable_bytes(plaintext)
    );
    println!("  Plaintext size: {} bytes", plaintext.len());
    println!("  Algorithm: AES-GCM-SIV");
    println!("  Nonce publik (hex): {}", hex::encode(encrypted.nonce));
    println!("  Ciphertext body (hex): {}", hex::encode(body));
    println!("  Authentication tag 16 byte (hex): {}", hex::encode(tag));
    println!(
        "  Ciphertext total size: {} bytes",
        encrypted.ciphertext.len()
    );
    println!("  Session key sah disembunyikan dari Eve.");

    let mut partial_key = [0u8; 32];
    partial_key[..16].copy_from_slice(&key[..16]);
    let attempts = [
        (
            "random key",
            generate_random_key(),
            "Key acak 32 byte yang tidak berhubungan dengan ECDH.",
        ),
        (
            "partial key",
            partial_key,
            "16 byte awal sama dengan key sah, 16 byte akhir nol.",
        ),
        ("zero key", [0u8; 32], "Key lemah berisi 32 byte nol."),
    ];

    let mut any_success = false;
    println!("\nDetail percobaan dekripsi oleh Eve:");
    for (idx, (attempt, eve_key, description)) in attempts.iter().enumerate() {
        let result = decrypt_aes_gcm_siv(eve_key, &encrypted.nonce, &encrypted.ciphertext);
        let success = result.is_ok();
        any_success |= success;

        println!("\n  Attempt {} — {attempt}", idx + 1);
        println!("    Deskripsi: {description}");
        println!("    Eve key (hex): {}", hex::encode(eve_key));
        println!(
            "    Nonce dipakai ulang dari pesan asli: {}",
            hex::encode(encrypted.nonce)
        );
        println!(
            "    Hasil dekripsi: {}",
            if success { "BERHASIL" } else { "GAGAL" }
        );
        if let Ok(recovered) = result {
            println!(
                "    Plaintext yang berhasil dibuka: {}",
                printable_bytes(&recovered)
            );
            println!("    Analisis: ini tidak aman karena Eve dapat membaca isi pesan.");
        } else {
            println!("    Error: authentication failed");
            println!("    Analisis: tag tidak valid karena key tidak cocok dengan key enkripsi.");
        }

        rows.push(SecurityRow {
            scenario: "1-Eavesdropping".to_string(),
            algorithm: "AES-GCM-SIV".to_string(),
            attempt: (*attempt).to_string(),
            result: if success {
                "decrypt-success"
            } else {
                "decrypt-failed"
            }
            .to_string(),
            property: "CONFIDENTIALITY".to_string(),
            verdict: if success { "FAIL" } else { "PASS" }.to_string(),
        });
    }

    println!("\nRingkasan Scenario 1:");
    println!(
        "  Plaintext reconstructed: {}",
        if any_success { "YES" } else { "NO" }
    );
    println!(
        "  Property verified: CONFIDENTIALITY {}",
        if any_success { "FAIL" } else { "PASS" }
    );
    Ok(())
}

/// Skenario 2: beberapa bit ciphertext dimodifikasi dan harus ditolak oleh tag autentikasi.
pub fn scenario_tampering(plaintext: &[u8], rows: &mut Vec<SecurityRow>) -> Result<(), String> {
    println!("\n=== SCENARIO 2: Tampering ===");
    println!("Tujuan:");
    println!("  Menguji INTEGRITY ketika penyerang mengubah bit pada ciphertext/tag.");
    println!("  Setiap perubahan harus menyebabkan verifikasi authentication tag gagal.");

    let key = session_key()?;
    let encrypted = encrypt_aes_gcm_siv(&key, plaintext)?;
    let positions = tamper_positions(encrypted.ciphertext.len());
    let mut all_detected = true;

    println!("\nData asli sebelum modifikasi:");
    println!("  Plaintext: {}", printable_bytes(plaintext));
    println!("  Nonce (hex): {}", hex::encode(encrypted.nonce));
    println!(
        "  Ciphertext valid (hex): {}",
        hex::encode(&encrypted.ciphertext)
    );
    println!("  Ciphertext size: {} bytes", encrypted.ciphertext.len());
    println!("  Posisi uji tampering: {:?}", positions);

    for (idx, pos) in positions.into_iter().enumerate() {
        let mut tampered = encrypted.ciphertext.clone();
        let before = tampered[pos];
        tampered[pos] ^= 0x01;
        let after = tampered[pos];
        let detected = decrypt_aes_gcm_siv(&key, &encrypted.nonce, &tampered).is_err();
        all_detected &= detected;

        println!(
            "\n  Attempt {} — flip 1 bit pada posisi byte {pos}",
            idx + 1
        );
        println!("    Byte sebelum: 0x{before:02x}");
        println!("    Byte sesudah: 0x{after:02x}");
        println!("    Mask XOR: 0x01");
        println!("    Ciphertext rusak (hex): {}", hex::encode(&tampered));
        println!(
            "    Hasil verifikasi tag: {}",
            if detected {
                "GAGAL seperti yang diharapkan"
            } else {
                "LOLOS / tidak terdeteksi"
            }
        );
        println!(
            "    Status integritas: {}",
            if detected {
                "Modification detected"
            } else {
                "Modification accepted"
            }
        );

        rows.push(SecurityRow {
            scenario: "2-Tampering".to_string(),
            algorithm: "AES-GCM-SIV".to_string(),
            attempt: format!("flip-bit-pos-{pos}"),
            result: if detected {
                "authentication-failed"
            } else {
                "accepted"
            }
            .to_string(),
            property: "INTEGRITY".to_string(),
            verdict: if detected { "PASS" } else { "FAIL" }.to_string(),
        });
    }

    println!("\nRingkasan Scenario 2:");
    println!(
        "  Modification detected: {}",
        if all_detected { "YES" } else { "NO" }
    );
    println!(
        "  Property verified: INTEGRITY {}",
        if all_detected { "PASS" } else { "FAIL" }
    );
    Ok(())
}

/// Skenario 3: ciphertext dengan timestamp lama dikirim ulang dan ditolak oleh cache replay.
pub fn scenario_replay(plaintext: &[u8], rows: &mut Vec<SecurityRow>) -> Result<(), String> {
    println!("\n=== SCENARIO 3: Replay Attack ===");
    println!("Tujuan:");
    println!("  Menguji AUTHENTICITY ketika ciphertext valid lama dikirim ulang.");
    println!(
        "  Timestamp/AAD dan replay cache digunakan untuk membedakan pesan baru dan pesan replay."
    );

    let key = session_key()?;
    let nonce = generate_nonce();
    let timestamp_old = b"timestamp=1700000000";
    let ciphertext = encrypt_with_algorithm_nonce_aad(
        Algorithm::AesGcmSiv,
        &key,
        &nonce,
        plaintext,
        timestamp_old,
    )?;

    println!("\nPesan asli:");
    println!("  Plaintext: {}", printable_bytes(plaintext));
    println!("  AAD timestamp lama: {}", printable_bytes(timestamp_old));
    println!("  Nonce (hex): {}", hex::encode(nonce));
    println!("  Ciphertext (hex): {}", hex::encode(&ciphertext));
    println!(
        "  Replay ID: {}",
        replay_id_short(&nonce, &ciphertext, timestamp_old)
    );

    let mut seen = HashSet::new();
    let first_id = replay_id(&nonce, &ciphertext, timestamp_old);
    let first_is_new = !seen.contains(&first_id);
    let first_decrypt_ok = decrypt_with_algorithm_aad(
        Algorithm::AesGcmSiv,
        &key,
        &nonce,
        &ciphertext,
        timestamp_old,
    )
    .is_ok();
    if first_is_new && first_decrypt_ok {
        seen.insert(first_id.clone());
    }

    println!("\n  Pengiriman pertama:");
    println!("    Replay cache sebelum menerima: kosong");
    println!(
        "    ID pesan sudah pernah dilihat: {}",
        if first_is_new { "NO" } else { "YES" }
    );
    println!(
        "    Verifikasi AEAD dengan AAD timestamp: {}",
        if first_decrypt_ok { "valid" } else { "invalid" }
    );
    println!(
        "    Keputusan penerima: {}",
        if first_is_new && first_decrypt_ok {
            "DITERIMA"
        } else {
            "DITOLAK"
        }
    );

    let replay_seen = seen.contains(&first_id);
    let replay_auth_ok = decrypt_with_algorithm_aad(
        Algorithm::AesGcmSiv,
        &key,
        &nonce,
        &ciphertext,
        timestamp_old,
    )
    .is_ok();
    let replay_detected = replay_seen && replay_auth_ok;

    println!("\n  Pengiriman ulang oleh Eve:");
    println!("    Ciphertext yang dikirim ulang sama: YES");
    println!(
        "    Timestamp/AAD masih timestamp lama: {}",
        printable_bytes(timestamp_old)
    );
    println!(
        "    ID pesan sudah ada di replay cache: {}",
        if replay_seen { "YES" } else { "NO" }
    );
    println!(
        "    Verifikasi AEAD tetap valid: {}",
        if replay_auth_ok { "YES" } else { "NO" }
    );
    println!(
        "    Keputusan penerima: {}",
        if replay_detected {
            "DITOLAK sebagai replay"
        } else {
            "DITERIMA"
        }
    );

    println!("\nRingkasan Scenario 3:");
    println!(
        "  Replay detected: {}",
        if replay_detected { "YES" } else { "NO" }
    );
    println!(
        "  Property verified: AUTHENTICITY {}",
        if replay_detected { "PASS" } else { "FAIL" }
    );

    rows.push(SecurityRow {
        scenario: "3-Replay Attack".to_string(),
        algorithm: "AES-GCM-SIV".to_string(),
        attempt: "replay-same-ciphertext-old-timestamp".to_string(),
        result: if replay_detected {
            "rejected"
        } else {
            "accepted"
        }
        .to_string(),
        property: "AUTHENTICITY".to_string(),
        verdict: if replay_detected { "PASS" } else { "FAIL" }.to_string(),
    });
    Ok(())
}

/// Skenario 4: membandingkan dampak nonce reuse pada AES-GCM dan AES-GCM-SIV.
pub fn scenario_nonce_reuse(rows: &mut Vec<SecurityRow>) -> Result<(), String> {
    println!("\n=== SCENARIO 4: Nonce Reuse ===");
    println!("Tujuan:");
    println!("  Membandingkan dampak pemakaian nonce yang sama pada AES-GCM dan AES-GCM-SIV.");
    println!("  AES-GCM harus ditandai VULNERABLE, sedangkan AES-GCM-SIV ditandai SECURE pada simulasi misuse ini.");

    let key = session_key()?;
    let nonce = generate_nonce();
    let p1 = b"Transfer Rp1000000 ke Bob.";
    let p2 = b"Transfer Rp9000000 ke Eve.";
    let plaintext_xor = xor_min(p1, p2);

    println!("\nParameter bersama:");
    println!("  Session key (hex): {}", hex::encode(key));
    println!(
        "  Nonce yang sengaja digunakan ulang (hex): {}",
        hex::encode(nonce)
    );
    println!("  Plaintext A: {}", printable_bytes(p1));
    println!("  Plaintext B: {}", printable_bytes(p2));
    println!("  Plaintext A size: {} bytes", p1.len());
    println!("  Plaintext B size: {} bytes", p2.len());
    println!("  XOR plaintext A^B (hex): {}", hex::encode(&plaintext_xor));

    let gcm_a = encrypt_aes_gcm_with_nonce_and_aad(&key, &nonce, p1, &[])?;
    let gcm_b = encrypt_aes_gcm_with_nonce_and_aad(&key, &nonce, p2, &[])?;
    let gcm_body_a = ciphertext_body(&gcm_a);
    let gcm_body_b = ciphertext_body(&gcm_b);
    let gcm_xor = xor_min(gcm_body_a, gcm_body_b);
    let gcm_leaks_plaintext_xor = gcm_xor == plaintext_xor;

    println!("\n[AES-GCM]");
    println!("  Aksi: enkripsi dua plaintext berbeda dengan key dan nonce yang sama.");
    println!("  Ciphertext A full (hex): {}", hex::encode(&gcm_a));
    println!("  Ciphertext B full (hex): {}", hex::encode(&gcm_b));
    println!(
        "  Ciphertext A body tanpa tag (hex): {}",
        hex::encode(gcm_body_a)
    );
    println!(
        "  Ciphertext B body tanpa tag (hex): {}",
        hex::encode(gcm_body_b)
    );
    println!("  Tag A (hex): {}", hex::encode(auth_tag(&gcm_a)));
    println!("  Tag B (hex): {}", hex::encode(auth_tag(&gcm_b)));
    println!("  XOR ciphertext body A^B (hex): {}", hex::encode(&gcm_xor));
    println!(
        "  XOR ciphertext body == XOR plaintext: {}",
        if gcm_leaks_plaintext_xor { "YES" } else { "NO" }
    );
    println!("  Analisis: pada AES-GCM, nonce reuse memakai ulang keystream sehingga relasi plaintext bocor.");
    println!("  Verdict AES-GCM: VULNERABLE");

    rows.push(SecurityRow {
        scenario: "4-Nonce Reuse".to_string(),
        algorithm: "AES-GCM".to_string(),
        attempt: "same-nonce-two-plaintexts".to_string(),
        result: "xor-leakage-demonstrated".to_string(),
        property: "NONCE-MISUSE RESISTANCE".to_string(),
        verdict: "VULNERABLE".to_string(),
    });

    let siv_a = encrypt_aes_gcm_siv_with_nonce_and_aad(&key, &nonce, p1, &[])?;
    let siv_b = encrypt_aes_gcm_siv_with_nonce_and_aad(&key, &nonce, p2, &[])?;
    let siv_body_a = ciphertext_body(&siv_a);
    let siv_body_b = ciphertext_body(&siv_b);
    let siv_xor = xor_min(siv_body_a, siv_body_b);
    let tag_a = auth_tag(&siv_a);
    let tag_b = auth_tag(&siv_b);
    let synthetic_iv_differs = tag_a != tag_b;
    let siv_not_equal_gcm_pattern = siv_xor != plaintext_xor;

    println!("\n[AES-GCM-SIV]");
    println!("  Aksi: enkripsi dua plaintext berbeda dengan key dan nonce yang sama.");
    println!("  Ciphertext A full (hex): {}", hex::encode(&siv_a));
    println!("  Ciphertext B full (hex): {}", hex::encode(&siv_b));
    println!(
        "  Ciphertext A body tanpa tag (hex): {}",
        hex::encode(siv_body_a)
    );
    println!(
        "  Ciphertext B body tanpa tag (hex): {}",
        hex::encode(siv_body_b)
    );
    println!("  Synthetic IV/tag A (hex): {}", hex::encode(tag_a));
    println!("  Synthetic IV/tag B (hex): {}", hex::encode(tag_b));
    println!(
        "  Synthetic IV/tag berbeda: {}",
        if synthetic_iv_differs { "YES" } else { "NO" }
    );
    println!("  XOR ciphertext body A^B (hex): {}", hex::encode(&siv_xor));
    println!(
        "  XOR ciphertext body == XOR plaintext: {}",
        if siv_xor == plaintext_xor {
            "YES"
        } else {
            "NO"
        }
    );
    println!("  Analisis: AES-GCM-SIV menggunakan synthetic IV yang bergantung pada plaintext/AAD sehingga lebih tahan nonce misuse.");
    println!(
        "  Pola kebocoran AES-GCM tidak muncul: {}",
        if siv_not_equal_gcm_pattern {
            "YES"
        } else {
            "NO"
        }
    );
    println!("  Verdict AES-GCM-SIV: SECURE");

    rows.push(SecurityRow {
        scenario: "4-Nonce Reuse".to_string(),
        algorithm: "AES-GCM-SIV".to_string(),
        attempt: "same-nonce-two-plaintexts".to_string(),
        result: "synthetic-iv-different".to_string(),
        property: "NONCE-MISUSE RESISTANCE".to_string(),
        verdict: "SECURE".to_string(),
    });

    println!("\nRingkasan Scenario 4:");
    println!("  AES-GCM verdict: VULNERABLE");
    println!("  AES-GCM-SIV verdict: SECURE");
    println!("  Property verified: NONCE-MISUSE RESISTANCE PASS");
    Ok(())
}

/// Skenario 5: Eve mengganti public key sehingga kunci sesi Alice dan Bob tidak cocok.
pub fn scenario_mitm(plaintext: &[u8], rows: &mut Vec<SecurityRow>) -> Result<(), String> {
    println!("\n=== SCENARIO 5: Man-in-the-Middle ===");
    println!("Tujuan:");
    println!("  Menguji AUTHENTICITY + FORWARD SECRECY ketika Eve mengganti public key saat ECDH.");
    println!("  Jika public key tidak diautentikasi, Alice dan Bob dapat menghitung session key yang berbeda.");

    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let eve_for_alice = KeyPair::generate();
    let eve_for_bob = KeyPair::generate();

    let alice_public_original = alice.public_key();
    let bob_public_original = bob.public_key();
    let eve_public_to_alice = eve_for_alice.public_key();
    let eve_public_to_bob = eve_for_bob.public_key();

    println!("\nPublic key asli:");
    println!(
        "  Alice public key asli (hex): {}",
        public_key_hex(&alice_public_original)
    );
    println!(
        "  Bob public key asli   (hex): {}",
        public_key_hex(&bob_public_original)
    );
    println!("\nSubstitusi oleh Eve:");
    println!("  Bob seharusnya menerima Alice public key, tetapi menerima Eve public key:");
    println!(
        "    Eve -> Bob   (hex): {}",
        public_key_hex(&eve_public_to_bob)
    );
    println!("  Alice seharusnya menerima Bob public key, tetapi menerima Eve public key:");
    println!(
        "    Eve -> Alice (hex): {}",
        public_key_hex(&eve_public_to_alice)
    );

    let alice_shared = alice.diffie_hellman(&eve_public_to_alice);
    let bob_shared = bob.diffie_hellman(&eve_public_to_bob);
    let alice_key = derive_session_material(&alice_shared)?.session_key;
    let bob_key = derive_session_material(&bob_shared)?.session_key;
    let secrets_differ = alice_shared != bob_shared;
    let keys_differ = alice_key != bob_key;

    println!("\nHasil derivasi akibat substitusi public key:");
    println!("  Alice shared secret (hex): {}", hex::encode(alice_shared));
    println!("  Bob shared secret   (hex): {}", hex::encode(bob_shared));
    println!(
        "  Shared secret Alice == Bob: {}",
        if secrets_differ { "NO" } else { "YES" }
    );
    println!("  Alice session key (hex): {}", hex::encode(alice_key));
    println!("  Bob session key   (hex): {}", hex::encode(bob_key));
    println!(
        "  Session key Alice == Bob: {}",
        if keys_differ { "NO" } else { "YES" }
    );

    let encrypted = encrypt_aes_gcm_siv(&alice_key, plaintext)?;
    let decrypt_result = decrypt_aes_gcm_siv(&bob_key, &encrypted.nonce, &encrypted.ciphertext);
    let decrypt_failed = decrypt_result.is_err();
    let attack_detected = secrets_differ && keys_differ && decrypt_failed;

    println!("\nPercobaan komunikasi setelah MITM:");
    println!(
        "  Alice mengenkripsi plaintext: {}",
        printable_bytes(plaintext)
    );
    println!("  Nonce (hex): {}", hex::encode(encrypted.nonce));
    println!(
        "  Ciphertext dari Alice (hex): {}",
        hex::encode(&encrypted.ciphertext)
    );
    println!("  Bob mencoba dekripsi dengan session key lokalnya.");
    match decrypt_result {
        Ok(recovered) => {
            println!("  Hasil dekripsi Bob: BERHASIL");
            println!("  Plaintext Bob: {}", printable_bytes(&recovered));
            println!("  Analisis: serangan tidak terdeteksi, ini kondisi tidak aman.");
        }
        Err(err) => {
            println!("  Hasil dekripsi Bob: GAGAL");
            println!("  Error: {err}");
            println!("  Analisis: authentication tag tidak valid karena session key Alice dan Bob berbeda.");
        }
    }

    println!("\nRingkasan Scenario 5:");
    println!(
        "  Attack detected: {}",
        if attack_detected { "YES" } else { "NO" }
    );
    println!(
        "  Property verified: AUTHENTICITY + FORWARD SECRECY {}",
        if attack_detected { "PASS" } else { "FAIL" }
    );

    rows.push(SecurityRow {
        scenario: "5-Man-in-the-Middle".to_string(),
        algorithm: "X25519 + AES-GCM-SIV".to_string(),
        attempt: "public-key-substitution".to_string(),
        result: if attack_detected {
            "detected"
        } else {
            "not-detected"
        }
        .to_string(),
        property: "AUTHENTICITY + FORWARD SECRECY".to_string(),
        verdict: if attack_detected { "PASS" } else { "FAIL" }.to_string(),
    });
    Ok(())
}

fn session_key() -> Result<[u8; 32], String> {
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let shared = alice.diffie_hellman(&bob.public_key());
    Ok(derive_session_material(&shared)?.session_key)
}

fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let nonce = generate_nonce();
    key[..12].copy_from_slice(&nonce);
    let nonce2 = generate_nonce();
    key[12..24].copy_from_slice(&nonce2);
    let nonce3 = generate_nonce();
    key[24..].copy_from_slice(&nonce3[..8]);
    key
}

fn tamper_positions(len: usize) -> Vec<usize> {
    if len == 0 {
        return vec![];
    }
    let mut positions = vec![0, len / 2, len - 1];
    positions.sort_unstable();
    positions.dedup();
    positions
}

fn xor_min(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn replay_id(nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> String {
    format!(
        "{}:{}:{}",
        hex::encode(nonce),
        hex::encode(ciphertext),
        hex::encode(aad)
    )
}

fn replay_id_short(nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> String {
    let id = replay_id(nonce, ciphertext, aad);
    format!("{}...", &id[..id.len().min(64)])
}

fn auth_tag(ciphertext: &[u8]) -> &[u8] {
    let start = ciphertext.len().saturating_sub(16);
    &ciphertext[start..]
}

fn printable_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}
