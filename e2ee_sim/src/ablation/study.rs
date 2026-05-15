use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::decrypt::decrypt_aes_gcm_siv;
use crate::crypto::encrypt::{
    ciphertext_body, encrypt_aes_gcm_siv, encrypt_aes_gcm_with_nonce_and_aad,
};
use crate::crypto::keygen::KeyPair;
use crate::output::csv::{write_csv, AblationSecurityRow};

/// Menjalankan ablation study berbasis keamanan untuk tiga konfigurasi dan mengekspor hasilnya ke CSV.
pub fn run_ablation(output_path: &str) -> Result<(), String> {
    println!("=== Security-Focused Ablation Study ===\n");
    let mut rows = Vec::new();

    rows.extend(run_no_hkdf()?);
    rows.extend(run_no_ecdh()?);
    rows.extend(run_aes_gcm_only()?);

    write_csv(output_path, &rows)?;
    println!("\nAblation security results exported to {output_path}");
    Ok(())
}

// ─── Configuration 1: no-hkdf ───────────────────────────────────────────────

fn run_no_hkdf() -> Result<Vec<AblationSecurityRow>, String> {
    println!("--- Configuration 1: no-hkdf ---");
    println!(
        "Vulnerability: ECDH shared secret used directly as AES-GCM-SIV key, bypassing HKDF.\n"
    );
    let config = "no-hkdf";
    let mut rows = Vec::new();

    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let shared = alice.diffie_hellman(&bob.public_key());
    let raw_key: [u8; 32] = shared;

    // Test 1: key_uniformity
    // Encrypt the same plaintext 5 times with the raw key; check byte frequency variance.
    let plaintext = b"uniformity test plaintext data!!";
    let mut ciphertexts: Vec<Vec<u8>> = Vec::new();
    for _ in 0..5 {
        let enc = encrypt_aes_gcm_siv(&raw_key, plaintext)?;
        ciphertexts.push(enc.ciphertext);
    }
    let all_distinct = ciphertexts.windows(2).all(|w| w[0] != w[1]);
    let variance = byte_frequency_variance(&raw_key);
    // Theoretical expected variance for 32 uniform random bytes over 256 buckets ≈ 0.124.
    // Threshold at 0.25 (2× expected) flags clearly non-uniform distributions.
    let uniformity_ok = variance <= 0.25;
    let passed1 = uniformity_ok;
    let detail1 = format!(
        "Raw ECDH key byte-frequency variance: {variance:.4} (threshold 0.25); \
         uniform={uniformity_ok}; 5 encryptions all distinct: {all_distinct}"
    );
    print_result(config, "key_uniformity", passed1, &detail1);
    rows.push(make_row(config, "key_uniformity", passed1, detail1));

    // Test 2: key_separation
    // Without HKDF both sessions use the raw shared secret — identical keys.
    // With HKDF + distinct info strings the keys are cryptographically independent.
    let key_s1 = raw_key;
    let key_s2 = raw_key; // same — no domain separation
    let key_hkdf1 = hkdf_derive(&shared, b"session-info-1")?;
    let key_hkdf2 = hkdf_derive(&shared, b"session-info-2")?;

    let ratio_no_hkdf = bit_diff_ratio(&key_s1, &key_s2);
    let bits_diff_hkdf: u32 = xor_bytes(&key_hkdf1, &key_hkdf2)
        .iter()
        .map(|byte| byte.count_ones())
        .sum();
    // Keys are independent if bit-difference ratio ≥ 45 % (close to the 50 % ideal).
    let independence_threshold = 0.45_f64;
    let keys_independent = ratio_no_hkdf >= independence_threshold;
    let passed2 = keys_independent;
    let ratio_pct = ratio_no_hkdf * 100.0;
    let threshold_pct = independence_threshold * 100.0;
    let detail2 = format!(
        "Without HKDF: session bit-diff ratio = {ratio_pct:.1}% (need ≥{threshold_pct:.0}% for independence); \
         with HKDF+distinct info strings: {bits_diff_hkdf}/256 bits differ — sessions isolated"
    );
    print_result(config, "key_separation", passed2, &detail2);
    rows.push(make_row(config, "key_separation", passed2, detail2));

    // Test 3: session_isolation
    // Two sessions from the same ECDH keypair share identical key material without HKDF re-keying.
    let enc_s1 = encrypt_aes_gcm_siv(&raw_key, b"session 1 payload data here!!!!!")?;
    let enc_s2 = encrypt_aes_gcm_siv(&raw_key, b"session 2 different payload data")?;
    let keys_identical = key_s1 == key_s2;
    let passed3 = !keys_identical;
    let detail3 = format!(
        "Session-1 key == Session-2 key: {keys_identical}; \
         nonce-s1={} nonce-s2={}; \
         same key material reused across sessions — HKDF re-keying absent",
        hex::encode(enc_s1.nonce),
        hex::encode(enc_s2.nonce),
    );
    print_result(config, "session_isolation", passed3, &detail3);
    rows.push(make_row(config, "session_isolation", passed3, detail3));

    println!(
        "\nSummary [no-hkdf]: Curve25519 output is already pseudo-random so byte uniformity \
         may pass, but HKDF domain separation is absent — both sessions share identical key \
         material (bit-diff ratio 0%), making cross-session key reuse a confirmed vulnerability.\n"
    );
    Ok(rows)
}

// ─── Configuration 2: no-ecdh ────────────────────────────────────────────────

fn run_no_ecdh() -> Result<Vec<AblationSecurityRow>, String> {
    println!("--- Configuration 2: no-ecdh ---");
    println!(
        "Vulnerability: Hardcoded static 32-byte symmetric key replaces ECDH key exchange.\n"
    );
    let config = "no-ecdh";
    let static_key: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
    let mut rows = Vec::new();

    // Test 1: forward_secrecy
    // Encrypt a message, then "compromise" the static key and attempt to decrypt past ciphertexts.
    let plaintext = b"session: message from alice/bob!";
    let enc = encrypt_aes_gcm_siv(&static_key, plaintext)?;
    let compromised_key = static_key; // attacker learns the static key
    let decryption_ok = decrypt_aes_gcm_siv(&compromised_key, &enc.nonce, &enc.ciphertext).is_ok();
    let passed1 = !decryption_ok;
    let detail1 = format!(
        "Key compromised → past ciphertext decrypted: {decryption_ok}; \
         static key exposes all past and future sessions — forward secrecy absent"
    );
    print_result(config, "forward_secrecy", passed1, &detail1);
    rows.push(make_row(config, "forward_secrecy", passed1, detail1));

    // Test 2: key_reuse_across_sessions
    // All three simulated sessions produce the same encryption key.
    let session_keys: [_; 3] = [static_key, static_key, static_key];
    let all_identical = session_keys.windows(2).all(|w| w[0] == w[1]);
    let passed2 = !all_identical;
    let detail2 = format!(
        "Key identical across all 3 sessions: {all_identical}; \
         session-1 = session-2 = session-3 key — no ephemeral re-keying"
    );
    print_result(config, "key_reuse_across_sessions", passed2, &detail2);
    rows.push(make_row(
        config,
        "key_reuse_across_sessions",
        passed2,
        detail2,
    ));

    // Test 3: replay_under_static_key
    // Ciphertext recorded in session 1 is replayed in session 3.
    // Without AAD session binding the static key accepts it unchanged.
    let session1_pt = b"session-1 confidential message!!";
    let session1_enc = encrypt_aes_gcm_siv(&static_key, session1_pt)?;
    let replay_ok =
        decrypt_aes_gcm_siv(&static_key, &session1_enc.nonce, &session1_enc.ciphertext).is_ok();
    let passed3 = !replay_ok;
    let detail3 = format!(
        "Session-1 ciphertext replayed in session-3 context: {replay_ok}; \
         no AAD session binding — static key accepts any past ciphertext regardless of session"
    );
    print_result(config, "replay_under_static_key", passed3, &detail3);
    rows.push(make_row(config, "replay_under_static_key", passed3, detail3));

    println!(
        "\nSummary [no-ecdh]: A single static key means no forward secrecy, no session \
         isolation, and no replay protection. One key compromise breaks every past and future \
         session simultaneously.\n"
    );
    Ok(rows)
}

// ─── Configuration 3: aes-gcm-only ──────────────────────────────────────────

fn run_aes_gcm_only() -> Result<Vec<AblationSecurityRow>, String> {
    println!("--- Configuration 3: aes-gcm-only ---");
    println!(
        "Vulnerability: AES-GCM replaces AES-GCM-SIV, enabling catastrophic nonce-reuse attacks.\n"
    );
    let config = "aes-gcm-only";
    let mut rows = Vec::new();

    // Normal ECDH + HKDF key derivation — only the AEAD primitive changes.
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let shared = alice.diffie_hellman(&bob.public_key());
    let key = hkdf_derive(&shared, b"e2ee-sim session material")?;

    // Two distinct messages encrypted with the same key AND the same nonce (simulated reuse).
    let fixed_nonce = [0x13u8; 12];
    let pt_a = b"hello, this is plaintext alpha!!"; // 32 bytes
    let pt_b = b"hello, this is plaintext beta!!!"; // 32 bytes

    let ct_a_full = encrypt_aes_gcm_with_nonce_and_aad(&key, &fixed_nonce, pt_a, &[])?;
    let ct_b_full = encrypt_aes_gcm_with_nonce_and_aad(&key, &fixed_nonce, pt_b, &[])?;

    // Strip authentication tags to obtain raw keystream-XOR'd bytes.
    let ct_a = ciphertext_body(&ct_a_full);
    let ct_b = ciphertext_body(&ct_b_full);

    // Test 1: nonce_reuse_exploit
    // For AES-GCM: ct = pt XOR keystream → XOR(ct_a, ct_b) = XOR(pt_a, pt_b).
    let xor_ct = xor_bytes(ct_a, ct_b);
    let xor_pt = xor_bytes(pt_a, pt_b);
    let min_len = xor_ct.len().min(xor_pt.len());
    let relation_holds = xor_ct[..min_len] == xor_pt[..min_len];
    let passed1 = !relation_holds;
    let detail1 = format!(
        "XOR(ct_a,ct_b)==XOR(pt_a,pt_b): {relation_holds}; \
         nonce={}; keystream reused — plaintext relationship fully exposed",
        hex::encode(fixed_nonce),
    );
    print_result(config, "nonce_reuse_exploit", passed1, &detail1);
    rows.push(make_row(config, "nonce_reuse_exploit", passed1, detail1));

    // Test 2: keystream_recovery
    // Given ct_a and known pt_a → keystream = ct_a XOR pt_a → pt_b = ct_b XOR keystream.
    let keystream = xor_bytes(ct_a, pt_a);
    let pt_b_recovered = xor_bytes(ct_b, &keystream);
    let recover_len = pt_b_recovered.len().min(pt_b.len());
    let recovery_ok = pt_b_recovered[..recover_len] == pt_b[..recover_len];
    let passed2 = !recovery_ok;
    let detail2 = format!(
        "Known-plaintext keystream recovery succeeded: {recovery_ok}; \
         recovered='{}'",
        String::from_utf8_lossy(&pt_b_recovered),
    );
    print_result(config, "keystream_recovery", passed2, &detail2);
    rows.push(make_row(config, "keystream_recovery", passed2, detail2));

    // Test 3: auth_key_leak (documented assertion)
    // AES-GCM authentication is GHASH, a polynomial MAC over GF(2^128) keyed by H = AES_K(0).
    // Nonce reuse makes the MAC equation linear in H, enabling algebraic recovery of H,
    // which then permits tag forgery on arbitrary ciphertexts (Joux 2006).
    let passed3 = false; // always a vulnerability in AES-GCM under nonce reuse
    let detail3 =
        "GHASH authentication key H recoverable via nonce reuse: true; \
         AES-GCM MAC is linear in H — two ciphertexts under the same nonce yield a system \
         of equations in GF(2^128) that uniquely determines H, enabling tag forgery \
         (cf. Joux 2006, Handschuh-Preneel 2008); AES-GCM-SIV is misuse-resistant against this"
            .to_string();
    print_result(config, "auth_key_leak", passed3, &detail3);
    rows.push(make_row(config, "auth_key_leak", passed3, detail3));

    println!(
        "\nSummary [aes-gcm-only]: Nonce reuse in AES-GCM exposes the full keystream, enables \
         complete plaintext recovery from a known-plaintext pair, and leaks the GHASH \
         authentication key H — allowing tag forgery. AES-GCM-SIV's synthetic IV construction \
         eliminates this attack class entirely.\n"
    );
    Ok(rows)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn hkdf_derive(ikm: &[u8; 32], info: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(key)
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn bit_diff_ratio(a: &[u8], b: &[u8]) -> f64 {
    let xored = xor_bytes(a, b);
    let bits_set: u32 = xored.iter().map(|byte| byte.count_ones()).sum();
    if xored.is_empty() {
        return 0.0;
    }
    bits_set as f64 / (xored.len() * 8) as f64
}

fn byte_frequency_variance(key: &[u8; 32]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in key.iter() {
        counts[b as usize] += 1;
    }
    let mean = 32.0_f64 / 256.0;
    counts
        .iter()
        .map(|&c| {
            let d = c as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / 256.0
}

fn make_row(config: &str, test_name: &str, passed: bool, detail: String) -> AblationSecurityRow {
    AblationSecurityRow {
        config: config.to_string(),
        test_name: test_name.to_string(),
        passed,
        detail,
    }
}

fn print_result(config: &str, test: &str, passed: bool, detail: &str) {
    let verdict = if passed { "PASS" } else { "VULNERABLE" };
    println!("  [{config}/{test}] {verdict}");
    println!("  {detail}\n");
}
