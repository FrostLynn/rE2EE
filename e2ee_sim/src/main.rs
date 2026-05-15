mod ablation;
mod benchmark;
mod crypto;
mod output;
mod security;

use std::env;

use stats_alloc::INSTRUMENTED_SYSTEM;

use crate::ablation::study::run_ablation;
use crate::benchmark::metrics::run_performance;
use crate::crypto::decrypt::{decrypt_aes_gcm, decrypt_aes_gcm_siv};
use crate::crypto::encrypt::{encrypt_aes_gcm, encrypt_aes_gcm_siv};
use crate::crypto::kdf::derive_session_material;
use crate::crypto::keygen::{public_key_hex, KeyPair};
use crate::security::scenarios::{parse_scenario_selection, run_security};

#[global_allocator]
static GLOBAL: &stats_alloc::StatsAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

const PERFORMANCE_CSV: &str = "results/performance.csv";
const SECURITY_CSV: &str = "results/security_tests.csv";
const ABLATION_CSV: &str = "results/ablation_security.csv";

/// Entry point CLI yang mengoordinasikan mode verbose, performa, security, ablation, dan all.
fn main() {
    if let Err(err) = run() {
        eprintln!("ERROR: {err}");
        std::process::exit(1);
    }
}

/// Mem-parse argumen CLI sederhana tanpa framework eksternal agar tetap sesuai dependency yang diminta.
fn run() -> Result<(), String> {
    let args = CliArgs::parse(env::args().skip(1).collect())?;

    match args.mode.as_str() {
        "verbose" => run_verbose(&args.input),
        "perf" => run_performance(&args.input, PERFORMANCE_CSV),
        "security" => {
            let selection = parse_scenario_selection(args.scenario.as_deref())?;
            run_security(&args.input, selection, SECURITY_CSV)
        }
        "ablation" => run_ablation(ABLATION_CSV),
        "all" => {
            run_verbose(&args.input)?;
            run_performance(&args.input, PERFORMANCE_CSV)?;
            run_security(
                "halo dunia",
                parse_scenario_selection(Some("all"))?,
                SECURITY_CSV,
            )?;
            run_ablation(ABLATION_CSV)?;
            Ok(())
        }
        other => Err(format!(
            "Mode tidak valid: {other}. Gunakan verbose, perf, security, ablation, atau all."
        )),
    }
}

/// Struktur argumen CLI hasil parsing flag --mode, --input, dan --scenario.
#[derive(Debug)]
struct CliArgs {
    mode: String,
    input: String,
    scenario: Option<String>,
}

impl CliArgs {
    /// Mem-parse pasangan flag CLI dan memberi validasi pesan error yang jelas.
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut mode = None;
        let mut input = None;
        let mut scenario = None;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--mode" => {
                    i += 1;
                    mode = args.get(i).cloned();
                }
                "--input" => {
                    i += 1;
                    input = args.get(i).cloned();
                }
                "--scenario" => {
                    i += 1;
                    scenario = args.get(i).cloned();
                }
                flag => return Err(format!("Argumen tidak dikenal: {flag}")),
            }
            i += 1;
        }

        Ok(Self {
            mode: mode.ok_or("Flag --mode wajib diisi")?,
            input: input.ok_or("Flag --input wajib diisi")?,
            scenario,
        })
    }
}

/// Menjalankan pipeline E2EE lengkap dan menampilkan setiap fase secara verbose.
fn run_verbose(input: &str) -> Result<(), String> {
    println!("=== Verbose E2EE Key Exchange and Encryption ===\n");

    println!("PHASE 1: Key Generation");
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let alice_public = alice.public_key();
    let bob_public = bob.public_key();
    println!(
        "  Alice public key (hex): {}",
        public_key_hex(&alice_public)
    );
    println!("  Bob public key (hex):   {}", public_key_hex(&bob_public));

    println!("\nPHASE 2: Public Key Exchange");
    println!("  Alice -> Bob: {}", public_key_hex(&alice_public));
    println!("  Bob -> Alice: {}", public_key_hex(&bob_public));

    println!("\nPHASE 3: Shared Secret Derivation");
    let alice_shared = alice.diffie_hellman(&bob_public);
    let bob_shared = bob.diffie_hellman(&alice_public);
    println!("  Alice shared secret (hex): {}", hex::encode(alice_shared));
    println!("  Bob shared secret (hex):   {}", hex::encode(bob_shared));
    println!(
        "  Secrets match: v {}",
        if alice_shared == bob_shared {
            "YES"
        } else {
            "NO"
        }
    );

    println!("\nPHASE 3.5: HKDF Key Derivation");
    let alice_material = derive_session_material(&alice_shared)?;
    let bob_material = derive_session_material(&bob_shared)?;
    println!(
        "  Session key (hex): {}",
        hex::encode(alice_material.session_key)
    );
    println!(
        "  Base nonce (hex):  {}",
        hex::encode(alice_material.base_nonce)
    );

    println!("\nPHASE 4: Encryption");
    let plaintext = input.as_bytes();
    let encrypted_siv = encrypt_aes_gcm_siv(&alice_material.session_key, plaintext)?;
    let encrypted_gcm = encrypt_aes_gcm(&alice_material.session_key, plaintext)?;
    println!("  Plaintext: {input}");
    println!("  Plaintext size: {} bytes", plaintext.len());
    println!("  Nonce (hex): {}", hex::encode(encrypted_siv.nonce));
    println!(
        "  Ciphertext (AES-GCM-SIV, hex): {}",
        hex::encode(&encrypted_siv.ciphertext)
    );
    println!(
        "  Ciphertext size: {} bytes (plaintext {} + tag 16)",
        encrypted_siv.ciphertext.len(),
        plaintext.len()
    );

    println!("\nPHASE 5: Decryption (AES-GCM-SIV)");
    let decrypted_siv = decrypt_aes_gcm_siv(
        &bob_material.session_key,
        &encrypted_siv.nonce,
        &encrypted_siv.ciphertext,
    )?;
    println!("  v Decryption succeeded");
    println!(
        "  Decrypted plaintext: {}",
        String::from_utf8_lossy(&decrypted_siv)
    );
    println!(
        "  Match original: v {}",
        if decrypted_siv == plaintext {
            "YES"
        } else {
            "NO"
        }
    );

    println!("\nPHASE 5: Decryption (AES-GCM baseline)");
    let decrypted_gcm = decrypt_aes_gcm(
        &bob_material.session_key,
        &encrypted_gcm.nonce,
        &encrypted_gcm.ciphertext,
    )?;
    println!("  v Decryption succeeded");
    println!(
        "  Decrypted plaintext: {}",
        String::from_utf8_lossy(&decrypted_gcm)
    );
    println!(
        "  Match original: v {}",
        if decrypted_gcm == plaintext {
            "YES"
        } else {
            "NO"
        }
    );

    println!("\n=== End Verbose Output ===");
    run_failure_scenarios(
        &alice_material.session_key,
        &encrypted_siv.ciphertext,
        &encrypted_siv.nonce,
    )?;
    Ok(())
}

/// Menampilkan failure scenarios dasar setelah mode verbose dengan detail parameter kriptografi.
fn run_failure_scenarios(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
) -> Result<(), String> {
    println!("\n=== Failure Scenarios ===");
    println!(
        "  Catatan: AES-GCM-SIV menghasilkan ciphertext yang sudah mencakup authentication tag 16 byte."
    );
    println!("  Jika key, ciphertext, atau nonce berubah, proses verifikasi tag harus gagal.");
    println!("  Session key benar (hex): {}", hex::encode(key));
    println!("  Nonce benar (hex):       {}", hex::encode(nonce));
    println!("  Ciphertext valid (hex):  {}", hex::encode(ciphertext));
    println!("  Ciphertext size:         {} bytes", ciphertext.len());

    println!("\nSCENARIO 1: Decryption with Wrong Key");
    let wrong_key = [7u8; 32];
    println!("  Tujuan:");
    println!("    Membuktikan confidentiality: ciphertext tidak dapat dibuka tanpa session key yang benar.");
    println!("  Input percobaan:");
    println!("    Key benar  (hex): {}", hex::encode(key));
    println!("    Wrong key  (hex): {}", hex::encode(wrong_key));
    println!("    Nonce      (hex): {}", hex::encode(nonce));
    println!("    Ciphertext (hex): {}", hex::encode(ciphertext));
    println!("  Aksi:");
    println!("    Bob/Eve mencoba mendekripsi ciphertext menggunakan wrong key.");
    match decrypt_aes_gcm_siv(&wrong_key, nonce, ciphertext) {
        Ok(plaintext) => {
            println!("  x Unexpected success");
            println!(
                "  Plaintext hasil dekripsi: {}",
                String::from_utf8_lossy(&plaintext)
            );
            println!("  Analisis: confidentiality gagal karena wrong key masih dapat membuka ciphertext.");
            println!("  Verdict: FAIL");
        }
        Err(err) => {
            println!("  v Expected failure: {err}");
            println!("  Analisis: authentication tag tidak valid karena key tidak cocok.");
            println!("  Plaintext reconstructed: NO");
            println!("  Property verified: CONFIDENTIALITY PASS");
        }
    }

    println!("\nSCENARIO 2: Decryption with Tampered Ciphertext");
    let mut tampered = ciphertext.to_vec();
    let tamper_pos = if ciphertext.is_empty() {
        0
    } else {
        ciphertext.len() / 2
    };
    let original_byte = tampered.get(tamper_pos).copied().unwrap_or_default();
    if let Some(byte) = tampered.get_mut(tamper_pos) {
        *byte ^= 0x01;
    }
    let tampered_byte = tampered.get(tamper_pos).copied().unwrap_or_default();
    println!("  Tujuan:");
    println!("    Membuktikan integrity: perubahan 1 bit pada ciphertext harus terdeteksi.");
    println!("  Input percobaan:");
    println!("    Posisi byte dimodifikasi: {tamper_pos}");
    println!("    Byte sebelum flip bit:   0x{original_byte:02x}");
    println!("    Byte sesudah flip bit:   0x{tampered_byte:02x}");
    println!("    Ciphertext asli (hex):   {}", hex::encode(ciphertext));
    println!("    Ciphertext rusak (hex):  {}", hex::encode(&tampered));
    println!("  Aksi:");
    println!("    Bob mencoba mendekripsi ciphertext yang sudah dimodifikasi 1 bit.");
    match decrypt_aes_gcm_siv(key, nonce, &tampered) {
        Ok(plaintext) => {
            println!("  x Unexpected success");
            println!(
                "  Plaintext hasil dekripsi: {}",
                String::from_utf8_lossy(&plaintext)
            );
            println!("  Analisis: integrity gagal karena ciphertext termodifikasi tetap diterima.");
            println!("  Verdict: FAIL");
        }
        Err(err) => {
            println!("  v Expected failure: {err}");
            println!(
                "  Analisis: authentication tag gagal diverifikasi setelah ciphertext berubah."
            );
            println!("  Modification detected: YES");
            println!("  Property verified: INTEGRITY PASS");
        }
    }

    println!("\nSCENARIO 3: Decryption with Wrong Nonce");
    let mut wrong_nonce = *nonce;
    let original_nonce_byte = wrong_nonce[0];
    wrong_nonce[0] ^= 0x01;
    let modified_nonce_byte = wrong_nonce[0];
    println!("  Tujuan:");
    println!("    Membuktikan nonce binding: ciphertext hanya valid untuk nonce yang dipakai saat enkripsi.");
    println!("  Input percobaan:");
    println!("    Nonce benar (hex): {}", hex::encode(nonce));
    println!("    Wrong nonce (hex): {}", hex::encode(wrong_nonce));
    println!("    Byte nonce[0] sebelum flip bit: 0x{original_nonce_byte:02x}");
    println!("    Byte nonce[0] sesudah flip bit: 0x{modified_nonce_byte:02x}");
    println!("    Ciphertext (hex):  {}", hex::encode(ciphertext));
    println!("  Aksi:");
    println!("    Bob mencoba mendekripsi ciphertext valid tetapi menggunakan nonce yang salah.");
    match decrypt_aes_gcm_siv(key, &wrong_nonce, ciphertext) {
        Ok(plaintext) => {
            println!("  x Unexpected success");
            println!(
                "  Plaintext hasil dekripsi: {}",
                String::from_utf8_lossy(&plaintext)
            );
            println!("  Analisis: nonce binding gagal karena wrong nonce tetap diterima.");
            println!("  Verdict: FAIL");
        }
        Err(err) => {
            println!("  v Expected failure: {err}");
            println!("  Analisis: authentication tag tidak cocok karena nonce adalah bagian dari konteks enkripsi.");
            println!("  Wrong nonce accepted: NO");
            println!("  Property verified: NONCE BINDING PASS");
        }
    }

    println!("\n=== End Failure Scenarios ===");
    Ok(())
}
