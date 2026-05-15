use std::fs;
use std::path::Path;
use std::time::Instant;

use stats_alloc::{Region, INSTRUMENTED_SYSTEM};

use crate::crypto::decrypt::decrypt_with_algorithm;
use crate::crypto::encrypt::{encrypt_with_algorithm, Algorithm};
use crate::crypto::kdf::derive_session_material;
use crate::crypto::keygen::KeyPair;
use crate::output::csv::{write_csv, PerformanceRow};

pub const ITERATIONS: usize = 30;

/// Data uji yang dipakai oleh benchmark performa.
#[derive(Clone, Debug)]
pub struct TestData {
    pub data_type: String,
    pub bytes: Vec<u8>,
}

/// Hasil pengukuran satu iterasi proses enkripsi dan dekripsi.
#[derive(Clone, Debug)]
pub struct Measurement {
    pub enc_time_us: f64,
    pub dec_time_us: f64,
    pub enc_throughput_mbs: f64,
    pub dec_throughput_mbs: f64,
    pub ciphertext_size_bytes: usize,
    pub overhead_bytes: isize,
    pub overhead_pct: f64,
    pub memory_mb: f64,
}

/// Membuat tiga pesan teks UTF-8 hardcode untuk pengujian performa dan ablation.
pub fn text_test_data() -> Vec<TestData> {
    vec![
        TestData {
            data_type: "text-small".to_string(),
            bytes: repeat_to_len("Pesan kecil E2EE aman. ", 100).into_bytes(),
        },
        TestData {
            data_type: "text-medium".to_string(),
            bytes: repeat_to_len("Pesan medium untuk simulasi end-to-end encryption. ", 350)
                .into_bytes(),
        },
        TestData {
            data_type: "text-large".to_string(),
            bytes: repeat_to_len(
                "Pesan besar untuk menguji performa pipeline E2EE lokal menggunakan Rust. ",
                2000,
            )
            .into_bytes(),
        },
    ]
}

/// Membaca seluruh data uji teks dan media dari folder eksperimen.
pub fn load_all_test_data(input_dir: &str) -> Result<Vec<TestData>, String> {
    let mut data = text_test_data();
    let media = [
        ("image-small", "Photo/image_1.jpg"),
        ("image-medium", "Photo/image_2.jpg"),
        ("image-large", "Photo/image_3.jpg"),
        ("audio-small", "Audio/audio_1.mp3"),
        ("audio-medium", "Audio/audio_2.mp3"),
        ("audio-large", "Audio/audio_3.mp3"),
        ("video-small", "Video/video_1.mp4"),
        ("video-medium", "Video/video_2.mp4"),
        ("video-large", "Video/video_3.mp4"),
    ];

    for (label, rel_path) in media {
        let path = Path::new(input_dir).join(rel_path);
        let bytes = fs::read(&path)
            .map_err(|e| format!("Gagal membaca file media {}: {e}", path.display()))?;
        data.push(TestData {
            data_type: label.to_string(),
            bytes,
        });
    }

    Ok(data)
}

/// Menjalankan benchmark performa untuk AES-GCM-SIV dan AES-GCM lalu mengekspor ke CSV.
pub fn run_performance(input_dir: &str, output_path: &str) -> Result<(), String> {
    println!("=== Mode Performa ===");
    println!("Membaca data uji dari: {input_dir}");

    let test_data = load_all_test_data(input_dir)?;
    let mut rows = Vec::new();

    for data in &test_data {
        println!(
            "Mengukur data {} ({} bytes)",
            data.data_type,
            data.bytes.len()
        );
        for algorithm in [Algorithm::AesGcmSiv, Algorithm::AesGcm] {
            let key = fresh_session_key()?;
            for iteration in 1..=ITERATIONS {
                let measurement = measure_crypto_operation(algorithm, &key, &data.bytes)?;
                rows.push(PerformanceRow {
                    iteration,
                    algorithm: algorithm.label().to_string(),
                    data_type: data.data_type.clone(),
                    data_size_bytes: data.bytes.len(),
                    enc_time_us: measurement.enc_time_us,
                    dec_time_us: measurement.dec_time_us,
                    enc_throughput_mbs: measurement.enc_throughput_mbs,
                    dec_throughput_mbs: measurement.dec_throughput_mbs,
                    ciphertext_size_bytes: measurement.ciphertext_size_bytes,
                    overhead_bytes: measurement.overhead_bytes,
                    overhead_pct: measurement.overhead_pct,
                    memory_mb: measurement.memory_mb,
                });
            }
        }
    }

    write_csv(output_path, &rows)?;
    println!("Hasil performa diekspor ke {output_path}");
    Ok(())
}

/// Mengukur waktu, throughput, overhead, dan alokasi heap aktual untuk satu operasi AEAD.
pub fn measure_crypto_operation(
    algorithm: Algorithm,
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Measurement, String> {
    let region = Region::new(&INSTRUMENTED_SYSTEM);

    let enc_start = Instant::now();
    let encrypted = encrypt_with_algorithm(algorithm, key, plaintext)?;
    let enc_duration = enc_start.elapsed();

    let dec_start = Instant::now();
    let decrypted =
        decrypt_with_algorithm(algorithm, key, &encrypted.nonce, &encrypted.ciphertext)?;
    let dec_duration = dec_start.elapsed();

    if decrypted != plaintext {
        return Err("Verifikasi dekripsi gagal: plaintext tidak sama".to_string());
    }

    let stats = region.change();
    let allocated_bytes = stats
        .bytes_allocated
        .saturating_sub(stats.bytes_deallocated);
    let memory_mb = allocated_bytes as f64 / (1024.0 * 1024.0);

    let enc_secs = enc_duration.as_secs_f64().max(1e-12);
    let dec_secs = dec_duration.as_secs_f64().max(1e-12);
    let size_mb = plaintext.len() as f64 / (1024.0 * 1024.0);
    let overhead_bytes = encrypted.ciphertext.len() as isize - plaintext.len() as isize;
    let overhead_pct = if plaintext.is_empty() {
        0.0
    } else {
        overhead_bytes as f64 / plaintext.len() as f64 * 100.0
    };

    Ok(Measurement {
        enc_time_us: enc_duration.as_secs_f64() * 1_000_000.0,
        dec_time_us: dec_duration.as_secs_f64() * 1_000_000.0,
        enc_throughput_mbs: size_mb / enc_secs,
        dec_throughput_mbs: size_mb / dec_secs,
        ciphertext_size_bytes: encrypted.ciphertext.len(),
        overhead_bytes,
        overhead_pct,
        memory_mb,
    })
}

/// Membuat session key normal dari ECDH dan HKDF untuk benchmark.
pub fn fresh_session_key() -> Result<[u8; 32], String> {
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let shared = alice.diffie_hellman(&bob.public_key());
    let material = derive_session_material(&shared)?;
    Ok(material.session_key)
}

fn repeat_to_len(seed: &str, len: usize) -> String {
    seed.chars().cycle().take(len).collect()
}
