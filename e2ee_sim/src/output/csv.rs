use serde::Serialize;
use std::fs::{create_dir_all, File};
use std::path::Path;

/// Baris CSV hasil pengukuran performa algoritma.
#[derive(Serialize, Clone, Debug)]
pub struct PerformanceRow {
    pub iteration: usize,
    pub algorithm: String,
    pub data_type: String,
    pub data_size_bytes: usize,
    pub enc_time_us: f64,
    pub dec_time_us: f64,
    pub enc_throughput_mbs: f64,
    pub dec_throughput_mbs: f64,
    pub ciphertext_size_bytes: usize,
    pub overhead_bytes: isize,
    pub overhead_pct: f64,
    pub memory_mb: f64,
}

/// Baris CSV hasil pengujian skenario keamanan.
#[derive(Serialize, Clone, Debug)]
pub struct SecurityRow {
    pub scenario: String,
    pub algorithm: String,
    pub attempt: String,
    pub result: String,
    pub property: String,
    pub verdict: String,
}

/// Baris CSV hasil ablation study performa (dipertahankan untuk kompatibilitas).
#[derive(Serialize, Clone, Debug)]
pub struct AblationRow {
    pub iteration: usize,
    pub config: String,
    pub data_type: String,
    pub data_size_bytes: usize,
    pub enc_time_us: f64,
    pub dec_time_us: f64,
    pub enc_throughput_mbs: f64,
    pub dec_throughput_mbs: f64,
    pub overhead_bytes: isize,
    pub overhead_pct: f64,
    pub memory_mb: f64,
}

/// Baris CSV hasil ablation study keamanan.
#[derive(Serialize, Clone, Debug)]
pub struct AblationSecurityRow {
    pub config: String,
    pub test_name: String,
    pub passed: bool,
    pub detail: String,
}

/// Menulis daftar record serializable ke file CSV dan membuat folder induk jika belum ada.
pub fn write_csv<T: Serialize>(path: &str, rows: &[T]) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        create_dir_all(parent).map_err(|e| format!("Gagal membuat folder output: {e}"))?;
    }

    let file = File::create(path).map_err(|e| format!("Gagal membuat file CSV {path}: {e}"))?;
    let mut writer = csv::Writer::from_writer(file);

    for row in rows {
        writer
            .serialize(row)
            .map_err(|e| format!("Gagal menulis baris CSV: {e}"))?;
    }

    writer
        .flush()
        .map_err(|e| format!("Gagal flush writer CSV: {e}"))?;
    Ok(())
}
