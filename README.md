# e2ee_sim

`e2ee_sim` adalah program simulasi End-to-End Encryption (E2EE) berbasis Rust untuk kebutuhan eksperimen skripsi S1 Informatika. Program ini mereplikasi alur komunikasi terenkripsi antara dua entitas lokal, yaitu Alice sebagai pengirim dan Bob sebagai penerima, tanpa membangun aplikasi chat atau infrastruktur jaringan sungguhan.

Seluruh pipeline berjalan dalam satu binary Rust dan mencakup:

- pembangkitan kunci ECDH menggunakan X25519/Curve25519,
- pertukaran public key secara simulatif,
- pembentukan shared secret,
- derivasi session key menggunakan HKDF-SHA256,
- enkripsi dan dekripsi menggunakan AES-GCM-SIV,
- perbandingan baseline menggunakan AES-GCM,
- benchmark performa,
- skenario uji keamanan,
- ablation study,
- ekspor hasil eksperimen ke CSV.

---

## 1. Struktur Proyek

```text
e2ee_sim/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── keygen.rs
│   │   ├── kdf.rs
│   │   ├── encrypt.rs
│   │   └── decrypt.rs
│   ├── benchmark/
│   │   ├── mod.rs
│   │   └── metrics.rs
│   ├── security/
│   │   ├── mod.rs
│   │   └── scenarios.rs
│   ├── ablation/
│   │   ├── mod.rs
│   │   └── study.rs
│   └── output/
│       ├── mod.rs
│       └── csv.rs
└── results/
    ├── performance.csv
    ├── security_tests.csv
    └── ablation.csv
```

---

## 2. Dependency Utama

Program menggunakan dependency berikut:

```toml
aes-gcm = "0.10"
aes-gcm-siv = "0.11"
hkdf = "0.12"
sha2 = "0.10"
x25519-dalek = { version = "2", features = ["static_secrets"] }
rand = "0.8"
hex = "0.4"
csv = "1.3"
serde = { version = "1", features = ["derive"] }
cpu-time = "1.0"
stats_alloc = "0.1"
```

Catatan:

- AES-GCM-SIV digunakan sebagai skema utama.
- AES-GCM digunakan sebagai baseline.
- X25519 digunakan untuk simulasi ECDH.
- HKDF-SHA256 digunakan untuk derivasi session key.
- `stats_alloc` digunakan untuk mengukur alokasi heap aktual selama proses kriptografi.

---

## 3. Cara Build

Masuk ke direktori proyek:

```bash
cd e2ee_sim
```

Lakukan pengecekan kompilasi:

```bash
cargo check
```

Build binary:

```bash
cargo build
```

Build mode release untuk eksperimen performa yang lebih stabil:

```bash
cargo build --release
```

---

## 4. Format CLI

Format umum:

```bash
cargo run -- --mode [verbose|perf|security|ablation|all] --input [path_file_atau_teks] --scenario [1|2|3|4|5|all]
```

Flag:

| Flag | Keterangan |
|---|---|
| `--mode` | Mode eksekusi program |
| `--input` | Input berupa teks atau path folder eksperimen |
| `--scenario` | Hanya digunakan untuk mode `security` |

Mode yang tersedia:

| Mode | Fungsi |
|---|---|
| `verbose` | Menampilkan pipeline E2EE lengkap secara detail |
| `perf` | Menjalankan benchmark performa dan ekspor CSV |
| `security` | Menjalankan skenario uji keamanan |
| `ablation` | Menjalankan ablation study |
| `all` | Menjalankan verbose, perf, security, dan ablation berurutan |

---

## 5. Mode Verbose

Mode `verbose` menampilkan alur E2EE lengkap dari pembangkitan kunci sampai dekripsi.

Perintah:

```bash
cargo run -- --mode verbose --input "halo dunia"
```

Output mencakup:

1. pembangkitan key pair Alice dan Bob,
2. pertukaran public key,
3. pembentukan shared secret,
4. derivasi session key dan base nonce menggunakan HKDF,
5. enkripsi AES-GCM-SIV,
6. dekripsi AES-GCM-SIV,
7. dekripsi AES-GCM baseline,
8. failure scenarios dasar:
   - wrong key,
   - tampered ciphertext,
   - wrong nonce.

Contoh bagian output:

```text
=== Verbose E2EE Key Exchange and Encryption ===

PHASE 1: Key Generation
  Alice public key (hex): ...
  Bob public key (hex):   ...

PHASE 3: Shared Secret Derivation
  Secrets match: v YES

PHASE 5: Decryption (AES-GCM-SIV)
  v Decryption succeeded
  Match original: v YES
```

---

## 6. Mode Performance Benchmark

Mode `perf` menjalankan pengukuran performa untuk kombinasi:

- algoritma:
  - AES-GCM-SIV,
  - AES-GCM,
- data uji:
  - teks hardcode,
  - file media dari folder eksperimen.

Perintah:

```bash
cargo run -- --mode perf --input ./experimen/
```

Disarankan menggunakan release mode:

```bash
cargo run --release -- --mode perf --input ./experimen/
```

Hasil akan diekspor ke:

```text
results/performance.csv
```

### 6.1 Struktur Folder Media

Untuk mode `perf`, folder input harus memiliki struktur berikut:

```text
experimen/
├── Photo/
│   ├── image_1.jpg
│   ├── image_2.jpg
│   └── image_3.jpg
├── Audio/
│   ├── audio_1.mp3
│   ├── audio_2.mp3
│   └── audio_3.mp3
└── Video/
    ├── video_1.mp4
    ├── video_2.mp4
    └── video_3.mp4
```

### 6.2 Data Teks Hardcode

Data teks yang digunakan:

| Label | Ukuran |
|---|---|
| `text-small` | 100 karakter |
| `text-medium` | 350 karakter |
| `text-large` | 2000 karakter |

### 6.3 Kolom CSV Performance

File `results/performance.csv` berisi kolom:

```text
iteration, algorithm, data_type, data_size_bytes,
enc_time_us, dec_time_us, enc_throughput_mbs,
dec_throughput_mbs, ciphertext_size_bytes, overhead_bytes,
overhead_pct, memory_mb
```

Keterangan metrik:

| Kolom | Keterangan |
|---|---|
| `iteration` | Nomor iterasi, 1 sampai 30 |
| `algorithm` | AES-GCM-SIV atau AES-GCM |
| `data_type` | Label data uji |
| `data_size_bytes` | Ukuran plaintext dalam byte |
| `enc_time_us` | Waktu enkripsi dalam mikrodetik |
| `dec_time_us` | Waktu dekripsi dalam mikrodetik |
| `enc_throughput_mbs` | Throughput enkripsi dalam MB/s |
| `dec_throughput_mbs` | Throughput dekripsi dalam MB/s |
| `ciphertext_size_bytes` | Ukuran ciphertext termasuk authentication tag |
| `overhead_bytes` | Selisih ukuran ciphertext dan plaintext |
| `overhead_pct` | Persentase overhead |
| `memory_mb` | Selisih alokasi heap aktual dalam MB |

Catatan:

- CPU usage tidak diukur karena tidak deterministik untuk operasi kriptografi berdurasi sangat singkat.
- Setiap kombinasi algoritma dan data dijalankan 30 iterasi.

### 6.4 Cara Menjalankan Benchmark Teks Saja

Mode `perf` saat ini memproses teks dan media sekaligus, sehingga membutuhkan folder `experimen/`.

Untuk benchmark berbasis teks saja yang tidak membutuhkan folder media, gunakan:

```bash
cargo run -- --mode ablation --input "halo dunia"
```

atau dengan release mode:

```bash
cargo run --release -- --mode ablation --input "halo dunia"
```

Output teks ablation akan ditulis ke:

```text
results/ablation.csv
```

---

## 7. Mode Security

Mode `security` menjalankan skenario uji keamanan.

Format:

```bash
cargo run -- --mode security --input "halo dunia" --scenario [1|2|3|4|5|all]
```

Jika `--scenario` tidak diberikan, default adalah `all`.

Contoh:

```bash
cargo run -- --mode security --input "halo dunia" --scenario all
cargo run -- --mode security --input "halo dunia" --scenario 1
cargo run -- --mode security --input "halo dunia" --scenario 4
```

Hasil ringkasan diekspor ke:

```text
results/security_tests.csv
```

### 7.1 Daftar Skenario

| Nomor | Skenario | Properti |
|---|---|---|
| 1 | Eavesdropping | CONFIDENTIALITY |
| 2 | Tampering | INTEGRITY |
| 3 | Replay Attack | AUTHENTICITY |
| 4 | Nonce Reuse | NONCE-MISUSE RESISTANCE |
| 5 | Man-in-the-Middle | AUTHENTICITY + FORWARD SECRECY |

### 7.2 Scenario 1 — Eavesdropping

Skenario ini mensimulasikan penyerang pasif bernama Eve yang hanya dapat mengamati komunikasi, tetapi tidak dapat mengubah pesan. Eve diasumsikan berhasil memperoleh:

- public key Alice,
- public key Bob,
- nonce,
- ciphertext,
- authentication tag.

Namun Eve tidak memiliki private key Alice, private key Bob, maupun session key hasil ECDH + HKDF.

Tujuan skenario:

- membuktikan bahwa ciphertext tidak dapat dikembalikan menjadi plaintext tanpa session key yang benar,
- membuktikan bahwa kepemilikan public key saja tidak cukup untuk mendekripsi pesan,
- memverifikasi properti `CONFIDENTIALITY`.

Alur pengujian:

1. Alice dan Bob menjalankan key exchange normal.
2. Alice mengenkripsi plaintext menggunakan AES-GCM-SIV.
3. Eve mengambil ciphertext dan nonce.
4. Eve mencoba mendekripsi ciphertext menggunakan tiga variasi key yang tidak valid:
   - `random key`, yaitu key acak 32 byte,
   - `partial key`, yaitu key yang hanya sebagian menyerupai session key asli,
   - `zero key`, yaitu key berisi 32 byte nol.
5. Program mencatat apakah setiap percobaan dekripsi berhasil atau gagal.
6. Jika seluruh percobaan gagal, sistem dianggap menjaga kerahasiaan pesan.

Ekspektasi hasil:

| Attempt | Kondisi | Hasil Aman |
|---|---|---|
| Random key | Eve memakai key acak | Dekripsi gagal |
| Partial key | Eve memakai key parsial | Dekripsi gagal |
| Zero key | Eve memakai key nol | Dekripsi gagal |

Output utama:

```text
Plaintext reconstructed: NO
Property verified: CONFIDENTIALITY PASS
```

Makna hasil:

- `Plaintext reconstructed: NO` berarti Eve tidak berhasil membangun ulang plaintext.
- `CONFIDENTIALITY PASS` berarti properti kerahasiaan terpenuhi.
- Jika salah satu percobaan berhasil mendekripsi pesan, maka verdict menjadi gagal karena ciphertext dapat dibuka tanpa key sah.

---

### 7.3 Scenario 2 — Tampering

Skenario ini mensimulasikan penyerang aktif yang memodifikasi ciphertext saat pesan sedang dikirim. Penyerang tidak perlu mengetahui plaintext atau session key; cukup mengubah bit pada ciphertext.

Tujuan skenario:

- membuktikan bahwa perubahan sekecil apa pun pada ciphertext dapat terdeteksi,
- membuktikan bahwa authentication tag melindungi integritas ciphertext,
- memverifikasi properti `INTEGRITY`.

Alur pengujian:

1. Alice mengenkripsi plaintext menggunakan session key valid.
2. Program menyimpan ciphertext asli.
3. Program membuat beberapa salinan ciphertext.
4. Pada setiap salinan, satu bit dimodifikasi di posisi berbeda, misalnya:
   - awal ciphertext,
   - tengah ciphertext,
   - akhir ciphertext.
5. Bob mencoba mendekripsi setiap ciphertext yang sudah dimodifikasi.
6. Program mencatat apakah dekripsi ditolak oleh proses verifikasi authentication tag.

Ekspektasi hasil:

| Modifikasi | Kondisi | Hasil Aman |
|---|---|---|
| Flip bit awal | Byte awal ciphertext diubah | Dekripsi gagal |
| Flip bit tengah | Byte tengah ciphertext diubah | Dekripsi gagal |
| Flip bit akhir | Byte akhir/tag diubah | Dekripsi gagal |

Output utama:

```text
Modification detected: YES
Property verified: INTEGRITY PASS
```

Makna hasil:

- `Modification detected: YES` berarti perubahan ciphertext berhasil dideteksi.
- `INTEGRITY PASS` berarti ciphertext tidak dapat dimodifikasi tanpa terdeteksi.
- Jika ciphertext termodifikasi masih dapat didekripsi, berarti integritas gagal.

---

### 7.4 Scenario 3 — Replay Attack

Skenario ini mensimulasikan serangan replay, yaitu penyerang mengirim ulang ciphertext lama yang sebelumnya valid. Dalam simulasi ini, pesan dilengkapi timestamp sebagai associated data.

Associated data adalah data yang tidak dienkripsi, tetapi ikut diautentikasi. Artinya, perubahan pada associated data akan membuat authentication tag tidak valid.

Tujuan skenario:

- membuktikan bahwa pesan lama dapat dikenali sebagai replay,
- membuktikan bahwa timestamp atau metadata autentikasi dapat membantu menolak pesan kedaluwarsa,
- memverifikasi properti `AUTHENTICITY`.

Alur pengujian:

1. Alice membuat pesan dengan timestamp.
2. Timestamp digunakan sebagai associated data.
3. Alice mengenkripsi plaintext.
4. Bob menerima ciphertext pertama dan menandainya sebagai pesan valid.
5. Eve mengirim ulang ciphertext yang sama dengan timestamp lama.
6. Program memeriksa apakah timestamp/message identifier sudah pernah dipakai.
7. Jika pesan lama terdeteksi, pesan replay ditolak.

Ekspektasi hasil:

| Percobaan | Kondisi | Hasil Aman |
|---|---|---|
| Pengiriman pertama | Ciphertext dan timestamp masih baru | Diterima |
| Replay | Ciphertext dan timestamp lama dikirim ulang | Ditolak |

Output utama:

```text
Replay detected: YES
Property verified: AUTHENTICITY PASS
```

Makna hasil:

- `Replay detected: YES` berarti sistem mengenali ciphertext lama sebagai pesan yang tidak boleh diterima ulang.
- `AUTHENTICITY PASS` berarti penerima dapat membedakan pesan baru yang sah dari pesan lama yang dikirim ulang.
- Jika replay diterima sebagai pesan baru, maka sistem gagal terhadap replay attack.

---

### 7.5 Scenario 4 — Nonce Reuse

Skenario ini adalah skenario paling penting karena membandingkan perilaku AES-GCM dan AES-GCM-SIV saat nonce yang sama digunakan lebih dari satu kali.

Pada AEAD berbasis GCM standar, penggunaan nonce yang sama dengan key yang sama sangat berbahaya. Jika dua plaintext berbeda dienkripsi dengan key dan nonce yang sama pada AES-GCM, bagian ciphertext dapat memiliki keystream yang sama. Akibatnya, XOR antara dua ciphertext dapat mengungkap relasi XOR antara dua plaintext.

AES-GCM-SIV dirancang lebih tahan terhadap nonce misuse. Walaupun penggunaan nonce unik tetap direkomendasikan, AES-GCM-SIV memberikan keamanan yang lebih baik ketika nonce tidak sengaja digunakan ulang.

Perintah:

```bash
cargo run -- --mode security --input "halo dunia" --scenario 4
```

Tujuan skenario:

- menunjukkan risiko nonce reuse pada AES-GCM,
- menunjukkan perbedaan perilaku AES-GCM-SIV dalam kondisi nonce reuse,
- memverifikasi properti `NONCE-MISUSE RESISTANCE`.

Alur pengujian AES-GCM:

1. Program membuat satu session key.
2. Program membuat satu nonce 12 byte.
3. Plaintext A dan plaintext B dibuat berbeda.
4. Plaintext A dienkripsi dengan AES-GCM menggunakan key dan nonce tersebut.
5. Plaintext B dienkripsi dengan AES-GCM menggunakan key dan nonce yang sama.
6. Program memisahkan bagian ciphertext body dari tag.
7. Program menghitung XOR antara ciphertext A dan ciphertext B.
8. Jika XOR ciphertext mengungkap pola/relasi plaintext, AES-GCM diberi verdict `VULNERABLE`.

Alur pengujian AES-GCM-SIV:

1. Program menggunakan key dan nonce yang sama.
2. Plaintext A dan plaintext B tetap berbeda.
3. Keduanya dienkripsi menggunakan AES-GCM-SIV.
4. Program menampilkan ciphertext A, ciphertext B, dan hasil XOR.
5. Karena AES-GCM-SIV menggunakan mekanisme synthetic IV, hasil ciphertext tetap berbeda dan lebih tahan terhadap nonce reuse.
6. AES-GCM-SIV diberi verdict `SECURE`.

Output menampilkan:

- nonce yang digunakan,
- plaintext A dan plaintext B,
- ciphertext A,
- ciphertext B,
- hasil XOR ciphertext,
- analisis per algoritma,
- verdict `VULNERABLE` atau `SECURE`.

Ekspektasi hasil:

| Algoritma | Kondisi | Verdict |
|---|---|---|
| AES-GCM | Dua plaintext berbeda, key sama, nonce sama | `VULNERABLE` |
| AES-GCM-SIV | Dua plaintext berbeda, key sama, nonce sama | `SECURE` |

Output utama:

```text
AES-GCM verdict: VULNERABLE
AES-GCM-SIV verdict: SECURE
Property verified: NONCE-MISUSE RESISTANCE PASS
```

Makna hasil:

- `AES-GCM verdict: VULNERABLE` berarti AES-GCM tidak aman jika nonce digunakan ulang.
- `AES-GCM-SIV verdict: SECURE` berarti skema usulan lebih tahan terhadap kesalahan penggunaan nonce.
- `NONCE-MISUSE RESISTANCE PASS` berarti eksperimen berhasil menunjukkan perbedaan keamanan kedua algoritma.

---

### 7.6 Scenario 5 — Man-in-the-Middle

Skenario ini mensimulasikan serangan Man-in-the-Middle (MITM), yaitu Eve berada di antara Alice dan Bob lalu mengganti public key yang dikirim saat key exchange.

Dalam ECDH normal:

- Alice menghitung shared secret dari private key Alice dan public key Bob,
- Bob menghitung shared secret dari private key Bob dan public key Alice,
- jika public key tidak dimodifikasi, shared secret Alice dan Bob sama.

Pada serangan MITM:

- Eve mengganti public key Alice yang dikirim ke Bob dengan public key Eve,
- Eve mengganti public key Bob yang dikirim ke Alice dengan public key Eve,
- Alice dan Bob akhirnya menghitung shared secret yang berbeda,
- session key Alice dan Bob berbeda,
- ciphertext dari Alice tidak dapat didekripsi oleh Bob.

Tujuan skenario:

- membuktikan bahwa substitusi public key menyebabkan shared secret tidak sama,
- membuktikan bahwa dekripsi gagal jika session key Alice dan Bob berbeda,
- menunjukkan pentingnya autentikasi public key dalam sistem E2EE nyata,
- memverifikasi properti `AUTHENTICITY + FORWARD SECRECY`.

Alur pengujian:

1. Alice membangkitkan key pair ECDH.
2. Bob membangkitkan key pair ECDH.
3. Eve membangkitkan key pair ECDH sendiri.
4. Saat Alice mengirim public key ke Bob, Eve menggantinya dengan public key Eve.
5. Saat Bob mengirim public key ke Alice, Eve menggantinya dengan public key Eve.
6. Alice menghitung shared secret menggunakan private key Alice dan public key Eve.
7. Bob menghitung shared secret menggunakan private key Bob dan public key Eve.
8. Program membandingkan shared secret Alice dan Bob.
9. Alice mengenkripsi pesan menggunakan session key miliknya.
10. Bob mencoba mendekripsi dengan session key hasil perhitungannya.
11. Dekripsi harus gagal karena key Alice dan Bob berbeda.

Ekspektasi hasil:

| Pemeriksaan | Hasil Aman |
|---|---|
| Shared secret Alice vs Bob | Berbeda |
| Session key Alice vs Bob | Berbeda |
| Dekripsi oleh Bob | Gagal |
| Deteksi serangan | Ya |

Output utama:

```text
Attack detected: YES
Property verified: AUTHENTICITY + FORWARD SECRECY PASS
```

Makna hasil:

- `Attack detected: YES` berarti sistem simulasi mendeteksi bahwa key exchange tidak menghasilkan shared secret yang sama.
- `AUTHENTICITY + FORWARD SECRECY PASS` berarti skenario berhasil menunjukkan bahwa autentikasi public key penting untuk mencegah MITM.
- Jika Bob tetap dapat mendekripsi pesan setelah public key diganti, maka simulasi gagal mendeteksi MITM.

### 7.7 Kolom CSV Security

File `results/security_tests.csv` berisi:

```text
scenario, algorithm, attempt, result, property, verdict
```

---

## 8. Mode Ablation Study

Mode `ablation` menjalankan studi ablation terhadap tiga konfigurasi dengan data teks:

- `text-small`,
- `text-medium`,
- `text-large`.

Setiap konfigurasi dijalankan 30 iterasi.

Perintah:

```bash
cargo run -- --mode ablation --input "halo dunia"
```

Disarankan untuk eksperimen:

```bash
cargo run --release -- --mode ablation --input "halo dunia"
```

Output:

```text
results/ablation.csv
```

### 8.1 Konfigurasi Ablation

| Config | Keterangan |
|---|---|
| `no-hkdf` | Shared secret ECDH digunakan langsung sebagai AES-256 key |
| `no-ecdh` | Menggunakan symmetric key hardcoded |
| `aes-gcm-only` | Pipeline penuh, tetapi algoritma diganti menjadi AES-GCM |

### 8.2 Kolom CSV Ablation

File `results/ablation.csv` berisi:

```text
iteration, config, data_type, data_size_bytes,
enc_time_us, dec_time_us, enc_throughput_mbs,
dec_throughput_mbs, overhead_bytes, overhead_pct, memory_mb
```

---

## 9. Mode All

Mode `all` menjalankan beberapa mode secara berurutan:

1. verbose,
2. performance benchmark,
3. security test,
4. ablation study.

Perintah:

```bash
cargo run -- --mode all --input ./experimen/
```

Disarankan:

```bash
cargo run --release -- --mode all --input ./experimen/
```

Catatan:

- Mode ini membutuhkan folder `experimen/`.
- Jika file media tidak tersedia, mode performance akan gagal karena file input tidak ditemukan.

---

## 10. Output CSV

Semua file hasil eksperimen berada di folder:

```text
results/
```

Daftar output:

| File | Dihasilkan oleh |
|---|---|
| `performance.csv` | mode `perf` dan `all` |
| `security_tests.csv` | mode `security` dan `all` |
| `ablation.csv` | mode `ablation` dan `all` |

---

## 11. Contoh Perintah Lengkap

### Verbose

```bash
cargo run -- --mode verbose --input "halo dunia"
```

### Performance

```bash
cargo run -- --mode perf --input ./experimen/
```

### Security Semua Skenario

```bash
cargo run -- --mode security --input "halo dunia" --scenario all
```

### Security Skenario Nonce Reuse

```bash
cargo run -- --mode security --input "halo dunia" --scenario 4
```

### Ablation

```bash
cargo run -- --mode ablation --input "halo dunia"
```

### All

```bash
cargo run -- --mode all --input ./experimen/
```

---

## 12. Validasi Program

Perintah yang sudah digunakan untuk validasi:

```bash
cargo check
cargo fmt --check
cargo run -- --mode verbose --input "halo dunia"
cargo run -- --mode security --input "halo dunia" --scenario 4
cargo run -- --mode ablation --input "halo dunia"
```

---

## 13. Catatan Eksperimen

Untuk pengukuran performa yang lebih representatif:

1. gunakan `--release`,
2. tutup aplikasi berat lain saat benchmark,
3. jalankan eksperimen beberapa kali,
4. gunakan file media yang sama untuk semua percobaan,
5. jangan membandingkan hasil debug build dengan release build.

Contoh:

```bash
cargo run --release -- --mode perf --input ./experimen/
```

---

## 14. Batasan Simulasi

Program ini adalah simulasi lokal, sehingga:

- tidak ada komunikasi jaringan sungguhan,
- tidak ada aplikasi chat,
- tidak ada penyimpanan private key permanen,
- tidak ada autentikasi identitas berbasis sertifikat,
- MITM disimulasikan dengan substitusi public key,
- replay detection disimulasikan dengan cache identifier pesan.

Tujuan program adalah menunjukkan pipeline E2EE dan karakteristik keamanan/performa algoritma dalam lingkungan eksperimen terkontrol.

---

## 15. Ringkasan Pipeline E2EE

Pipeline utama:

```text
Alice KeyPair        Bob KeyPair
     │                   │
     ├── public key ────>│
     │<──── public key ──┤
     │                   │
ECDH shared secret   ECDH shared secret
     │                   │
     └──── HKDF-SHA256 ──┘
              │
        Session Key
              │
        AES-GCM-SIV
              │
 ciphertext + auth tag
              │
          Decryption
              │
       plaintext verified
```

---

## 16. Troubleshooting

### Error: folder media tidak ditemukan

Jika menjalankan:

```bash
cargo run -- --mode perf --input ./experimen/
```

pastikan folder `experimen/` berada di dalam direktori `e2ee_sim/` atau gunakan path yang benar.

### Error: scenario tidak valid

Gunakan hanya:

```text
1, 2, 3, 4, 5, all
```

Contoh valid:

```bash
cargo run -- --mode security --input "halo dunia" --scenario all
```

### Benchmark terasa lambat

Gunakan release mode:

```bash
cargo run --release -- --mode perf --input ./experimen/
```
