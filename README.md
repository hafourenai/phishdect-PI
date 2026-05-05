# PhishDect - Phishing Detector

PhishDect adalah sebuah aplikasi web berbasis **Streamlit** yang dirancang untuk mendeteksi URL phishing secara *real-time*. Aplikasi ini menggunakan pendekatan *hybrid* yang menggabungkan **Machine Learning (Random Forest)**, dan **Pengecekan Konten HTML** (Web Scraping) untuk memberikan hasil deteksi yang akurat (kali).

---

## Fitur Utama

- **Deteksi URL**
- **Analisis Konten Web**
- **Login & Register**
- **Riwayat Deteksi**
---

## Teknologi yang Digunakan

- **Frontend/Backend**: [Streamlit](https://streamlit.io/) (Python)
- **Machine Learning**: `scikit-learn`, `pandas`, `numpy`
- **Web Scraping**: `requests`, `beautifulsoup4`, `lxml`
- **Database**: [Supabase](https://supabase.com/) (PostgreSQL)
- **Keamanan**: `bcrypt` untuk enkripsi password.

---

## Cara Instalasi & Menjalankan Aplikasi

### 1. Prasyarat (Prerequisites)
Pastikan Anda sudah menginstal **Python 3.8+** di sistem Anda. 

### 2. Kloning Repositori (Opsional)
Jika Anda menggunakan git, clone repositori ini:
```bash
git clone https://github.com/hafourenai/PhisDect_PI
cd PhisDect_PI
```

### 3. Instalasi Dependensi
```bash
pip install -r requirements.txt
```

### 4. Pengaturan Environment Variables
Aplikasi ini membutuhkan koneksi ke Supabase. Buat file `.env` di *root directory* proyek dan masukkan kredensial Supabase Anda:
```env
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_KEY=<anon-key-anda>
```

### 5. Jalankan Aplikasi
Gunakan perintah berikut untuk menyalakan server lokal Streamlit:
```bash
streamlit run app.py
```
Aplikasi akan otomatis terbuka di browser pada alamat `http://localhost:8501`.

---

## Akun Admin Bawaan
Untuk tujuan pengujian, aplikasi ini memiliki akun admin *hardcoded* yang memiliki hak istimewa (seperti fitur *Reset Database*):
- **Username**: `admin`
- **Password**: `admin`

*(Pastikan untuk menghapus atau mengganti kredensial ini jika ingin mempublikasikan aplikasi ke lingkungan produksi!)*

---

*tau ga si? kayaknya ini dilakuin karena gua haus validasi. pengen dibilang keren. padahal? gada yang peduli sm gue 😖*
*mudah2an dengan selesai nya ini. bisa buat tidur gua kembali teratur ya*
*1 lagi. jgn sampe mood lu dipengaruhi oleh seseorang. rusak. dia ga peduli sm lu. knp mood lu bergantung dgn sikap dia?*

