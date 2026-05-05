import streamlit as st
import logging
import pandas as pd
import re
import os
import math
import joblib
import requests
import urllib3
import shutil
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Suppress InsecureRequestWarning for verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Automatic Pycache Cleanup
@st.cache_resource
def cleanup_pycache():
    """Menghapus semua folder __pycache__ di direktori proyek saat startup."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    for root, dirs, files in os.walk(current_dir, topdown=False):
        for name in dirs:
            if name == "__pycache__":
                pycache_path = os.path.join(root, name)
                try:
                    shutil.rmtree(pycache_path)
                    logging.info(f"Berhasil menghapus: {pycache_path}")
                except Exception as e:
                    logging.error(f"Gagal menghapus {pycache_path}: {e}")

# Jalankan cleanup
cleanup_pycache()

# Load environment variables
load_dotenv()

# Rule-based heuristic module
from heuristic import final_prediction as heuristic_final_prediction
from database import DatabaseManager

# Database Initialization
db = DatabaseManager()

# Page Configuration
st.set_page_config(
    page_title="PhishDect – Phishing Detector",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Database Persistence
def load_history(user_id=None):
    if user_id is not None:
        return db.get_history_by_user(user_id)
    return []

def save_to_history(url, result, final_score, user_id=None):
    return db.save_history(url, result, final_score, user_id)


st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
    /* Reset & Typography */

    .stApp {
        font-family: 'Inter', sans-serif;
        background: #f8fafc !important; /* Neutral light grey background for good contrast */
    }

    /* Typography Cleanup */
    .stApp, .stApp p, .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6, .stApp label, .stApp li {
        font-family: 'Inter', sans-serif !important;
        color: #111111;
    }

    /* Hide Default Elements */
    #MainMenu, footer { visibility: hidden; }
    header { background: transparent !important; }

    /* Sidebar Toggle - Custom Look */
    [data-testid="stSidebarCollapsedControl"] {
        background-color: #2563eb !important; /* Primary Blue */
        color: #FFFFFF !important;
        border-radius: 0 12px 12px 0;
        top: 15px !important;
        left: 0 !important;
        z-index: 9999 !important;
        box-shadow: 4px 0 15px rgba(37, 99, 235, 0.2);
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
    }
    [data-testid="stSidebarCollapsedControl"] svg {
        fill: #FFFFFF !important;
        color: #FFFFFF !important;
    }

    /* Sidebar - scoped to avoid clashing */
    [data-testid="stSidebar"] {
        background: #111827 !important; /* Dark background */
    }
    [data-testid="stSidebar"] h1, 
    [data-testid="stSidebar"] h2, 
    [data-testid="stSidebar"] p, 
    [data-testid="stSidebar"] span,
    [data-testid="stSidebar"] label {
        color: #FFFFFF !important; /* Force high contrast white text inside sidebar */
    }
    [data-testid="stSidebar"] div[data-testid="stButton"] > button {
        background-color: transparent !important;
        border: 1px solid rgba(255,255,255,0.6) !important;
        color: #FFFFFF !important;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"] > button:hover {
        background-color: rgba(255,255,255,0.1) !important;
        border-color: #FFFFFF !important;
    }
    [data-testid="stSidebar"] div[data-testid="stButton"] > button * {
        color: #FFFFFF !important;
    }

    /* Sidebar Brand */
    .sidebar-brand { 
        font-size: 24px; 
        font-weight: 800; 
        color: #FFFFFF !important; 
        text-align: center;
        padding: 20px 0 30px;
        letter-spacing: -0.5px;
    }

    /* Main Content Area */
    .block-container { 
        padding: 4rem 4rem !important; 
        max-width: 1100px; 
    }

    /* Custom Premium Card */
    .custom-card { 
        background: #FFFFFF;
        padding: 40px; 
        border-radius: 16px; 
        border: 1px solid #e2e8f0; 
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); 
        margin-bottom: 30px; 
    }
    
    /* Result Boxes */
    .res-box { 
        border-radius: 12px; 
        padding: 24px 30px; 
        display: flex; 
        gap: 24px; 
        align-items: center; 
        border: 2px solid; 
        margin-top: 30px;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    }
    /* Danger (Phishing) */
    .res-phish { 
        background-color: #fee2e2; 
        border-color: #dc2626; 
    }
    .res-phish, .res-phish * {
        color: #7f1d1d !important; 
    }
    /* Success (Aman) */
    .res-safe { 
        background-color: #dcfce7; 
        border-color: #16a34a; 
    }
    .res-safe, .res-safe * {
        color: #14532d !important; 
    }
    
    /* Stats Grid */
    .stat-grid {
        display: flex;
        gap: 20px;
        margin-bottom: 30px;
    }
    .stat-item { 
        flex: 1;
        background: #FFFFFF; 
        padding: 24px; 
        border-radius: 12px; 
        border: 1px solid #e2e8f0; 
        text-align: center;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    }
    .stat-val { font-size: 32px; font-weight: 800; color: #111111; }
    .stat-lbl { font-size: 14px; color: #333333; font-weight: 600; text-transform: uppercase; margin-top: 8px; }

    /* Inputs */
    .stTextInput input {
        border-radius: 8px !important;
        padding: 12px 16px !important;
        border: 1px solid #64748b !important; /* Darker border for contrast */
        color: #111111 !important;
        background-color: #FFFFFF !important;
        caret-color: #2563eb !important; /* Blue blinking cursor */
    }
    .stTextInput input::placeholder {
        color: #64748b !important;
    }
    
    .stTextInput input:focus {
        border-color: #2563eb !important;
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.2) !important;
        transition: all 0.3s ease-in-out !important;
        outline: none !important;
    }
    
    /* Main Buttons & Form Submit */
    div[data-testid="stButton"] > button,
    div[data-testid="stFormSubmitButton"] > button { 
        border-radius: 8px !important; 
        transition: all 0.2s !important; 
        font-weight: 600 !important;
        padding: 0.75rem 2rem !important;
    }
    
    /* Primary / Form Submit Buttons */
    div[data-testid="stButton"] > button[kind="primary"],
    div[data-testid="stFormSubmitButton"] > button {
        background-color: #2563eb !important; /* Trust Blue */
        color: #FFFFFF !important;
        border: none !important;
    }
    div[data-testid="stButton"] > button[kind="primary"] *,
    div[data-testid="stFormSubmitButton"] > button * {
        color: #FFFFFF !important;
    }

    /* Secondary Button (Default) */
    div[data-testid="stButton"] > button[kind="secondary"] {
        background-color: #FFFFFF !important;
        color: #111111 !important;
        border: 2px solid #333333 !important;
    }
    div[data-testid="stButton"] > button[kind="secondary"] * {
        color: #111111 !important;
    }

    /* Expander text visibility fix - Main Content */
    .block-container div[data-testid="stExpander"] details {
        border: 1px solid #e2e8f0 !important;
        border-radius: 8px !important;
        background-color: #FFFFFF !important;
    }
    .block-container div[data-testid="stExpander"] summary {
        color: #111111 !important;
        background-color: #f1f5f9 !important;
        padding: 10px 15px !important;
        border-radius: 8px 8px 0 0 !important;
    }
    
    /* Sidebar Expander Styling */
    [data-testid="stSidebar"] div[data-testid="stExpander"] {
        border: 1px solid #374151 !important;
        background-color: #1f2937 !important;
        border-radius: 8px !important;
        margin-bottom: 10px;
    }
    [data-testid="stSidebar"] div[data-testid="stExpander"] summary {
        color: #FFFFFF !important;
        background-color: #1f2937 !important;
    }
    [data-testid="stSidebar"] div[data-testid="stExpander"] [data-testid="stVerticalBlock"] {
        background-color: #1f2937 !important;
        color: #FFFFFF !important;
    }

    /* Force text color for all markdown inside result boxes */
    .res-box div, .res-box span, .res-box p {
        color: inherit !important;
    }

    /* Login Card */
    .login-card {
        background: #FFFFFF;
        padding: 40px;
        border-radius: 16px;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        text-align: center;
        margin-bottom: 24px;
        border: 1px solid #e2e8f0;
    }
    .login-card h1 { color: #111111; margin-bottom: 12px; font-weight: 800; }
    .login-card p { color: #333333; font-size: 16px; font-weight: 500; }

    /* --- RESPONSIVE DESIGN --- */
    @media (max-width: 768px) {
        .block-container {
            padding: 2rem 1rem !important;
        }
        .stat-grid {
            flex-direction: column;
            gap: 12px;
        }
        .stat-item {
            padding: 16px;
        }
        .custom-card, .login-card {
            padding: 24px 16px !important;
        }
        .res-box {
            flex-direction: column;
            text-align: center;
            padding: 20px;
            gap: 16px;
        }
        .res-box div[style*="font-size:36px"] {
            font-size: 48px !important;
        }
        .sidebar-brand {
            font-size: 20px;
            padding: 15px 0;
        }
    }

</style>
""", unsafe_allow_html=True)

# Session State Initialization
if "login" not in st.session_state:
    st.session_state.login = False
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "username" not in st.session_state:
    st.session_state.username = ""
if "page" not in st.session_state:
    st.session_state.page = "detect"
if "history" not in st.session_state:
    st.session_state.history = []
if "auth_page" not in st.session_state:
    st.session_state.auth_page = "login"

# CSS to hide sidebar if not logged in
if not st.session_state.login:
    st.markdown("""
    <style>
        [data-testid="stSidebar"] {
            display: none;
        }
        [data-testid="stSidebarCollapsedControl"] {
            display: none;
        }
    </style>
    """, unsafe_allow_html=True)

# Model Loading
@st.cache_resource(show_spinner=False)
def load_artifacts():
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
    paths = {
        "model": os.path.join(base_dir, "random_forest_phishing_model.pkl"),
        "features": os.path.join(base_dir, "feature_names.pkl"),
        "scaler": os.path.join(base_dir, "minmax_scaler.pkl"),
        "threshold": os.path.join(base_dir, "optimal_threshold.pkl"),
    }
    res = {}
    for k, v in paths.items():
        if os.path.exists(v):
            try: res[k] = joblib.load(v)
            except: res[k] = None
        else: res[k] = None
    return res

artifacts = load_artifacts()

# Detection Logic
TLD_LEGIT_PROB = {"com": 0.9, "org": 0.8, "net": 0.75, "edu": 0.95, "gov": 0.98, "id": 0.8}
SPECIAL_CHARS = set("!@#$%^&*()+=[]{}|;:,<>?`~\\\"\\'")

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    url_len = len(url)
    
    # Pre-calculate common counts
    digits = sum(c.isdigit() for c in url)
    special = sum(1 for c in url if c in SPECIAL_CHARS)
    
    raw = {
        "url_length": url_len,
        "domain_length": len(hostname),
        "is_domain_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        "num_subdomains": max(len(hostname.split(".")) - 2, 0),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "num_digits": digits,
        "digit_ratio": digits / max(url_len, 1),
        "num_special_chars": special,
        "special_char_ratio": special / max(url_len, 1),
        "tld_length": len(hostname.split(".")[-1]) if "." in hostname else 0,
        "has_obfuscation": 1 if "%" in url else 0,
        "char_continuation_rate": 0,
        "num_query_parameters": len(parsed.query.split("&")) if parsed.query else 0,
        "num_fragments": 1 if parsed.fragment else 0,
        "num_path_segments": len([s for s in parsed.path.split("/") if s]),
        "hostname_length": len(hostname),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "num_hyphens": url.count("-"),
        "num_dots": url.count("."),
        "tld_legitimate_prob": TLD_LEGIT_PROB.get(hostname.split(".")[-1], 0.4) if "." in hostname else 0.4,
    }
    
    if url_len > 0:
        freq = {}
        for c in url: freq[c] = freq.get(c, 0) + 1
        raw["entropy"] = -sum((v/url_len) * math.log2(v/url_len) for v in freq.values())
    else:
        raw["entropy"] = 0
        
    return raw

def analyze_content(url):
    """Menganalisis konten HTML dari URL menggunakan BeautifulSoup"""
    # Pastikan URL memiliki skema (http/https)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        logging.info(f"Mencoba mengambil konten dari: {url}")
        # Headers lebih lengkap untuk meniru browser sungguhan
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,id;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
        }
        
        # Gunakan session untuk menangani cookies (beberapa situs phishing butuh ini)
        session = requests.Session()
        response = session.get(url, timeout=15, headers=headers, verify=False, allow_redirects=True)
        
        logging.info(f"Response status: {response.status_code} untuk {url} (Final URL: {response.url})")
        
        # Jika status code 200, atau bahkan jika tidak 200 tapi ada konten (beberapa situs error tetap ada form)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Ekstrak beberapa indikator sederhana
            title = soup.title.string.strip() if (soup.title and soup.title.string) else "Tanpa Judul"
            forms = soup.find_all('form')
            
            # Cari tanda-tanda form login
            has_login = False
            for f in forms:
                f_str = str(f).lower()
                if any(k in f_str for k in ["password", "login", "signin", "kata sandi"]):
                    has_login = True
                    break
            
            links = soup.find_all('a')
            
            logging.info(f"Analisis konten berhasil untuk {url}. Judul: {title}, Form: {len(forms)}")
            return {
                "success": True,
                "title": title,
                "num_forms": len(forms),
                "has_login_form": has_login,
                "num_links": len(links),
                "content_length": len(response.text)
            }
        else:
            logging.warning(f"Gagal mengambil konten {url}. Status code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error saat mengambil konten {url}: {str(e)}")
        
    return {"success": False}

def predict_url(url, arts):
    """Prediksi URL menggunakan model ML

    Alur:
      1. Ekstrak fitur numerik dari URL.
      2. Dapatkan probabilitas phishing dari model Random Forest.
      3. Kirim URL + probabilitas ML ke fungsi final_prediction (heuristic.py)
         yang menggabungkannya menjadi Model Komposit (Hybrid).
      4. Kembalikan final_score, is_phishing, fitur mentah, dan detail h_result.
    """
    # Langkah 1: Ekstraksi fitur
    raw = extract_features(url)

    # Langkah 2: Prediksi model ML
    X = pd.DataFrame([{n: raw.get(n, 0) for n in arts["features"]}])
    if arts["scaler"]:
        X = pd.DataFrame(arts["scaler"].transform(X), columns=arts["features"])
    proba = arts["model"].predict_proba(X)[0]
    p_idx = list(arts["model"].classes_).index(1) if 1 in arts["model"].classes_ else 1
    ml_prob = float(proba[p_idx])

    # Gunakan threshold dari file pkl jika tersedia, fallback ke 0.5
    thr = float(arts["threshold"]) if arts["threshold"] else 0.5

    # Langkah 3: Analisis Konten HTML (BeautifulSoup)
    html_info = analyze_content(url)

    # Langkah 4: Gabungkan ML + heuristic melalui modul heuristic.py (Model Komposit)
    h_result = heuristic_final_prediction(url, ml_prob, threshold=thr, html_info=html_info)

    # Langkah 5: Kembalikan hasil
    return (
        h_result["final_score"],      
        h_result["is_phishing"], 
        raw,                          
        h_result,
        html_info                  
    )

#  HALAMAN AUTH (LOGIN & REGISTER)
def show_auth():
    st.markdown('<div class="login-container">', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="login-card"><h1>🛡️ PhishDect</h1><p>Sistem Deteksi Phishing Berbasis ML</p></div>', unsafe_allow_html=True)
        
        if st.session_state.auth_page == "login":
            with st.form("login_form"):
                st.subheader("Login ke Akun Anda")
                user = st.text_input("Username", placeholder="Masukkan Username")
                pwd = st.text_input("Password", type="password", placeholder="Masukkan Password")
                submit = st.form_submit_button("Masuk Sekarang", width="stretch")
                
                if submit:
                    admin_hash = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
                    if user == "admin" and db.hash_password(pwd) == admin_hash:
                        st.session_state.login, st.session_state.user_id, st.session_state.username = True, 0, "admin"
                        st.session_state.history = load_history(0)
                        st.rerun()
                    else:
                        hashed = db.hash_password(pwd)
                        auth_res = db.authenticate_user(user, hashed)
                        if auth_res:
                            st.session_state.login, st.session_state.user_id, st.session_state.username = True, auth_res['id'], auth_res['username']
                            st.session_state.history = load_history(auth_res['id'])
                            st.rerun()
                        else:
                            st.error("Username atau password salah")
            
            st.markdown("<div style='text-align: center; margin-top: 10px;'>", unsafe_allow_html=True)
            if st.button("Belum punya akun? Daftar disini"):
                st.session_state.auth_page = "register"
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
            
        else:
            with st.form("register_form"):
                st.subheader("Buat Akun Baru")
                user = st.text_input("Username", placeholder="Pilih Username")
                pwd = st.text_input("Password", type="password", placeholder="Minimal 6 Karakter")
                submit = st.form_submit_button("Daftar Sekarang", width="stretch")
                
                if submit:
                    if not user or len(pwd) < 6:
                        st.error("Lengkapi data dengan benar (Password min 6 karakter)")
                    elif user.lower() == "admin":
                        st.error("Username 'admin' tidak tersedia")
                    else:
                        hashed = db.hash_password(pwd)
                        uid, msg = db.register_user(user, hashed)
                        if uid: 
                            st.success(msg)
                            st.session_state.auth_page = "login"
                            st.rerun()
                        else: st.error(msg)
            
            st.markdown("<div style='text-align: center; margin-top: 10px;'>", unsafe_allow_html=True)
            if st.button("Sudah punya akun? Login disini"):
                st.session_state.auth_page = "login"
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

#  HALAMAN DETEKSI
def show_detect():
    st.markdown("## 🔍 Deteksi URL Phishing")
    
    # Stats
    hist = st.session_state.history
    n_total = len(hist)
    n_phish = sum(1 for x in hist if x["result"] == "Phishing")
    
    st.markdown(f"""
    <div class="stat-grid">
        <div class="stat-item"><div class="stat-val">{n_total}</div><div class="stat-lbl">Total Scan</div></div>
        <div class="stat-item"><div class="stat-val" style="color:#b91c1c">{n_phish}</div><div class="stat-lbl">Phishing</div></div>
        <div class="stat-item"><div class="stat-val" style="color:#15803d">{n_total - n_phish}</div><div class="stat-lbl">Aman</div></div>
    </div>
    """, unsafe_allow_html=True)

    with st.container():
        st.markdown('<div class="custom-card">', unsafe_allow_html=True)
        url_input = st.text_input("Masukkan URL Suspisius", placeholder="Tempel disini URL nya")
        btn = st.button("Analisis Sekarang", type="primary", width="stretch")
        st.markdown('</div>', unsafe_allow_html=True)

    if btn and url_input:
        if any(v is None for v in artifacts.values()):
            st.error("Model tidak ditemukan di folder /models")
        else:
            with st.spinner("Menganalisis URL & Konten..."):
                # predict_url kini mengembalikan skor komposit dan info HTML
                score, is_phish, feat, h_detail, html_info = predict_url(url_input, artifacts)
                res_text = "Phishing" if is_phish else "Aman"

                # Simpan ke Database & session state (termasuk komponen pendukung)
                new_entry = save_to_history(
                    url_input, 
                    res_text, 
                    round(score*100, 1),
                    user_id=st.session_state.user_id
                )
                if new_entry:
                    st.session_state.history.insert(0, new_entry)

                # ── Tampilkan hasil utama  
                cls  = "res-phish" if is_phish else "res-safe"
                icon = "🚨" if is_phish else "✅"

                st.markdown(f"""
                <div class="res-box {cls}">
                    <div style="font-size:36px;">{icon}</div>
                    <div style="flex:1;">
                        <div style="font-weight:800; font-size:20px; margin-bottom:8px;">Hasil Deteksi: {res_text} (Tetap Waspaya)</div>
                        <div style="font-size:14px; font-weight:600;">
                            Skor Risiko Phishing: {round(score*100, 1)}%
                        </div>
                        <div style="font-size:14px; font-weight:500; margin-top:8px;">
                            {h_detail['decision_reason']}
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Tampilkan detail analisis dalam satu expander terpadu
                with st.expander("📋 Detail Analisis & Konten", expanded=is_phish):
                    if h_detail["explanations"]:
                        st.markdown("**Aturan yang terpicu:**")
                        for exp in h_detail["explanations"]:
                            st.markdown(f"- {exp}")

                        # Tabel skor per aturan
                        rule_df = pd.DataFrame([
                            {"Aturan": k.replace("_", " ").title(),
                             "Skor": f"{v*100:.1f}%",
                             "Status": "🔴 Aktif" if v > 0 else "🟢 Aman"}
                            for k, v in h_detail["rule_hits"].items()
                        ])
                        st.dataframe(rule_df, hide_index=True, width="stretch")

                    else:
                        st.success("✅ Tidak ada aturan mencurigakan yang terpicu pada URL ini.")

                    # --- Bagian Analisis Konten (Selalu Tampilkan) ---
                    st.markdown("---")
                    st.markdown("**🔍 Analisis 'Daleman' Web (Konten HTML):**")
                    if html_info["success"]:
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.write(f"🏷️ **Judul:** {html_info['title']}")
                            st.write(f"📝 **Formulir:** {html_info['num_forms']}")
                        with col_b:
                            st.write(f"🔗 **Total Link:** {html_info['num_links']}")
                            login_status = "🔴 Ditemukan" if html_info['has_login_form'] else "🟢 Tidak Ada"
                            st.write(f"🔑 **Form Login:** {login_status}")
                        
                        if html_info['has_login_form'] and is_phish:
                            st.warning("⚠️ Situs ini memiliki formulir login dan terdeteksi mencurigakan. JANGAN masukkan data sensitif!")
                    else:
                        st.info("ℹ️ Tidak dapat mengambil konten HTML secara otomatis. (Situs mungkin tidak aktif, memblokir bot, atau memerlukan verifikasi manusia).")

#  HALAMAN RIWAYAT
def show_history():
    st.markdown("## 📋 Riwayat Hasil Deteksi")
    if not st.session_state.history:
        st.info("Belum ada riwayat deteksi.")
        return

    df = pd.DataFrame(st.session_state.history)
    
    # Filter hanya kolom yang benar-benar ada untuk menghindari KeyError
    cols = ["time", "result", "final_score", "url"]
    display_cols = [c for c in cols if c in df.columns]
    
    if not display_cols:
        st.info("Riwayat tersedia dalam format lama atau tidak lengkap.")
        st.dataframe(df, width="stretch", hide_index=True)
    else:
        st.dataframe(df[display_cols], width="stretch", hide_index=True)
    
    if st.button("Hapus Riwayat"):
        db.clear_history(user_id=st.session_state.user_id)
        st.session_state.history = []
        st.rerun()

#  ROUTER & SIDEBAR
if not st.session_state.login:
    show_auth()
else:
    with st.sidebar:
        st.markdown('<div class="sidebar-brand">🛡️ PhishDect</div>', unsafe_allow_html=True)
        
        if st.button("🔍 Deteksi URL", width="stretch"): st.session_state.page = "detect"
        if st.button("📋 Riwayat", width="stretch"): st.session_state.page = "history"
        st.markdown("<br><br>", unsafe_allow_html=True)
        
        # Opsi Pengaturan Akun
        with st.expander("⚙️ Pengaturan Akun"):
            # Sembunyikan 'Hapus Akun Saya' untuk admin hardcoded
            if st.session_state.username != "admin":
                if st.button("🗑️ Hapus Akun Saya", use_container_width=True):
                    if db.delete_user(st.session_state.user_id):
                        st.success("Akun berhasil dihapus")
                        st.session_state.login = False
                        st.rerun()
                    else:
                        st.error("Gagal menghapus akun")
            
            #   START RESET DATABASE FEATURE
            if st.session_state.username == "admin":
                st.markdown("---")
                st.warning("⚠️ **Development Only**: Reset Database akan menghapus SEMUA user dan riwayat.")
                confirm_reset = st.checkbox("Konfirmasi hapus total data", key="db_reset_confirm")
                if st.button("🔥 Reset Database Sekarang", use_container_width=True, type="primary", disabled=not confirm_reset):
                    if db.reset_database():
                        st.success("Database berhasil di-reset!")
                        st.session_state.clear()
                        st.rerun()
                    else:
                        st.error("Gagal reset database")
            # END RESET DATABASE FEATURE

        if st.button("🚪 Keluar", width="stretch"):
            st.session_state.login = False
            st.session_state.user_id = None
            st.session_state.username = ""
            st.rerun()

    if st.session_state.page == "detect": show_detect()
    else: show_history()
