import re
from urllib.parse import urlparse

RULE_WEIGHTS = {
    "http_only":          0.20,   # Aturan 1: Tidak menggunakan HTTPS
    "digits_in_domain":   0.15,   # Aturan 2: Domain mengandung angka
    "suspicious_symbols": 0.20,   # Aturan 3: Simbol mencurigakan di URL
    "long_url":           0.15,   # Aturan 4: URL terlalu panjang
    "login_form_risk":    0.20,   # Aturan 5: Ada form login (Content)
    "suspicious_content": 0.10,   # Aturan 6: Konten/Judul mencurigakan (Content)
}

# Threshold panjang URL untuk dianggap mencurigakan
URL_LENGTH_THRESHOLD = 75

# Threshold keputusan akhir (nilai 0.0–1.0)
DEFAULT_FINAL_THRESHOLD = 0.60

# FUNGSI UTAMA: heuristic_score(url, html_info)
# Mengembalikan dict berisi skor per aturan dan total risk score.
def heuristic_score(url: str, html_info: dict = None) -> dict:
    """
    Menghitung risk score berbasis aturan dari sebuah URL dan kontennya.

    Parameter:
        url (str): URL yang akan dianalisis.
        html_info (dict): Hasil analisis BeautifulSoup (opsional).

    Mengembalikan:
        dict dengan kunci:
          - 'risk_score'   (float 0.0–1.0): skor risiko total
          - 'rule_hits'    (dict)          : skor tiap aturan yang terpicu
          - 'explanations' (list[str])     : penjelasan aturan yang terpicu
    """
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    rule_hits = {}
    explanations = []

    # Aturan 1: Protokol HTTP (bukan HTTPS) 
    if parsed.scheme.lower() == "http":
        rule_hits["http_only"] = RULE_WEIGHTS["http_only"]
        explanations.append(
            f"⚠️ Protokol HTTP (tidak terenkripsi)  {RULE_WEIGHTS['http_only']:.0%}"
        )
    else:
        rule_hits["http_only"] = 0.0

    # Aturan 2: Angka dalam domain
    if re.search(r"\d", domain):
        digit_count = len(re.findall(r"\d", domain))
        partial = min(digit_count / 4, 1.0)
        score = RULE_WEIGHTS["digits_in_domain"] * partial
        rule_hits["digits_in_domain"] = round(score, 4)
        explanations.append(
            f"⚠️ Domain mengandung {digit_count} angka — tambah {score:.0%} risiko"
        )
    else:
        rule_hits["digits_in_domain"] = 0.0

    # Aturan 3: Simbol mencurigakan
    suspicious_score = 0.0
    suspicious_reasons = []
    if "@" in url:
        suspicious_score += 0.5
        suspicious_reasons.append("'@' dalam URL")
    hyphen_count = domain.count("-")
    if hyphen_count > 2:
        suspicious_score += min(hyphen_count / 5, 0.5)
        suspicious_reasons.append(f"{hyphen_count} tanda '-' di domain")
    if "_" in domain:
        suspicious_score += 0.3
        suspicious_reasons.append("'_' di domain")
    dot_count = url.count(".")
    if dot_count > 4:
        suspicious_score += min((dot_count - 4) / 5, 0.4)
        suspicious_reasons.append(f"{dot_count} titik dalam URL")

    suspicious_score = min(suspicious_score, 1.0)
    weighted_suspicious = RULE_WEIGHTS["suspicious_symbols"] * suspicious_score

    if suspicious_reasons:
        rule_hits["suspicious_symbols"] = round(weighted_suspicious, 4)
        explanations.append(
            f"⚠️ Simbol mencurigakan ({', '.join(suspicious_reasons)}) "
            f" {weighted_suspicious:.0%} "
        )
    else:
        rule_hits["suspicious_symbols"] = 0.0

    # Aturan 4: Panjang URL berlebihan
    url_length = len(url)
    if url_length > URL_LENGTH_THRESHOLD:
        excess = url_length - URL_LENGTH_THRESHOLD
        partial = min(excess / 75, 1.0)
        score = RULE_WEIGHTS["long_url"] * partial
        rule_hits["long_url"] = round(score, 4)
        explanations.append(
            f"⚠️ URL sangat panjang ({url_length} karakter)  {score:.0%}"
        )
    else:
        rule_hits["long_url"] = 0.0

    # --- ATURAN BERBASIS KONTEN (BeautifulSoup) ---
    rule_hits["login_form_risk"] = 0.0
    rule_hits["suspicious_content"] = 0.0

    if html_info and html_info.get("success"):
        # Aturan 5: Ada form login (sangat berisiko jika di situs mencurigakan)
        if html_info.get("has_login_form"):
            score = RULE_WEIGHTS["login_form_risk"]
            # Penalti tambahan jika form login di HTTP
            if parsed.scheme.lower() == "http":
                score *= 1.5 
            rule_hits["login_form_risk"] = round(score, 4)
            explanations.append(f"⚠️ Ditemukan formulir login otomatis — tambah {score:.0%} risiko")

        # Aturan 6: Judul atau konten mencurigakan
        title = html_info.get("title", "").lower()
        suspicious_keywords = ["login", "verify", "account", "bank", "secure", "update", "signin", "konfirmasi"]
        if any(kw in title for kw in suspicious_keywords):
            score = RULE_WEIGHTS["suspicious_content"]
            rule_hits["suspicious_content"] = round(score, 4)
            explanations.append(f"⚠️ Judul halaman mencurigakan ('{html_info['title']}') — tambah {score:.0%} risiko")

    # Hitung total risk score
    total_risk = min(sum(rule_hits.values()), 1.0)

    return {
        "risk_score":   round(total_risk, 4),
        "rule_hits":    rule_hits,
        "explanations": explanations,
    }

# FUNGSI UTAMA: final_prediction(url, ml_probability, threshold, html_info)
# Menggabungkan output ML dan Heuristic menjadi Model Komposit.

def final_prediction(
    url: str,
    ml_probability: float,
    threshold: float = DEFAULT_FINAL_THRESHOLD,
    html_info: dict = None
) -> dict:
    """
    Menghasilkan prediksi akhir berdasarkan Model Komposit (ML + Heuristic + Content).
    """

    # Langkah 1: Hitung heuristic score (termasuk konten jika ada)
    h_result = heuristic_score(url, html_info)
    risk_score = h_result["risk_score"]

    # Langkah 2: Hitung Final Score (Additive Penalty)
    final_score = round(min(ml_probability + risk_score, 1.0), 4)

    # Langkah 3: Tentukan keputusan
    is_phishing = final_score >= threshold
    
    if is_phishing:
        reason = (
            f"🔴 Phishing terdeteksi oleh analisis Model Gabungan "
            f"(Skor Risiko: {final_score:.0%})"
        )
    else:
        reason = (
            f"🟢 Aman menurut hasil analisis Model Gabungan "
            f"(Skor Risiko: {final_score:.0%})"
        )

    return {
        "is_phishing":       is_phishing,
        "final_score":       final_score,
        "decision_reason":   reason,
        "rule_hits":         h_result["rule_hits"],
        "explanations":      h_result["explanations"],
    }


# PENGUJIAN MANDIRI (jalankan: python heuristic.py)
if __name__ == "__main__":
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    test_cases = [
        # (url, ml_probability_simulasi, label_ekspektasi)
        ("https://google.com", 0.05, "Aman"),
        ("http://g00gle-secure.login.com/verify?token=abc123xyz456&redirect=true", 0.72, "Phishing"),
        ("http://paypa1-account.verify@evil.com/update", 0.45, "Aman (warning heuristic tinggi)"),
        ("https://normal-bank.co.id/login", 0.30, "Aman"),
        ("http://192.168.1.1/admin/phishing_page.html?user=victim&pass=1234", 0.80, "Phishing"),
        ("https://fake-login-site.com", 0.20, "Phishing (via Content)"),
    ]

    print("=" * 70)
    print("  PENGUJIAN HEURISTIC PHISHING DETECTION")
    print("=" * 70)

    for url, ml_prob, expected in test_cases:
        # Tambahkan html_info simulasi untuk kasus terakhir
        html_info = None
        if "fake-login-site" in url:
            html_info = {"success": True, "title": "Login to your account", "has_login_form": True}
        
        result = final_prediction(url, ml_prob, html_info=html_info)
        verdict = "PHISHING" if result["is_phishing"] else "AMAN"
        print(f"\nURL    : {url[:60]}{'...' if len(url) > 60 else ''}")
        print(f"ML Prob: {ml_prob:.0%}  "
              f"|  Final Score: {result['final_score']:.0%}")
        print(f"Verdict: {verdict}  (ekspektasi: {expected})")
        print(f"Alasan : {result['decision_reason']}")
        if result["explanations"]:
            print("Detail :")
            for exp in result["explanations"]:
                print(f"  {exp}")
        print("-" * 70)
