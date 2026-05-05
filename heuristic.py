import re
from urllib.parse import urlparse

RULE_WEIGHTS = {
    "http_only":          0.20, 
    "digits_in_domain":   0.15,   
    "suspicious_symbols": 0.20,   
    "long_url":           0.15,  
    "login_form_risk":    0.20,  
    "suspicious_content": 0.10,   
}

URL_LENGTH_THRESHOLD = 75
DEFAULT_FINAL_THRESHOLD = 0.60

def heuristic_score(url: str, html_info: dict = None) -> dict:
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    rule_hits = {}
    explanations = []

    if parsed.scheme.lower() == "http":
        rule_hits["http_only"] = RULE_WEIGHTS["http_only"]
        explanations.append(
            f"⚠️ Protokol HTTP (tidak terenkripsi)  {RULE_WEIGHTS['http_only']:.0%}"
        )
    else:
        rule_hits["http_only"] = 0.0

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

    rule_hits["login_form_risk"] = 0.0
    rule_hits["suspicious_content"] = 0.0

    if html_info and html_info.get("success"):
        if html_info.get("has_login_form"):
            score = RULE_WEIGHTS["login_form_risk"]
            if parsed.scheme.lower() == "http":
                score *= 1.5 
            rule_hits["login_form_risk"] = round(score, 4)
            explanations.append(f"⚠️ Ditemukan formulir login otomatis — tambah {score:.0%} risiko")
        title = html_info.get("title", "").lower()
        suspicious_keywords = ["login", "verify", "account", "bank", "secure", "update", "signin", "konfirmasi"]
        if any(kw in title for kw in suspicious_keywords):
            score = RULE_WEIGHTS["suspicious_content"]
            rule_hits["suspicious_content"] = round(score, 4)
            explanations.append(f"⚠️ Judul halaman mencurigakan ('{html_info['title']}') — tambah {score:.0%} risiko")

    total_risk = min(sum(rule_hits.values()), 1.0)

    return {
        "risk_score":   round(total_risk, 4),
        "rule_hits":    rule_hits,
        "explanations": explanations,
    }

def final_prediction(
    url: str,
    ml_probability: float,
    threshold: float = DEFAULT_FINAL_THRESHOLD,
    html_info: dict = None
) -> dict:
    h_result = heuristic_score(url, html_info)
    risk_score = h_result["risk_score"]

    final_score = round(min(ml_probability + risk_score, 1.0), 4)
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

if __name__ == "__main__":
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    test_cases = [
        ("https://google.com", 0.05, "Aman"),
        ("http://g00gle-secure.login.com/verify?token=abc123xyz456&redirect=true", 0.72, "Phishing"),
        ("http://paypa1-account.verify@evil.com/update", 0.45, "Aman (warning heuristic tinggi)"),
        ("https://normal-bank.co.id/login", 0.30, "Aman"),
        ("http://192.168.1.1/admin/phishing_page.html?user=victim&pass=1234", 0.80, "Phishing"),
        ("https://fake-login-site.com", 0.20, "Phishing (via Content)"),
    ]
    print("  PENGUJIAN HEURISTIC PHISHING DETECTION")
    for url, ml_prob, expected in test_cases:
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
