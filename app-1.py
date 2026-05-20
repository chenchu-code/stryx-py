from flask import Flask, render_template, request, jsonify
import re
from datetime import datetime

app = Flask(__name__)

# ── Detection Rules ───────────────────────────────────────────────────────────
URL_RULES = [
    {"test": lambda u: not u.startswith("https://"),
     "score": 15, "sev": "MEDIUM", "type": "PROTOCOL",
     "detail": "HTTP used — connection is not encrypted"},
    {"test": lambda u: bool(re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', u)),
     "score": 40, "sev": "CRITICAL", "type": "IP AS HOST",
     "detail": "Raw IP address used instead of a real domain"},
    {"test": lambda u: bool(re.search(r'\.(xyz|tk|top|ml|ga|cf|gq|pw|cc|su|icu|cyou|buzz|click|link|vip|life|online|site|website|space|fun|host|uno)(\W|$)', u)),
     "score": 25, "sev": "HIGH", "type": "SUSPICIOUS TLD",
     "detail": "High-risk TLD commonly used in phishing"},
    {"test": lambda u: bool(re.search(r'(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|rb\.gy|tiny\.cc|cutt\.ly)', u)),
     "score": 20, "sev": "MEDIUM", "type": "URL SHORTENER",
     "detail": "Shortener hides the real destination"},
    {"test": lambda u: bool(re.search(r'pay[p]a[l1]|pay-pal|g[o0]{2}gle|g00gle|amaz[o0]n|faceb[o0]{2}k|micr[o0]s[o0]ft|app[l1]e-|netfl[i1]x|[i1]nstagram|tw[i1]tter|l[i1]nked[i1]n|y[o0]utube', u.lower())),
     "score": 40, "sev": "CRITICAL", "type": "LOOKALIKE DOMAIN",
     "detail": "Domain mimics a brand via character substitution"},
    {"test": lambda u: bool(re.search(r'/(login|verify|account|suspend|update|confirm|secure|banking|password|credential|signin|auth|wallet|recover)[/\?_-]', u.lower())),
     "score": 20, "sev": "HIGH", "type": "SUSPICIOUS PATH",
     "detail": "Path contains credential-harvesting keywords"},
    {"test": lambda u: len(u.split("?")[0].replace("https://","").replace("http://","").split("/")[0].split(".")) > 4,
     "score": 20, "sev": "MEDIUM", "type": "EXCESS SUBDOMAINS",
     "detail": "4+ subdomains — common evasion technique"},
    {"test": lambda u: len(re.findall(r'%[0-9a-fA-F]{2}', u)) > 3,
     "score": 20, "sev": "HIGH", "type": "OBFUSCATION",
     "detail": "Multiple encoded characters — possible obfuscation"},
    {"test": lambda u: len(u) > 120,
     "score": 10, "sev": "LOW", "type": "LONG URL",
     "detail": "Unusually long URL may hide the destination"},
    {"test": lambda u: len(re.findall(r'[&?]', u)) > 5,
     "score": 10, "sev": "LOW", "type": "MANY PARAMETERS",
     "detail": "Excessive query params — redirect/tracking attack"},
    {"test": lambda u: '@' in u.replace("https://","").replace("http://",""),
     "score": 35, "sev": "HIGH", "type": "AT-SIGN IN URL",
     "detail": "@ in URL can redirect to a malicious host"},
    {"test": lambda u: bool(re.search(r'(paypal-|amazon-|google-|apple-|microsoft-|netflix-|bank-|secure-)(support|help|verify|login|update|account)', u.lower())),
     "score": 35, "sev": "CRITICAL", "type": "BRAND IMPERSONATION",
     "detail": "Brand name + action keyword = phishing pattern"},
]

EMAIL_RULES = [
    {"test": lambda e: len(re.findall(r'urgent|immediately|asap|act now|within 24|expire|suspended|locked|verify now|action required|limited time', e, re.I)),
     "spm": 12, "max": 40, "sev": "HIGH", "type": "URGENCY LANGUAGE",
     "detail": lambda n: f"{n} urgency phrase{'s' if n>1 else ''} detected"},
    {"test": lambda e: len(re.findall(r'password|credit card|ssn|social security|cvv|pin number|bank account|verify your|confirm your identity|billing info', e, re.I)),
     "spm": 20, "max": 40, "sev": "CRITICAL", "type": "CREDENTIAL REQUEST",
     "detail": lambda n: f"{n} credential-harvesting phrase{'s' if n>1 else ''} found"},
    {"test": lambda e: len([u for u in re.findall(r'https?://[^\s)>"]+', e) if re.search(r'\.xyz|\.tk|\.top|\.ml|paypa1|g00gle|amaz0n|login\.|verify\.', u, re.I)]),
     "spm": 30, "max": 60, "sev": "CRITICAL", "type": "SUSPICIOUS LINK",
     "detail": lambda n: f"{n} high-risk URL{'s' if n>1 else ''} embedded in body"},
    {"test": lambda e: len(re.findall(r'paypal|amazon|google|apple|microsoft|netflix|facebook|instagram|twitter|linkedin|bank of america|wells fargo|chase bank|irs|tax refund', e, re.I)),
     "spm": 8, "max": 24, "sev": "MEDIUM", "type": "BRAND MENTION",
     "detail": lambda n: f"{n} brand{'s' if n>1 else ''} mentioned — verify sender domain"},
    {"test": lambda e: 1 if re.search(r'dear (customer|user|valued|account holder|member|client)', e, re.I) else 0,
     "spm": 10, "max": 10, "sev": "LOW", "type": "GENERIC GREETING",
     "detail": lambda n: "Generic greeting instead of your real name"},
    {"test": lambda e: _check_spoofed(e),
     "spm": 45, "max": 45, "sev": "CRITICAL", "type": "SPOOFED SENDER",
     "detail": lambda n: "Display name claims to be a brand but domain doesn't match"},
    {"test": lambda e: len(re.findall(r'transfer|wire|payment|send money|gift card|itunes|google play|zelle|venmo|western union', e, re.I)),
     "spm": 15, "max": 30, "sev": "HIGH", "type": "PAYMENT REQUEST",
     "detail": lambda n: f"{n} financial keyword{'s' if n>1 else ''} found"},
    {"test": lambda e: len(re.findall(r'will be (closed|deleted|suspended|terminated|blocked)|legal action|lawsuit|report to|arrest|penalty|fine of', e, re.I)),
     "spm": 15, "max": 30, "sev": "HIGH", "type": "THREAT LANGUAGE",
     "detail": lambda n: f"{n} threat phrase{'s' if n>1 else ''} detected"},
]

MITRE_MAP = {
    "LOOKALIKE DOMAIN":   "T1566.002 — Spearphishing via Lookalike Domain",
    "SPOOFED SENDER":     "T1566.001 — Sender Spoofing",
    "CREDENTIAL REQUEST": "T1598 — Phishing for Information",
    "SUSPICIOUS LINK":    "T1566.002 — Spearphishing Link",
    "BRAND IMPERSONATION":"T1566 — Phishing / Brand Impersonation",
    "IP AS HOST":         "T1071 — Application Layer Protocol Abuse",
    "PAYMENT REQUEST":    "T1657 — Financial Theft",
}

def _check_spoofed(text):
    m = re.search(r'from:\s*([^\n<]+)?<([^>]+)>', text, re.I)
    if not m:
        return 0
    name = (m.group(1) or "").lower()
    domain = (m.group(2) or "").split("@")[-1].lower()
    brands = ["paypal", "google", "amazon", "apple", "microsoft"]
    return 1 if any(b in name and b not in domain for b in brands) else 0

def get_verdict(score):
    if score >= 75: return "CRITICAL"
    if score >= 55: return "HIGH"
    if score >= 35: return "MEDIUM"
    if score >= 15: return "LOW"
    return "SAFE"

def analyze_url(url):
    url = url.strip()[:2000]
    indicators = []
    score = 0
    for rule in URL_RULES:
        try:
            if rule["test"](url):
                score = min(score + rule["score"], 100)
                indicators.append({"type": rule["type"], "detail": rule["detail"], "sev": rule["sev"]})
        except:
            pass
    verdict = get_verdict(score)
    return build_result(verdict, score, indicators, "URL", url)

def analyze_email(text):
    text = text.strip()[:5000]
    indicators = []
    score = 0
    for rule in EMAIL_RULES:
        try:
            n = rule["test"](text)
            if n and n > 0:
                score = min(score + min(n * rule["spm"], rule["max"]), 100)
                indicators.append({"type": rule["type"], "detail": rule["detail"](n), "sev": rule["sev"]})
        except:
            pass
    verdict = get_verdict(score)
    return build_result(verdict, score, indicators, "EMAIL", text[:100])

def build_result(verdict, score, indicators, mode, inp):
    mitre_type = next((i["type"] for i in indicators if i["type"] in MITRE_MAP), None)
    simple_map = {
        "SAFE":     f"This {'URL' if mode=='URL' else 'email'} looks safe. No suspicious patterns detected.",
        "LOW":      "Minor concerns detected. Verify the source before proceeding.",
        "MEDIUM":   "Suspicious. Avoid interacting unless verified.",
        "HIGH":     "Likely malicious. Do not click or respond.",
        "CRITICAL": "DANGER: Confirmed threat. Do not open. Report immediately.",
    }
    action_map = {
        "SAFE":     "No action needed. Appears legitimate.",
        "LOW":      "Verify the source independently before proceeding.",
        "MEDIUM":   "Do not click. Report to your security team.",
        "HIGH":     "Block immediately. Escalate to L2. Log in SIEM.",
        "CRITICAL": "CRITICAL: Block, quarantine, file incident report now.",
    }
    return {
        "verdict": verdict,
        "score": score,
        "mode": mode,
        "input": inp,
        "indicators": indicators,
        "mitre": MITRE_MAP.get(mitre_type),
        "simple": simple_map.get(verdict, ""),
        "action": action_map.get(verdict, ""),
        "summary": f"{len(indicators)} indicator{'s' if len(indicators)!=1 else ''} detected." if indicators else "No threat indicators found.",
        "ts": datetime.now().strftime("%d %b %Y, %I:%M %p"),
    }

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    mode = data.get("mode", "URL")
    text = data.get("input", "").strip()
    if not text:
        return jsonify({"error": "No input provided"}), 400
    if mode == "URL":
        result = analyze_url(text)
    else:
        result = analyze_email(text)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
