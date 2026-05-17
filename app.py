import streamlit as st
import re
from datetime import datetime

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="STRYX — Threat Analyzer",
    page_icon="🔍",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');

html, body, [class*="css"] {
    background-color: #080b0f !important;
    color: #c5d8c5 !important;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
}

.stApp { background-color: #080b0f !important; }

.main .block-container {
    padding-top: 2rem;
    padding-bottom: 4rem;
    max-width: 860px;
}

h1, h2, h3 { color: #eef4ee !important; font-weight: 900 !important; }

.stButton > button {
    background: #3dff8f !important;
    color: #080b0f !important;
    border: none !important;
    border-radius: 10px !important;
    font-weight: 800 !important;
    font-size: 15px !important;
    padding: 12px 32px !important;
    width: 100% !important;
    letter-spacing: 0.05em !important;
    transition: all 0.2s !important;
}

.stButton > button:hover {
    background: #5fffaa !important;
    box-shadow: 0 0 24px #3dff8f44 !important;
}

.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: #0d1117 !important;
    border: 1px solid #1c2a3a !important;
    border-radius: 10px !important;
    color: #eef4ee !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 14px !important;
    padding: 12px 16px !important;
}

.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: #3dff8f88 !important;
    box-shadow: 0 0 0 3px #3dff8f11 !important;
}

.stSelectbox > div > div {
    background: #0d1117 !important;
    border: 1px solid #1c2a3a !important;
    border-radius: 10px !important;
    color: #eef4ee !important;
}

.stTabs [data-baseweb="tab-list"] {
    background: #0d1117 !important;
    border-radius: 10px !important;
    padding: 4px !important;
    border: 1px solid #1c2a3a !important;
    gap: 4px !important;
}

.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: #6a8a7a !important;
    border-radius: 7px !important;
    font-weight: 700 !important;
    font-size: 12px !important;
    letter-spacing: 0.12em !important;
    border: none !important;
}

.stTabs [aria-selected="true"] {
    background: #3dff8f !important;
    color: #080b0f !important;
}

.stAlert { border-radius: 10px !important; }

div[data-testid="stMetricValue"] {
    font-size: 2.5rem !important;
    font-weight: 900 !important;
}

.stryx-card {
    background: #111620;
    border: 1px solid #1c2a3a;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 12px;
}

.stryx-header {
    text-align: center;
    padding: 20px 0 32px;
    border-bottom: 1px solid #1c2a3a;
    margin-bottom: 28px;
}

.stryx-logo {
    color: #3dff8f;
    font-size: 42px;
    font-weight: 900;
    letter-spacing: 0.14em;
    text-shadow: 0 0 40px #3dff8f44;
    font-family: -apple-system, sans-serif;
}

.stryx-sub {
    color: #6a8a7a;
    font-size: 14px;
    margin-top: 6px;
    letter-spacing: 0.08em;
}

.verdict-critical { color: #ff1f44 !important; }
.verdict-high     { color: #ff6b00 !important; }
.verdict-medium   { color: #f5c842 !important; }
.verdict-low      { color: #3dff8f !important; }
.verdict-safe     { color: #00d4ff !important; }

.indicator-card {
    background: #080b0f;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 8px;
    border-left: 3px solid #1c2a3a;
}

.section-label {
    color: #6a8a7a;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.2em;
    margin-bottom: 10px;
}

.chip {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.07em;
}

.footer {
    text-align: center;
    color: #3d5060;
    font-size: 11px;
    padding-top: 24px;
    border-top: 1px solid #1c2a3a;
    margin-top: 48px;
    letter-spacing: 0.1em;
}

hr { border-color: #1c2a3a !important; }
</style>
""", unsafe_allow_html=True)

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
    {"test": lambda u: bool(re.search(r'(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rb\.gy|tiny\.cc|cutt\.ly|shorturl\.at)', u)),
     "score": 20, "sev": "MEDIUM", "type": "URL SHORTENER",
     "detail": "Shortener hides the real destination"},
    {"test": lambda u: bool(re.search(r'pay[p]a[l1]|pay-pal|g[o0]{2}gle|g00gle|amaz[o0]n|faceb[o0]{2}k|micr[o0]s[o0]ft|app[l1]e-|netfl[i1]x|[i1]nstagram|tw[i1]tter|l[i1]nked[i1]n|y[o0]utube', u.lower())),
     "score": 40, "sev": "CRITICAL", "type": "LOOKALIKE DOMAIN",
     "detail": "Domain mimics a brand via character substitution"},
    {"test": lambda u: bool(re.search(r'/(login|verify|account|suspend|update|confirm|secure|banking|password|credential|signin|auth|validation|wallet|recover)[/\?_-]', u.lower())),
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

SEV_COLORS = {
    "CRITICAL": "#ff1f44",
    "HIGH":     "#ff6b00",
    "MEDIUM":   "#f5c842",
    "LOW":      "#3dff8f",
    "SAFE":     "#00d4ff",
}

SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "SAFE":     "🔵",
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

def get_simple(verdict, mode):
    messages = {
        "SAFE":     f"This {mode} looks safe. No suspicious patterns detected.",
        "LOW":      f"Minor concerns detected. Verify the source before {'clicking' if mode=='URL' else 'acting'}.",
        "MEDIUM":   f"This {mode} looks suspicious. {'Avoid clicking unless verified.' if mode=='URL' else 'Do not click links or share personal info.'}",
        "HIGH":     f"{'Likely malicious. Do not visit this link.' if mode=='URL' else 'Likely phishing. Delete and report to your IT team.'}",
        "CRITICAL": f"{'DANGER: Strong phishing indicators. Do not open this URL.' if mode=='URL' else 'PHISHING CONFIRMED. Do not interact. Report immediately.'}",
    }
    return messages.get(verdict, "")

def get_action(verdict):
    actions = {
        "SAFE":     "No action needed. Appears legitimate.",
        "LOW":      "Verify the source independently before proceeding.",
        "MEDIUM":   "Do not click. Report to your security team.",
        "HIGH":     "Block immediately. Escalate to L2 analyst. Log in SIEM.",
        "CRITICAL": "CRITICAL: Block, quarantine affected systems, file incident report now.",
    }
    return actions.get(verdict, "")

def analyze_url(url):
    url = url.strip()
    indicators = []
    score = 0
    for rule in URL_RULES:
        try:
            if rule["test"](url):
                score = min(score + rule["score"], 100)
                indicators.append({
                    "type": rule["type"],
                    "detail": rule["detail"],
                    "sev": rule["sev"],
                })
        except:
            pass
    verdict = get_verdict(score)
    mitre = MITRE_MAP.get(indicators[0]["type"]) if indicators else None
    return {
        "verdict": verdict, "score": score, "mode": "URL",
        "input": url, "indicators": indicators,
        "simple": get_simple(verdict, "URL"),
        "action": get_action(verdict), "mitre": mitre,
        "summary": f"{len(indicators)} indicator{'s' if len(indicators)!=1 else ''} detected." if indicators else "No threat indicators found.",
        "ts": datetime.now().strftime("%d %b %Y, %I:%M %p"),
    }

def analyze_email(text):
    text = text.strip()
    indicators = []
    score = 0
    for rule in EMAIL_RULES:
        try:
            n = rule["test"](text)
            if n and n > 0:
                score = min(score + min(n * rule["spm"], rule["max"]), 100)
                indicators.append({
                    "type": rule["type"],
                    "detail": rule["detail"](n),
                    "sev": rule["sev"],
                })
        except:
            pass
    verdict = get_verdict(score)
    mitre_type = next((i["type"] for i in indicators if i["type"] in MITRE_MAP), None)
    mitre = MITRE_MAP.get(mitre_type)
    return {
        "verdict": verdict, "score": score, "mode": "EMAIL",
        "input": text[:100] + ("…" if len(text) > 100 else ""),
        "indicators": indicators,
        "simple": get_simple(verdict, "email"),
        "action": get_action(verdict), "mitre": mitre,
        "summary": f"{len(indicators)} indicator{'s' if len(indicators)!=1 else ''} detected." if indicators else "No phishing indicators found.",
        "ts": datetime.now().strftime("%d %b %Y, %I:%M %p"),
    }

def generate_report(r):
    lines = [
        "STRYX — THREAT ANALYSIS REPORT",
        "=" * 44,
        f"Date     : {r['ts']}",
        f"Mode     : {r['mode']} Scan",
        f"Verdict  : {r['verdict']} ({r['score']}/100)",
        f"Summary  : {r['summary']}",
        f"MITRE    : {r['mitre'] or 'N/A'}",
        f"Action   : {r['action']}",
        "",
        "INDICATORS:",
    ]
    if r["indicators"]:
        for i in r["indicators"]:
            lines.append(f"  [{i['sev']}] {i['type']}: {i['detail']}")
    else:
        lines.append("  No indicators found.")
    lines += ["", "─" * 44, "STRYX v1.0 — Silent Storm", "stryx.streamlit.app"]
    return "\n".join(lines)

# ── Session state ─────────────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []
if "result" not in st.session_state:
    st.session_state.result = None

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="stryx-header">
    <div class="stryx-logo">⟩ STRYX</div>
    <div class="stryx-sub">EMAIL & URL THREAT ANALYZER · v1.0 · SILENT STORM</div>
</div>
""", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["SCAN", "DASHBOARD", "HISTORY"])

# ════════════════════════════════════
# TAB 1 — SCAN
# ════════════════════════════════════
with tab1:
    st.markdown("### Threat Scanner")
    st.markdown("<p style='color:#6a8a7a;font-size:14px;margin-bottom:20px'>Paste a URL or email to analyze for phishing and social engineering.</p>", unsafe_allow_html=True)

    mode = st.selectbox("Scan Mode", ["URL", "EMAIL"], label_visibility="collapsed")

    SAMPLES_URL = [
        "http://paypa1-secure-login.xyz/verify?user=account&token=8fx2k",
        "https://amaz0n-support.tk/account-suspended/login.php",
        "http://192.168.1.1/admin/update-credentials",
        "https://www.google.com",
    ]
    SAMPLES_EMAIL = [
        "From: security@paypa1-alerts.com\nSubject: URGENT: Your account will be suspended!\n\nDear Valued Customer,\nWe detected suspicious activity. Click here: http://paypa1-secure.xyz/verify\n\nPayPal Security Team",
        "From: noreply@gooogle-account-security.com\nSubject: Sign-in attempt blocked!\n\nSomeone tried accessing your Google account from Russia.\nClick: http://g00gle-security-alert.tk/protect\n\nGoogle Security",
        "From: hr@company.com\nSubject: Team lunch Friday\n\nHi team, lunch at 1 PM Friday. See you there!",
    ]

    # Sample buttons
    st.markdown("<div class='section-label'>TRY A SAMPLE</div>", unsafe_allow_html=True)
    samples = SAMPLES_URL if mode == "URL" else SAMPLES_EMAIL
    cols = st.columns(len(samples))
    for i, (col, sample) in enumerate(zip(cols, samples)):
        with col:
            if st.button(f"#{i+1}", key=f"sample_{i}"):
                st.session_state[f"input_val"] = sample

    default_val = st.session_state.get("input_val", "")

    if mode == "URL":
        user_input = st.text_input(
            "URL Input",
            value=default_val,
            placeholder="Paste URL here — e.g. https://paypa1-login.xyz/verify",
            label_visibility="collapsed",
            max_chars=2000,
        )
    else:
        user_input = st.text_area(
            "Email Input",
            value=default_val,
            placeholder="From: sender@example.com\nSubject: ...\n\nPaste full email content here…",
            label_visibility="collapsed",
            height=200,
            max_chars=5000,
        )

    analyze_clicked = st.button("⟩ Analyze " + mode, type="primary")

    if analyze_clicked:
        if not user_input.strip():
            st.warning("Please paste a URL or email first.")
        else:
            with st.spinner("Scanning…"):
                import time
                time.sleep(0.5)
                if mode == "URL":
                    result = analyze_url(user_input)
                else:
                    result = analyze_email(user_input)
                st.session_state.result = result
                st.session_state.history.insert(0, result)
                if len(st.session_state.history) > 50:
                    st.session_state.history = st.session_state.history[:50]

    # ── Results ──
    if st.session_state.result:
        r = st.session_state.result
        verdict = r["verdict"]
        color = SEV_COLORS.get(verdict, "#3dff8f")
        emoji = SEV_EMOJI.get(verdict, "🔵")

        st.markdown("---")

        # Output level toggle
        output_level = st.radio(
            "Output Level",
            ["SIMPLE", "ADVANCED"],
            horizontal=True,
            label_visibility="collapsed",
        )

        # Verdict banner
        st.markdown(f"""
        <div class="stryx-card" style="border-left: 4px solid {color}; background: linear-gradient(135deg, {color}0d, #111620);">
            <div style="display:flex; align-items:center; gap:16px; flex-wrap:wrap;">
                <div style="text-align:center; min-width:80px;">
                    <div style="font-size:36px; font-weight:900; color:{color}; line-height:1; text-shadow: 0 0 20px {color}66">{r['score']}</div>
                    <div style="color:#3d5060; font-size:10px; letter-spacing:0.15em">RISK SCORE</div>
                </div>
                <div style="flex:1">
                    <div style="color:{color}; font-size:22px; font-weight:900; margin-bottom:8px; text-shadow:0 0 18px {color}66">
                        {emoji} {verdict}
                    </div>
                    <div style="color:#c5d8c5; font-size:{'15' if output_level=='SIMPLE' else '13'}px; line-height:1.65">
                        {r['simple'] if output_level == 'SIMPLE' else r['summary']}
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if output_level == "SIMPLE":
            # Simple: just show action
            st.markdown(f"""
            <div class="stryx-card">
                <div class="section-label">⟩ RECOMMENDED ACTION</div>
                <div style="color:#eef4ee; font-size:15px; line-height:1.7">{r['action']}</div>
            </div>
            """, unsafe_allow_html=True)

        else:
            # Advanced: full breakdown
            if r["indicators"]:
                st.markdown(f"<div class='section-label'>⟩ THREAT INDICATORS — {len(r['indicators'])} FOUND</div>", unsafe_allow_html=True)
                for ind in r["indicators"]:
                    ic = SEV_COLORS.get(ind["sev"], "#334")
                    st.markdown(f"""
                    <div class="indicator-card" style="border-left-color: {ic}">
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:5px; flex-wrap:wrap">
                            <span style="color:#6a8a7a; font-size:10px; font-weight:700; letter-spacing:0.14em">{ind['type']}</span>
                            <span style="background:{ic}22; color:{ic}; border:1px solid {ic}44; padding:2px 8px; border-radius:10px; font-size:10px; font-weight:700">{ind['sev']}</span>
                        </div>
                        <div style="color:#c5d8c5; font-size:13px">{ind['detail']}</div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("No threat indicators triggered. All rule checks passed.")

            col1, col2 = st.columns(2)
            with col1:
                if r["mitre"]:
                    st.markdown(f"""
                    <div class="stryx-card">
                        <div class="section-label">⟩ MITRE ATT&CK</div>
                        <div style="color:#f5c842; font-size:13px; font-family:monospace; line-height:1.6">{r['mitre']}</div>
                    </div>
                    """, unsafe_allow_html=True)
            with col2:
                st.markdown(f"""
                <div class="stryx-card">
                    <div class="section-label">⟩ ANALYST ACTION</div>
                    <div style="color:#eef4ee; font-size:13px; line-height:1.65">{r['action']}</div>
                </div>
                """, unsafe_allow_html=True)

        # Download report
        report_text = generate_report(r)
        st.download_button(
            label="⟩ Download Report (.txt)",
            data=report_text,
            file_name=f"stryx_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
        )

# ════════════════════════════════════
# TAB 2 — DASHBOARD
# ════════════════════════════════════
with tab2:
    st.markdown("### Dashboard")
    st.markdown("<p style='color:#6a8a7a;font-size:14px;margin-bottom:20px'>Your scan history and threat patterns.</p>", unsafe_allow_html=True)

    history = st.session_state.history

    if not history:
        st.markdown("""
        <div style="text-align:center; padding:60px 0; color:#3d5060">
            <div style="font-size:48px; opacity:0.3; margin-bottom:16px">◈</div>
            <div style="font-size:16px; font-weight:700; color:#6a8a7a; margin-bottom:8px">No scan data yet</div>
            <div style="font-size:13px">Run scans in the SCAN tab to populate this dashboard</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Stat cards
        total = len(history)
        crits = sum(1 for h in history if h["verdict"] == "CRITICAL")
        avg = round(sum(h["score"] for h in history) / total)
        last = history[0]["verdict"]
        last_color = SEV_COLORS.get(last, "#3dff8f")

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Total Scans", total)
        with c2:
            st.metric("Criticals", crits)
        with c3:
            st.metric("Avg Risk Score", f"{avg}/100")
        with c4:
            st.metric("Last Verdict", last)

        st.markdown("---")

        # Score trend
        st.markdown("<div class='section-label'>⟩ RISK SCORE TREND</div>", unsafe_allow_html=True)
        scores = [h["score"] for h in reversed(history[:20])]
        st.line_chart(scores, use_container_width=True)

        col1, col2 = st.columns(2)

        with col1:
            # Verdict distribution
            st.markdown("<div class='section-label'>⟩ VERDICT BREAKDOWN</div>", unsafe_allow_html=True)
            from collections import Counter
            vc = Counter(h["verdict"] for h in history)
            st.bar_chart(dict(vc), use_container_width=True)

        with col2:
            # Top threat types
            st.markdown("<div class='section-label'>⟩ TOP THREAT TYPES</div>", unsafe_allow_html=True)
            from collections import Counter
            all_inds = [i["type"] for h in history for i in h.get("indicators", [])]
            if all_inds:
                tc = Counter(all_inds).most_common(6)
                tc_dict = {k: v for k, v in tc}
                st.bar_chart(tc_dict, use_container_width=True)
            else:
                st.caption("No indicator data yet")

        # Recent scans
        st.markdown("---")
        st.markdown("<div class='section-label'>⟩ RECENT SCANS</div>", unsafe_allow_html=True)
        for h in history[:5]:
            c = SEV_COLORS.get(h["verdict"], "#334")
            e = SEV_EMOJI.get(h["verdict"], "🔵")
            st.markdown(f"""
            <div class="stryx-card" style="border-left:3px solid {c}; padding:12px 18px; margin-bottom:8px">
                <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:4px">
                    <span style="color:{c}; font-weight:700">{e} {h['verdict']}</span>
                    <span style="color:{c}; font-family:monospace; font-size:13px">{h['score']}/100</span>
                    <span style="background:#080b0f; color:#6a8a7a; font-size:10px; padding:2px 8px; border-radius:5px">{h['mode']}</span>
                    <span style="color:#3d5060; font-size:10px; margin-left:auto">{h['ts']}</span>
                </div>
                <div style="color:#6a8a7a; font-size:11px; font-family:monospace; overflow:hidden; text-overflow:ellipsis; white-space:nowrap">{h['input']}</div>
            </div>
            """, unsafe_allow_html=True)

# ════════════════════════════════════
# TAB 3 — HISTORY
# ════════════════════════════════════
with tab3:
    st.markdown("### History")
    st.markdown(f"<p style='color:#6a8a7a;font-size:14px;margin-bottom:20px'>{len(st.session_state.history)} entries · session only</p>", unsafe_allow_html=True)

    if not st.session_state.history:
        st.markdown("""
        <div style="text-align:center; padding:60px 0; color:#3d5060">
            <div style="font-size:48px; opacity:0.3; margin-bottom:16px">◈</div>
            <div style="font-size:16px; font-weight:700; color:#6a8a7a">No scans yet</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        if st.button("Clear History"):
            st.session_state.history = []
            st.session_state.result = None
            st.rerun()

        for i, h in enumerate(st.session_state.history):
            c = SEV_COLORS.get(h["verdict"], "#334")
            e = SEV_EMOJI.get(h["verdict"], "🔵")
            with st.expander(f"[{str(i+1).zfill(2)}] {e} {h['verdict']} — {h['score']}/100 — {h['mode']} — {h['ts']}"):
                st.markdown(f"<div style='color:#6a8a7a; font-size:11px; font-family:monospace; margin-bottom:8px'>{h['input']}</div>", unsafe_allow_html=True)
                st.markdown(f"<div style='color:#eef4ee; font-size:13px; margin-bottom:8px'>{h['simple']}</div>", unsafe_allow_html=True)
                if h.get("mitre"):
                    st.markdown(f"<div style='color:#f5c842; font-size:11px; font-family:monospace'>{h['mitre']}</div>", unsafe_allow_html=True)
                report = generate_report(h)
                st.download_button(
                    label="Download Report",
                    data=report,
                    file_name=f"stryx_report_{i+1}.txt",
                    mime="text/plain",
                    key=f"dl_{h['id']}",
                )

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="footer">
    ⟩ STRYX v1.0 · Email & URL Threat Analyzer · Silent Storm · Open Source
</div>
""", unsafe_allow_html=True)
