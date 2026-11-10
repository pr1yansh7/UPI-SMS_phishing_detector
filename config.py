# config.py — Central configuration for UPI Phishing Detector

import os

# Load variables from a local .env file if present (never committed to git —
# see .env.example for the template). Falls back silently if python-dotenv
# isn't installed or .env doesn't exist, so the project still runs out of
# the box with placeholder keys.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ─── API Keys ─────────────────────────────────────────────────────────────────
# Each key is read from the environment first (i.e. from your .env file).
# If not set, falls back to the placeholder string so feature functions can
# detect "not configured" and degrade gracefully (see feature_extractor.py).

# PhishTank: free at https://www.phishtank.com/api_info.php
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY") or "YOUR_PHISHTANK_API_KEY"

# WHOIS domain age: https://www.whoisxmlapi.com  (500 free queries/month)
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY") or "YOUR_WHOIS_API_KEY"

# Google Safe Browsing: https://console.cloud.google.com → enable Safe Browsing API
GOOGLE_SAFE_BROWSING_API_KEY = (
    os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
)

# VirusTotal: free at https://www.virustotal.com/gui/sign-in (500 lookups/day)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") or "YOUR_VIRUSTOTAL_API_KEY"

# ─── Data Sources ─────────────────────────────────────────────────────────────
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
PHISHTANK_FEED_URL = "https://data.phishtank.com/data/{key}/online-valid.csv"

# ─── UPI Brand Keywords ───────────────────────────────────────────────────────
UPI_BRANDS = {
    # ── UPI Payment Apps ──────────────────────────────────────────────────────
    "phonepe":    "phonepe.com",
    "gpay":       "pay.google.com",
    "paytm":      "paytm.com",
    "bhim":       "bhimupi.org.in",
    "amazonpay":  "pay.amazon.in",
    "mobikwik":   "mobikwik.com",
    "freecharge":  "freecharge.in",
    "npci":       "npci.org.in",
    "upi":        "upi.npci.org.in",
    # ── Aadhaar / Government Identity ────────────────────────────────────────
    "uidai":      "uidai.gov.in",
    "aadhar":     "uidai.gov.in",      # common misspelling used by phishers
    "aadhaar":    "uidai.gov.in",
    "maadhaar":   "uidai.gov.in",      # official UIDAI mobile app name
    "digilocker": "digilocker.gov.in",
    "eaadhaar":   "uidai.gov.in",
    "resident":   "resident.uidai.gov.in",
}

# Real domains used for Levenshtein edit distance comparison
REAL_UPI_DOMAINS = [
    # UPI payment apps
    "phonepe.com", "pay.google.com", "paytm.com",
    "bhimupi.org.in", "pay.amazon.in", "mobikwik.com",
    "freecharge.in", "npci.org.in",
    # Aadhaar / Government Identity
    "uidai.gov.in", "resident.uidai.gov.in",
    "digilocker.gov.in", "maadhaar.uidai.gov.in",
]

# Legitimate domains (whitelist for HTML similarity baseline)
LEGITIMATE_UPI_DOMAINS = list(UPI_BRANDS.values())

# ─── Phishing Keywords ────────────────────────────────────────────────────────
PHISH_KEYWORDS = [
    # General phishing signals
    "verify", "secure", "update", "login", "signin", "account",
    "alert", "suspend", "block", "urgent", "confirm", "validate",
    # UPI-specific
    "wallet", "kyc", "otp", "pin", "reward", "cashback", "refund",
    "upi", "payment", "pay", "bhim", "phonepe", "gpay", "paytm",
    # Aadhaar-specific
    "aadhaar", "aadhar", "uidai", "biometric", "enrollment", "enrolment",
    "ekyc", "eaadhaar", "maadhaar", "digilocker", "linked", "link-aadhaar",
    "aadhaar-card", "download-aadhaar", "update-aadhaar", "aadhaar-update",
    "aadhaar-link", "aadhaar-mobile", "aadhaar-bank",
]

# Sensitive URL parameter names that only phishing pages expose in URLs
SENSITIVE_PARAMS = {
    # General
    "token", "otp", "pin", "password", "passwd",
    "secret", "cvv", "card", "account", "auth", "session",
    # UPI-specific
    "upi_id",
    # Aadhaar-specific
    "aadhaar", "uid", "aadhaar_no", "aadhar_no",
    "enrollment_id", "enrolment_id", "biometric", "otp_aadhaar",
}

# ─── Feature Extraction Settings ──────────────────────────────────────────────
REQUEST_TIMEOUT = 10
MAX_REDIRECTS   = 5
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# Suspicious free/bulletproof TLDs
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".top", ".click", ".link", ".online", ".site", ".icu",
    ".buzz", ".live", ".fun", ".win", ".bid", ".loan",
}

# Trusted SSL Certificate Authorities
TRUSTED_CA_ISSUERS = {
    "Let's Encrypt", "DigiCert", "Comodo", "GlobalSign",
    "GoDaddy", "Sectigo", "Amazon", "Google Trust Services",
}

# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "short.io", "rebrand.ly", "cutt.ly",
    "tiny.cc", "shorte.st", "adf.ly", "bc.vc", "s.id",
}

# ASNs known for bulletproof / abuse-tolerant hosting
SHADY_ASNS = {
    "AS197695", "AS9009",  "AS60781", "AS49870",
    "AS202425", "AS16276", "AS51167", "AS59253",
}

# DNS TTL below this threshold (seconds) is suspicious (fast-flux)
SUSPICIOUS_DNS_TTL = 300

# IPFS gateways — decentralised hosting used by phishers to evade takedowns
IPFS_GATEWAYS = [
    "ipfs.io", "gateway.pinata.cloud", "cloudflare-ipfs.com",
    "dweb.link", "ipfs.fleek.co", "ipfs.infura.io",
    "gateway.ipfs.io", "hardbin.com", "cf-ipfs.com",
]

# Tranco popularity rank API (no key needed)
TRANCO_API_URL = "https://tranco-list.eu/api/ranks/domain/{domain}"

# ─── SMS Phishing Keywords ────────────────────────────────────────────────────
# English keywords found in Indian UPI/Aadhaar phishing SMSes
SMS_PHISH_KEYWORDS = [
    "click here", "verify now", "update aadhaar", "link aadhaar",
    "otp expired", "account blocked", "kyc pending", "kyc update",
    "upi blocked", "reactivate", "re-activate", "cashback credited",
    "prize won", "lucky winner", "claim reward", "refund initiated",
    "download aadhaar", "biometric update", "aadhaar link mobile",
    "share otp", "enter otp", "do not share", "never share",
]

# Urgency manipulation phrases used in phishing SMSes
SMS_URGENCY_PHRASES = [
    "immediately", "urgent", "last chance", "expire", "suspended",
    "blocked", "within 24 hours", "action required", "verify now",
    "do not ignore", "final warning", "account will be closed",
    "service discontinued", "last opportunity", "act now",
]

# Fake sender IDs phishers use to impersonate official services
SMS_FAKE_SENDER_IDS = [
    "UIDAI-", "NPCI-", "PAYTM-", "PHONEPE-", "GPAY-",
    "BHIM-", "BANKOF", "SBIBANK", "HDFCBK", "ICICI-",
    "GOVIND", "INCGOV", "GOVINDIA",
]

# ─── Regional Language SMS Phishing Keywords ──────────────────────────────────
# Hindi (Devanagari script)
SMS_PHISH_KEYWORDS_HINDI = [
    "खाता",      # account
    "बंद",       # blocked/closed
    "तुरंत",     # immediately
    "सत्यापन",   # verification
    "ओटीपी",     # OTP
    "आधार",      # Aadhaar
    "अपडेट",     # update
    "पुरस्कार",  # reward/prize
    "कैशबैक",    # cashback
    "लिंक करें", # link (verb)
    "बैंक खाता", # bank account
    "जल्दी करें", # hurry up
]

# Tamil
SMS_PHISH_KEYWORDS_TAMIL = [
    "கணக்கு",          # account
    "தடுக்கப்பட்டது",  # blocked
    "சரிபார்க்க",      # verify
    "ஆதார்",           # Aadhaar
    "புதுப்பிக்க",     # update
    "பரிசு",           # prize
    "இப்போதே",         # immediately
    "OTP உள்ளிடவும்",  # enter OTP
]

# Telugu
SMS_PHISH_KEYWORDS_TELUGU = [
    "ఖాతా",       # account
    "బ్లాక్",     # blocked
    "వెంటనే",     # immediately
    "ధృవీకరించు", # verify
    "ఆధార్",      # Aadhaar
    "నవీకరించు",  # update
    "బహుమతి",    # reward
]

# Bengali
SMS_PHISH_KEYWORDS_BENGALI = [
    "অ্যাকাউন্ট",  # account
    "ব্লক",         # blocked
    "যাচাই",        # verify
    "আধার",         # Aadhaar
    "আপডেট",        # update
    "পুরস্কার",     # reward
    "এখনই",         # immediately
    "OTP দিন",      # give OTP
]

# ─── Model Training ───────────────────────────────────────────────────────────
MODEL_DIR    = "models/"
DATA_DIR     = "data/"
RESULTS_DIR  = "results/"
RANDOM_STATE = 42
TEST_SIZE    = 0.2
CV_FOLDS     = 5

FEATURE_COLUMNS = [
    # A. URL Structure (13)
    "url_length", "dot_count", "digit_ratio", "special_char_count",
    "subdomain_depth", "has_ip_address", "has_at_symbol", "url_entropy",
    "path_depth", "has_double_slash_in_path", "has_non_standard_port",
    "sensitive_query_params", "phish_keyword_count",
    # B. Domain (7)
    "domain_age_days", "suspicious_tld", "brand_in_subdomain",
    "brand_in_path", "brand_in_hostname", "min_brand_edit_distance", "has_homograph_chars",
    "is_punycode_domain",
    # C. SSL/TLS (4)
    "has_https", "cert_age_days", "is_self_signed", "trusted_ca",
    # D. HTML Content (7)
    "form_count", "password_field_count", "hidden_field_count",
    "external_resource_ratio", "html_similarity_score",
    "https_form_mismatch", "favicon_external",
    # E. Network (4)
    "redirect_count", "hosting_country_suspicious",
    "asn_is_suspicious", "has_mx_record",
    # F. OSINT / Intel (3)
    "is_url_shortener", "dns_ttl", "google_safe_browsing",
]

TARGET_COLUMN = "is_phishing"

# ─── Prediction Thresholds ────────────────────────────────────────────────────
PHISH_PROBABILITY_THRESHOLD = 0.6

# Edit distance ≤ this → typosquatting alert
TYPOSQUAT_DISTANCE_THRESHOLD = 3

# ─── Dashboard ────────────────────────────────────────────────────────────────
DASHBOARD_TITLE = "UPI & Aadhaar Phishing Detector"
DASHBOARD_PORT  = 8501


# ═════════════════════════════════════════════════════════════════════════════
# Official-domain allowlist, SMS/WhatsApp patterns, UPI deep-link rules,
# reporting channels.  SINGLE SOURCE OF TRUTH — the browser copy
# (static/upi-config.js) is GENERATED from this file: run `make sync-js`.
# ═════════════════════════════════════════════════════════════════════════════

# Domains we treat as genuine when served over HTTPS (exact match or subdomain).
# Deliberately narrow: no google.com / amazon.com / *.gov.in (user content and
# compromised sites live there).
OFFICIAL_DOMAINS = [
    "phonepe.com", "paytm.com", "pay.google.com", "bhimupi.org.in",
    "pay.amazon.in", "mobikwik.com", "freecharge.in", "npci.org.in",
    "uidai.gov.in", "digilocker.gov.in",
    "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com",
]

# ── SMS patterns (shared by sms_features.py and the WhatsApp analyser) ───────
SMS_URL_PATTERN = r'https?://\S+|www\.\S+|bit\.ly/\S+|tinyurl\.com/\S+'

SMS_OTP_REQUEST_PATTERNS = [
    r'share\s+(?:your\s+)?otp',
    r'send\s+(?:the\s+)?otp',
    r'give\s+(?:your\s+)?otp',
    r'provide\s+(?:the\s+)?otp',
    r'enter\s+otp\s+on',
    r'otp\s+(?:ko\s+)?(?:share|send|de\s+do|batao)',
]

SMS_ACCOUNT_THREAT_PATTERNS = [
    r'account\s+(?:will\s+be\s+)?(?:blocked|suspended|deactivated|closed)',
    r'(?:upi|aadhaar|card)\s+(?:will\s+be\s+)?(?:blocked|suspended|deactivated)',
    r'(?:block|suspend|deactivate)\s+(?:your\s+)?(?:account|aadhaar|upi)',
    r'service\s+(?:will\s+be\s+)?(?:suspended|stopped|blocked)',
    r'(?:खाता|सेवा)\s+(?:बंद|ब्लॉक)',
]

# ── WhatsApp scam patterns (matched case-insensitively) ──────────────────────
WA_URL_PATTERN = (
    r'''https?://[^\s<>"']+|www\.[^\s<>"']+|'''
    r'''\b(?:bit\.ly|tinyurl\.com|t\.co|wa\.me|chat\.whatsapp\.com|t\.me)/[^\s<>"']+'''
)
UPI_LINK_PATTERN = r'''upi://[^\s"'<>]+'''

WA_PATTERNS = {
    "lottery_prize": [
        r"you\s+(?:have|'ve)\s+won", r"lucky\s+draw", r"\blottery\b", r"\bkbc\b",
        r"prize\s+money", r"congratulations[^.!\n]{0,40}\b(?:won|winner|selected)\b",
    ],
    "forward_chain": [
        r"forward\s+(?:this|it)\s+to", r"share\s+(?:this\s+)?(?:message\s+)?with\s+\d+",
        r"send\s+(?:this\s+)?to\s+(?:all|\d+)", r"forwarded\s+many\s+times",
        r"share\s+with\s+all\s+(?:your\s+)?(?:contacts|friends|groups)",
    ],
    "fake_job": [
        r"work\s+from\s+home", r"part[\s-]?time\s+job",
        r"(?:earn|income)[^.\n]{0,25}(?:₹|rs\.?|inr)\s?\d[\d,]*[^.\n]{0,20}(?:daily|per\s+day|a\s+day|/day)",
        r"(?:daily|per\s+day)[^.\n]{0,20}(?:₹|rs\.?|inr)\s?\d[\d,]*",
        r"like\s+(?:and|&)\s+subscribe[^.\n]{0,40}(?:earn|pay)",
    ],
    "apk_download": [
        r"\.apk\b",
        r"download[^.\n]{0,30}\bapp\b[^.\n]{0,60}(?:challan|kyc|bill|kisan|ration|update|reward)",
    ],
    "govt_lure": [
        r"pm[\s-]?kisan", r"ration\s+card", r"gas\s+subsidy",
        r"free\s+(?:laptop|recharge|ration|gas|scooty|mobile)",
        r"government\s+scheme[^.\n]{0,30}(?:free|benefit|apply)",
    ],
    "utility_threat": [
        r"electricity\s+bill[^.\n]{0,60}(?:disconnect|cut|tonight|today)",
        r"power\s+(?:supply\s+)?will\s+be\s+(?:cut|disconnected)",
        r"(?:sim|number)\s+will\s+be\s+(?:blocked|deactivated|disconnected)",
        r"e-?challan", r"traffic\s+challan", r"rto\s+challan",
        r"parcel[^.\n]{0,40}(?:held|customs|pending)",
    ],
    "group_invite": [r"chat\.whatsapp\.com/", r"\bt\.me/", r"telegram\.me/"],
    "otp_request": list(SMS_OTP_REQUEST_PATTERNS),
    "account_threat": list(SMS_ACCOUNT_THREAT_PATTERNS),
}
WA_PATTERN_WEIGHTS = {
    "lottery_prize": 0.30, "forward_chain": 0.15, "fake_job": 0.30,
    "apk_download": 0.35, "govt_lure": 0.20, "utility_threat": 0.25,
    "group_invite": 0.10, "otp_request": 0.40, "account_threat": 0.30,
}
WA_PHISHING_THRESHOLD = 0.35

# ── UPI deep-link (upi://pay?pa=…) rules ─────────────────────────────────────
# Handle list is NOT exhaustive — an unknown handle is only a soft signal.
UPI_KNOWN_HANDLES = [
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl", "paytm",
    "apl", "upi", "sbi", "hdfcbank", "icici", "axisbank", "pnb", "boi", "cnrb",
    "kotak", "yesbank", "idfcbank", "indus", "fbl", "aubank", "rbl", "freecharge",
    "airtel", "jio", "postbank", "ikwik", "pthdfc", "ptyes", "ptsbi", "ptaxis",
    "barodampay", "unionbank", "uboi", "federal", "dbs", "hsbc", "okbizaxis",
]
UPI_VPA_BAIT_WORDS = [
    "refund", "support", "helpdesk", "care", "cashback", "reward", "lottery",
    "prize", "kyc", "uidai", "aadhaar", "aadhar", "npci", "rbi", "govt", "tax",
]
UPI_NOTE_BAIT_WORDS = [
    "refund", "cashback", "reward", "lottery", "prize", "kyc", "claim",
    "winner", "verification",
]
UPI_PAYEE_TERMS = [
    "phonepe", "paytm", "gpay", "google pay", "npci", "uidai", "aadhaar",
    "aadhar", "rbi", "customer care", "helpline", "refund", "cashback", "income tax",
]

# ── Where to report (verified against sancharsaathi.gov.in / cybercrime.gov.in) ──
REPORTING_CHANNELS = [
    {"name": "National Cyber Crime Helpline", "contact": "1930", "url": "",
     "when": "You already lost money (UPI / card / net banking). Call immediately — speed improves the chance of freezing the transfer."},
    {"name": "National Cyber Crime Reporting Portal", "contact": "cybercrime.gov.in",
     "url": "https://cybercrime.gov.in",
     "when": "File a formal complaint for any online fraud."},
    {"name": "Sanchar Saathi · Chakshu", "contact": "sancharsaathi.gov.in",
     "url": "https://sancharsaathi.gov.in/sfc/",
     "when": "Suspicious call / SMS / WhatsApp message and no money lost yet — report it so the number can be acted on."},
    {"name": "Your bank / UPI app", "contact": "In-app Report option or the number on your card", "url": "",
     "when": "Block cards or UPI access and raise a dispute right away."},
]


# ─── Feature sets ─────────────────────────────────────────────────────────────
# "lexical" = computable from the URL string ALONE (no network, no page fetch).
# Why it matters: SSL/HTML/DNS/hosting features only work when a site is ALIVE, and
# phishing URLs taken from feeds are often already dead — so "unreachable" leaks the
# label and inflates accuracy. The lexical set is the fair baseline and is instant.
LEXICAL_FEATURES = [
    "url_length", "dot_count", "digit_ratio", "special_char_count", "subdomain_depth",
    "has_ip_address", "has_at_symbol", "url_entropy", "path_depth",
    "has_double_slash_in_path", "has_non_standard_port", "sensitive_query_params",
    "phish_keyword_count", "suspicious_tld", "brand_in_subdomain", "brand_in_path",
    "brand_in_hostname", "min_brand_edit_distance", "has_homograph_chars",
    "is_punycode_domain", "has_https", "is_url_shortener",
]

# Public Tranco top list (rank,domain), used for legitimate-URL negatives.
TRANCO_TOP_LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"
