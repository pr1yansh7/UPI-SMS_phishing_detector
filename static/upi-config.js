/* ════════════════════════════════════════════════════════════════════════
   upi-config.js — AUTO-GENERATED from config.py by tools/sync_js_config.py
   DO NOT EDIT BY HAND. To change a brand / keyword / pattern list:
     1. edit config.py
     2. run:  make sync-js      (or: python tools/sync_js_config.py)
   ════════════════════════════════════════════════════════════════════════ */

const API_BASE = 'http://localhost:5050';
const PHISH_THRESHOLD = 0.6;
const WA_PHISHING_THRESHOLD = 0.35;

const UPI_BRANDS = [
  "phonepe",
  "gpay",
  "paytm",
  "bhim",
  "amazonpay",
  "mobikwik",
  "freecharge",
  "npci",
  "upi",
  "uidai",
  "aadhar",
  "aadhaar",
  "maadhaar",
  "digilocker",
  "eaadhaar",
  "resident"
];

const REAL_UPI_DOMAINS = [
  "phonepe.com",
  "pay.google.com",
  "paytm.com",
  "bhimupi.org.in",
  "pay.amazon.in",
  "mobikwik.com",
  "freecharge.in",
  "npci.org.in",
  "uidai.gov.in",
  "resident.uidai.gov.in",
  "digilocker.gov.in",
  "maadhaar.uidai.gov.in"
];

const SUSPICIOUS_TLDS = [
  ".bid",
  ".buzz",
  ".cf",
  ".click",
  ".fun",
  ".ga",
  ".gq",
  ".icu",
  ".link",
  ".live",
  ".loan",
  ".ml",
  ".online",
  ".pw",
  ".site",
  ".tk",
  ".top",
  ".win",
  ".xyz"
];

const PHISH_KEYWORDS = [
  "verify",
  "secure",
  "update",
  "login",
  "signin",
  "account",
  "alert",
  "suspend",
  "block",
  "urgent",
  "confirm",
  "validate",
  "wallet",
  "kyc",
  "otp",
  "pin",
  "reward",
  "cashback",
  "refund",
  "upi",
  "payment",
  "pay",
  "bhim",
  "phonepe",
  "gpay",
  "paytm",
  "aadhaar",
  "aadhar",
  "uidai",
  "biometric",
  "enrollment",
  "enrolment",
  "ekyc",
  "eaadhaar",
  "maadhaar",
  "digilocker",
  "linked",
  "link-aadhaar",
  "aadhaar-card",
  "download-aadhaar",
  "update-aadhaar",
  "aadhaar-update",
  "aadhaar-link",
  "aadhaar-mobile",
  "aadhaar-bank"
];

const URL_SHORTENERS = [
  "adf.ly",
  "bc.vc",
  "bit.ly",
  "buff.ly",
  "cutt.ly",
  "goo.gl",
  "is.gd",
  "ow.ly",
  "rebrand.ly",
  "s.id",
  "short.io",
  "shorte.st",
  "t.co",
  "tiny.cc",
  "tinyurl.com"
];

const OFFICIAL_DOMAINS = [
  "phonepe.com",
  "paytm.com",
  "pay.google.com",
  "bhimupi.org.in",
  "pay.amazon.in",
  "mobikwik.com",
  "freecharge.in",
  "npci.org.in",
  "uidai.gov.in",
  "digilocker.gov.in",
  "onlinesbi.sbi",
  "sbi.co.in",
  "hdfcbank.com",
  "icicibank.com"
];

const SMS_URL_PATTERN = "https?://\\S+|www\\.\\S+|bit\\.ly/\\S+|tinyurl\\.com/\\S+";

const SMS_OTP_REQUEST_PATTERNS = [
  "share\\s+(?:your\\s+)?otp",
  "send\\s+(?:the\\s+)?otp",
  "give\\s+(?:your\\s+)?otp",
  "provide\\s+(?:the\\s+)?otp",
  "enter\\s+otp\\s+on",
  "otp\\s+(?:ko\\s+)?(?:share|send|de\\s+do|batao)"
];

const SMS_ACCOUNT_THREAT_PATTERNS = [
  "account\\s+(?:will\\s+be\\s+)?(?:blocked|suspended|deactivated|closed)",
  "(?:upi|aadhaar|card)\\s+(?:will\\s+be\\s+)?(?:blocked|suspended|deactivated)",
  "(?:block|suspend|deactivate)\\s+(?:your\\s+)?(?:account|aadhaar|upi)",
  "service\\s+(?:will\\s+be\\s+)?(?:suspended|stopped|blocked)",
  "(?:खाता|सेवा)\\s+(?:बंद|ब्लॉक)"
];

const SMS_PHISH_KEYWORDS = [
  "click here",
  "verify now",
  "update aadhaar",
  "link aadhaar",
  "otp expired",
  "account blocked",
  "kyc pending",
  "kyc update",
  "upi blocked",
  "reactivate",
  "re-activate",
  "cashback credited",
  "prize won",
  "lucky winner",
  "claim reward",
  "refund initiated",
  "download aadhaar",
  "biometric update",
  "aadhaar link mobile",
  "share otp",
  "enter otp",
  "do not share",
  "never share"
];

const SMS_URGENCY_PHRASES = [
  "immediately",
  "urgent",
  "last chance",
  "expire",
  "suspended",
  "blocked",
  "within 24 hours",
  "action required",
  "verify now",
  "do not ignore",
  "final warning",
  "account will be closed",
  "service discontinued",
  "last opportunity",
  "act now"
];

const SMS_FAKE_SENDER_IDS = [
  "UIDAI-",
  "NPCI-",
  "PAYTM-",
  "PHONEPE-",
  "GPAY-",
  "BHIM-",
  "BANKOF",
  "SBIBANK",
  "HDFCBK",
  "ICICI-",
  "GOVIND",
  "INCGOV",
  "GOVINDIA"
];

const SMS_PHISH_KEYWORDS_HINDI = [
  "खाता",
  "बंद",
  "तुरंत",
  "सत्यापन",
  "ओटीपी",
  "आधार",
  "अपडेट",
  "पुरस्कार",
  "कैशबैक",
  "लिंक करें",
  "बैंक खाता",
  "जल्दी करें"
];

const SMS_PHISH_KEYWORDS_TAMIL = [
  "கணக்கு",
  "தடுக்கப்பட்டது",
  "சரிபார்க்க",
  "ஆதார்",
  "புதுப்பிக்க",
  "பரிசு",
  "இப்போதே",
  "OTP உள்ளிடவும்"
];

const SMS_PHISH_KEYWORDS_TELUGU = [
  "ఖాతా",
  "బ్లాక్",
  "వెంటనే",
  "ధృవీకరించు",
  "ఆధార్",
  "నవీకరించు",
  "బహుమతి"
];

const SMS_PHISH_KEYWORDS_BENGALI = [
  "অ্যাকাউন্ট",
  "ব্লক",
  "যাচাই",
  "আধার",
  "আপডেট",
  "পুরস্কার",
  "এখনই",
  "OTP দিন"
];

const WA_URL_PATTERN = "https?://[^\\s<>\"']+|www\\.[^\\s<>\"']+|\\b(?:bit\\.ly|tinyurl\\.com|t\\.co|wa\\.me|chat\\.whatsapp\\.com|t\\.me)/[^\\s<>\"']+";

const UPI_LINK_PATTERN = "upi://[^\\s\"'<>]+";

const WA_PATTERNS = {
  "lottery_prize": [
    "you\\s+(?:have|'ve)\\s+won",
    "lucky\\s+draw",
    "\\blottery\\b",
    "\\bkbc\\b",
    "prize\\s+money",
    "congratulations[^.!\\n]{0,40}\\b(?:won|winner|selected)\\b"
  ],
  "forward_chain": [
    "forward\\s+(?:this|it)\\s+to",
    "share\\s+(?:this\\s+)?(?:message\\s+)?with\\s+\\d+",
    "send\\s+(?:this\\s+)?to\\s+(?:all|\\d+)",
    "forwarded\\s+many\\s+times",
    "share\\s+with\\s+all\\s+(?:your\\s+)?(?:contacts|friends|groups)"
  ],
  "fake_job": [
    "work\\s+from\\s+home",
    "part[\\s-]?time\\s+job",
    "(?:earn|income)[^.\\n]{0,25}(?:₹|rs\\.?|inr)\\s?\\d[\\d,]*[^.\\n]{0,20}(?:daily|per\\s+day|a\\s+day|/day)",
    "(?:daily|per\\s+day)[^.\\n]{0,20}(?:₹|rs\\.?|inr)\\s?\\d[\\d,]*",
    "like\\s+(?:and|&)\\s+subscribe[^.\\n]{0,40}(?:earn|pay)"
  ],
  "apk_download": [
    "\\.apk\\b",
    "download[^.\\n]{0,30}\\bapp\\b[^.\\n]{0,60}(?:challan|kyc|bill|kisan|ration|update|reward)"
  ],
  "govt_lure": [
    "pm[\\s-]?kisan",
    "ration\\s+card",
    "gas\\s+subsidy",
    "free\\s+(?:laptop|recharge|ration|gas|scooty|mobile)",
    "government\\s+scheme[^.\\n]{0,30}(?:free|benefit|apply)"
  ],
  "utility_threat": [
    "electricity\\s+bill[^.\\n]{0,60}(?:disconnect|cut|tonight|today)",
    "power\\s+(?:supply\\s+)?will\\s+be\\s+(?:cut|disconnected)",
    "(?:sim|number)\\s+will\\s+be\\s+(?:blocked|deactivated|disconnected)",
    "e-?challan",
    "traffic\\s+challan",
    "rto\\s+challan",
    "parcel[^.\\n]{0,40}(?:held|customs|pending)"
  ],
  "group_invite": [
    "chat\\.whatsapp\\.com/",
    "\\bt\\.me/",
    "telegram\\.me/"
  ],
  "otp_request": [
    "share\\s+(?:your\\s+)?otp",
    "send\\s+(?:the\\s+)?otp",
    "give\\s+(?:your\\s+)?otp",
    "provide\\s+(?:the\\s+)?otp",
    "enter\\s+otp\\s+on",
    "otp\\s+(?:ko\\s+)?(?:share|send|de\\s+do|batao)"
  ],
  "account_threat": [
    "account\\s+(?:will\\s+be\\s+)?(?:blocked|suspended|deactivated|closed)",
    "(?:upi|aadhaar|card)\\s+(?:will\\s+be\\s+)?(?:blocked|suspended|deactivated)",
    "(?:block|suspend|deactivate)\\s+(?:your\\s+)?(?:account|aadhaar|upi)",
    "service\\s+(?:will\\s+be\\s+)?(?:suspended|stopped|blocked)",
    "(?:खाता|सेवा)\\s+(?:बंद|ब्लॉक)"
  ]
};

const WA_PATTERN_WEIGHTS = {
  "lottery_prize": 0.3,
  "forward_chain": 0.15,
  "fake_job": 0.3,
  "apk_download": 0.35,
  "govt_lure": 0.2,
  "utility_threat": 0.25,
  "group_invite": 0.1,
  "otp_request": 0.4,
  "account_threat": 0.3
};

const UPI_KNOWN_HANDLES = [
  "okaxis",
  "okhdfcbank",
  "okicici",
  "oksbi",
  "ybl",
  "ibl",
  "axl",
  "paytm",
  "apl",
  "upi",
  "sbi",
  "hdfcbank",
  "icici",
  "axisbank",
  "pnb",
  "boi",
  "cnrb",
  "kotak",
  "yesbank",
  "idfcbank",
  "indus",
  "fbl",
  "aubank",
  "rbl",
  "freecharge",
  "airtel",
  "jio",
  "postbank",
  "ikwik",
  "pthdfc",
  "ptyes",
  "ptsbi",
  "ptaxis",
  "barodampay",
  "unionbank",
  "uboi",
  "federal",
  "dbs",
  "hsbc",
  "okbizaxis"
];

const UPI_VPA_BAIT_WORDS = [
  "refund",
  "support",
  "helpdesk",
  "care",
  "cashback",
  "reward",
  "lottery",
  "prize",
  "kyc",
  "uidai",
  "aadhaar",
  "aadhar",
  "npci",
  "rbi",
  "govt",
  "tax"
];

const UPI_NOTE_BAIT_WORDS = [
  "refund",
  "cashback",
  "reward",
  "lottery",
  "prize",
  "kyc",
  "claim",
  "winner",
  "verification"
];

const UPI_PAYEE_TERMS = [
  "phonepe",
  "paytm",
  "gpay",
  "google pay",
  "npci",
  "uidai",
  "aadhaar",
  "aadhar",
  "rbi",
  "customer care",
  "helpline",
  "refund",
  "cashback",
  "income tax"
];

const REPORTING_CHANNELS = [
  {
    "name": "National Cyber Crime Helpline",
    "contact": "1930",
    "url": "",
    "when": "You already lost money (UPI / card / net banking). Call immediately — speed improves the chance of freezing the transfer."
  },
  {
    "name": "National Cyber Crime Reporting Portal",
    "contact": "cybercrime.gov.in",
    "url": "https://cybercrime.gov.in",
    "when": "File a formal complaint for any online fraud."
  },
  {
    "name": "Sanchar Saathi · Chakshu",
    "contact": "sancharsaathi.gov.in",
    "url": "https://sancharsaathi.gov.in/sfc/",
    "when": "Suspicious call / SMS / WhatsApp message and no money lost yet — report it so the number can be acted on."
  },
  {
    "name": "Your bank / UPI app",
    "contact": "In-app Report option or the number on your card",
    "url": "",
    "when": "Block cards or UPI access and raise a dispute right away."
  }
];

const SENSITIVE_PARAMS = new Set([
  "aadhaar",
  "aadhaar_no",
  "aadhar_no",
  "account",
  "auth",
  "biometric",
  "card",
  "cvv",
  "enrollment_id",
  "enrolment_id",
  "otp",
  "otp_aadhaar",
  "passwd",
  "password",
  "pin",
  "secret",
  "session",
  "token",
  "uid",
  "upi_id"
]);
