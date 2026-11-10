/* ════════════════════════════════════════════════════════════════════════
   messages.js — browser rules for SMS / WhatsApp / UPI deep links (NO DOM).

   Exact port of features/sms_features.py, features/deeplink_features.py and
   features/whatsapp_features.py. tests/test_js_parity.py runs the same fixtures
   through Python and this file and fails if the verdicts or reasons differ.

   Edit THIS file for: how these checks are computed (weights, reason texts).
   Do NOT edit for: word lists / patterns → config.py, then `make sync-js`.
   Depends on: upi-config.js, scoring.js (isOfficialDomain).
   ════════════════════════════════════════════════════════════════════════ */

function _round4(x) { return Math.round(x * 10000) / 10000; }
function _tokens(text) { return text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean); }
function _containsTerm(text, term) {
  const lower = text.toLowerCase();
  if (term.indexOf(' ') !== -1) return lower.indexOf(term) !== -1;
  return _tokens(lower).some(t => t === term || (term.length >= 5 && t.startsWith(term)));
}
function _dedupe(arr) { return Array.from(new Set(arr)); }

const UPI_ADVICE = 'A UPI PIN is only needed to SEND money — you never enter it to receive money. ' +
  'If you did not expect to pay, do not proceed; verify the payee directly.';
const WA_ADVICE = 'Do not click links, install apps or share OTP/PIN. Real banks, UIDAI and UPI apps ' +
  'never ask for these on WhatsApp. ' + UPI_ADVICE;

/* ── SMS ─────────────────────────────────────────────────────────────── */
function scoreSMSHeuristic(text, sender) {
  text = text || ''; sender = sender || '';
  const lower = text.toLowerCase();
  const urgency = text ? _round4(SMS_URGENCY_PHRASES.filter(p => lower.includes(p)).length / SMS_URGENCY_PHRASES.length) : 0;
  const hasUrl = (text && new RegExp(SMS_URL_PATTERN, 'i').test(text)) ? 1 : 0;
  const up = sender.toUpperCase();
  const spoofed = (sender && SMS_FAKE_SENDER_IDS.map(s => s.replace(/-+$/, '')).some(k => up.includes(k))) ? 1 : 0;
  const kw = text ? SMS_PHISH_KEYWORDS.filter(k => lower.includes(k)).length : 0;
  const brand = (text && UPI_BRANDS.some(b => lower.includes(b))) ? 1 : 0;
  const asksOtp = (text && SMS_OTP_REQUEST_PATTERNS.some(p => new RegExp(p).test(lower))) ? 1 : 0;
  const threat = (text && SMS_ACCOUNT_THREAT_PATTERNS.some(p => new RegExp(p).test(lower))) ? 1 : 0;
  const regional = SMS_PHISH_KEYWORDS_HINDI.concat(SMS_PHISH_KEYWORDS_TAMIL, SMS_PHISH_KEYWORDS_TELUGU, SMS_PHISH_KEYWORDS_BENGALI);
  const hing = (text && regional.length) ? _round4(regional.filter(k => text.includes(k)).length / regional.length) : 0;

  const score = urgency * 0.12 + hasUrl * 0.18 + spoofed * 0.12 + Math.min(kw / 5, 1) * 0.08 +
                brand * 0.08 + asksOtp * 0.28 + threat * 0.12 + hing * 0.08;
  const risk = _round4(Math.min(score, 1));
  const isPhish = risk >= 0.25;

  const flags = [];
  if (asksOtp) flags.push('Asks you to share/send an OTP — no real service ever does this');
  if (threat) flags.push('Threatens to block/suspend your account, UPI or Aadhaar');
  if (hasUrl) flags.push("Contains a link — real OTP/bank SMSes don't");
  if (spoofed) flags.push('Sender ID imitates UIDAI/NPCI/a bank/a UPI app');
  if (urgency > 0.1) flags.push('Uses urgency/pressure wording');
  if (kw >= 2) flags.push('Contains several known phishing phrases');
  if (hing > 0.05) flags.push('Contains phishing wording in Hindi/Tamil/Telugu/Bengali');

  return {
    sms_urgency_score: urgency, has_url_in_sms: hasUrl, sender_id_spoofed: spoofed,
    sms_phish_keyword_count: kw, sms_impersonates_brand: brand, sms_asks_for_otp: asksOtp,
    sms_threatens_account: threat, sms_hinglish_phish_score: hing,
    sms_risk_score: risk, is_phishing_sms: isPhish,
    flags: flags, risk_score: risk, is_phishing: isPhish, source: 'browser rules',
  };
}

/* ── UPI deep links ──────────────────────────────────────────────────── */
function extractUpiLinks(text) {
  const m = (text || '').match(new RegExp(UPI_LINK_PATTERN, 'gi')) || [];
  return m.map(s => s.replace(/[.,;)]+$/, ''));
}

function parseUpiLink(uri) {
  uri = (uri || '').trim();
  if (!uri.toLowerCase().startsWith('upi://')) return null;
  const rest = uri.slice(6).split('#')[0];
  const i = rest.indexOf('?');
  const action = (i === -1 ? rest : rest.slice(0, i)).replace(/^\/+|\/+$/g, '').toLowerCase();
  const query = i === -1 ? '' : rest.slice(i + 1);
  const params = Object.create(null);
  new URLSearchParams(query).forEach((v, k) => { k = k.toLowerCase(); if (!(k in params)) params[k] = v; });
  return { action: action, params: params };
}

function analyseUpiLinkHeuristic(uri) {
  const result = {
    uri: uri, valid_upi_link: 0, action: '', payee_vpa: '', payee_name: '', amount: null,
    currency: '', note: '', flags: [], risk_score: 0, risk_level: 'unknown',
    is_suspicious_link: false, is_phishing: false, advice: UPI_ADVICE, source: 'browser rules',
  };
  const parsed = parseUpiLink(uri);
  if (!parsed) { result.flags = ['Not a upi:// link']; return result; }

  const action = parsed.action, p = parsed.params;
  let score = 0; const flags = [];

  const pa = (p.pa || '').trim();
  if (!pa) { score += 0.30; flags.push('No payee UPI ID in the link'); }
  else if (!/^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$/.test(pa)) { score += 0.30; flags.push('Payee UPI ID is malformed'); }
  else {
    const at = pa.lastIndexOf('@'), local = pa.slice(0, at), handle = pa.slice(at + 1);
    if (UPI_KNOWN_HANDLES.indexOf(handle.toLowerCase()) === -1) {
      score += 0.10; flags.push("Unrecognised UPI handle '@" + handle + "' (list is not exhaustive)");
    }
    if (UPI_VPA_BAIT_WORDS.some(w => _containsTerm(local, w))) {
      score += 0.35; flags.push('Payee UPI ID contains scam-bait words (refund / support / kyc …)');
    }
  }
  const pn = p.pn || '';
  if (pn && UPI_PAYEE_TERMS.some(t => _containsTerm(pn, t))) { score += 0.25; flags.push('Payee name imitates a brand or authority'); }
  const tn = p.tn || '';
  if (tn && UPI_NOTE_BAIT_WORDS.some(w => _containsTerm(tn, w))) { score += 0.25; flags.push('Payment note uses refund / prize / KYC bait'); }

  const am = (p.am || '').trim();
  if (am) {
    if (!/^\d+(?:\.\d{1,2})?$/.test(am)) { score += 0.15; flags.push('Amount is not a valid number'); }
    else if (Number(am) >= 10000) { score += 0.20; flags.push('High pre-filled amount'); }
    else if (Number(am) > 0) { score += 0.05; flags.push('Amount is pre-filled — check it is what you expect'); }
  }
  const cu = (p.cu || '').toUpperCase();
  if (cu && cu !== 'INR') { score += 0.15; flags.push('Currency is ' + cu + ', not INR'); }
  if (action === 'mandate') { score += 0.15; flags.push('Recurring auto-debit (mandate) link'); }
  else if (action !== 'pay') { score += 0.15; flags.push("Unusual UPI action '" + action + "'"); }
  if ('url' in p) { score += 0.05; flags.push('Link carries an extra URL parameter'); }

  score = _round4(Math.min(score, 1));
  Object.assign(result, {
    valid_upi_link: 1, action: action, payee_vpa: pa, payee_name: pn, amount: am || null,
    currency: cu, note: tn, flags: flags, risk_score: score,
    risk_level: score < 0.25 ? 'low' : (score < 0.5 ? 'medium' : 'high'),
    is_suspicious_link: score >= 0.40, is_phishing: score >= 0.40,
  });
  return result;
}

function scoreUpiFromText(text) {
  const links = extractUpiLinks(text);
  return analyseUpiLinkHeuristic(links.length ? links[0] : text);
}

/* ── WhatsApp ────────────────────────────────────────────────────────── */
const WA_REASONS = {
  lottery_prize: "Claims you won a prize/lottery — you can't win a contest you never entered",
  forward_chain: 'Asks you to forward it to contacts/groups (chain-message pattern)',
  fake_job: 'Work-from-home / easy daily-income offer (common task & investment scam)',
  apk_download: 'Asks you to install an app file (.apk) — a common way to steal UPI/SMS access',
  govt_lure: 'Uses a government-scheme or free-benefit lure (PM-Kisan, ration, free recharge…)',
  utility_threat: 'Threatens disconnection/blocking or a fine (electricity, SIM, challan, parcel)',
  group_invite: 'Pushes you into a WhatsApp/Telegram group',
  otp_request: 'Asks you to share/send an OTP — no real service ever does this',
  account_threat: 'Threatens to block/suspend your account, UPI or Aadhaar',
};

function extractUrls(text) {
  const raw = (text || '').match(new RegExp(WA_URL_PATTERN, 'gi')) || [];
  return raw.map(m => {
    let u = m.replace(/[.,;:!?)]+$/, '');
    if (!u.toLowerCase().startsWith('http')) u = 'https://' + u;
    return u;
  });
}

function _hostOf(url) { try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; } }

function linkRisk(url) {
  if (isOfficialDomain(url)) return [0, []];
  let risk = 0; const flags = [];
  const host = _hostOf(url);
  if (URL_SHORTENERS.some(s => host === s || host.endsWith('.' + s))) { risk += 0.40; flags.push('Link uses a URL shortener (hides the real destination)'); }
  if (SUSPICIOUS_TLDS.some(t => host.endsWith(t))) { risk += 0.40; flags.push('Link uses a domain extension common in scams (.xyz, .tk, .top …)'); }
  if (UPI_BRANDS.some(b => host.includes(b))) { risk += 0.30; flags.push('Link imitates a UPI/Aadhaar brand but is not the official site'); }
  let u = null; try { u = new URL(url); } catch (e) { u = null; }
  if (u && u.protocol === 'http:') { risk += 0.15; flags.push('Link is not HTTPS'); }
  if (u && u.pathname.toLowerCase().endsWith('.apk')) { risk += 0.35; flags.push('Link downloads an app file (.apk)'); }
  return [Math.min(risk, 1), flags];
}

function scoreWhatsAppHeuristic(text) {
  text = text || '';
  const sms = scoreSMSHeuristic(text, '');
  const hits = {}; let points = 0;
  Object.keys(WA_PATTERNS).forEach(n => {
    const h = WA_PATTERNS[n].some(p => new RegExp(p, 'i').test(text)) ? 1 : 0;
    hits[n] = h; if (h) points += WA_PATTERN_WEIGHTS[n];
  });
  const urls = extractUrls(text);
  const linkInfo = urls.map(linkRisk);
  const maxLink = linkInfo.reduce((m, x) => Math.max(m, x[0]), 0);
  const upiLinks = extractUpiLinks(text);
  const upiResults = upiLinks.map(analyseUpiLinkHeuristic);
  const maxUpi = upiResults.reduce((m, r) => Math.max(m, r.risk_score), 0);

  const score = _round4(Math.min(1, 0.5 * sms.sms_risk_score + points + 0.5 * maxLink + 0.5 * maxUpi));

  let flags = Object.keys(WA_PATTERNS).filter(n => hits[n]).map(n => WA_REASONS[n]);
  linkInfo.forEach(x => { flags = flags.concat(x[1]); });
  upiResults.forEach(r => { if (r.risk_score >= 0.25) flags = flags.concat(r.flags.map(f => 'UPI link: ' + f)); });
  if (sms.sms_urgency_score > 0.1) flags.push('Uses urgency/pressure wording');
  if (sms.sms_phish_keyword_count >= 2) flags.push('Contains several known phishing phrases');
  if (sms.sms_hinglish_phish_score > 0.05) flags.push('Contains phishing wording in Hindi/Tamil/Telugu/Bengali');

  const result = {};
  Object.keys(WA_PATTERNS).forEach(n => { result['wa_' + n] = hits[n]; });
  Object.assign(result, {
    sms_risk_score: sms.sms_risk_score, max_link_risk: _round4(maxLink), max_upi_risk: _round4(maxUpi),
    urls_found: urls, upi_links_found: upiLinks,
    whatsapp_risk_score: score, risk_score: score,
    is_phishing_whatsapp: score >= WA_PHISHING_THRESHOLD, is_phishing: score >= WA_PHISHING_THRESHOLD,
    flags: _dedupe(flags), advice: WA_ADVICE, source: 'browser rules',
  });
  return result;
}

/* ── One-click example messages for the UI ───────────────────────────── */
const MSG_EXAMPLES = {
  sms: [
    { label: 'Aadhaar block + link', bad: true, sender: 'VK-UIDAI', text: 'URGENT: Your Aadhaar will be suspended immediately. Verify now at http://uidai-kyc.xyz to avoid account blocked.' },
    { label: 'Asks to share OTP', bad: true, text: 'Your UPI OTP is 847291. Share OTP with our executive to complete KYC verification.' },
    { label: 'Normal OTP SMS', bad: false, text: 'Your PhonePe OTP is 482910. Valid for 10 minutes. Do NOT share with anyone.' },
  ],
  whatsapp: [
    { label: 'KBC lottery', bad: true, text: 'Congratulations! You have won Rs 25 lakh in KBC lucky draw. Forward this to 10 contacts and claim at http://kbc-prize.xyz' },
    { label: 'Fake RTO challan .apk', bad: true, text: 'RTO challan pending. Download app http://rto-echallan.top/challan.apk and pay fine today' },
    { label: 'Work-from-home task', bad: true, text: 'Work from home! Earn ₹5000 daily. Join telegram t.me/jobs123 now' },
    { label: 'Friend sharing location', bad: false, text: 'Hi! Dinner at 8? Location https://maps.google.com/?q=cafe' },
  ],
  upi: [
    { label: 'Fake refund link', bad: true, text: 'upi://pay?pa=phonepe.refund@ybl&pn=PhonePe%20Refund%20Dept&am=15000&tn=Refund%20claim' },
    { label: 'Normal shop payment', bad: false, text: 'upi://pay?pa=merchant@okaxis&pn=Sharma%20Store&am=250&cu=INR&tn=Groceries' },
  ],
};
