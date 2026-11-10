// Unit tests for extension/logic.js — run by tests/test_extension.py (or: node tests/js/test_extension_logic.js)
const assert = require('assert'); const L = require('../../extension/logic.js');
const OFF = ['uidai.gov.in', 'phonepe.com', 'pay.google.com'];
let n = 0; const t = (name, fn) => { fn(); n++; };

t('shouldCheck: only real web pages', () => {
  assert(L.shouldCheck('https://example.com/a') && L.shouldCheck('http://evil.xyz/'));
  ['chrome://settings', 'about:blank', 'file:///etc/passwd', 'javascript:alert(1)', 'data:text/html,x', 'http://localhost:5050/health',
   'http://127.0.0.1/x', 'https://printer.local/', 'not a url', ''].forEach(u => assert(!L.shouldCheck(u), u));
});
t('isOfficial accepts real hosts, rejects lookalikes', () => {
  ['https://uidai.gov.in/', 'https://resident.uidai.gov.in/x', 'https://PHONEPE.com./'].forEach(u => assert(L.isOfficial(u, OFF), u));
  ['http://uidai.gov.in/', 'https://uidai.gov.in.evil.xyz/', 'https://evil-uidai.gov.in/', 'https://uidai.gov.in@evil.xyz/', 'https://google.com/', 'nope']
    .forEach(u => assert(!L.isOfficial(u, OFF), u));
});
t('shouldBlock needs phishing + high probability + not official', () => {
  assert(L.shouldBlock({ is_phishing: true, probability: 0.95 }, 0.9));
  assert(!L.shouldBlock({ is_phishing: true, probability: 0.85 }, 0.9));
  assert(!L.shouldBlock({ is_phishing: false, probability: 0.99 }, 0.9));
  assert(!L.shouldBlock({ is_phishing: true, probability: 0.99, official_domain: true }, 0.9));
  assert(!L.shouldBlock(null, 0.9) && !L.shouldBlock(undefined, 0.9) && !L.shouldBlock({}, 0.9));
});
t('warning URL round-trips awkward characters', () => {
  const url = 'http://evil.xyz/a?b=1&c=<script>"x"#frag';
  const w = L.buildWarningUrl('chrome-extension://abc/warning.html', url, { probability: 0.9712, suspicious_flags: ['a,b', 'suspicious_tld'] });
  const p = L.parseWarningParams(w.slice(w.indexOf('?')));
  assert.strictEqual(p.url, url); assert.strictEqual(p.prob, 0.97);
  assert(p.flags.includes('suspicious_tld'));
});
t('parseWarningParams tolerates missing/garbage params', () => {
  assert.deepStrictEqual(L.parseWarningParams(''), { url: '', prob: 0, flags: [] });
  assert.strictEqual(L.parseWarningParams('?p=abc').prob, 0);
});
t('isHttpUrl refuses non-web schemes (used before "proceed anyway")', () => {
  assert(L.isHttpUrl('https://a.b/') && L.isHttpUrl('http://a.b/'));
  ['javascript:alert(1)', 'data:text/html,x', 'file:///x', 'chrome://x', ''].forEach(u => assert(!L.isHttpUrl(u), u));
});
t('cache honours the TTL', () => {
  const c = {}; L.cacheSet(c, 'u', { a: 1 }, 1000);
  assert.deepStrictEqual(L.cacheGet(c, 'u', 1500, 1000), { a: 1 });
  assert.strictEqual(L.cacheGet(c, 'u', 2500, 1000), null); assert.strictEqual(L.cacheGet(c, 'other', 1500, 1000), null);
});
console.log(n + ' extension logic tests passed');
