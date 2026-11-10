/* logic.js — pure decision logic for the extension (no chrome.* calls) so it can be unit-tested
   in Node: tests/js/test_extension_logic.js.  Edit THIS file to change WHEN a warning is shown. */
(function (root) {
  function hostOf(url) { try { return new URL(url).hostname.toLowerCase().replace(/\.$/, ''); } catch (e) { return ''; } }

  function isHttpUrl(url) { try { return /^https?:$/.test(new URL(url).protocol); } catch (e) { return false; } }

  // Only real web pages; never the local backend itself or private/dev hosts.
  function shouldCheck(url) {
    if (!isHttpUrl(url)) return false;
    const h = hostOf(url);
    return !(h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h.endsWith('.local'));
  }

  // Same rule as allowlist.py / scoring.js: HTTPS + exact official host or real subdomain.
  function isOfficial(url, domains) {
    let u; try { u = new URL(url); } catch (e) { return false; }
    if (u.protocol !== 'https:') return false;
    const h = hostOf(url);
    return domains.some(d => h === d || h.endsWith('.' + d));
  }

  // A deliberately high bar (default 0.90) — the backend flags at 0.60, but interrupting
  // browsing on a weak signal would make people disable the extension.
  function shouldBlock(result, threshold) {
    return !!(result && result.is_phishing && !result.official_domain && Number(result.probability) >= threshold);
  }

  function buildWarningUrl(base, url, result) {
    return base + '?u=' + encodeURIComponent(url) +
      '&p=' + Number(result.probability).toFixed(2) +
      '&f=' + encodeURIComponent((result.suspicious_flags || []).slice(0, 6).join(','));
  }

  function parseWarningParams(search) {
    const q = new URLSearchParams(search);
    return { url: q.get('u') || '', prob: parseFloat(q.get('p') || '0') || 0,
             flags: (q.get('f') || '').split(',').filter(Boolean) };
  }

  function cacheGet(cache, key, now, ttlMs) {
    const e = cache[key];
    return e && now - e.t < ttlMs ? e.result : null;
  }
  function cacheSet(cache, key, result, now) { cache[key] = { t: now, result: result }; }

  const api = { hostOf, isHttpUrl, shouldCheck, isOfficial, shouldBlock, buildWarningUrl, parseWarningParams, cacheGet, cacheSet };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.PhishLogic = api;
})(typeof self !== 'undefined' ? self : this);
