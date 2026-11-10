/* popup.js — "check this page" button. Needs the backend: python api.py */
(async () => {
  const $ = id => document.getElementById(id);
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab && tab.url;
  $('url').textContent = url || '';
  if (!url || !PhishLogic.shouldCheck(url)) { $('verdict').textContent = 'Nothing to check on this page.'; return; }
  try {
    const resp = await fetch(EXT_CONFIG.API_BASE + '/predict', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, fetch_html: false }), signal: AbortSignal.timeout(5000),
    });
    const r = await resp.json();
    const bad = r.is_phishing && !r.official_domain;
    $('verdict').textContent = (bad ? '🚨 Likely phishing' : (r.official_domain ? '✅ Official domain' : '✅ No strong signs')) +
      ' — ' + Math.round(r.probability * 100) + '%';
    $('verdict').className = 'verdict ' + (bad ? 'bad' : 'ok');
    (r.suspicious_flags || []).slice(0, 6).forEach(f => { const li = document.createElement('li'); li.textContent = f; $('flags').appendChild(li); });
    $('note').textContent = 'Automated guess — can be wrong. Model: ' + (r.source || 'ml_model');
  } catch (e) {
    $('verdict').textContent = 'Backend not running';
    $('note').textContent = 'Start it with: python api.py   (listens on ' + EXT_CONFIG.API_BASE + ')';
  }
})();
