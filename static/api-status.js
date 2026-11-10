/* api-status.js — green/grey status bar: is the Flask backend (api.py) running?
   Edit THIS file for the status bar text/behaviour only. */
async function checkAPI() {
  const dot = document.getElementById('apiDot'), label = document.getElementById('apiLabel');
  const mode = document.getElementById('apiMode'), badge = document.getElementById('modelBadge');
  try {
    const resp = await fetch(API_BASE + '/health', { signal: AbortSignal.timeout(2000) });
    if (!resp.ok) throw new Error();
    const data = await resp.json();
    dot.className = 'api-dot online';
    label.textContent = '✓ Backend connected — ' + (data.model || 'model loaded') +
      (data.feature_set ? ' (' + data.feature_set + ' features: ' + data.n_features + ')' : '');
    label.style.color = 'var(--safe)';
    mode.textContent = 'URLs: trained ML model';
    badge.textContent = 'ML model · UPI + Aadhaar';
  } catch (e) {
    dot.className = 'api-dot offline';
    label.textContent = 'Backend offline — URL check uses browser heuristics';
    label.style.color = 'var(--muted)';
    mode.textContent = 'Mode: browser rules';
    badge.textContent = 'Heuristic · UPI + Aadhaar';
  }
}
checkAPI();
setInterval(checkAPI, 10000);
