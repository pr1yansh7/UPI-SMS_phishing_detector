/* background.js — MV3 service worker.
   On every top-level navigation: ask the local backend, and if the verdict is a confident
   "phishing", replace the tab with warning.html.
   NOT a hard block: the page may start loading for a moment before the warning replaces it. */
importScripts('config.js', 'logic.js');

const CACHE = {};
const CACHE_TTL_MS = 10 * 60 * 1000;
const BYPASS_MS = 60 * 60 * 1000;

async function isBypassed(host) {
  const { bypass = {} } = await chrome.storage.session.get('bypass');
  return !!bypass[host] && bypass[host] > Date.now();
}

async function check(url) {
  const hit = PhishLogic.cacheGet(CACHE, url, Date.now(), CACHE_TTL_MS);
  if (hit) return hit;
  try {
    const resp = await fetch(EXT_CONFIG.API_BASE + '/predict', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, fetch_html: false }), signal: AbortSignal.timeout(5000),
    });
    if (!resp.ok) return null;
    const result = await resp.json();
    PhishLogic.cacheSet(CACHE, url, result, Date.now());
    return result;
  } catch (e) { return null; }            // backend not running: do nothing, never break browsing
}

chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0) return;
  const url = d.url;
  if (!PhishLogic.shouldCheck(url) || PhishLogic.isOfficial(url, EXT_CONFIG.OFFICIAL_DOMAINS)) return;
  if (await isBypassed(PhishLogic.hostOf(url))) return;
  const result = await check(url);
  if (PhishLogic.shouldBlock(result, EXT_CONFIG.BLOCK_THRESHOLD)) {
    chrome.tabs.update(d.tabId, { url: PhishLogic.buildWarningUrl(chrome.runtime.getURL('warning.html'), url, result) });
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === 'bypass' && PhishLogic.isHttpUrl(msg.url)) {
    const host = PhishLogic.hostOf(msg.url);
    chrome.storage.session.get('bypass').then(({ bypass = {} }) => {
      bypass[host] = Date.now() + BYPASS_MS;
      return chrome.storage.session.set({ bypass: bypass });
    }).then(() => sendResponse({ ok: true }));
    return true;                           // keep the channel open for the async reply
  }
});
