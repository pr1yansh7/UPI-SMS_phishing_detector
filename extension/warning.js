/* warning.js — fills warning.html. Everything user-controlled goes in via textContent (never parsed as HTML). */
const params = PhishLogic.parseWarningParams(location.search);
document.getElementById('url').textContent = params.url;
document.getElementById('prob').textContent = Math.round(params.prob * 100) + '%';
const ul = document.getElementById('flags');
params.flags.forEach(f => { const li = document.createElement('li'); li.textContent = f; ul.appendChild(li); });

const report = document.getElementById('report');
EXT_CONFIG.REPORTING_CHANNELS.forEach(c => {
  const p = document.createElement('p');
  const b = document.createElement('strong'); b.textContent = c.name + ' — ' + c.contact;
  p.appendChild(b); p.appendChild(document.createElement('br'));
  p.appendChild(document.createTextNode(c.when));
  report.appendChild(p);
});

document.getElementById('close').onclick = () =>
  chrome.tabs.getCurrent(tab => chrome.tabs.remove(tab.id));

document.getElementById('proceed').onclick = () => {
  if (!PhishLogic.isHttpUrl(params.url)) return;          // never navigate to javascript:/data: etc.
  chrome.runtime.sendMessage({ type: 'bypass', url: params.url }, () => { location.href = params.url; });
};
