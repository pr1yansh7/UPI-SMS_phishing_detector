// Runs the browser analysers (static/*.js) on the shared fixtures and prints JSON.
// Used by tests/test_js_parity.py — not meant to be run by hand.
const fs = require('fs'), vm = require('vm'), path = require('path');
const root = path.join(__dirname, '..', '..');
const read = f => fs.readFileSync(path.join(root, f), 'utf8');
const code = ['static/upi-config.js', 'static/scoring.js', 'static/messages.js'].map(read).join('\n;\n');
const fx = JSON.parse(read('tests/fixtures/message_cases.json'));
const sandbox = { URL, URLSearchParams, fx, out: null };
vm.createContext(sandbox);
vm.runInContext(code + `
;out = {
  sms: fx.sms.map(c => scoreSMSHeuristic(c.text, c.sender || '')),
  whatsapp: fx.whatsapp.map(t => scoreWhatsAppHeuristic(t)),
  upi: fx.upi.map(u => scoreUpiFromText(u)),
  official: fx.official.map(u => isOfficialDomain(u)),
};`, sandbox);
process.stdout.write(JSON.stringify(sandbox.out));
