// Headless-DOM test of START.html (clicks, verdicts, report panel). Needs: npm install (jsdom).
// Run: node tests/js/ui_test.js   or   python -m pytest tests/test_ui.py
const { JSDOM, VirtualConsole } = require('jsdom'); const fs = require('fs');
const html = fs.readFileSync(require('path').join(__dirname, '..', '..', 'START.html'), 'utf8');
const errors = []; const vc = new VirtualConsole();
vc.on('jsdomError', e => errors.push(String(e.message).slice(0, 120)));
const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'http://localhost/', pretendToBeVisual: true, virtualConsole: vc });
const w = dom.window, $ = id => w.document.getElementById(id);
w.HTMLElement.prototype.scrollIntoView = () => {};
let pass = 0, fail = 0;
const check = (name, ok) => { (ok ? pass++ : fail++); console.log((ok ? '  PASS ' : '  FAIL ') + name); };
async function msg(mode, text, sender) {
  w.setMsgMode(mode); $('msgText').value = text; $('msgSender').value = sender || '';
  await w.analyseMessage(); return $('msgResult').innerHTML;
}
(async () => {
  let h = await msg('whatsapp', 'RTO challan pending. Download app http://rto-echallan.top/challan.apk and pay fine today');
  check('WhatsApp apk scam -> LIKELY SCAM', h.includes('LIKELY SCAM'));
  check('  report panel shows 1930 + cybercrime.gov.in', h.includes('1930') && h.includes('cybercrime.gov.in') && h.includes('sancharsaathi.gov.in'));
  h = await msg('whatsapp', 'Hi! Dinner at 8? Location https://maps.google.com/?q=cafe');
  check('WhatsApp normal msg -> NO STRONG SCAM SIGNALS, no report panel', h.includes('NO STRONG SCAM SIGNALS') && !h.includes('What to do now'));
  h = await msg('whatsapp', 'Your electricity bill is unpaid, power will be disconnected tonight. Call now');
  check('Ambiguous utility threat -> SOME WARNING SIGNS', h.includes('SOME WARNING SIGNS'));
  h = await msg('sms', 'Your UPI OTP is 847291. Share OTP with our executive to complete KYC verification.', 'VK-UIDAI');
  check('SMS asks for OTP -> LIKELY SCAM', h.includes('LIKELY SCAM'));
  h = await msg('upi', 'upi://pay?pa=phonepe.refund@ybl&pn=PhonePe%20Refund%20Dept&am=15000&tn=Refund%20claim');
  check('UPI refund link -> LIKELY SCAM + payee shown', h.includes('LIKELY SCAM') && h.includes('phonepe.refund@ybl'));
  h = await msg('upi', 'upi://pay?pa=merchant@okaxis&pn=Sharma%20Store&am=250&cu=INR');
  check('UPI normal shop link -> not flagged', !h.includes('LIKELY SCAM'));
  check('example chips render per mode', $('msgExamples').children.length === 2);

  $('urlInput').value = 'http://uidai-update-kyc.xyz/verify'; await w.analyse();
  check('URL phishing -> PHISHING + report panel', $('verdictLabel').textContent === 'PHISHING' && $('reportPanel').innerHTML.includes('cybercrime.gov.in'));
  $('urlInput').value = 'https://uidai.gov.in/'; await w.analyse();
  check('Official URL -> LEGITIMATE, allowlist note, no report panel',
        $('verdictLabel').textContent === 'LEGITIMATE' && $('flagsWrap').innerHTML.includes('Official domain') && $('reportPanel').innerHTML === '');
  $('urlInput').value = 'https://uidai.gov.in.evil.xyz/login'; await w.analyse();
  check('Lookalike of official domain is NOT allowlisted', !$('flagsWrap').innerHTML.includes('Official domain'));
  check('status bar fell back to offline text', $('apiLabel').textContent.includes('offline'));
  check('no script errors', errors.length === 0);
  if (errors.length) console.log('  errors:', errors);
  console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})();
