# Phishing Guard — Chrome extension (experimental)

Warns when a page you navigate to looks like UPI/Aadhaar phishing.

## Install (developer mode)
1. Start the backend from the project folder: `python api.py` (needs a trained model — `./run.sh` does everything).
2. Chrome → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → choose this `extension/` folder.
3. Click the toolbar icon on any page to check it, or just browse — a confident detection replaces the tab with a warning page.

## What it does / does not do
- Sends each visited page's URL to **your own backend on localhost:5050** and nowhere else. If the backend is off it does nothing.
- Warns only at ≥ 90% risk (the backend itself flags at 60%) to avoid nagging; official HTTPS domains are skipped.
- It is **not a hard block**: the page may begin loading for a moment before the warning replaces it.
- Permissions: `webNavigation`, `storage`, `activeTab`, and host access to `http://localhost:5050` only.
- **Not yet tested in a real Chrome** — the decision logic is unit-tested in Node (`tests/js/test_extension_logic.js`); the browser wiring is not.
- `config.js` is generated from `config.py` (`make sync-js`) — don't edit it by hand.
