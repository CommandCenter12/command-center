# Command Center

Mohammad's personal AI command center: an iOS-style home screen that runs entirely as a static
site on GitHub Pages. Everything personal (assignments, to-dos, Robinhood data, Robinhood
screenshots, study guides) is published **only as AES-256-GCM ciphertext** and decrypted in the
browser after the lock screen.

## What's inside

| File | Purpose |
| --- | --- |
| `index.html`, `styles.css`, `app.js` | The app: lock screen (passcode + Face ID / Touch ID), greeting + market status, assistant briefing, quick-command bar, Most Important + To-Do widgets, app launcher with live website previews, Stocks command center, Study Guides, settings |
| `manifest.json`, `sw.js`, `icons/` | "Add to Home Screen" PWA support (full-screen on iPhone/iPad, offline shell) |
| `data.json` → `data.enc` | Private data (never committed) → encrypted copy (committed) |
| `screenshots/*.png` → `screenshots/*.enc` | Real Robinhood screenshots (never committed) → encrypted copies (committed) |
| `encrypt.js` | Encrypts `data.json` and screenshots with a key derived from `.passcode` |
| `publish.sh` | `encrypt → git commit "Morning sync: YYYY-MM-DD HH:MM" → push → GitHub Pages` |
| `tools/merge-data.js` | Merge a JSON fragment into `data.json` (upserts by `id` / `ticker`) |
| `tools/calendar-sync.js` | Push assignment deadlines into Apple Calendar without duplicates (AppleScript) |
| `.passcode`, `.salt` | The 8-digit passcode (gitignored) and the public PBKDF2 salt |

## How the security works

* **Key**: `PBKDF2-SHA256(passcode, salt, 600 000 iterations)` → AES-256-GCM key.
  The browser derives the same key with Web Crypto (`crypto.subtle`) when you enter the passcode.
* **File format**: `"CCE1" | salt (16) | iv (12) | ciphertext ‖ GCM tag (16)`. A wrong passcode fails the
  GCM authentication, so the lock screen shakes instead of showing garbage.
* **Session**: the derived key lives in `sessionStorage` for the open tab only. **Lock** or 5 minutes of
  inactivity wipes it and the decrypted data; closing the tab does too.
* **Face ID / Touch ID**: Settings → *Enroll this device* creates a platform passkey (WebAuthn,
  `userVerification: "required"`). The passcode is wrapped with a key derived from the passkey's PRF
  output (hardware-bound; Safari 18+/iOS 18+/Chrome 116+). On browsers without PRF the wrap key is a
  non-extractable key in IndexedDB gated by the biometric ceremony. Enrollment never leaves the device;
  the passcode always works as a fallback.
* **API keys and tokens are per-device only.** The GitHub sync token and the OpenVerse/Gemini key live in each
  browser's own storage (paste once per device in Settings) and, on the Mac, in the gitignored `.secrets.local.json`.
  `encrypt.js`, cloud sync and unlock all strip them, so they never go into `data.enc`. Older commits of `data.enc`
  may still contain them encrypted, so rotate any key that was published before Nov 23, 2026.
* **Limits to know**: the only secret is an 8-digit passcode. The published ciphertext is protected by
  600k PBKDF2 rounds, which slows brute force but cannot make 10⁸ combinations unbreakable against a
  determined attacker with GPUs. Treat the repo as "private enough", not as a vault; a private repo
  (GitHub Pro) is the easy upgrade.

## Daily use

1. Open the site (or the Home Screen app), enter `••••••••` or tap **Unlock with Face ID / Touch ID**.
2. The briefing card and widgets show what Claude synced last. Tap **📘 Study guide** on any assignment
   to get a ready-to-paste request for Claude.
3. **Stocks** → Holdings & Watchlist shows price vs 50/200-day averages, RSI, 20/60-day and 52-week
   levels, analyst targets and earnings dates. Action tags (`WATCH / HOLD / BUY MORE / SET LIMIT ORDER /
   TRIM`) and plan notes are yours and stay in this browser.
4. **Tell Claude to Buy / Trade** builds the exact instruction for Claude. Claude fills the Robinhood
   ticket up to **Review Order**, screenshots it, and stops. **You** press Submit.
5. The quick-command bar understands `Add … to my list`, `Buy $200 of NVDA`, `Buy 3 shares of AMD limit
   500`, `Make me a study guide for …`, `Open <app>`, `Lock`, `Dark mode`. Anything else is copied as a
   message for Claude.

## Syncing (what `/morning-sync` does)

```bash
# 1. Claude updates data.json (Livetop assignments, Robinhood readings, briefing, study guides)
node tools/merge-data.js fragment.json
# 2. Deadlines → Apple Calendar (no duplicates)
node tools/calendar-sync.js
# 3. Encrypt + deploy
./publish.sh
```

`publish.sh` stages only: `index.html styles.css app.js README.md data.enc manifest.json sw.js icons/
.nojekyll .gitignore .salt encrypt.js publish.sh tools/ screenshots/*.enc`. It refuses to run if
`.passcode`, `.env`, `data.json` or a raw screenshot is ever staged.

## Local preview

```bash
python3 -m http.server 8765
```

Then open http://localhost:8765 (biometrics need a secure context: localhost or HTTPS).
