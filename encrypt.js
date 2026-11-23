#!/usr/bin/env node
/* encrypt.js — encrypts data.json → data.enc and screenshots/*.png → screenshots/*.enc
   Key   : PBKDF2-SHA256(passcode from .passcode, salt, 600000 iterations) → AES-256-GCM
   Format: "CCE1" | salt(16) | iv(12) | ciphertext || GCM tag(16)
   The browser (app.js) derives the same key from the passcode and decrypts in memory.
   Usage : node encrypt.js [--verify]   (CC_PASSCODE env var overrides .passcode) */
'use strict';
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const ROOT = __dirname, ITER = 600000;
const read = f => { try { return fs.readFileSync(path.join(ROOT, f), 'utf8'); } catch { return ''; } };
const passcode = (process.env.CC_PASSCODE || read('.passcode')).trim();
if (!/^\d{8}$/.test(passcode)) { console.error('encrypt.js: .passcode must contain the 8-digit passcode'); process.exit(1); }

// A stable salt keeps the derived key the same across publishes, so Face ID / Touch ID
// enrollment and open sessions keep working. The salt is not secret (it is in every .enc header).
let salt = Buffer.from(read('.salt').trim(), 'hex');
if (salt.length !== 16) { salt = crypto.randomBytes(16); fs.writeFileSync(path.join(ROOT, '.salt'), salt.toString('hex') + '\n'); }
const key = crypto.pbkdf2Sync(passcode, salt, ITER, 32, 'sha256');

function seal(buf) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([Buffer.from('CCE1'), salt, iv, ct, c.getAuthTag()]);
}
function open(buf) {
  if (buf.subarray(0, 4).toString() !== 'CCE1') throw new Error('bad magic');
  const iv = buf.subarray(20, 32), body = buf.subarray(32), ct = body.subarray(0, body.length - 16), tag = body.subarray(body.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}
const labelFor = f => { const s = f.replace(/\.(png|jpe?g|webp)$/i, '').replace(/[-_]+/g, ' ').trim(); return s.charAt(0).toUpperCase() + s.slice(1); };
const mimeFor = f => /\.png$/i.test(f) ? 'image/png' : /\.webp$/i.test(f) ? 'image/webp' : 'image/jpeg';

// ---- screenshots -------------------------------------------------------------
const shotsDir = path.join(ROOT, 'screenshots'); fs.mkdirSync(shotsDir, { recursive: true });
const raws = fs.readdirSync(shotsDir).filter(f => /\.(png|jpe?g|webp)$/i.test(f)).sort();
const keep = new Set(), shots = [];
for (const f of raws) {
  const out = f.replace(/\.(png|jpe?g|webp)$/i, '.enc');
  fs.writeFileSync(path.join(shotsDir, out), seal(fs.readFileSync(path.join(shotsDir, f))));
  keep.add(out);
  shots.push({ file: 'screenshots/' + out, label: labelFor(f), taken_at: fs.statSync(path.join(shotsDir, f)).mtime.toISOString(), mime: mimeFor(f) });
}
for (const f of fs.readdirSync(shotsDir)) if (f.endsWith('.enc') && !keep.has(f)) fs.unlinkSync(path.join(shotsDir, f)); // stale ciphertext

// ---- data.json → data.enc ----------------------------------------------------
const dataPath = path.join(ROOT, 'data.json');
const data = fs.existsSync(dataPath) ? JSON.parse(fs.readFileSync(dataPath, 'utf8')) : {};
// Never publish API keys/tokens, even encrypted: they live in .secrets.local.json and each browser's own storage.
if (data.settings) for (const k of ['gh_token', 'gemini_key', 'openverse_key']) {
  if (k in data.settings) { delete data.settings[k]; console.log(`• Left ${k} out of data.enc (keys are per-device only)`); }
}
data.stocks = data.stocks || {};
const prev = new Map((data.stocks.screenshots || []).map(s => [s.file, s]));
data.stocks.screenshots = shots.map(s => ({ ...s, label: (prev.get(s.file) || {}).label || s.label }));
data.encrypted_at = new Date().toISOString();
fs.writeFileSync(dataPath.replace(/\.json$/, '.enc'), seal(Buffer.from(JSON.stringify(data))));

// ---- self-test ---------------------------------------------------------------
const check = JSON.parse(open(fs.readFileSync(path.join(ROOT, 'data.enc'))).toString());
if (check.encrypted_at !== data.encrypted_at) throw new Error('self-test failed');
console.log(`✔ data.json → data.enc (${fs.statSync(path.join(ROOT, 'data.enc')).size.toLocaleString()} bytes), ${shots.length} screenshot(s) encrypted, salt ${salt.toString('hex').slice(0, 8)}…`);
