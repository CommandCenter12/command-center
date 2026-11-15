#!/usr/bin/env node
/* merge-data.js — merge a JSON fragment into data.json (creates it if missing).
   usage: node tools/merge-data.js fragment.json      or:  cat fragment.json | node tools/merge-data.js
   Rules: plain objects deep-merge · arrays whose items have "id" (or "ticker") are upserted by that key
          (existing fields are kept unless the fragment overrides them) · other arrays are replaced ·
          a null value deletes the key · "_remove": {"assignments": ["id1", ...]} removes items by key.
   Always refreshes generated_at. Never touches .passcode or anything outside data.json. */
'use strict';
const fs = require('fs'), path = require('path');
const dataPath = path.join(__dirname, '..', 'data.json');
const src = process.argv[2] ? fs.readFileSync(process.argv[2], 'utf8') : fs.readFileSync(0, 'utf8');
const frag = JSON.parse(src);
const data = fs.existsSync(dataPath) ? JSON.parse(fs.readFileSync(dataPath, 'utf8')) : {};
const isObj = v => v && typeof v === 'object' && !Array.isArray(v);
const keyOf = it => isObj(it) ? (it.id != null ? ['id', it.id] : it.ticker != null ? ['ticker', it.ticker] : null) : null;
function merge(base, add) {
  for (const [k, v] of Object.entries(add)) {
    if (k === '_remove') continue;
    if (v === null) { delete base[k]; continue; }
    if (Array.isArray(v)) {
      const keyed = v.length && v.every(keyOf);
      if (keyed && Array.isArray(base[k])) {
        const out = [...base[k]];
        for (const it of v) { const [kk, kv] = keyOf(it); const i = out.findIndex(o => isObj(o) && o[kk] === kv); if (i >= 0) out[i] = merge({ ...out[i] }, it); else out.push(it); }
        base[k] = out;
      } else base[k] = v;
    } else if (isObj(v)) { base[k] = merge(isObj(base[k]) ? base[k] : {}, v); }
    else base[k] = v;
  }
  return base;
}
merge(data, frag);
for (const [k, ids] of Object.entries(frag._remove || {})) if (Array.isArray(data[k])) data[k] = data[k].filter(o => !(isObj(o) && (ids.includes(o.id) || ids.includes(o.ticker))));
data.generated_at = new Date().toISOString();
fs.writeFileSync(dataPath, JSON.stringify(data, null, 2) + '\n');
console.log(`✔ data.json updated (${Object.keys(frag).filter(k => k !== '_remove').join(', ')})`);
