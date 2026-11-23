/* Command Center — app.js
   Everything runs in the browser. Personal data is fetched as AES-GCM
   ciphertext (data.enc, screenshots/*.enc) and decrypted in memory only. */
(() => {
'use strict';

/* ------------------------------------------------------------------ helpers */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
const enc = new TextEncoder();
const dec = new TextDecoder();
const DATA_URL = 'data.enc';
const PBKDF2_ITER = 600000;
const LOCK_AFTER_MS = 5 * 60 * 1000;
const OWNER_FALLBACK = 'Mohammad';
const APP_VERSION = '2.0.0';
const LS = { apps: 'cc.customApps', hidden: 'cc.hiddenApps', todo: 'cc.todoState', theme: 'cc.theme', previews: 'cc.previews', actions: 'cc.actions', notes: 'cc.notes', bio: 'cc.bio', userId: 'cc.userId', gemini: 'cc.openverseKey', model: 'cc.model' };
const SS_KEY = 'cc.session';

const state = { data: null, key: null, salt: null, passcode: null, urls: [], lastActivity: Date.now(), idleTimer: null, unlocked: false, shotsLoaded: false };

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const lsGet = (k, fb) => { try { const v = localStorage.getItem(k); return v == null ? fb : JSON.parse(v); } catch { return fb; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } scheduleSync(); };
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const hex = u8 => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('');
const unhex = s => new Uint8Array((s.match(/../g) || []).map(h => parseInt(h, 16)));
const b64u = u8 => btoa(Array.from(u8, c => String.fromCharCode(c)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0));

let toastTimer;
function toast(msg, ms = 2600) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), ms); }

const money = (n, d = 2) => (n < 0 ? '-' : '') + '$' + Math.abs(+n || 0).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d });
const pct = n => (n >= 0 ? '+' : '') + (+n).toFixed(2) + '%';
const num = (n, d = 2) => (+n).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d });

function parseDate(s) {
  if (!s) return null;
  if (s instanceof Date) return s;
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d, 23, 59); }
  const d = new Date(s); return isNaN(d) ? null : d;
}
const startOfDay = d => { const x = new Date(d); x.setHours(0, 0, 0, 0); return x; };
const dayDiff = d => Math.round((startOfDay(d) - startOfDay(new Date())) / 864e5);
function relDay(d) {
  const n = dayDiff(d);
  if (n < 0) return n === -1 ? 'Yesterday' : `${-n}d overdue`;
  if (n === 0) return 'Today';
  if (n === 1) return 'Tomorrow';
  if (n < 7) return d.toLocaleDateString('en-US', { weekday: 'long' });
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}
const fmtDate = d => d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
const fmtTime = d => d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
function relTime(iso) {
  const d = new Date(iso); if (isNaN(d)) return '';
  const m = Math.round((Date.now() - d) / 60000);
  if (m < 2) return 'just now'; if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60); if (h < 24) return `${h} h ago`;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ', ' + fmtTime(d);
}
const isTouch = matchMedia('(hover: none)').matches;

/* ------------------------------------------------------------------- crypto */
function parseEnc(buf) {
  const u = new Uint8Array(buf);
  if (u.length < 48 || u[0] !== 0x43 || u[1] !== 0x43 || u[2] !== 0x45 || u[3] !== 0x31) throw new Error('Not an encrypted Command Center file');
  return { salt: u.slice(4, 20), iv: u.slice(20, 32), ct: u.slice(32) };
}
const keyCache = new Map();
async function deriveKey(passcode, salt) {
  const ck = hex(salt) + ':' + passcode;
  if (keyCache.has(ck)) return keyCache.get(ck);
  const base = await crypto.subtle.importKey('raw', enc.encode(passcode), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  keyCache.set(ck, key); return key;
}
const importRawKey = raw => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
async function decryptBuf(buf, key) { const { iv, ct } = parseEnc(buf); return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct); }

let encCache = null;
async function fetchEnc(force) {
  if (!encCache || force) {
    const r = await fetch(DATA_URL, { cache: 'no-store' });
    if (!r.ok) throw new Error('data.enc is missing — run ./publish.sh');
    encCache = await r.arrayBuffer();
  }
  return encCache;
}
async function keyForSalt(salt) {
  if (state.key && state.salt && hex(salt) === hex(state.salt)) return state.key;
  if (state.passcode) return deriveKey(state.passcode, salt);
  throw new Error('Locked');
}
async function decryptFile(path) {
  const r = await fetch(path, { cache: 'no-store' });
  if (!r.ok) throw new Error('Missing ' + path);
  const buf = await r.arrayBuffer();
  const { salt } = parseEnc(buf);
  const key = await keyForSalt(salt);
  return decryptBuf(buf, key);
}

/* ------------------------------------------------------------------ session */
async function saveSession(key, salt) {
  try { const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key)); sessionStorage.setItem(SS_KEY, JSON.stringify({ salt: hex(salt), key: hex(raw) })); } catch { /* ignore */ }
}
async function restoreSession() {
  let s; try { s = JSON.parse(sessionStorage.getItem(SS_KEY) || 'null'); } catch { s = null; }
  if (!s || !s.salt || !s.key) return false;
  const buf = await fetchEnc();
  const { salt } = parseEnc(buf);
  if (hex(salt) !== s.salt) return false;
  const key = await importRawKey(unhex(s.key));
  const plain = await decryptBuf(buf, key);
  state.key = key; state.salt = salt;
  onUnlocked(JSON.parse(dec.decode(plain)), true);
  return true;
}
async function unlockWithPasscode(code) {
  const buf = await fetchEnc();
  const { salt } = parseEnc(buf);
  const key = await deriveKey(code, salt);
  const plain = await decryptBuf(buf, key); // throws on a wrong passcode (GCM auth)
  state.key = key; state.salt = salt; state.passcode = code;
  await saveSession(key, salt);
  return JSON.parse(dec.decode(plain));
}

/* --------------------------------------------------------------- lock screen */
const lock = { code: '', busy: false, mode: 'unlock', resolve: null };
const lockEl = $('#lock'), dotsEl = $('#dots'), lockLabel = $('#lock-label'), lockHint = $('#lock-hint');
function renderDots() { dotsEl.innerHTML = Array.from({ length: 8 }, (_, i) => `<span class="${i < lock.code.length ? 'on' : ''}"></span>`).join(''); }
function tickClock() {
  const d = new Date();
  $('#lock-time').textContent = d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }).replace(/\s?[AP]M/i, '');
  $('#lock-date').textContent = d.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });
}
function pressKey(k) {
  if (lock.busy || lock.code.length >= 8) return;
  lock.code += k; renderDots();
  if (lock.code.length === 8) setTimeout(submitCode, 80);
}
function delKey() { if (lock.busy) return; lock.code = lock.code.slice(0, -1); renderDots(); }
function lockFail(msg) {
  dotsEl.classList.add('shake');
  if (navigator.vibrate) navigator.vibrate([40, 40, 40]);
  setTimeout(() => { dotsEl.classList.remove('shake'); lock.code = ''; renderDots(); if ($('#pin')) $('#pin').value = ''; lockLabel.textContent = msg || 'Wrong Passcode'; }, 480);
}
async function submitCode() {
  if (lock.busy || lock.code.length !== 8) return;
  lock.busy = true; lockLabel.textContent = 'Unlocking…';
  const code = lock.code;
  try {
    if (lock.mode === 'confirm') {            // re-enter passcode to enroll biometrics
      const buf = await fetchEnc(); const { salt } = parseEnc(buf);
      await decryptBuf(buf, await deriveKey(code, salt));
      state.passcode = code; lock.code = ''; renderDots(); lock.mode = 'unlock';
      hideLock(); lock.resolve && lock.resolve(code); lock.resolve = null;
    } else {
      const data = await unlockWithPasscode(code);
      onUnlocked(data);
    }
  } catch (e) {
    console.warn(e);
    lockFail(/missing|publish/.test(String(e.message)) ? 'No data yet — run ./publish.sh' : 'Wrong Passcode');
  } finally { lock.busy = false; }
}
function showLock(mode = 'unlock') {
  lock.mode = mode; lock.code = ''; renderDots(); if ($('#pin')) $('#pin').value = '';
  lockLabel.textContent = mode === 'confirm' ? 'Confirm Passcode' : 'Enter your 8-digit PIN';
  lockHint.textContent = '';
  lockEl.hidden = false; requestAnimationFrame(() => lockEl.classList.remove('hide'));
  document.body.classList.add('locked');
  refreshBioButtons();
}
function hideLock() {
  lockEl.classList.add('hide'); document.body.classList.remove('locked');
  setTimeout(() => { if (lockEl.classList.contains('hide')) lockEl.hidden = true; }, 600);
}
function askPasscode() { return new Promise(res => { lock.resolve = res; showLock('confirm'); }); }

const keypadEl = $('#keypad'); if (keypadEl) keypadEl.addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  if (b.dataset.key != null) pressKey(b.dataset.key);
  else if (b.id === 'key-del') delKey();
  else if (b.id === 'key-bio') bioUnlock();
});
$('#bio-btn').addEventListener('click', bioUnlock);
document.addEventListener('keydown', e => {
  if (lockEl.hidden || lockEl.classList.contains('hide')) return;
  if (e.target && e.target.id === 'pin') return;
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  if (/^[0-9]$/.test(e.key)) { pressKey(e.key); flashKey(e.key); e.preventDefault(); }
  else if (e.key === 'Backspace') { delKey(); e.preventDefault(); }
  else if (e.key === 'Enter') { submitCode(); e.preventDefault(); }
  else if (e.key === 'Escape') { lock.code = ''; renderDots(); }
});
function flashKey(k) { const b = $(`#keypad button[data-key="${k}"]`); if (!b) return; b.classList.add('pressed'); setTimeout(() => b.classList.remove('pressed'), 120); }

/* -------------------------------------------------- Face ID / Touch ID (WebAuthn) */
const RP_ID = location.hostname;
const bioRec = () => lsGet(LS.bio, null);
let bioAvailable = false;
async function detectBio() {
  try { bioAvailable = !!(window.PublicKeyCredential && window.isSecureContext) && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); }
  catch { bioAvailable = false; }
  refreshBioButtons();
}
function refreshBioButtons() {
  const rec = bioRec();
  const ok = bioAvailable && rec && rec.wrapped && lock.mode === 'unlock';
  $('#key-bio').hidden = true; $('#bio-btn').hidden = false;
}
function userIdBytes() { let id = lsGet(LS.userId, null); if (!id) { id = b64u(rand(16)); lsSet(LS.userId, id); } return unb64u(id); }
async function hkdfKey(secret) {
  const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: enc.encode('cc-bio-wrap-v1'), info: enc.encode('passcode') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
function idb() { return new Promise((res, rej) => { const r = indexedDB.open('cc-keys', 1); r.onupgradeneeded = () => r.result.createObjectStore('keys'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
async function localWrapKey(create) {
  const db = await idb();
  const get = () => new Promise((res, rej) => { const q = db.transaction('keys', 'readonly').objectStore('keys').get('wrap'); q.onsuccess = () => res(q.result || null); q.onerror = () => rej(q.error); });
  let k = await get();
  if (!k && create) {
    k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    await new Promise((res, rej) => { const tx = db.transaction('keys', 'readwrite'); tx.objectStore('keys').put(k, 'wrap'); tx.oncomplete = res; tx.onerror = () => rej(tx.error); });
  }
  if (!k) throw new Error('This browser has no local biometric key. Enroll again.');
  return k;
}
// Step 1: create a platform passkey (Face ID / Touch ID) for this origin.
async function bioEnrollStep1() {
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: rand(32),
    rp: { name: 'Command Center', id: RP_ID },
    user: { id: userIdBytes(), name: 'mohammad', displayName: state.data?.owner?.name || OWNER_FALLBACK },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
    timeout: 60000, attestation: 'none', extensions: { prf: {} }
  } });
  const ext = (cred.getClientExtensionResults && cred.getClientExtensionResults()) || {};
  lsSet(LS.bio, { v: 1, credId: b64u(new Uint8Array(cred.rawId)), prfSalt: b64u(rand(32)), prfHint: ext.prf ? !!ext.prf.enabled : null, pending: true, enrolledAt: new Date().toISOString() });
}
// Step 2: evaluate the credential once (PRF) and wrap the passcode with the result.
async function bioEnrollStep2() {
  const rec = bioRec(); if (!rec) throw new Error('Start enrollment first');
  if (!state.passcode) await askPasscode();
  const prfSalt = unb64u(rec.prfSalt);
  let secret = null, assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: { challenge: rand(32), rpId: RP_ID, allowCredentials: [{ type: 'public-key', id: unb64u(rec.credId), transports: ['internal'] }], userVerification: 'required', timeout: 60000, extensions: { prf: { eval: { first: prfSalt } } } } });
    const r = assertion.getClientExtensionResults && assertion.getClientExtensionResults().prf;
    if (r && r.results && r.results.first) secret = new Uint8Array(r.results.first);
  } catch (e) { throw e; }
  const method = secret ? 'prf' : 'local';
  const wrapKey = secret ? await hkdfKey(secret) : await localWrapKey(true);
  const iv = rand(12);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, enc.encode(state.passcode)));
  lsSet(LS.bio, { ...rec, pending: false, method, iv: b64u(iv), wrapped: b64u(wrapped), confirmedAt: new Date().toISOString() });
  return method;
}
async function bioUnwrapPasscode() {
  const rec = bioRec(); if (rec && rec.pending && !rec.wrapped) throw new Error('setup not finished. Open Settings and press Enroll this device'); if (!rec || !rec.wrapped) throw new Error('not set up on this device. Open Settings and press Enroll this device');
  const opts = { challenge: rand(32), rpId: RP_ID, allowCredentials: [{ type: 'public-key', id: unb64u(rec.credId), transports: ['internal'] }], userVerification: 'required', timeout: 60000 };
  if (rec.method === 'prf') opts.extensions = { prf: { eval: { first: unb64u(rec.prfSalt) } } };
  const a = await navigator.credentials.get({ publicKey: opts });
  let wrapKey;
  if (rec.method === 'prf') {
    const r = a.getClientExtensionResults && a.getClientExtensionResults().prf;
    if (!r || !r.results || !r.results.first) throw new Error('This browser did not return the biometric key. Use the passcode.');
    wrapKey = await hkdfKey(new Uint8Array(r.results.first));
  } else wrapKey = await localWrapKey(false);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(rec.iv) }, wrapKey, unb64u(rec.wrapped));
  return dec.decode(plain);
}
function bioMsg(e) {
  const m = { NotAllowedError: 'Face ID / Touch ID was cancelled or timed out. Use your PIN.', SecurityError: 'This browser blocked biometrics for this site. Use your PIN.', NotSupportedError: 'This browser does not support Face ID / Touch ID here. Use your PIN.', InvalidStateError: 'No biometric key on this device yet. Enroll it in Settings, or use your PIN.', AbortError: 'Biometric check stopped. Use your PIN.' };
  if (e && m[e.name]) return m[e.name];
  return e && e.message ? 'Biometrics unavailable (' + String(e.message).slice(0, 80) + '). Use your PIN.' : 'Biometrics unavailable. Use your PIN.';
}
async function bioUnlock() {
  if (lock.busy) return;
  if (!bioAvailable) { lockHint.textContent = 'Face ID / Touch ID is not available in this browser. Use your PIN.'; return; }
  lock.busy = true; lockHint.textContent = ''; lockLabel.textContent = 'Face ID / Touch ID…';
  try {
    const code = await bioUnwrapPasscode();
    lockLabel.textContent = 'Unlocking…';
    const data = await unlockWithPasscode(code);
    onUnlocked(data);
  } catch (e) {
    console.warn(e);
    lockLabel.textContent = 'Enter your 8-digit PIN';
    lockHint.textContent = bioMsg(e);
  } finally { lock.busy = false; }
}

/* ------------------------------------------------------------------ unlock */
function onUnlocked(data, restored) {
  const gt = state.data && state.data.settings && state.data.settings.gh_token; if (gt && !lsGet('cc.ghToken', '')) lsSet('cc.ghToken', gt);
  hydrateImages().catch(() => {}); pullRemote(false).catch(e => setSync('Cloud load skipped: ' + e.message));
  // The synced file wraps the app data as { sync, updated, ls, images, data }. Unwrap it, or the lists stay empty
  // whenever the cloud copy is not newer than this browser's last load.
  const unwrapped = data && data.sync !== undefined && data.data ? data.data : data;
  state.data = unwrapped || {}; state.unlocked = true;
  hideLock();
  $('#app').hidden = false;
  renderAll();
  resetIdle();
  if (!restored) toast(`Welcome back, ${state.data.owner?.name || OWNER_FALLBACK}`);
}
function lockNow(reason) {
  state.urls.forEach(u => URL.revokeObjectURL(u)); state.urls = [];
  state.data = null; state.key = null; state.salt = null; state.passcode = null; state.unlocked = false; state.shotsLoaded = false;
  keyCache.clear();
  try { sessionStorage.removeItem(SS_KEY); } catch { /* ignore */ }
  $$('.sheet.open').forEach(s => closeSheet(s));
  hidePreview(); $('#lightbox').hidden = true;
  $('#app').hidden = true;
  $('#pane-shots').innerHTML = ''; $('#guide-view').innerHTML = '';
  showLock('unlock');
  if (reason) lockHint.textContent = reason;
}
function resetIdle() {
  state.lastActivity = Date.now();
  clearTimeout(state.idleTimer);
  if (state.unlocked) state.idleTimer = setTimeout(() => lockNow('Locked after 5 minutes of inactivity'), LOCK_AFTER_MS);
}
['pointerdown', 'keydown', 'touchstart', 'scroll'].forEach(ev => document.addEventListener(ev, () => { if (state.unlocked) resetIdle(); }, { passive: true }));
let mmTick = 0; document.addEventListener('mousemove', () => { if (state.unlocked && Date.now() - mmTick > 5000) { mmTick = Date.now(); resetIdle(); } }, { passive: true });
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && state.unlocked && Date.now() - state.lastActivity > LOCK_AFTER_MS) lockNow('Locked while you were away'); });
$('#btn-lock').addEventListener('click', () => lockNow());

/* ------------------------------------------------------------------- theme */
const mqLight = matchMedia('(prefers-color-scheme: light)');
function applyTheme() {
  const pref = lsGet(LS.theme, 'auto');
  const t = 'light';
  document.documentElement.setAttribute('data-theme', t);
  $$('#theme-seg button').forEach(b => b.classList.toggle('active', b.dataset.theme === pref));
}
mqLight.addEventListener('change', applyTheme);
$('#btn-theme').addEventListener('click', () => { const cur = document.documentElement.getAttribute('data-theme'); lsSet(LS.theme, cur === 'dark' ? 'light' : 'dark'); applyTheme(); });
$('#theme-seg').addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; lsSet(LS.theme, b.dataset.theme); applyTheme(); });

/* ------------------------------------------------------------------ header */
const HOLIDAYS = new Set(['2026-01-01', '2026-01-19', '2026-02-16', '2026-04-03', '2026-05-25', '2026-06-19', '2026-07-03', '2026-09-07', '2026-11-26', '2026-12-25', '2027-01-01', '2027-01-18', '2027-02-15', '2027-03-26', '2027-05-31', '2027-06-18', '2027-07-05', '2027-09-06', '2027-11-25', '2027-12-24']);
const EARLY_CLOSE = new Set(['2026-11-27', '2026-12-24', '2027-11-26']);
function marketStatus() {
  const f = new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', weekday: 'short', hour: 'numeric', minute: 'numeric', hour12: false, year: 'numeric', month: '2-digit', day: '2-digit' });
  const p = Object.fromEntries(f.formatToParts(new Date()).map(x => [x.type, x.value]));
  const t = (+p.hour % 24) * 60 + +p.minute, ymd = `${p.year}-${p.month}-${p.day}`;
  if (p.weekday === 'Sat' || p.weekday === 'Sun' || HOLIDAYS.has(ymd)) return { label: 'Market closed', cls: 'closed' };
  const close = EARLY_CLOSE.has(ymd) ? 13 * 60 : 16 * 60;
  if (t >= 240 && t < 570) return { label: 'Pre-market', cls: 'pre' };
  if (t >= 570 && t < close) return { label: 'Market open', cls: 'open' };
  if (t >= close && t < 1200) return { label: 'After hours', cls: 'after' };
  return { label: 'Market closed', cls: 'closed' };
}
function renderHeader() {
  const h = new Date().getHours();
  const g = h < 12 ? 'Good morning' : h < 17 ? 'Good afternoon' : 'Good evening';
  $('#greeting').textContent = `${g}, ${state.data?.owner?.name || OWNER_FALLBACK}`;
  const d = new Date();
  $('#today').textContent = d.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });
  const m = marketStatus(); const el = $('#market'); el.textContent = m.label; el.className = 'market ' + m.cls;
  $('#cal-dow').textContent = d.toLocaleDateString('en-US', { weekday: 'short' }).toUpperCase();
  $('#cal-day').textContent = d.getDate();
}

/* ------------------------------------------------------------- items / todo */
function allItems() {
  const d = state.data || {}; const items = [];
  (d.assignments || []).forEach(a => items.push({ ...a, kind: 'assignment', date: parseDate(a.due) }));
  (d.events || []).forEach(e => items.push({ ...e, kind: 'event', date: parseDate(e.start) }));
  return items.filter(i => i.date).sort((a, b) => a.date - b.date);
}
const prioClass = p => p === 'high' ? 'high' : p === 'low' ? 'low' : 'med';
function renderImportant() {
  const ts = todoState();
  const items = allItems().filter(i => dayDiff(i.date) >= -2 && !(i.kind === 'assignment' && (ts.done[i.id] || i.status === 'done'))).slice(0, 6);
  $('#imp-count').textContent = items.length ? `${items.length} upcoming` : '';
  $('#important-list').innerHTML = items.length ? items.map(i => {
    const n = dayDiff(i.date);
    const when = `<span class="when ${n <= 0 ? 'today' : n <= 2 ? 'soon' : ''}">${esc(relDay(i.date))}<br>${i.kind === 'event' ? esc(fmtTime(i.date)) : esc(i.date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }))}</span>`;
    const sub = [i.course, i.location, i.source].filter(Boolean).join(' · ');
    const joinOk = i.kind === 'event' && typeof i.url === 'string' && /^https:\/\//.test(i.url);
    const act = i.kind === 'assignment' ? `<button type="button" class="pill tiny" data-guide="${esc(i.id)}" title="Make Study Guide">📘 Study guide</button>`
      : joinOk ? `<a class="pill tiny" href="${esc(i.url)}" target="_blank" rel="noopener" title="Open the meeting link">🎥 Join</a>` : '';
    return `<li><span class="bar ${i.kind === 'event' ? 'event' : prioClass(i.priority)}"></span>${when}<div class="body"><div class="title">${esc(i.title)}</div>${sub ? `<div class="sub">${esc(sub)}</div>` : ''}</div><div class="acts">${act}</div></li>`;
  }).join('') : '<li class="empty">Nothing urgent. Enjoy the calm ☀️</li>';
}
function todoState() { const s = lsGet(LS.todo, null); return s && typeof s === 'object' ? { done: s.done || {}, custom: s.custom || [], removed: s.removed || {} } : { done: {}, custom: [], removed: {} }; }
function allTodos() {
  const d = state.data || {}; const ts = todoState(); const base = [];
  (d.todos || []).forEach(t => base.push({ ...t, source: 'data' }));
  (d.assignments || []).forEach(a => { if (!(d.todos || []).some(t => t.id === a.id)) base.push({ id: a.id, title: a.title, due: a.due, priority: a.priority, course: a.course, kind: 'assignment', source: 'assignment', done: a.status === 'done' }); });
  ts.custom.forEach(c => base.push({ ...c, source: 'custom' }));
  return base.filter(t => !ts.removed[t.id]).map(t => ({ ...t, done: !!ts.done[t.id] || t.done === true, dueDate: parseDate(t.due) }))
    .sort((a, b) => (a.done - b.done) || ((a.dueDate || 8.64e15) - (b.dueDate || 8.64e15)));
}
function renderTodo() {
  const todos = allTodos(); const open = todos.filter(t => !t.done).length;
  $('#todo-count').textContent = `${open} open`;
  $('#todo-list').innerHTML = todos.length ? todos.map(t => {
    const due = t.dueDate ? `<span class="${dayDiff(t.dueDate) < 0 && !t.done ? 'down' : ''}">${esc(relDay(t.dueDate))}</span>` : '';
    const sub = [t.course, due].filter(Boolean).join(' · ');
    const flag = t.priority === 'high' ? '<span class="flag" title="High priority">🚩</span>' : '';
    const guide = (t.kind === 'assignment' || t.source === 'assignment') && !t.done ? `<button type="button" class="pill tiny" data-guide="${esc(t.id)}">📘 Study guide</button>` : '';
    return `<li class="${t.done ? 'done' : ''}" data-id="${esc(t.id)}"><button type="button" class="check ${t.done ? 'on' : ''}" aria-label="Toggle done">${t.done ? '✓' : ''}</button><div class="body"><div class="title">${esc(t.title)} ${flag}</div>${sub ? `<div class="sub">${sub}</div>` : ''}</div><div class="acts">${guide}<button type="button" class="del" aria-label="Remove">✕</button></div></li>`;
  }).join('') : '<li class="empty">No reminders yet.</li>';
}
$('#todo-list').addEventListener('click', e => {
  const li = e.target.closest('li[data-id]'); if (!li) return;
  const id = li.dataset.id; const ts = todoState();
  if (e.target.closest('.check')) { if (ts.done[id]) delete ts.done[id]; else ts.done[id] = Date.now(); lsSet(LS.todo, ts); renderTodo(); renderImportant(); renderBriefing(); }
  else if (e.target.closest('.del')) { ts.removed[id] = true; ts.custom = ts.custom.filter(c => c.id !== id); lsSet(LS.todo, ts); renderTodo(); toast('Removed'); }
});
function addTodo(title, due, priority) {
  if (!title) return;
  const ts = todoState();
  ts.custom.push({ id: 'c-' + Date.now().toString(36), title, due: due || null, priority: priority || 'med', created: new Date().toISOString() });
  lsSet(LS.todo, ts); renderTodo(); renderBriefing();
}
$('#todo-add').addEventListener('submit', e => { e.preventDefault(); const t = $('#todo-input').value.trim(); if (!t) return; addTodo(t, $('#todo-date').value || null); $('#todo-input').value = ''; $('#todo-date').value = ''; toast('Added to your list'); });
document.addEventListener('click', e => { const b = e.target.closest('[data-guide]'); if (b) { e.preventDefault(); requestStudyGuide(b.dataset.guide); } });

/* ---------------------------------------------------------------- briefing */
function renderBriefing() {
  const d = state.data || {}; const b = d.briefing || {};
  $('#briefing-text').textContent = b.text || 'No briefing yet — run /morning-sync in Claude to generate one.';
  $('#briefing-time').textContent = d.generated_at ? 'Synced ' + relTime(d.generated_at) : '';
  const ts = todoState();
  const prios = (b.priorities && b.priorities.length) ? b.priorities : allTodos().filter(t => !t.done).slice(0, 3).map(t => t.title);
  $('#brief-priorities').innerHTML = prios.length ? prios.map((p, i) => `<li><span class="tag ${i === 0 ? 'red' : i === 1 ? 'orange' : 'blue'}">${i + 1}</span><span>${esc(p)}</span></li>`).join('') : '<li class="muted">Nothing queued</li>';
  const dl = allItems().filter(i => i.kind === 'assignment' && dayDiff(i.date) >= 0 && dayDiff(i.date) <= 10 && !ts.done[i.id]).slice(0, 4);
  $('#brief-deadlines').innerHTML = dl.length ? dl.map(i => `<li><span class="tag ${dayDiff(i.date) <= 1 ? 'red' : dayDiff(i.date) <= 3 ? 'orange' : 'gray'}">${esc(relDay(i.date))}</span><span>${esc(i.title)}${i.course ? ` <span class="muted">· ${esc(i.course)}</span>` : ''}</span></li>`).join('') : '<li class="muted">No deadlines in the next 10 days</li>';
  const st = (b.stock_items && b.stock_items.length) ? b.stock_items.map(s => `<li><span class="tag purple">${esc(s.ticker || '')}</span><span>${esc(s.text || s)}</span></li>`) : stockRows().filter(r => actionFor(r) !== 'HOLD' && actionFor(r) !== 'WATCH').slice(0, 4).map(r => `<li><span class="tag ${actionColor(actionFor(r))}">${esc(actionFor(r))}</span><span>${esc(r.ticker)} ${esc(money(r.price))} · ${esc(signalFor(r).label)}</span></li>`);
  $('#brief-stocks').innerHTML = st.length ? st.join('') : '<li class="muted">No stock action items. Open Stocks for levels and signals.</li>';
}

/* -------------------------------------------------------------------- apps */
const SVG_DOCS = `<svg viewBox="0 0 48 48" width="34" height="34" aria-hidden="true"><path fill="#fff" d="M30 4H13a3 3 0 0 0-3 3v34a3 3 0 0 0 3 3h22a3 3 0 0 0 3-3V12z"/><path fill="#c6dafc" d="M30 4v8h8z"/><g fill="#4285f4"><rect x="16" y="22" width="16" height="2.4" rx="1.2"/><rect x="16" y="27" width="16" height="2.4" rx="1.2"/><rect x="16" y="32" width="11" height="2.4" rx="1.2"/></g></svg>`;
const SVG_DRIVE = `<svg viewBox="0 0 87.3 78" width="34" height="34" aria-hidden="true"><path d="M6.6 66.85l3.85 6.65c.8 1.4 1.95 2.5 3.3 3.3l13.75-23.8H0c0 1.55.4 3.1 1.2 4.5z" fill="#0066da"/><path d="M43.65 25L29.9 1.2c-1.35.8-2.5 1.9-3.3 3.3L1.2 48.5C.4 49.9 0 51.45 0 53h27.5z" fill="#00ac47"/><path d="M73.55 76.8c1.35-.8 2.5-1.9 3.3-3.3l1.6-2.75L86.1 57.5c.8-1.4 1.2-2.95 1.2-4.5H59.8l5.85 11.5z" fill="#ea4335"/><path d="M43.65 25L57.4 1.2C56.05.4 54.5 0 52.9 0H34.4c-1.6 0-3.15.45-4.5 1.2z" fill="#00832d"/><path d="M59.8 53H27.5L13.75 76.8c1.35.8 2.9 1.2 4.5 1.2h50.8c1.6 0 3.15-.45 4.5-1.2z" fill="#2684fc"/><path d="M73.4 26.5L60.7 4.5c-.8-1.4-1.95-2.5-3.3-3.3L43.65 25 59.8 53h27.45c0-1.55-.4-3.1-1.2-4.5z" fill="#ffba00"/></svg>`;
const DEFAULT_APPS = [
  { id: 'livetop', name: 'Livetop', url: 'https://secure.livetop.net/', icon: 'LT', bg: 'linear-gradient(145deg,#2f8bff,#0b3fb8)' },
  { id: 'gdocs', name: 'Google Docs', url: 'https://docs.google.com', svg: SVG_DOCS, bg: 'linear-gradient(145deg,#5a9bff,#2b6fe0)' },
  { id: 'gdrive', name: 'Google Drive', url: 'https://drive.google.com', svg: SVG_DRIVE, bg: 'linear-gradient(145deg,#ffffff,#e8edf5)' },
  { id: 'horizons', name: 'Horizons Academy', url: 'https://fportal.horizons-pal.net/requests/student/planned-courses/', icon: '🎓', bg: 'linear-gradient(145deg,#8e7bff,#3b22b5)' },
  { id: 'nayzak', name: 'Horizons Courses', url: 'https://nayzakcourses.net/my/', icon: '📚', bg: 'linear-gradient(145deg,#ffb340,#ff5e3a)' },
  { id: 'makerworld', name: 'MakerWorld', url: 'https://makerworld.com', icon: '🧩', bg: 'linear-gradient(145deg,#35e0a8,#0a9f6e)' },
  { id: 'hmh', name: 'HMH Ed', url: 'https://www.hmhco.com/ui/login/', icon: '📖', bg: 'linear-gradient(145deg,#ff5f7e,#b3123a)' },
  { id: 'flashforge', name: 'FlashForge Printer', builtin: 'printer', icon: '🖨️', bg: 'linear-gradient(145deg,#4b5163,#15171f)' },
  { id: 'stocks', name: 'Robinhood Stocks', builtin: 'stocks', icon: '📈', bg: 'linear-gradient(145deg,#2c2c2e,#000)' },
  { id: 'guides', name: 'Study Guides', builtin: 'guides', icon: '📘', bg: 'linear-gradient(145deg,#6e6cff,#2d2b9a)' },
];
const LOGOS = { livetop: 'assets/logos/livetop.png', gdocs: 'assets/logos/google-docs.png', gdrive: 'assets/logos/google-drive.png', horizons: 'assets/logos/horizons-academy.png', nayzak: 'assets/logos/horizons-courses.png', makerworld: 'assets/logos/makerworld.png', hmh: 'assets/logos/hmh-ed.png', flashforge: 'assets/logos/flashforge.png', stocks: 'assets/logos/robinhood.png' };
DEFAULT_APPS.forEach(x => { if (LOGOS[x.id]) x.image = LOGOS[x.id]; });
const DOCK_IDS = ['livetop', 'gdocs', 'stocks', 'guides'];
function allApps() {
  const hidden = new Set(lsGet(LS.hidden, []));
  const fromData = (state.data && Array.isArray(state.data.apps) && state.data.apps.length) ? state.data.apps : DEFAULT_APPS;
  const custom = lsGet(LS.apps, []).map(a => ({ ...a, custom: true }));
  return [...fromData, ...custom].filter(a => !hidden.has(a.id));
}
function iconHtml(a0) {
  const a = Object.assign({}, a0, imgOf(a0) ? { image: imgOf(a0) } : {});
  const inner = a.image ? `<img src="${a.image}" alt="">` : a.svg ? a.svg : /^https?:\/\//.test(a.icon || '') ? `<img src="${esc(a.icon)}" alt="">` : (a.icon && /\p{Extended_Pictographic}/u.test(a.icon)) ? `<span>${esc(a.icon)}</span>` : `<span class="glyph-text">${esc((a.icon || a.name || '?').slice(0, 2))}</span>`;
  return `<div class="icon${a.image ? ' logo' : ''}" style="background:${a.image ? '#ffffff' : esc(a.bg || a.color || '#5e5ce6')}">${inner}</div>`;
}
function appHtml(a, inDock) {
  const href = a.builtin ? '#' : a.url;
  const badge = a.builtin ? '' : `<button type="button" class="pv-badge" data-pv="${esc(a.id)}" aria-label="Preview ${esc(a.name)}">👁</button>`;
  return `<a class="app-item ${a.custom ? 'custom' : ''}" href="${esc(href)}" ${a.builtin ? `data-builtin="${esc(a.builtin)}"` : 'target="_blank" rel="noopener"'} data-app="${esc(a.id)}" title="${esc(a.name)}">${badge}${iconHtml(a)}<span class="app-label">${esc(a.name)}</span></a>`;
}
function renderApps() {
  const apps = allApps();
  $('#app-grid').innerHTML = apps.map(a => appHtml(a)).join('');
  $('#dock').innerHTML = DOCK_IDS.map(id => apps.find(a => a.id === id)).filter(Boolean).map(a => appHtml(a, true)).join('');
}
function findApp(id) { return allApps().find(a => a.id === id); }
document.addEventListener('click', e => {
  const badge = e.target.closest('.pv-badge');
  if (badge) { e.preventDefault(); e.stopPropagation(); const a = findApp(badge.dataset.pv); if (a) showPreview(a, badge.closest('.app-item')); return; }
  const item = e.target.closest('.app-item');
  if (item && item.dataset.builtin) { e.preventDefault(); openBuiltin(item.dataset.builtin); return; }
  if (item && longPressed) { e.preventDefault(); longPressed = false; }
});
function openBuiltin(which) { if (which === 'stocks') openStocks(); else if (which === 'guides') openGuides(); else if (which === 'printer') $('#widget-printer').scrollIntoView({ behavior: 'smooth', block: 'center' }); }

/* -------------------------------------------------------------- previews */
const previewsOn = () => lsGet(LS.previews, true);
const thumbUrl = (url, bust) => `https://s0.wp.com/mshots/v1/${encodeURIComponent(url)}?w=640&h=400${bust ? `&_=${bust}` : ''}`;
const favUrl = url => { try { return `https://www.google.com/s2/favicons?domain=${new URL(url).hostname}&sz=64`; } catch { return ''; } };
const pv = $('#preview'); let pvApp = null, pvTimer = null, pvRetry = 0, hoverTimer = null, longPressed = false;
function showPreview(app, anchor) {
  if (!app || app.builtin) return;
  pvApp = app; pvRetry = 0;
  $('#pv-name').textContent = app.name;
  try { $('#pv-host').textContent = new URL(app.url).hostname; } catch { $('#pv-host').textContent = app.url; }
  $('#pv-favicon').src = favUrl(app.url);
  $('#pv-open').href = app.url;
  $('#pv-remove').hidden = !app.custom;
  pv.hidden = false;
  loadThumb(app.url, false);
  if (!isTouch && anchor) {
    const r = anchor.getBoundingClientRect(); const w = 340, h = 330; let left = r.left + r.width / 2 - w / 2, top = r.bottom + 10;
    left = Math.max(12, Math.min(innerWidth - w - 12, left));
    if (top + h > innerHeight - 20) top = Math.max(12, r.top - h - 10);
    pv.style.left = left + 'px'; pv.style.top = top + 'px'; pv.style.bottom = 'auto';
  }
}
function loadThumb(url, bust) {
  const img = $('#pv-img'), ld = $('#pv-loading'); clearTimeout(pvTimer);
  if (!previewsOn()) { img.removeAttribute('src'); ld.textContent = 'Live previews are off (Settings)'; ld.hidden = false; return; }
  ld.textContent = 'Loading preview…'; ld.hidden = false;
  img.onload = () => { ld.hidden = true; if (pvRetry < 2) { pvRetry++; pvTimer = setTimeout(() => { if (!pv.hidden && pvApp && pvApp.url === url) { const i2 = new Image(); i2.onload = () => { img.src = i2.src; }; i2.src = thumbUrl(url, Date.now()); } }, 4000); } };
  img.onerror = () => { ld.textContent = 'Preview unavailable'; };
  img.src = thumbUrl(url, bust ? Date.now() : '');
}
function hidePreview() { pv.hidden = true; pvApp = null; clearTimeout(pvTimer); }
$('#pv-close').addEventListener('click', hidePreview);
$('#pv-refresh').addEventListener('click', () => pvApp && loadThumb(pvApp.url, true));
$('#pv-remove').addEventListener('click', () => { if (!pvApp) return; lsSet(LS.apps, lsGet(LS.apps, []).filter(a => a.id !== pvApp.id)); hidePreview(); renderApps(); toast('App removed'); });
document.addEventListener('pointerdown', e => { if (!pv.hidden && !pv.contains(e.target) && !e.target.closest('.pv-badge')) hidePreview(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') { hidePreview(); const s = $('.sheet.open'); if (s) closeSheet(s); $('#lightbox').hidden = true; } });
// Desktop hover previews
document.addEventListener('mouseover', e => {
  if (isTouch || !previewsOn()) return;
  const item = e.target.closest('.app-item'); if (!item || item.dataset.builtin) return;
  clearTimeout(hoverTimer); hoverTimer = setTimeout(() => { const a = findApp(item.dataset.app); if (a) showPreview(a, item); }, 500);
});
document.addEventListener('mouseout', e => { const item = e.target.closest('.app-item'); if (item) clearTimeout(hoverTimer); });
// Touch long-press previews
let lpTimer = null;
document.addEventListener('touchstart', e => { const item = e.target.closest('.app-item'); if (!item || item.dataset.builtin) return; lpTimer = setTimeout(() => { longPressed = true; const a = findApp(item.dataset.app); if (a) { showPreview(a, item); if (navigator.vibrate) navigator.vibrate(15); } }, 480); }, { passive: true });
['touchend', 'touchmove', 'touchcancel'].forEach(ev => document.addEventListener(ev, () => clearTimeout(lpTimer), { passive: true }));

/* ------------------------------------------------------------------ sheets */
function openSheet(el) { el.inert = false; el.classList.add('open'); el.setAttribute('aria-hidden', 'false'); hidePreview(); }
function closeSheet(el) { if (el.contains(document.activeElement) && document.activeElement.blur) document.activeElement.blur(); el.inert = true; el.classList.remove('open'); el.setAttribute('aria-hidden', 'true'); }
$$('.sheet').forEach(s => s.addEventListener('click', e => { if (e.target.closest('[data-close]')) closeSheet(s); }));

/* ----------------------------------------------------------------- add app */
let aaImage = null;
$('#aa-file').addEventListener('change', e => {
  const f = e.target.files && e.target.files[0]; if (!f) return;
  if (!/^image\//.test(f.type)) { toast('Please choose an image file'); return; }
  const src = URL.createObjectURL(f); const img = new Image();
  img.onload = () => {
    const s = 128, c = document.createElement('canvas'); c.width = s; c.height = s;
    const x = c.getContext('2d'), k = Math.max(s / img.width, s / img.height), w = img.width * k, h = img.height * k;
    x.drawImage(img, (s - w) / 2, (s - h) / 2, w, h);
    aaImage = c.toDataURL('image/png');
    $('#aa-icon-preview').innerHTML = `<img src="${aaImage}" alt="" style="width:100%;height:100%;object-fit:cover;border-radius:inherit">`;
    $('#aa-img-note').textContent = 'Using image: ' + f.name;
    URL.revokeObjectURL(src);
  };
  img.onerror = () => { toast('Could not read that image'); URL.revokeObjectURL(src); };
  img.src = src;
});
$('#btn-add-app').addEventListener('click', () => { $('#addapp-form').reset(); aaImage = null; $('#aa-img-note').textContent = 'No image chosen. The icon above is used.'; $('#aa-icon-preview').textContent = '📚'; $('#aa-icon-preview').style.background = '#5e5ce6'; $('#aa-thumb').removeAttribute('src'); openSheet($('#sheet-addapp')); setTimeout(() => $('#aa-name').focus(), 100); });
$('#aa-icon').addEventListener('input', e => { $('#aa-icon-preview').textContent = e.target.value.trim() || ($('#aa-name').value.trim().slice(0, 2) || '📚'); });
$('#aa-name').addEventListener('input', e => { if (!aaImage && !$('#aa-icon').value.trim()) $('#aa-icon-preview').textContent = e.target.value.trim().slice(0, 2) || '📚'; });
$('#aa-color').addEventListener('input', e => { $('#aa-icon-preview').style.background = e.target.value; });
let aaTimer; $('#aa-url').addEventListener('input', e => { clearTimeout(aaTimer); const v = e.target.value.trim(); if (!/^https?:\/\/\S+\.\S+/.test(v) || !previewsOn()) return; aaTimer = setTimeout(() => { $('#aa-thumb').src = thumbUrl(v); }, 700); });
$('#addapp-form').addEventListener('submit', e => {
  e.preventDefault();
  let url = $('#aa-url').value.trim(); if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  const name = $('#aa-name').value.trim(); const icon = $('#aa-icon').value.trim() || name.slice(0, 2); const color = $('#aa-color').value;
  const apps = lsGet(LS.apps, []); const aid = 'u-' + Date.now().toString(36); if (aaImage) idbPut('img-' + aid, aaImage).catch(() => {}); apps.push({ id: aid, name, url, icon, imageKey: aaImage ? 'img-' + aid : undefined, bg: `linear-gradient(145deg, ${color}, ${shade(color, -35)})` }); lsSet(LS.apps, apps);
  closeSheet($('#sheet-addapp')); renderApps(); toast(`${name} added to your Home Screen`);
});
function shade(hexc, amt) { const n = parseInt(hexc.slice(1), 16); const c = v => Math.max(0, Math.min(255, v + amt)); return '#' + [(n >> 16) & 255, (n >> 8) & 255, n & 255].map(v => c(v).toString(16).padStart(2, '0')).join(''); }

/* ------------------------------------------------------------------ stocks */
const ACTIONS = ['WATCH', 'HOLD', 'BUY MORE', 'SET LIMIT ORDER', 'TRIM'];
const actionColor = a => ({ 'BUY MORE': 'green', 'TRIM': 'red', 'SET LIMIT ORDER': 'orange', 'HOLD': 'blue', 'WATCH': 'gray' }[a] || 'gray');
function stockRows() { const s = (state.data && state.data.stocks) || {}; return [...(s.holdings || []).map(h => ({ ...h, held: true })), ...(s.watchlist || [])]; }
function actionFor(r) { const o = lsGet(LS.actions, {}); return o[r.ticker] || r.action || (r.held ? 'HOLD' : 'WATCH'); }
function noteFor(r) { const o = lsGet(LS.notes, {}); return o[r.ticker] != null ? o[r.ticker] : (r.plan || ''); }
function signalFor(r) {
  const L = r.levels || {}; const p = +r.price || 0; const parts = []; let cls = 'gray';
  if (L.sma50 && L.sma200) {
    if (p > L.sma50 && L.sma50 > L.sma200) { parts.push('Uptrend'); cls = 'green'; }
    else if (p < L.sma50 && p > L.sma200) { parts.push('Pullback'); cls = 'orange'; }
    else if (p < L.sma50 && p < L.sma200) { parts.push('Downtrend'); cls = 'red'; }
    else { parts.push('Mixed trend'); cls = 'gray'; }
  }
  if (L.rsi14 != null) { if (L.rsi14 >= 70) parts.push('overbought'); else if (L.rsi14 <= 30) parts.push('oversold'); }
  if (L.low20 && p <= L.low20 * 1.02) parts.push('at 20d support'); else if (L.high20 && p >= L.high20 * 0.98) parts.push('at 20d resistance');
  return { label: parts.join(' · ') || 'No data', cls };
}
function openStocks() { openSheet($('#sheet-stocks')); renderStocks(); switchTab('overview'); }
function switchTab(name) { $$('#stocks-tabs .tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name)); $$('#sheet-stocks .tabpane').forEach(p => p.classList.toggle('active', p.dataset.pane === name)); if (name === 'shots') loadScreenshots(); }
$('#stocks-tabs').addEventListener('click', e => { const t = e.target.closest('.tab'); if (t) switchTab(t.dataset.tab); });
function renderStocks() {
  const s = (state.data && state.data.stocks) || {}; const sum = s.summary || {};
  $('#stocks-asof').textContent = s.as_of ? 'As of ' + relTime(s.as_of) : '';
  const stats = [
    ['Portfolio value', money(sum.total_value || 0), sum.day_change != null ? `<span class="${sum.day_change >= 0 ? 'up' : 'down'}">${money(sum.day_change)} today</span>` : ''],
    ['Cash', money(sum.cash || 0), sum.unsettled ? `${money(sum.unsettled)} unsettled` : ''],
    ['Buying power', money(sum.buying_power || 0), ''],
    ['Realized P&amp;L (YTD)', `<span class="${(sum.realized_ytd || 0) >= 0 ? 'up' : 'down'}">${money(sum.realized_ytd || 0)}</span>`, sum.realized_ytd_pct != null ? pct(sum.realized_ytd_pct) : ''],
    ['Realized P&amp;L (90d)', `<span class="${(sum.realized_90d || 0) >= 0 ? 'up' : 'down'}">${money(sum.realized_90d || 0)}</span>`, sum.trades_90d != null ? `${sum.trades_90d} closing trades` : ''],
  ];
  const accounts = (s.accounts || []).map(a => `<div class="kv"><span>${esc(a.label)} ••••${esc(a.last4 || '')}</span><b>${money(a.value || 0)}</b></div>`).join('');
  const trades = (s.recent_trades || []).slice(0, 12).map(t => `<li><span class="muted">${esc(t.date)}</span><span class="${t.side === 'buy' ? 'up' : 'down'}">${esc(String(t.side).toUpperCase())}</span><span><b>${esc(t.ticker)}</b> ${esc(num(t.qty, +t.qty % 1 ? 4 : 0))} @ ${money(t.price)}</span><span class="${(t.realized || 0) >= 0 ? 'up' : 'down'}">${t.realized != null ? money(t.realized) : ''}</span></li>`).join('');
  const rows = stockRows();
  const act = rows.filter(r => actionFor(r) !== 'HOLD' && actionFor(r) !== 'WATCH');
  $('#pane-overview').innerHTML = `
    <div class="stats">${stats.map(([k, v, d]) => `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div><div class="d">${d}</div></div>`).join('')}</div>
    ${goalHtml(sum)}<div class="twocol">
      <div class="box"><h3>Recent trades</h3>${trades ? `<ul class="trades">${trades}</ul>` : '<p class="muted small">No trades in the window.</p>'}</div>
      <div>
        <div class="box" style="margin-bottom:12px"><h3>Accounts</h3>${accounts || '<p class="muted small">No account data</p>'}</div>
        <div class="box"><h3>Action items</h3>${act.length ? act.map(r => `<div class="kv"><span><b>${esc(r.ticker)}</b> <span class="tag ${actionColor(actionFor(r))}">${esc(actionFor(r))}</span></span><span class="muted small">${esc(signalFor(r).label)}</span></div>`).join('') : '<p class="muted small">No action tags set. Tag any ticker in Holdings &amp; Watchlist.</p>'}</div>
      </div>
    </div>
    ${s.notes ? `<div class="box" style="margin-top:12px"><h3>Sync notes</h3><p class="small" style="margin:0;white-space:pre-wrap">${esc(s.notes)}</p></div>` : ''}
    <p class="disclaimer">${esc(s.disclaimer || 'Signals are mechanical descriptions of price vs. moving averages, RSI and recent ranges. Analyst targets are third-party data. Nothing here is investment advice — you decide every trade.')}</p>`;
  renderHoldings();
}
function renderHoldings() {
  const rows = stockRows();
  if (!rows.length) { $('#pane-holdings').innerHTML = '<p class="muted">No holdings or watchlist items yet.</p>'; return; }
  const body = rows.map(r => {
    const L = r.levels || {}; const sig = signalFor(r); const a = actionFor(r);
    const vs50 = L.sma50 ? ((r.price / L.sma50 - 1) * 100) : null; const vs200 = L.sma200 ? ((r.price / L.sma200 - 1) * 100) : null;
    const earn = r.earnings && r.earnings.date ? `${esc(r.earnings.date)}${r.earnings.timing ? ' ' + esc(r.earnings.timing.toUpperCase()) : ''}${r.earnings.verified === false ? ' <span class="muted">(est.)</span>' : ''}` : '—';
    const held = r.held ? `<div class="sub">${esc(num(r.shares, 4))} sh · avg ${money(r.avg_cost)}</div>` : '';
    return `<tr class="main" data-t="${esc(r.ticker)}"><td><span class="sym">${esc(r.ticker)}</span><span class="name">${esc(r.name || '')}</span>${held}</td>
      <td><b>${money(r.price)}</b><div class="sub ${r.day_change_pct >= 0 ? 'up' : 'down'}">${r.day_change_pct != null ? pct(r.day_change_pct) : ''}</div></td>
      <td>${vs50 != null ? `<span class="${vs50 >= 0 ? 'up' : 'down'}">${pct(vs50)}</span>` : '—'}<div class="sub">${vs200 != null ? `<span class="${vs200 >= 0 ? 'up' : 'down'}">${pct(vs200)}</span> vs 200d` : ''}</div></td>
      <td>${L.rsi14 != null ? num(L.rsi14, 0) : '—'}</td>
      <td><span class="tag ${sig.cls}">${esc(sig.label)}</span></td>
      <td><select class="action-select" data-act="${esc(r.ticker)}">${ACTIONS.map(x => `<option ${x === a ? 'selected' : ''}>${x}</option>`).join('')}</select></td>
      <td class="small">${earn}</td></tr>
      <tr class="detail" data-for="${esc(r.ticker)}" hidden><td colspan="7">${detailHtml(r)}</td></tr>`;
  }).join('');
  $('#pane-holdings').innerHTML = `<div class="tbl-wrap"><table class="hold"><thead><tr><th>Ticker</th><th>Price</th><th>vs 50d</th><th>RSI 14</th><th>Signal</th><th>Action tag</th><th>Next earnings</th></tr></thead><tbody>${body}</tbody></table></div>
    <p class="disclaimer">Tap a row for levels, analyst targets, catalysts and your plan notes. Action tags and notes are yours and stay in this browser. Signals are mechanical, not advice.</p>`;
}
function detailHtml(r) {
  const L = r.levels || {}; const A = r.analyst || {}; const p = +r.price || 0;
  const kv = (k, v) => v == null || v === '' ? '' : `<div class="kv"><span>${k}</span><b>${v}</b></div>`;
  const up = A.target_mean ? ((A.target_mean / p - 1) * 100) : null;
  return `<div class="detail-grid">
    <div><h4>Technical levels</h4>${kv('20-day low / high', L.low20 ? `${money(L.low20)} / ${money(L.high20)}` : null)}${kv('60-day low / high', L.low60 ? `${money(L.low60)} / ${money(L.high60)}` : null)}${kv('52-week low / high', L.low52 ? `${money(L.low52)} / ${money(L.high52)}` : null)}${kv('50-day avg', L.sma50 ? money(L.sma50) : null)}${kv('200-day avg', L.sma200 ? money(L.sma200) : null)}${kv('ATR (14d)', L.atr14 ? money(L.atr14) : null)}${kv('Prev close', r.prev_close ? money(r.prev_close) : null)}</div>
    <div><h4>Analysts</h4>${kv('Buy / Hold / Sell', A.buy != null ? `${A.buy} / ${A.hold} / ${A.sell}` : null)}${kv('Avg target', A.target_mean ? `${money(A.target_mean)} <span class="${up >= 0 ? 'up' : 'down'}">(${pct(up)})</span>` : null)}${kv('Target range', A.target_low ? `${money(A.target_low)} – ${money(A.target_high)}` : null)}${kv('P/E', r.pe != null ? num(r.pe, 1) : null)}${kv('Market cap', r.market_cap ? fmtCap(r.market_cap) : null)}</div>
    <div><h4>Catalysts &amp; plan</h4>${(r.catalysts || []).length ? `<ul class="plain small">${r.catalysts.map(c => `<li>${esc(c)}</li>`).join('')}</ul>` : '<p class="muted small">No catalysts listed.</p>'}
      <textarea class="plan-note" data-note="${esc(r.ticker)}" placeholder="Your plan for ${esc(r.ticker)} (entry, target, stop)…">${esc(noteFor(r))}</textarea>
      <div class="form-actions"><button type="button" class="pill tiny accent" data-ticket="${esc(r.ticker)}">Build order ticket</button><a class="pill tiny" target="_blank" rel="noopener" href="https://robinhood.com/stocks/${esc(r.ticker)}">Open on Robinhood</a></div></div>
  </div>`;
}
/* Trading-bot alignment: rules and scans come from ~/trading-bot (CLAUDE.md + journal), synced into data.trading_bot. */
const BOT_RULES = { budget: 500, max_risk: 10, min_rr: 2, window_et: '11:30 AM – 2:30 PM ET' };
const bot = () => (state.data && state.data.trading_bot) || null;
function goalHtml(sum) {
  const g = (state.data && state.data.goal) || {}; const b = bot() || {}; const ex = b.expectancy || {};
  const start = g.start_balance ?? BOT_RULES.budget, target = g.monthly_profit_goal ?? 1000;
  const cur = +(g.current_balance ?? sum.total_value ?? 0);
  const made = +(g.month_realized ?? 0);
  const done = Math.max(0, Math.min(100, made / target * 100));
  const fund = cur < start;
  const winner = BOT_RULES.max_risk * BOT_RULES.min_rr;
  const note = fund ? `Deposit ${money(start - cur)} into the MCP portfolio to start the ${money(start, 0)} plan.`
    : `${money(target, 0)}/month on ${money(cur, 0)} is a ${Math.round(target / Math.max(cur, 1) * 100)}% monthly return. At ${money(BOT_RULES.max_risk, 0)} max risk a 2:1 winner makes about ${money(winner, 0)} (${(winner / target * 100).toFixed(0)}% of the goal), so the goal isn't reachable without more capital. The rules never raise risk to chase it.`;
  return `<div class="box goal-box"><h3>${money(target, 0)}/month goal · ${money(cur, 0)} account</h3>
    <div class="kv"><span>Realized this month</span><b class="${made >= 0 ? 'up' : 'down'}">${money(made)}</b></div>
    <div class="bar-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(done)}"><div class="bar-fill" style="width:${done.toFixed(1)}%"></div></div>
    <div class="small muted">${done.toFixed(1)}% of ${money(target, 0)}. ${esc(note)}</div>
    ${ex.weekly_low != null ? `<div class="kv" style="margin-top:8px"><span>Realistic expectancy</span><b>${money(ex.weekly_low, 0)}–${money(ex.weekly_high, 0)}/week · ${money(ex.monthly_low, 0)}–${money(ex.monthly_high, 0)}/month</b></div>` : ''}
    ${swingPlanHtml()}</div>`;
}
function swingPlanHtml() {
  const b = bot();
  const rules = `<ul class="plain small rules-list">
      <li><b>Halal gate first</b> (AAOIFI): permissible business, debt &lt; 30% and cash &lt; 30% of market cap, non-permissible income &lt; 5%. Unverified = reject.</li>
      <li><b>${money(BOT_RULES.budget, 0)} cash, no margin, whole shares.</b> Max loss ${money(BOT_RULES.max_risk, 0)} per trade (2%). Reward:risk ≥ ${BOT_RULES.min_rr}:1. Hard stop on every trade.</li>
      <li><b>Swing, not day trade:</b> hold overnight or longer, so no PDT round trips. Buy window ${BOT_RULES.window_et}.</li>
      <li><b>Insiders:</b> block heavy CEO/insider selling or bad news; prefer open-market insider buying.</li>
      <li><b>Preview only.</b> Claude scores and previews. You say YES and place the order yourself.</li></ul>`;
  if (!b) return `<div class="goal-plan"><h3>Halal swing plan</h3>${rules}<p class="small muted">No trading-bot scan synced yet. Tap “Run Halal scan”.</p></div>`;
  const s = b.last_scan || {};
  const buying = /BUY/i.test(s.verdict || '') && !/NO TRADE/i.test(s.verdict || '');
  const rows = (b.watchlist || []).map(w => `<tr>
      <td><b>${esc(w.ticker)}</b>${w.priority ? ' <span class="tag green">priority</span>' : ''}<div class="sub">${esc(w.status || 'WATCH')}</div></td>
      <td>${money(w.price)}<div class="sub">ATR ${num(w.atr_pct, 1)}%</div></td>
      <td>${money(w.entry)} / <span class="down">${money(w.stop)}</span> / <span class="up">${money(w.target)}</span><div class="sub">${esc(String(w.qty))} sh · ${money(w.qty * w.entry, 0)}</div></td>
      <td><span class="up">+${money(w.reward)}</span> / <span class="down">−${money(w.risk)}</span><div class="sub">${num(w.goal_pct, 2)}% of goal</div></td>
      <td class="small">${esc(w.insider || '')}</td></tr>`).join('');
  const rejects = Object.entries(b.rejected || {}).map(([t, why]) => `<b>${esc(t)}</b> ${esc(why)}`).join(' · ');
  return `<div class="goal-plan"><h3>Halal swing plan</h3>
    <div class="verdict ${buying ? 'buy' : 'hold'}"><b>${esc(s.verdict || '—')}</b><span class="small">${esc(s.reason || '')}</span><span class="small muted">Scan ${s.at ? esc(relTime(s.at)) : '—'}${s.universe ? ` · ${esc(String(s.universe))} scanned → ${esc(String(s.halal_pass))} Halal pass` : ''}</span></div>
    ${rows ? `<div class="tbl-wrap"><table class="hold swing"><thead><tr><th>Watching</th><th>Price</th><th>Entry / stop / target</th><th>+$ / −$</th><th>Insiders</th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="small muted">Nothing on the watchlist.</p>'}
    ${rejects ? `<p class="small muted" style="margin-top:8px">Rejected: ${rejects}</p>` : ''}
    ${(b.events || []).length ? `<h4 style="margin:12px 0 4px">This week</h4><ul class="plain small">${b.events.map(e => `<li><b>${esc(e.when)}</b> ${esc(e.what)}</li>`).join('')}</ul>` : ''}
    <details class="small" style="margin-top:8px"><summary>Rules</summary>${rules}</details>
    <p class="disclaimer">Plans are conditional: each needs a pullback that holds and a bounce confirmed inside the window. The Halal screen is a filter, not a fatwa. Not investment advice. You place every order.</p></div>`;
}
function fmtCap(n) { n = +n; if (n >= 1e12) return '$' + (n / 1e12).toFixed(2) + 'T'; if (n >= 1e9) return '$' + (n / 1e9).toFixed(1) + 'B'; if (n >= 1e6) return '$' + (n / 1e6).toFixed(0) + 'M'; return money(n, 0); }
$('#pane-holdings').addEventListener('click', e => {
  if (e.target.closest('select, textarea, a, button')) { const b = e.target.closest('[data-ticket]'); if (b) { prefillTicket({ symbol: b.dataset.ticket }); switchTab('ticket'); } return; }
  const tr = e.target.closest('tr.main'); if (!tr) return;
  const d = $(`tr.detail[data-for="${tr.dataset.t}"]`); if (d) d.hidden = !d.hidden;
});
$('#pane-holdings').addEventListener('change', e => {
  if (e.target.matches('[data-act]')) { const o = lsGet(LS.actions, {}); o[e.target.dataset.act] = e.target.value; lsSet(LS.actions, o); renderBriefing(); toast(`${e.target.dataset.act}: ${e.target.value}`); }
});
$('#pane-holdings').addEventListener('input', e => { if (e.target.matches('[data-note]')) { const o = lsGet(LS.notes, {}); o[e.target.dataset.note] = e.target.value; lsSet(LS.notes, o); } });

async function loadScreenshots() {
  const pane = $('#pane-shots'); const list = (state.data && state.data.stocks && state.data.stocks.screenshots) || [];
  if (state.shotsLoaded) return;
  if (!list.length) { pane.innerHTML = '<p class="muted">No Robinhood screenshots yet. Sign in to Robinhood in the built-in browser once, then run /morning-sync — Claude captures the portfolio, chart and holdings and encrypts them before publishing.</p>'; return; }
  pane.innerHTML = `<div class="shots">${list.map((s, i) => `<figure class="shot" data-i="${i}"><img alt="${esc(s.label || 'Screenshot')}" id="shot-${i}"><figcaption class="cap"><b>${esc(s.label || s.file)}</b><span>${s.taken_at ? esc(relTime(s.taken_at)) : ''}</span></figcaption></figure>`).join('')}</div>`;
  state.shotsLoaded = true;
  for (const [i, s] of list.entries()) {
    try { const buf = await decryptFile(s.file); const url = URL.createObjectURL(new Blob([buf], { type: s.mime || 'image/png' })); state.urls.push(url); const img = $(`#shot-${i}`); if (img) { img.src = url; img.dataset.cap = `${s.label || ''} — ${s.taken_at ? new Date(s.taken_at).toLocaleString() : ''}`; } }
    catch (e) { console.warn(e); const img = $(`#shot-${i}`); if (img) img.alt = 'Could not decrypt ' + s.file; }
  }
}
$('#pane-shots').addEventListener('click', e => { const img = e.target.closest('img'); if (!img || !img.src) return; $('#lb-img').src = img.src; $('#lb-cap').textContent = img.dataset.cap || ''; $('#lightbox').hidden = false; });
$('#lightbox').addEventListener('click', () => { $('#lightbox').hidden = true; });

/* ------------------------------------------------------------ order ticket */
function prefillTicket(o) {
  if (o.symbol) $('#tk-symbol').value = o.symbol.toUpperCase();
  if (o.side) $('#tk-side').value = o.side;
  if (o.type) $('#tk-type').value = o.type;
  if (o.unit) $('#tk-unit').value = o.unit;
  if (o.amount) $('#tk-amount').value = o.amount;
  if (o.limit) $('#tk-limit').value = o.limit;
  $('#tk-limit-wrap').hidden = $('#tk-type').value !== 'limit';
  openSheet($('#sheet-stocks')); if (!$('#pane-overview').innerHTML) renderStocks();
  if (o.build) buildTicket();
}
$('#tk-type').addEventListener('change', e => { $('#tk-limit-wrap').hidden = e.target.value !== 'limit'; });
function buildTicket() {
  const sym = $('#tk-symbol').value.trim().toUpperCase(); const side = $('#tk-side').value; const type = $('#tk-type').value; const unit = $('#tk-unit').value; const amt = +$('#tk-amount').value; const lim = +$('#tk-limit').value; const tif = $('#tk-tif').value;
  if (!sym || !amt) { toast('Enter a ticker and an amount'); return; }
  const qty = unit === 'dollars' ? money(amt) + ' worth' : `${amt} share${amt === 1 ? '' : 's'}`;
  const text = `Prepare a Robinhood ${side.toUpperCase()} order for ${sym}: ${type} order, ${qty}${type === 'limit' && lim ? `, limit price ${money(lim)}` : ''}, ${tif === 'gtc' ? 'good till cancelled' : 'good for the day'}.\n\nFirst give me a quick read on ${sym} (price vs. 50/200-day averages, RSI, next earnings, analyst range). Then open Robinhood in the built-in browser, fill this ticket up to the Review Order screen, screenshot it for me, and STOP there. Do not press Submit — I will press it myself.`;
  $('#tk-out').textContent = text; $('#tk-copy').disabled = false; $('#tk-share').hidden = !navigator.share;
  const open = $('#tk-open'); open.href = `https://robinhood.com/stocks/${sym}`; open.hidden = false;
  return text;
}
$('#ticket').addEventListener('submit', e => { e.preventDefault(); buildTicket(); });
$('#tk-copy').addEventListener('click', async () => { await copyText($('#tk-out').textContent); });
$('#tk-share').addEventListener('click', () => navigator.share({ title: 'Trade command for Claude', text: $('#tk-out').textContent }).catch(() => {}));
async function copyText(t) { try { await navigator.clipboard.writeText(t); toast('Copied — paste it to Claude'); } catch { toast('Select the text and copy it manually'); } }

/* ------------------------------------------------------------ study guides */
function guides() { return (state.data && state.data.study_guides) || []; }
function openGuides(id) { openSheet($('#sheet-guides')); renderGuides(id); }
function renderGuides(activeId) {
  const g = guides(); const list = $('#guides-list');
  list.innerHTML = g.length ? g.map(x => `<li><button type="button" data-g="${esc(x.id)}" class="${x.id === activeId ? 'active' : ''}"><b>${esc(x.title)}</b><span>${esc([x.course, x.created_at ? new Date(x.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : ''].filter(Boolean).join(' · '))}</span></button></li>`).join('') : '<li class="muted small" style="padding:8px">No study guides yet. Press “Make Study Guide” on an assignment, then paste the command to Claude.</li>';
  const active = g.find(x => x.id === activeId) || g[0];
  $('#guide-view').innerHTML = active ? guideHtml(active) : '<p class="muted">Pick a study guide on the left, or press “Make Study Guide” on any assignment.</p>';
}
function guideHtml(g) {
  const sec = (title, inner) => inner ? `<h3>${title}</h3>${inner}` : '';
  return `<h2>${esc(g.title)}</h2><div class="gmeta">${esc([g.course, g.source, g.created_at ? 'Made ' + new Date(g.created_at).toLocaleDateString() : ''].filter(Boolean).join(' · '))}</div>
    ${g.summary ? `<p>${esc(g.summary)}</p>` : ''}
    ${(g.charts || []).map(svgBarChart).join('')}
    ${(g.el5 || []).length ? `<details class="el5"><summary>👶 Explain More (Like I'm a Baby)</summary>${g.el5.map(s => `<div class="step"><b>${esc(s.title)}</b>${esc(s.text)}</div>`).join('')}</details>` : ''}
    ${sec('🎯 Memorize this: key terms', (g.key_terms || []).length ? `<dl>${g.key_terms.map(t => `<dt>${esc(t.term)}</dt><dd>${esc(t.definition)}</dd>`).join('')}</dl>` : '')}
    ${sec('💡 Understand this: main concepts', (g.concepts || []).length ? `<ul>${g.concepts.map(c => `<li>${c.heading ? `<b>${esc(c.heading)}:</b> ` : ''}${esc(c.text)}</li>`).join('')}</ul>` : '')}
    ${sec('Worked examples', (g.examples || []).length ? g.examples.map(x => `<div class="example"><b>${esc(x.title)}</b><ol>${(x.steps || []).map(s => `<li>${esc(s)}</li>`).join('')}</ol></div>`).join('') : '')}
    ${sec('Self-check', (g.practice || []).length ? g.practice.map((q, i) => `<details><summary>${i + 1}. ${esc(q.q)}</summary><p>${esc(q.a)}</p></details>`).join('') : '')}
    ${g.tips ? sec('Tips', `<p>${esc(g.tips)}</p>`) : ''}`;
}
$('#guides-list').addEventListener('click', e => { const b = e.target.closest('[data-g]'); if (b) renderGuides(b.dataset.g); });
$('#guides-request').addEventListener('click', () => openCommand(studyGuideCommand(null), 'Request a study guide'));
function studyGuideCommand(a) {
  const what = a ? `"${a.title}"${a.course ? ` for ${a.course}` : ''}${a.due ? ` (due ${a.due})` : ''}` : 'my next assignment';
  return `Make me a study guide for ${what}.\n\nUse the /morning-sync study-guide procedure: open HMH Ed, find the matching textbook chapter/lesson, read the sections that cover this topic, and write the guide in simple 9th-grade language with key terms, main concepts, worked examples and self-check questions. Save it into data.json under study_guides and run ./publish.sh so it shows up in my Study Guides app.`;
}
function requestStudyGuide(id) {
  const a = ((state.data && state.data.assignments) || []).find(x => x.id === id) || allTodos().find(t => t.id === id);
  const existing = guides().find(g => g.assignment_id === id);
  if (existing) { openGuides(existing.id); return; }
  openCommand(studyGuideCommand(a || { title: 'this assignment' }), 'Make Study Guide');
}
function openCommand(text, title) { $('#cmd-desc').textContent = 'This page can\'t talk to Claude directly, so copy (or share) this message and paste it to Claude. Claude will do the work and publish the result back here.'; $('#cmd-title').textContent = title || 'Send to Claude'; $('#cmd-text').textContent = text; $('#cmd-share').hidden = !navigator.share; openSheet($('#sheet-cmd')); }
$('#cmd-copy').addEventListener('click', () => copyText($('#cmd-text').textContent));
$('#cmd-share').addEventListener('click', () => navigator.share({ title: 'For Claude', text: $('#cmd-text').textContent }).catch(() => {}));

/* ------------------------------------------------------------- command bar */
function runCommand(raw) {
  const t = raw.trim(); if (!t) return; const l = t.toLowerCase(); let m;
  if ((m = t.match(/^(?:add|remind me to|todo:?|task:?)\s+(.+?)(?:\s+to my (?:list|to-?do(?: list)?|reminders|tasks))?\.?$/i))) { addTodo(cap(m[1].trim())); toast('Added to your list'); return; }
  if (/^(run\s+)?(halal|swing|trading[- ]bot)\s+scan/.test(l)) { openCommand(HALAL_SCAN_CMD, 'Run Halal scan'); return; }
  if (/^buy\b/.test(l)) toast('Manual ticket: run the Halal scan first so it\'s screened and sized to $10 max risk', 4200);
  if ((m = l.match(/^(buy|sell)\s+\$\s?([\d,.]+)\s*(?:(?:worth\s+)?of\s+)?([a-z.]{1,6})\b(?:.*?limit\s+\$?([\d.]+))?/))) { prefillTicket({ side: m[1], unit: 'dollars', amount: m[2].replace(/,/g, ''), symbol: m[3], type: m[4] ? 'limit' : 'market', limit: m[4], build: true }); switchTab('ticket'); return; }
  if ((m = l.match(/^(buy|sell)\s+([\d.]+)\s+(?:shares?\s+(?:of\s+)?)?([a-z.]{1,6})\b(?:.*?limit\s+\$?([\d.]+))?/))) { prefillTicket({ side: m[1], unit: 'shares', amount: m[2], symbol: m[3], type: m[4] ? 'limit' : 'market', limit: m[4], build: true }); switchTab('ticket'); return; }
  if ((m = l.match(/^(buy|sell)\s+([a-z.]{1,6})\b/))) { prefillTicket({ side: m[1], symbol: m[2] }); switchTab('ticket'); return; }
  if (/study guide/.test(l)) {
    const a = ((state.data && state.data.assignments) || []).find(x => l.includes((x.course || '').toLowerCase()) && x.course) ;
    openCommand(a ? studyGuideCommand(a) : t + '\n\n(Use the /morning-sync study-guide procedure: open HMH Ed, read the matching chapter, write a 9th-grade study guide, save it to data.json and run ./publish.sh.)', 'Make Study Guide'); return;
  }
  if ((m = l.match(/^(?:open|launch|go to)\s+(.+)/))) { const name = m[1].trim(); const a = allApps().find(x => x.name.toLowerCase().includes(name) || x.id === name); if (a) { if (a.builtin) openBuiltin(a.builtin); else window.open(a.url, '_blank', 'noopener'); return; } }
  if (/^(stocks|portfolio|robinhood)/.test(l)) { openStocks(); return; }
  if (/^lock/.test(l)) { lockNow(); return; }
  if ((m = l.match(/^(dark|light|auto) (?:mode|theme)/))) { lsSet(LS.theme, m[1]); applyTheme(); return; }
  if (/^(settings|preferences)/.test(l)) { openSettings(); return; }
  openCommand(t, 'Send to Claude');
}
const cap = s => s.charAt(0).toUpperCase() + s.slice(1);
const HALAL_SCAN_CMD = 'Read ~/trading-bot/CLAUDE.md and journal/scans.md, then run the full pipeline: universe scan → Halal gate → chart → insiders/news → 3-question scorecard. Preview only, never place orders. Log it in the journal, then sync the result into the Command Center (data.trading_bot) and ask me before publishing.';
let aiModel = 'openverse';
const setModelUI = () => $$('#model-seg button').forEach(b => b.classList.toggle('active', b.dataset.model === aiModel));
setModelUI();
$('#model-seg').addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; aiModel = b.dataset.model; lsSet(LS.model, aiModel); setModelUI(); });
const TOOL_CMD = /^(run halal|halal|swing scan|buy|sell|add|remind|todo|task|open|launch|go to|lock|stocks|portfolio|robinhood|settings|preferences|dark|light|auto|make me a study guide|study guide)/i;
$('#cmdbar').addEventListener('submit', e => {
  e.preventDefault(); const v = $('#cmd-input').value.trim(); $('#cmd-input').value = '';
  if (!v) return;
  if (aiModel === 'openverse' && !TOOL_CMD.test(v)) askOpenVerse(v); else runCommand(v);
});
const OVA_URL = 'https://open-verse-ai.boukeilehm.workers.dev';
async function askOpenVerse(q) {
  const key = lsGet(LS.gemini, '');
  if (!key) { toast('Add your OpenVerse AI key in Settings first'); openSettings(); return; }
  toast('Asking OpenVerse AI…', 8000);
  try {
    let r = null;
    for (let attempt = 0; attempt < 4; attempt++) {
      r = await fetch(OVA_URL + '/v1/ask', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
        body: JSON.stringify({ question: q, top_k: 3 })
      });
      // 429 = rate limit (Retry-After tells us how long), 503 = busy. Wait and retry.
      if (r.status !== 429 && r.status !== 503) break;
      if (attempt < 3) {
        const wait = (+r.headers.get('Retry-After')) || (2 ** attempt);
        toast('OpenVerse AI is busy. Retrying in ' + wait + 's…', 2000);
        await new Promise(res => setTimeout(res, wait * 1000));
      }
    }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((j.error && j.error.message) || r.statusText);
    const lines = [j.answer || (j.general_unavailable ? 'No answer: ' + j.general_unavailable : 'No answer came back.')];
    if (j.confidence) lines.push('', 'Confidence: ' + j.confidence);
    if (Array.isArray(j.sources) && j.sources.length) lines.push('', 'Sources:', ...j.sources.map(s => '[' + s.ref + '] ' + s.title + (s.section ? ' — ' + s.section : '') + (s.url ? '\n' + s.url : '')));
    if (j.disclaimer) lines.push('', j.disclaimer);
    $('#cmd-title').textContent = 'OpenVerse AI'; $('#cmd-desc').textContent = 'Question: ' + q;
    $('#cmd-text').textContent = lines.join('\n'); $('#cmd-share').hidden = !navigator.share; openSheet($('#sheet-cmd'));
  } catch (e) {
    // Keep the error on screen (in the answer sheet) until the user closes it.
    $('#cmd-title').textContent = 'OpenVerse AI could not answer'; $('#cmd-desc').textContent = 'Question: ' + q;
    $('#cmd-text').textContent = e.message; $('#cmd-share').hidden = true; openSheet($('#sheet-cmd'));
  }
}
$('#printer-save').addEventListener('click', () => { lsSet(PRINTER_KEY, { ip: $('#printer-ip').value.trim(), check: $('#printer-check').value.trim() }); renderPrinter(); toast('Printer settings saved'); });
$('#openverse-save').addEventListener('click', () => { const k = $('#openverse-key').value.trim(); if (!k) return; lsSet(LS.gemini, k); $('#openverse-key').value = ''; toast('OpenVerse AI key saved in this browser'); });
$('#cmd-chips').addEventListener('click', e => { const c = e.target.closest('.chip'); if (c) runCommand(c.dataset.cmd); });

/* ---------------------------------------------------------------- settings */
function openSettings() { openSheet($('#sheet-settings')); renderSettings(); }
$('#btn-settings').addEventListener('click', openSettings);
function renderSettings() {
  applyTheme(); const pc = printerCfg(); $('#printer-ip').value = pc.ip || ''; $('#printer-check').value = pc.check || '';
  $('#set-previews').checked = previewsOn();
  const rec = bioRec(); const st = $('#bio-status'); const en = $('#bio-enroll'); const rm = $('#bio-remove');
  if (!bioAvailable) { st.textContent = !window.isSecureContext ? 'Biometrics need HTTPS (works on the GitHub Pages site).' : 'No Face ID / Touch ID authenticator found on this device/browser.'; en.hidden = true; rm.hidden = !rec; }
  else if (rec && rec.wrapped) { st.textContent = `Enrolled on this device ${new Date(rec.confirmedAt || rec.enrolledAt).toLocaleDateString()} · ${rec.method === 'prf' ? 'hardware-bound key (PRF)' : 'device-bound key'}.`; en.hidden = true; rm.hidden = false; }
  else if (rec && rec.pending) { st.textContent = 'Passkey created. Confirm once with Face ID / Touch ID to finish.'; en.hidden = false; en.textContent = 'Confirm with Face ID / Touch ID'; rm.hidden = false; }
  else { st.textContent = 'Not enrolled on this device. Enroll once to unlock with Face ID / Touch ID.'; en.hidden = false; en.textContent = 'Enroll this device'; rm.hidden = true; }
  $('#build-info').textContent = `Command Center v${APP_VERSION}${state.data && state.data.generated_at ? ' · data synced ' + new Date(state.data.generated_at).toLocaleString() : ''}`;
}
$('#bio-enroll').addEventListener('click', async () => {
  const rec = bioRec();
  try {
    if (!rec || !rec.pending) await bioEnrollStep1();
    const method = await bioEnrollStep2(); renderSettings(); refreshBioButtons();
    toast(method === 'prf' ? 'Face ID / Touch ID enabled (hardware-bound)' : 'Face ID / Touch ID enabled');
  } catch (e) { console.warn(e); toast(e.name === 'NotAllowedError' ? 'Cancelled' : 'Could not enroll: ' + (e.message || e.name)); }
});
$('#bio-remove').addEventListener('click', () => { localStorage.removeItem(LS.bio); renderSettings(); refreshBioButtons(); toast('Biometric unlock removed from this device'); });
$('#set-previews').addEventListener('change', e => lsSet(LS.previews, e.target.checked));
$('#set-reset').addEventListener('click', () => { [LS.apps, LS.hidden, LS.todo, LS.actions, LS.notes].forEach(k => localStorage.removeItem(k)); renderAll(); closeSheet($('#sheet-settings')); toast('Local apps, tasks and tags reset'); });

/* ------------------------------------------------------------------ render */
const PRINTER_KEY = 'cc.printer';
function printerCfg() { return lsGet(PRINTER_KEY, { ip: '', check: '' }); }
let liveP = null;
async function pollPrinter() {
  const cfg = printerCfg(); if (!cfg.ip) return;
  if (location.protocol === 'https:') { $('#printer-msg').textContent = 'The printer is on your home network. Browsers block that from a secure page, so open the app at http://localhost to see live numbers.'; return; }
  try {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 4000);
    const r = await fetch(`http://${cfg.ip}:8898/`, { signal: ctl.signal, cache: 'no-store' }); clearTimeout(t);
    const txt = await r.text(); let j = null; try { j = JSON.parse(txt); } catch { /* not JSON */ }
    if (j) {
      liveP = { status: j.status || j.state, job: j.job || j.filename || j.job_name, progress: j.progress ?? j.percent, nozzle_c: j.nozzle_temp ?? j.nozzle, nozzle_target_c: j.nozzle_target ?? j.nozzle_target_temp, bed_c: j.bed_temp ?? j.bed, bed_target_c: j.bed_target ?? j.bed_target_temp, filament: j.filament || j.material, as_of: new Date().toISOString() };
      renderPrinterStats(); $('#printer-msg').textContent = 'Live reading from ' + cfg.ip;
    } else $('#printer-msg').textContent = 'Printer answered, but not with JSON. Raw reply: ' + txt.slice(0, 120);
  } catch (e) { $('#printer-msg').textContent = `No answer from ${cfg.ip}:8898. Check the IP, that this device is on the same Wi-Fi, and that the page is open at http://localhost.`; }
}
function renderPrinter() {
  const cfg = printerCfg(); const p = (state.data && state.data.printer) || {};
  if (!cfg.ip) {
    $('#printer-asof').textContent = 'Not connected';
    $('#printer-body').innerHTML = '<div class="stat" style="text-align:center;padding:18px"><div class="v" style="font-size:18px">Not Connected</div><div class="d">Enter Printer IP in Settings</div></div><p id="printer-msg" class="muted small"></p>';
    return;
  }
  renderPrinterStats(p);
  pollPrinter();
}
function renderPrinterStats() {
  const p = liveP || (state.data && state.data.printer) || {};
  const known = !!p.status && p.status !== 'unknown';
  $('#printer-asof').textContent = p.as_of ? 'Read ' + relTime(p.as_of) : 'Waiting for reading';
  const v = (x, f) => (x == null || x === '' ? '—' : f ? f(x) : esc(x));
  const pct = Math.max(0, Math.min(100, +p.progress || 0));
  $('#printer-body').innerHTML = '<p id="printer-msg" class="muted small" style="margin:0 0 6px"></p>' + (known ? '' : '<p class="muted small" style="margin:0 0 6px">No live reading yet. The printer is on your home Wi-Fi, so /morning-sync reads it from your Mac and publishes the numbers here.</p>') +
    `<div class="p-grid">
      <div class="stat"><div class="k">Printer status</div><div class="v" style="font-size:18px">${v(p.status === 'printing' ? 'Printing' : p.status === 'idle' ? 'Idle' : null)}</div></div>
      <div class="stat"><div class="k">Current job</div><div class="v" style="font-size:15px;font-weight:700">${v(p.job)}</div></div>
      <div class="stat"><div class="k">Nozzle</div><div class="v">${v(p.nozzle_c, x => x + ' °C')}</div><div class="d">target ${v(p.nozzle_target_c, x => x + ' °C')}</div></div>
      <div class="stat"><div class="k">Bed</div><div class="v">${v(p.bed_c, x => x + ' °C')}</div><div class="d">target ${v(p.bed_target_c, x => x + ' °C')}</div></div>
      <div class="stat"><div class="k">Filament</div><div class="v" style="font-size:18px">${v(p.filament)}</div></div>
    </div>
    <div class="small muted" style="margin-top:12px">Progress ${known && p.status === 'printing' ? pct + '%' : '—'}</div>
    <div class="bar-track"><div class="bar-fill" style="width:${known && p.status === 'printing' ? pct : 0}%"></div></div>`;
}
function renderGoalWidget() {
  const s = (state.data && state.data.stocks) || {}; const n = +(s.day_trades_5d || 0);
  $('#goal-body').innerHTML = goalHtml({ total_value: (s.summary || {}).total_value }) +
    `<div class="box" style="margin-top:12px"><h3>PDT counter (5 business days)</h3><div class="kv"><span>Day trades used</span><b class="${n >= 3 ? 'down' : ''}">${n} of 3</b></div><p class="small muted" style="margin:6px 0 0">${n >= 3 ? 'Limit reached. Another same-day round trip would flag the account.' : 'Accounts under $25,000 may make 3 day trades per rolling 5 business days. The swing plan holds overnight, so it shouldn\'t use any.'}</p></div>`;
}
function renderAll() { renderGoalWidget(); renderPrinter(); renderHeader(); renderBriefing(); renderImportant(); renderTodo(); renderApps(); if ($('#sheet-stocks').classList.contains('open')) renderStocks(); }
setInterval(() => { tickClock(); if (state.unlocked) renderHeader(); }, 15000);

const pinEl = $('#pin');
pinEl.addEventListener('input', () => { const v = pinEl.value.replace(/\D/g, '').slice(0, 8); pinEl.value = v; lock.code = v; renderDots(); if (v.length === 8) setTimeout(submitCode, 120); });
pinEl.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); submitCode(); } });
$('#lock-submit').addEventListener('click', submitCode);

/* ------------------------------------------------- persistent storage & sync */
const SYNC = { token: 'cc.ghToken', seen: 'cc.syncSeen' };
const imgCache = new Map();
const imgOf = a => a.image || (a.imageKey && imgCache.get(a.imageKey)) || null;
function idbAssets() { return new Promise((res, rej) => { const r = indexedDB.open('cc-assets', 1); r.onupgradeneeded = () => r.result.createObjectStore('img'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
async function idbPut(k, v) { const db = await idbAssets(); return new Promise((res, rej) => { const tx = db.transaction('img', 'readwrite'); tx.objectStore('img').put(v, k); tx.oncomplete = res; tx.onerror = () => rej(tx.error); }); }
async function idbGet(k) { const db = await idbAssets(); return new Promise((res, rej) => { const q = db.transaction('img', 'readonly').objectStore('img').get(k); q.onsuccess = () => res(q.result || null); q.onerror = () => rej(q.error); }); }
async function hydrateImages() {
  for (const x of allApps()) if (x.imageKey && !imgCache.has(x.imageKey)) { const v = await idbGet(x.imageKey); if (v) imgCache.set(x.imageKey, v); }
  renderApps();
}
const setSync = msg => { const el = $('#sync-status'); if (el) el.textContent = msg; };
const syncRepo = () => ({ owner: location.hostname.split('.')[0], repo: location.pathname.split('/').filter(Boolean)[0] || 'command-center' });
const bytesToB64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
const b64ToBytes = b => Uint8Array.from(atob(b.replace(/\s/g, '')), c => c.charCodeAt(0));
function snapshotLS() {
  const o = {}; [LS.apps, LS.hidden, LS.todo, LS.actions, LS.notes, LS.theme, LS.previews, LS.gemini, 'cc.printer'].forEach(k => { const v = localStorage.getItem(k); if (v != null) o[k] = v; });
  return o;
}
async function snapshotImages() {
  const out = {}; for (const x of lsGet(LS.apps, [])) if (x.imageKey) { const v = await idbGet(x.imageKey); if (v) out[x.imageKey] = v; }
  return out;
}
async function sealState(obj) {
  const iv = rand(12); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, enc.encode(JSON.stringify(obj))));
  const out = new Uint8Array(32 + ct.length); out.set(enc.encode('CCE1'), 0); out.set(state.salt, 4); out.set(iv, 20); out.set(ct, 32); return out;
}
let syncTimer = null, pushing = false;
function scheduleSync() {
  if (!state.unlocked || !lsGet(SYNC.token, '')) return;
  clearTimeout(syncTimer); syncTimer = setTimeout(() => pushRemote().catch(e => setSync('Auto-save failed: ' + e.message)), 3000);
}
async function pushRemote(attempt = 1) {
  const tok = lsGet(SYNC.token, ''); if (!tok) throw new Error('add a GitHub token in Settings');
  if (!state.key) throw new Error('unlock first');
  if (pushing) return; pushing = true;
  try {
    const { owner, repo } = syncRepo(); const api = `https://api.github.com/repos/${owner}/${repo}/contents/data.enc`;
    const h = { Authorization: 'Bearer ' + tok, Accept: 'application/vnd.github+json' };
    setSync('Saving to GitHub…');
    const g = await fetch(api, { headers: h, cache: 'no-store' });
    if (!g.ok && g.status !== 404) throw new Error(ghErr(g.status));
    const sha = g.ok ? (await g.json()).sha : undefined;
    const updated = new Date().toISOString();
    const bytes = await sealState({ sync: true, updated, ls: snapshotLS(), images: await snapshotImages(), data: state.data });
    const p = await fetch(api, { method: 'PUT', headers: { ...h, 'Content-Type': 'application/json' }, body: JSON.stringify({ message: 'Save: ' + updated.slice(0, 16).replace('T', ' '), content: bytesToB64(bytes), sha, branch: 'main' }) });
    if (p.status === 409 && attempt < 4) { pushing = false; setSync('Save conflict, retrying…'); await new Promise(r => setTimeout(r, 900 * attempt)); return pushRemote(attempt + 1); }
    if (p.status === 409) throw new Error('GitHub kept changing. Try again in a moment.');
    if (!p.ok) throw new Error(ghErr(p.status));
    lsSet(SYNC.seen, updated); setSync('Saved to GitHub at ' + new Date().toLocaleTimeString());
  } finally { pushing = false; }
}
async function pullRemote(force) {
  if (!location.hostname.endsWith('.github.io')) return false;
  const tok = lsGet(SYNC.token, ''); const { owner, repo } = syncRepo(); let buf;
  if (tok) {
    const r = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/data.enc`, { headers: { Authorization: 'Bearer ' + tok, Accept: 'application/vnd.github+json' }, cache: 'no-store' });
    if (!r.ok) return false; buf = b64ToBytes((await r.json()).content).buffer;
  } else {
    const r = await fetch(`https://${owner}.github.io/${repo}/data.enc?t=${Date.now()}`, { cache: 'no-store' });
    if (!r.ok) return false; buf = await r.arrayBuffer();
  }
  if (!state.key) return false;
  const { salt } = parseEnc(buf); if (hex(salt) !== hex(state.salt)) return false;
  const remote = JSON.parse(dec.decode(await decryptBuf(buf, state.key)));
  if (!remote.sync) return false;                       // plain publish.sh copy, nothing to merge
  const seen = lsGet(SYNC.seen, ''); if (!force && seen && remote.updated <= seen) return false;
  // Keep the Gemini key this device has now: a saved copy from before a key change would otherwise put the old key back.
  const localGemini = localStorage.getItem(LS.gemini);
  Object.entries(remote.ls || {}).forEach(([k, v]) => localStorage.setItem(k, v));
  if (localGemini != null) localStorage.setItem(LS.gemini, localGemini);
  for (const [k, v] of Object.entries(remote.images || {})) await idbPut(k, v);
  state.data = remote.data || state.data; lsSet(SYNC.seen, remote.updated);
  imgCache.clear(); renderAll(); await hydrateImages();
  setSync('Loaded latest saved copy from GitHub'); return true;
}
$('#sync-save').addEventListener('click', async () => {
  const t = $('#sync-token').value.trim(); if (t) { lsSet(SYNC.token, t); state.data = state.data || {}; state.data.settings = { ...(state.data.settings || {}), gh_token: t }; $('#sync-token').value = ''; }
  if (!lsGet(SYNC.token, '')) { setSync('Paste a GitHub token first'); return; }
  try { await pushRemote(); toast('Saved forever. It will load on all your devices.'); } catch (e) { setSync('Save failed: ' + e.message); }
});
$('#sync-forget').addEventListener('click', () => { localStorage.removeItem(SYNC.token); setSync('Token removed from this browser'); });

/* ------------------------------------------------ charts, calendar export, printer */
function svgBarChart(c) {
  const W = 560, H = 260, P = 40, max = Math.max(...c.values.map(Math.abs)) || 1, bw = (W - 2 * P) / c.labels.length;
  const bars = c.values.map((v, i) => {
    const h = (Math.abs(v) / max) * (H - 2 * P), x = P + i * bw + bw * 0.15, y = H - P - h;
    return `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${(bw * 0.7).toFixed(1)}" height="${h.toFixed(1)}" rx="6" fill="${i % 2 ? '#328cc1' : '#0f4c5c'}"/><text x="${(x + bw * 0.35).toFixed(1)}" y="${(y - 6).toFixed(1)}" text-anchor="middle" font-size="12" fill="#0f4c5c">${v}</text><text x="${(x + bw * 0.35).toFixed(1)}" y="${H - P + 18}" text-anchor="middle" font-size="12" fill="#5e6e72">${esc(c.labels[i])}</text>`;
  }).join('');
  return `<figure class="chart"><figcaption>${esc(c.title)}</figcaption><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(c.title)}"><line x1="${P}" y1="${H - P}" x2="${W - P}" y2="${H - P}" stroke="#e0e6ed"/>${bars}</svg></figure>`;
}
const icsStamp = d => d.toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '');
function icsDate(d, allDay) { const p = n => String(n).padStart(2, '0'); const day = `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}`; return allDay ? day : `${day}T${p(d.getHours())}${p(d.getMinutes())}00`; }
const icsText = s => String(s ?? '').replace(/\\/g, '\\\\').replace(/;/g, '\;').replace(/,/g, '\\,').replace(/\r?\n/g, '\\n');
function buildICS() {
  const stamp = icsStamp(new Date()); const L = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Command Center//EN', 'CALSCALE:GREGORIAN', 'X-WR-CALNAME:Mohammad'];
  for (const i of allItems()) {
    const allDay = i.kind === 'assignment', s = i.date;
    const e = allDay ? new Date(s.getFullYear(), s.getMonth(), s.getDate() + 1) : (i.end ? parseDate(i.end) : new Date(s.getTime() + 3600e3));
    L.push('BEGIN:VEVENT', `UID:${icsText(i.id)}@command-center`, `DTSTAMP:${stamp}`,
      allDay ? `DTSTART;VALUE=DATE:${icsDate(s, true)}` : `DTSTART:${icsDate(s, false)}`,
      allDay ? `DTEND;VALUE=DATE:${icsDate(e, true)}` : `DTEND:${icsDate(e, false)}`,
      `SUMMARY:${icsText((allDay ? 'Due: ' : '') + i.title)}`,
      `DESCRIPTION:${icsText([i.course, i.teacher, i.notes].filter(Boolean).join('\n'))}`, 'END:VEVENT');
  }
  L.push('END:VCALENDAR'); return L.join('\r\n');
}
$('#ics-export').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([buildICS()], { type: 'text/calendar' }));
  const a = document.createElement('a'); a.href = url; a.download = 'command-center-mohammad.ics'; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000); toast('Calendar file downloaded. Open it to add to Mohammad.');
});
setInterval(() => { if (state.unlocked && printerCfg().ip && location.protocol === 'http:') pollPrinter(); }, 15000);

/* -------------------------------------------------------------------- init */
function ghErr(s) { if (s === 401 || s === 403) return 'token rejected (' + s + '). Create a new fine-grained token with Contents: Read and write for this repository, then paste it in Settings'; if (s === 404) return 'repository or file not found (404)'; return 'GitHub error ' + s; }
async function init() {
  $$('.sheet').forEach(s => { s.inert = true; });
  applyTheme(); tickClock(); renderDots(); document.body.classList.add('locked');
  if ('serviceWorker' in navigator && window.isSecureContext && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
  await detectBio();
  try { if (await restoreSession()) return; } catch (e) { console.warn('session restore failed', e); try { sessionStorage.removeItem(SS_KEY); } catch {} }
  showLock('unlock');
}
init();
})();
