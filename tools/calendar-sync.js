#!/usr/bin/env node
/* calendar-sync.js — push assignment deadlines and events from data.json into Apple Calendar (Calendar.app)
   without creating duplicates. Uses AppleScript via osascript, so it only runs on this Mac.
   usage: node tools/calendar-sync.js [--calendar "Mohammad"] [--days 60] [--dry-run]
   Dedupe: an item is skipped when an event with the same title already exists on the same day in the target
   calendar OR in any calendar listed in data.calendar.dedupe_against (e.g. the school's "Online school " feed). */
'use strict';
const { execFileSync } = require('child_process'); const fs = require('fs'); const path = require('path');
const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data.json'), 'utf8'));
const args = process.argv.slice(2); const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const target = opt('--calendar', (data.calendar && data.calendar.target) || 'Mohammad');
const horizon = +opt('--days', 60); const dry = args.includes('--dry-run');
const dedupe = [target, ...(((data.calendar && data.calendar.dedupe_against) || []).filter(c => c !== target))];
const q = s => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
const osa = script => execFileSync('osascript', ['-e', script], { encoding: 'utf8', timeout: 120000 }).trim();
const HELPERS = `on mkdate(y, m, d, h, mi)
  set dt to current date
  set day of dt to 1
  set year of dt to y
  set month of dt to m
  set day of dt to d
  set time of dt to (h * 3600 + mi * 60)
  return dt
end mkdate
`;
const parse = s => { if (!s) return null; if (/^\d{4}-\d{2}-\d{2}$/.test(s)) { const [y, m, d] = s.split('-').map(Number); return { y, m, d, h: 0, mi: 0, allDay: true }; } const dt = new Date(s); if (isNaN(dt)) return null; return { y: dt.getFullYear(), m: dt.getMonth() + 1, d: dt.getDate(), h: dt.getHours(), mi: dt.getMinutes(), allDay: false }; };
const items = [];
const SKIP_COURSE = /hebrew/i;
for (const a of data.assignments || []) { if (a.status === 'done' || SKIP_COURSE.test(a.course || '') || SKIP_COURSE.test(a.title || '')) continue; const t = parse(a.due); if (t) items.push({ ...t, raw: a.title, title: `${a.type === 'exam' ? '📝 Exam' : '📚 Due'}: ${a.title}${a.course ? ` (${a.course})` : ''}`, desc: [a.course, a.source ? `Source: ${a.source}` : '', a.url || '', a.notes || ''].filter(Boolean).join('\n'), url: a.url || '', dur: 60 }); }
for (const e of data.events || []) { const t = parse(e.start); if (t) items.push({ ...t, raw: e.title, title: e.title, desc: [e.location, e.notes].filter(Boolean).join('\n'), url: e.url || '', dur: e.end ? Math.max(15, (new Date(e.end) - new Date(e.start)) / 60000) : 60 }); }
const today = new Date(); today.setHours(0, 0, 0, 0);
let created = 0, skipped = 0;
for (const it of items) {
  const when = new Date(it.y, it.m - 1, it.d); const days = Math.round((when - today) / 864e5);
  if (days < -1 || days > horizon) continue;
  const d0 = `(my mkdate(${it.y}, ${it.m}, ${it.d}, 0, 0))`, d1 = `(${d0} + 1 * days)`;
  const checks = dedupe.map(c => `try
  tell calendar ${q(c)}
    set n to n + (count of (every event whose (summary is ${q(it.title)} or summary is ${q(it.raw)}) and start date ≥ ${d0} and start date < ${d1}))
  end tell
end try`).join('\n');
  const found = +osa(`${HELPERS}
tell application "Calendar"
  set n to 0
${checks}
  return n
end tell`);
  if (found > 0) { skipped++; continue; }
  const start = it.allDay ? d0 : `(my mkdate(${it.y}, ${it.m}, ${it.d}, ${it.h}, ${it.mi}))`;
  const end = it.allDay ? d1 : `(${start} + ${Math.round(it.dur)} * minutes)`;
  const props = `{summary:${q(it.title)}, start date:${start}, end date:${end}, description:${q(it.desc)}${it.allDay ? ', allday event:true' : ''}${it.url ? `, url:${q(it.url)}` : ''}}`;
  if (dry) { console.log(`would create: ${it.title} on ${it.y}-${it.m}-${it.d}`); created++; continue; }
  osa(`${HELPERS}
tell application "Calendar"
  tell calendar ${q(target)}
    make new event with properties ${props}
  end tell
end tell`);
  console.log(`+ ${it.title} → ${target} (${it.y}-${String(it.m).padStart(2, '0')}-${String(it.d).padStart(2, '0')})`);
  created++;
}
console.log(`✔ Apple Calendar: ${created} created${dry ? ' (dry run)' : ''}, ${skipped} already present`);
