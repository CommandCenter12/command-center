#!/bin/bash
# Daily automatic run for the Command Center.
#  1. Apple Calendar sync (no Claude needed)
#  2. FlashForge printer reading over the home network (no Claude needed)
#  3. Claude runs the morning-sync skill for the parts that need it, WITHOUT publishing.
# Publishing is never automatic: run ./publish.sh yourself after you check the changes.
set -u
PROJECT="$HOME/Developer/ai-assistant"
LOG="$HOME/Library/Logs/command-center-morning.log"
cd "$PROJECT" || exit 1
mkdir -p "$(dirname "$LOG")"
exec >>"$LOG" 2>&1
echo "=== $(date '+%Y-%m-%d %H:%M:%S') daily run start"

# 1. Apple Calendar: dry run first, then the real sync (skips duplicates and the Hebrew class)
node tools/calendar-sync.js --dry-run || echo "calendar dry run failed"
node tools/calendar-sync.js || echo "calendar sync failed"

# 2. Printer: read status over the printer's TCP command port (IP and port in tools/printer.env)
if [ -f tools/printer.env ]; then
  if python3 tools/printer_status.py > /tmp/cc-printer-fragment.json 2>>"$LOG"; then
    node tools/merge-data.js /tmp/cc-printer-fragment.json && echo "printer updated"
  else
    echo "printer did not answer (kept last reading)"
  fi
else
  echo "tools/printer.env missing; skipping printer"
fi

# 3. Claude: Livetop, Horizons, Robinhood and the briefing. No publishing.
PROMPT='Run the morning-sync skill for the Command Center in this folder, but do NOT run publish.sh and do not ask questions. Skip any site that is not already signed in. Never submit a trade or a school task. Skip the Hebrew class. Save the 3-bullet briefing to morning-report.txt in this folder.'
claude -p "$PROMPT" \
  --permission-mode acceptEdits \
  --allowedTools "Read" "Write" "Edit" "Bash(node *)" "Bash(curl *)" "Bash(python3 *)" "Skill" \
  || echo "claude run failed"

echo "=== $(date '+%Y-%m-%d %H:%M:%S') daily run end"
