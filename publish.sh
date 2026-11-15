#!/usr/bin/env bash
# publish.sh — encrypt private data with the passcode, commit the public files and push to GitHub Pages.
# First run also creates the GitHub repo and turns on Pages. Usage: ./publish.sh   (CC_REPO_NAME overrides the repo name)
set -euo pipefail
cd "$(dirname "$0")"
REPO_NAME="${CC_REPO_NAME:-command-center}"

[ -f .passcode ] || { echo "✖ Missing .passcode (the 8-digit passcode). Create it: printf '09152012\n' > .passcode"; exit 1; }
command -v node >/dev/null || { echo "✖ node is required"; exit 1; }
command -v gh   >/dev/null || { echo "✖ GitHub CLI (gh) is required: brew install gh && gh auth login"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "✖ Run: gh auth login"; exit 1; }

echo "▶ Encrypting data.json and screenshots/*.png …"
node encrypt.js

# ---- git bootstrap ----------------------------------------------------------
[ -d .git ] || git init -q -b main
OWNER="$(gh api user --jq .login)"
git config user.name  >/dev/null 2>&1 || git config user.name  "$OWNER"
git config user.email >/dev/null 2>&1 || git config user.email "$OWNER@users.noreply.github.com"
touch .nojekyll

if ! git remote get-url origin >/dev/null 2>&1; then
  if gh repo view "$OWNER/$REPO_NAME" >/dev/null 2>&1; then
    echo "▶ Using existing GitHub repo $OWNER/$REPO_NAME"
  else
    echo "▶ Creating GitHub repo $OWNER/$REPO_NAME …"
    gh repo create "$REPO_NAME" --public --description "Personal AI Command Center (all personal data AES-GCM encrypted)" >/dev/null
  fi
  git remote add origin "https://github.com/$OWNER/$REPO_NAME.git"
fi

# ---- stage only public, non-sensitive files ---------------------------------
PUBLIC=(index.html styles.css app.js README.md data.enc manifest.json sw.js icons .nojekyll .gitignore .salt encrypt.js publish.sh tools)
for f in "${PUBLIC[@]}"; do [ -e "$f" ] && git add -A -- "$f"; done
shopt -s nullglob; ENC=(screenshots/*.enc); shopt -u nullglob
[ ${#ENC[@]} -gt 0 ] && git add -A -- "${ENC[@]}"
git add -A -- screenshots 2>/dev/null || true   # picks up deletions of old .enc files; raw images stay ignored

if git diff --cached --name-only | grep -Eq '^(\.passcode|\.env|data\.json)$|^screenshots/.*\.(png|jpe?g|webp|heic)$'; then
  echo "✖ Refusing to publish — a private file is staged:"; git diff --cached --name-only; exit 1
fi

STAMP="$(date '+%Y-%m-%d %H:%M')"
if git diff --cached --quiet; then
  echo "• Nothing changed since the last publish."
else
  git commit -q -m "Morning sync: $STAMP" -m "Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>" && echo "▶ Committed: Morning sync: $STAMP"
fi

echo "▶ Pushing to origin main …"
git push -q -u origin main

# ---- GitHub Pages -----------------------------------------------------------
if ! gh api "repos/$OWNER/$REPO_NAME/pages" >/dev/null 2>&1; then
  echo "▶ Enabling GitHub Pages (branch main, folder /) …"
  gh api -X POST "repos/$OWNER/$REPO_NAME/pages" -f 'source[branch]=main' -f 'source[path]=/' >/dev/null || true
fi
URL="$(gh api "repos/$OWNER/$REPO_NAME/pages" --jq .html_url 2>/dev/null || echo "https://$OWNER.github.io/$REPO_NAME/")"
echo "✔ Published → $URL   (Pages usually updates within a minute)"
