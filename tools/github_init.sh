#!/usr/bin/env bash
# One-time import of this folder into a NEW, PRIVATE GitHub repository, from Termux, proot-distro Ubuntu or any Linux shell.
#
#   bash tools/github_init.sh                      # uses `gh` if it is installed and logged in, otherwise prints the two commands to finish by hand
#   REMOTE_URL=https://github.com/<you>/apkrelab.git bash tools/github_init.sh
#   REPO_NAME=apkrelab GIT_NAME="Your Name" GIT_EMAIL=you@example.com bash tools/github_init.sh
#
# It creates ONE fresh commit (no old history: the history of the sandbox repository held scan reports of the company's apps), after a safety gate.
# The repository MUST be private: tools/company/ names the company's apps, their versions and counts of findings.
# Never put a token in this file. For HTTPS pushes use `gh auth login` (recommended) or a GitHub personal access token typed when git asks for the password.
set -euo pipefail
cd "$(dirname "$0")/.."

BRANCH="${BRANCH:-main}"
VERSION="$(grep -m1 'versionName' app/build.gradle.kts | sed -E 's/.*"([^"]+)".*/\1/' || echo unknown)"
MSG="${COMMIT_MSG:-APKReLab $VERSION: initial import for Claude Code (Termux)}"
say() { printf '\n== %s\n' "$*"; }
die() { printf '\nSTOPPED: %s\n' "$*" >&2; exit 1; }

say "1/6 tools"
command -v git >/dev/null || die "git is not installed. Termux: pkg install git openssh gh     proot Ubuntu: apt install git"
if [ -e .git ] && [ "${KEEP_HISTORY:-0}" != "1" ]; then
  die "a .git already exists here. For the clean single-commit import delete it (rm -rf .git) and run again; set KEEP_HISTORY=1 only if you know the old history holds nothing private."
fi

say "2/6 git identity"
if [ -z "$(git config --global user.email || true)" ] && [ -z "${GIT_EMAIL:-}" ]; then
  die "no git identity. Run: git config --global user.name 'Your Name'; git config --global user.email you@example.com   (or pass GIT_NAME and GIT_EMAIL)"
fi
[ -n "${GIT_NAME:-}" ]  && git config --global user.name  "$GIT_NAME"
[ -n "${GIT_EMAIL:-}" ] && git config --global user.email "$GIT_EMAIL"

say "3/6 safety gate (nothing private may enter the repository)"
bad=0
# APKs, bundles and decoded apps are the owner's data: they stay on the phone
if find . -path ./.git -prune -o \( -iname '*.apk' -o -iname '*.apks' -o -iname '*.xapk' -o -iname '*.apkm' -o -iname '*.aab' \) -print | grep -q .; then
  echo "  an APK / bundle is inside the folder:"; find . -path ./.git -prune -o \( -iname '*.apk' -o -iname '*.apks' -o -iname '*.xapk' -o -iname '*.apkm' -o -iname '*.aab' \) -print | head -5; bad=1
fi
if find . -path ./.git -prune -o -type d \( -name 'dec_*' -o -name decoded \) -print | grep -q .; then echo "  a decoded-app folder (dec_*) is inside the folder"; bad=1; fi
# key shapes outside the test fixtures (the fixtures all carry "fake" / "abc123" / "EXAMPLE" and live under app/src/test and tools/recall)
hits="$(grep -rIlE 'sk-ant-(api|admin)[0-9]*-[A-Za-z0-9_-]{60,}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' . --exclude-dir=.git --exclude-dir=test --exclude-dir=recall 2>/dev/null | head -5 || true)"
if [ -n "$hits" ]; then echo "  a key-shaped string outside the test fixtures in:"; echo "$hits" | sed 's/^/    /'; bad=1; fi
# reports of scanned apps
if find . -path ./.git -prune -o -type f \( -name '*-report*.md' -o -name '*.sarif.json' -o -name '*.sarif' \) -print | grep -q .; then echo "  a scan report / SARIF file is inside the folder (move it to ./private/, which is ignored)"; bad=1; fi
[ "$bad" = "0" ] || die "fix the items above, then run again."
echo "  clean."

say "4/6 fresh repository and one commit"
git init -q -b "$BRANCH" 2>/dev/null || { git init -q; git symbolic-ref HEAD "refs/heads/$BRANCH"; }
git add -A
n="$(git ls-files | wc -l | tr -d ' ')"
[ "$n" -gt 100 ] || die "only $n files staged: something is wrong with .gitignore."
git commit -q -m "$MSG"
echo "  $n files, commit $(git rev-parse --short HEAD) on '$BRANCH'"

say "5/6 remote"
if [ -n "${REMOTE_URL:-}" ]; then
  git remote add origin "$REMOTE_URL" 2>/dev/null || git remote set-url origin "$REMOTE_URL"
  git push -u origin "$BRANCH"
elif command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
  gh repo create "${REPO_NAME:-apkrelab}" --private --source . --remote origin --push
else
  cat <<MSGEND
  No remote yet. Finish by hand (two ways):
    A) gh auth login        # once; then:   gh repo create ${REPO_NAME:-apkrelab} --private --source . --remote origin --push
    B) create an EMPTY PRIVATE repository on github.com (no README, no .gitignore), then:
         git remote add origin https://github.com/<you>/${REPO_NAME:-apkrelab}.git
         git push -u origin $BRANCH        # user name = your GitHub login, password = a personal access token (repo scope)
MSGEND
  exit 0
fi

say "6/6 check"
git ls-remote --heads origin | head -3
echo
echo "Done. Open the repository on github.com and confirm that it says PRIVATE. Then, on the phone:  git clone <url> && cd apkrelab && claude"
