#!/usr/bin/env bash
# Checks that the sign-in proxy in front of the files portal can't be tricked into passing
# a forged identity header. Run it from any computer, against the live portal in setup mode
# (PORTAL_HEADER_VERIFIED=false), BEFORE setting PORTAL_HEADER_VERIFIED=true.
#
#   scripts/portal-spoof-test.sh https://files.example.org
#
# It asks for the Cookie header of a signed-in browser session (DevTools > Network > any
# request to the portal > Request Headers > cookie). The cookie is read without echo and
# passed to curl on stdin, never on the command line.
#
# What it checks, through the real Cloudflare > Pangolin > portal path:
#   1. Signed out, with a forged Remote-Email: the request never reaches the portal.
#   2. Signed in, no forged header: the portal sees exactly one e-mail, yours.
#   3. Signed in, forged header in several spellings (as sent, lower case, twice,
#      underscore): the forged value never arrives on its own. If it arrives together
#      with the real one the portal refuses the request (two values), which is safe.
# Exit 0 = safe to set PORTAL_HEADER_VERIFIED=true. Anything else: don't.
set -eo pipefail  # no -u: macOS bash 3.2 treats empty arrays as unset

URL="${1:-}"
HEADER="${PORTAL_IDENTITY_HEADER:-Remote-Email}"
if [[ ! "$URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$ ]]; then
  echo "usage: $0 https://files.example.org" >&2
  exit 2
fi
URL="${URL%/}"
PROBE="$URL/api/portal/probe"
SPOOF="spoof-$(date +%s)-$RANDOM@example.invalid"
UNDERSCORE="${HEADER//-/_}"
fail=0
warn=0

# values <status-file> : prints the JSON "values" list one per line, or nothing
values() {
  python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
if isinstance(d, dict) and d.get("setup_mode") is True:
    print("__probe__")
    for v in d.get("values", []):
        print(v)
' "$1"
}

# read_values <file>: sets is_probe (0/1) and the array got (bash 3.2 compatible)
read_values() {
  is_probe=0
  got=()
  local line
  while IFS= read -r line; do
    if [[ "$line" == "__probe__" ]]; then is_probe=1; else got+=("$line"); fi
  done < <(values "$1")
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "== 1. signed out, forged $HEADER"
code=$(curl -sS -o "$tmp/out1" -w '%{http_code}' --max-redirs 0 \
  -H "$HEADER: $SPOOF" "$PROBE" || true)
read_values "$tmp/out1"
if [[ $is_probe -eq 1 ]]; then
  echo "   FAIL: an unauthenticated request reached the portal (HTTP $code)."
  echo "         Pangolin's authentication is not on for this resource."
  fail=1
else
  echo "   ok: stopped before the portal (HTTP $code)"
fi

printf 'Paste the Cookie header of a signed-in browser session (input hidden): '
IFS= read -rs COOKIE
echo
if [[ -z "$COOKIE" ]]; then
  echo "no cookie given; only check 1 ran" >&2
  exit 1
fi
COOKIE="${COOKIE#[Cc]ookie: }"
esc=${COOKIE//\\/\\\\}
esc=${esc//\"/\\\"}

probe() { # probe <outfile> [curl header args...]
  local out="$1"
  shift
  printf 'header = "Cookie: %s"\n' "$esc" |
    curl -sS -K - -o "$out" -w '%{http_code}' --max-redirs 0 "$@" "$PROBE" || true
}

echo "== 2. signed in, no forged header"
code=$(probe "$tmp/out2")
read_values "$tmp/out2"
if [[ $is_probe -ne 1 ]]; then
  echo "   FAIL: no probe answer (HTTP $code). Is the cookie current, and is the portal"
  echo "         in setup mode (PORTAL_HEADER_VERIFIED=false)?"
  exit 1
fi
if [[ ${#got[@]} -ne 1 ]]; then
  echo "   FAIL: expected exactly one $HEADER, got ${#got[@]}: ${got[*]}"
  echo "         Turn on Pangolin SSO for the resource so it forwards the user's e-mail."
  exit 1
fi
REAL="${got[0]}"
echo "   ok: the portal sees one e-mail: $REAL"

check() { # check <name> [curl header args...]
  local name="$1"
  shift
  local code
  code=$(probe "$tmp/out" "$@")
  read_values "$tmp/out"
  if [[ $is_probe -ne 1 ]]; then
    echo "   ok ($name): request did not reach the portal (HTTP $code)"
    return
  fi
  local has_spoof=0 v
  for v in "${got[@]}"; do [[ "$v" == *"$SPOOF"* ]] && has_spoof=1; done
  if [[ $has_spoof -eq 1 && ${#got[@]} -eq 1 ]]; then
    echo "   FAIL ($name): the forged e-mail arrived on its own: ${got[*]}"
    fail=1
  elif [[ $has_spoof -eq 1 ]]; then
    echo "   safe ($name): forged and real e-mail both arrived; the portal refuses such"
    echo "         requests (more than one value). Better: strip $HEADER in Traefik."
    warn=1
  elif [[ ${#got[@]} -eq 1 && "${got[0]}" == "$REAL" ]]; then
    echo "   ok ($name): replaced by the real e-mail"
  else
    echo "   ok ($name): forged value removed; portal saw: ${got[*]}"
  fi
}

echo "== 3. signed in, forged header"
check "as sent" -H "$HEADER: $SPOOF"
check "lower case" -H "$(tr '[:upper:]' '[:lower:]' <<<"$HEADER"): $SPOOF"
check "sent twice" -H "$HEADER: $SPOOF" -H "$HEADER: $SPOOF"
check "underscore" -H "$UNDERSCORE: $SPOOF"
check "with real" -H "$HEADER: $SPOOF, $REAL"

echo
if [[ $fail -ne 0 ]]; then
  echo "RESULT: NOT SAFE. Leave PORTAL_HEADER_VERIFIED=false. Add a Traefik headers"
  echo "middleware that removes $HEADER from incoming requests before Pangolin's"
  echo "authentication runs, then run this again."
  exit 1
fi
echo "RESULT: safe. Set PORTAL_HEADER_VERIFIED=true in .env and run: docker compose up -d"
if [[ $warn -ne 0 ]]; then echo "(with the note above)"; fi
exit 0
