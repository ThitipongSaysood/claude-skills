#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Web Security Scan — passive checks
#  ใช้กับเว็บที่คุณเป็นเจ้าของหรือได้รับอนุญาตเท่านั้น
#
#  ทำอะไร: อ่าน HTTP header, ตรวจ TLS/cert, ขอ URL ปกติเพื่อดูว่า
#          ไฟล์ที่ไม่ควรเข้าถึงได้เปิดอยู่ไหม, ดู DNS, ตรวจ dependency ในเครื่อง
#  ไม่ทำ:  ไม่ยิง payload เจาะระบบ ไม่ brute force ไม่แก้ข้อมูลใด ๆ
#
#  วิธีใช้:
#    ./scan.sh example.com
#    ./scan.sh example.com --project /var/www/site
# ─────────────────────────────────────────────────────────────
set -uo pipefail

DOMAIN="${1:-}"
PROJECT=""
ASSUME_YES=0
shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="${2:-}"; shift 2 ;;
    # Consent given on the command line. Still explicit — it is a flag the
    # person running this has to type — but it no longer needs a terminal,
    # so the scan can run from a script or CI on your own domain.
    --yes|-y) ASSUME_YES=1; shift ;;
    *) shift ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  echo "usage: ./scan.sh <domain> [--project /path/to/code]" >&2
  exit 1
fi
DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"

echo "ตรวจ: $DOMAIN"
if [[ $ASSUME_YES -eq 1 ]]; then
  echo "ยืนยันสิทธิ์ด้วย --yes แล้ว"
else
  read -r -p "ยืนยันว่าคุณเป็นเจ้าของหรือได้รับอนุญาตให้ตรวจโดเมนนี้ (พิมพ์ yes): " OK
  [[ "$OK" == "yes" ]] || { echo "ยกเลิก"; exit 1; }
fi

OUT="scan-${DOMAIN}-$(date +%Y%m%d).json"
UA="Mozilla/5.0 (compatible; SelfSecurityAudit/1.0)"
CURL=(curl -sS --max-time 20 -A "$UA")

# curl prints "000" and ALSO exits non-zero when it cannot reach the host, so
# `$(curl -w '%{http_code}' ... || echo 0)` produced "0000" — not a number, and
# not valid JSON, which killed the whole run on any unreachable host. Always
# hand back a plain integer.
num() { local v="${1//[!0-9]/}"; echo $((10#${v:-0})); }

have() { command -v "$1" >/dev/null 2>&1; }

# Run a command under a time limit, wherever we are.
#
# macOS has no `timeout` — it is GNU coreutils. Every openssl probe below used
# to call it directly, so on a Mac they all failed with "command not found",
# the TLS section came back empty, and the report scored the empty result as a
# PASS on the highest-risk item in the checklist. Falls back to a watchdog.
run_to() {
  local secs="$1"; shift
  if have timeout; then timeout "$secs" "$@"
  elif have gtimeout; then gtimeout "$secs" "$@"
  else
    "$@" &
    local pid=$!
    ( sleep "$secs"; kill -9 "$pid" 2>/dev/null ) >/dev/null 2>&1 &
    local watchdog=$!
    wait "$pid" 2>/dev/null
    local rc=$?
    kill -9 "$watchdog" 2>/dev/null
    wait "$watchdog" 2>/dev/null
    return $rc
  fi
}

have curl    || { echo "ต้องมี curl"; exit 1; }
have openssl || echo "หมายเหตุ: ไม่พบ openssl — ข้ามการตรวจ TLS"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# ── 1. HTTP headers ────────────────────────────────────────────
echo "  [1/6] headers"
"${CURL[@]}" -D "$TMP/h.txt" -o "$TMP/body.html" -L "https://$DOMAIN/" >/dev/null 2>&1
FINAL_CODE=$(num "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -L "https://$DOMAIN/" 2>/dev/null)")

hdr() { grep -i "^$1:" "$TMP/h.txt" 2>/dev/null | tail -1 | cut -d: -f2- | sed 's/^ *//;s/\r$//'; }

# ── 2. HTTP → HTTPS redirect ───────────────────────────────────
echo "  [2/6] redirect"
REDIR=$("${CURL[@]}" -o /dev/null -w '%{redirect_url}' "http://$DOMAIN/" 2>/dev/null || echo "")
REDIR_CODE=$(num "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "http://$DOMAIN/" 2>/dev/null)")

# ── 3. TLS / certificate ───────────────────────────────────────
echo "  [3/6] tls"
TLS_JSON='{"skipped":true}'
if have openssl; then
  # Three answers per protocol, not two.
  #
  # A modern OpenSSL (3.x) refuses to OFFER TLS 1.0/1.1 at all — it answers
  # "no protocols available" without ever reaching the server. Treating that as
  # "the server does not support it" is how a site still accepting TLS 1.0 was
  # reported as passing. Anything we could not actually ask goes in
  # `protocols_unknown`, and the report says "ยังไม่ตรวจ" for it.
  PROTOS=""
  UNKNOWN=""
  for p in tls1 tls1_1 tls1_2 tls1_3; do
    ERR=$(echo | run_to 10 openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" -"$p" 2>&1 >/dev/null)
    RC=$?
    if [[ $RC -eq 0 ]]; then
      PROTOS="$PROTOS \"$p\","
    elif echo "$ERR" | grep -qiE 'no protocols available|unsupported protocol|unknown option'; then
      UNKNOWN="$UNKNOWN \"$p\","
    fi
  done
  PROTOS="[${PROTOS%,}]"
  UNKNOWN="[${UNKNOWN%,}]"
  CERT=$(echo | run_to 10 openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -dates -issuer -subject -text 2>/dev/null)
  NOTAFTER=$(echo "$CERT" | grep -m1 'notAfter=' | cut -d= -f2-)
  ISSUER=$(echo "$CERT"   | grep -m1 'issuer='   | cut -d= -f2- | tr -d '"')
  SANS=$(echo "$CERT" | grep -A1 'Subject Alternative Name' | tail -1 | sed 's/^ *//' | tr -d '"')
  KEYBITS=$(echo "$CERT" | grep -m1 -oE '[0-9]+ bit' | grep -oE '[0-9]+' || echo "")
  # Only meaningful once the handshake itself worked — otherwise "no stapling"
  # is a statement about our own openssl, not about the server.
  HANDSHAKE_OK=$([[ -n "$CERT" ]] && echo 1 || echo 0)
  if echo | run_to 10 openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" -status 2>/dev/null | grep -q 'OCSP Response Status: successful'; then STAPLE=1; else STAPLE=0; fi
  DAYS_LEFT=""
  if [[ -n "$NOTAFTER" ]] && have python3; then
    DAYS_LEFT=$(python3 - "$NOTAFTER" <<'PY' 2>/dev/null || echo ""
import sys,datetime
try:
    d=datetime.datetime.strptime(sys.argv[1].strip(),"%b %d %H:%M:%S %Y %Z")
    print((d-datetime.datetime.utcnow()).days)
except Exception: print("")
PY
)
  fi
  TLS_JSON=$(python3 - "$PROTOS" "$NOTAFTER" "$ISSUER" "$SANS" "$KEYBITS" "$STAPLE" "$DAYS_LEFT" "$UNKNOWN" "$HANDSHAKE_OK" <<'PY'
import json,sys
p,na,iss,sans,kb,st,dl,unk,hs = sys.argv[1:10]
print(json.dumps({"protocols":json.loads(p),"protocols_unknown":json.loads(unk),
 "handshake_ok":hs.strip()=="1","not_after":na.strip(),"issuer":iss.strip(),
 "sans":sans.strip(),"key_bits":kb.strip(),"ocsp_stapling":st.strip()=="1",
 "days_left":dl.strip()},ensure_ascii=False))
PY
)
fi

# ── 4. Sensitive paths ─────────────────────────────────────────
echo "  [4/6] exposed files"
PATHS=(/.git/config /.git/HEAD /.env /.env.local /.env.production /config.php.bak /phpinfo.php
       /info.php /test.php /package.json /composer.json /composer.lock /package-lock.json
       /yarn.lock /.DS_Store /backup/ /backups/ /old/ /temp/ /tmp/ /dev/ /test/ /db.sql
       /dump.sql /database.sql /backup.zip /wp-config.php.bak /.svn/entries /.htaccess
       /server-status /adminer.php /phpmyadmin/ /storage/logs/laravel.log /.well-known/security.txt /robots.txt)
# A control request first.
#
# "200 with a body" only means a file is exposed if the site 404s properly. A
# single-page app, a CDN catch-all or a soft-404 answers 200 for ANY path, and
# without this the report calls all 36 paths below exposed and hands the owner
# three dozen invented Criticals. This asks for a path that cannot exist; the
# report treats every path result as unverifiable when it comes back 200.
BASE_PATH="/zz-does-not-exist-$(date +%s)-baseline"
BASE_CODE=$(num "$("${CURL[@]}" -o "$TMP/b.out" -w '%{http_code}' "https://$DOMAIN$BASE_PATH" 2>/dev/null)")
BASE_SIZE=$(num "$(wc -c < "$TMP/b.out" 2>/dev/null)")

PATH_JSON="{"
for p in "${PATHS[@]}"; do
  code=$(num "$("${CURL[@]}" -o "$TMP/p.out" -w '%{http_code}' "https://$DOMAIN$p" 2>/dev/null)")
  size=$(num "$(wc -c < "$TMP/p.out" 2>/dev/null)")
  PATH_JSON="$PATH_JSON\"$p\":{\"code\":$code,\"size\":$size},"
done
PATH_JSON="${PATH_JSON%,}}"

# directory listing indicator — several places, since a venue that leaves one
# directory open rarely leaves exactly /assets/ open.
DIRLIST=0
for d in /assets/ /uploads/ /images/ /files/ /static/ /media/; do
  if "${CURL[@]}" -s "https://$DOMAIN$d" 2>/dev/null | grep -qi 'index of'; then DIRLIST=1; fi
done

# ── 5. DNS ─────────────────────────────────────────────────────
echo "  [5/6] dns"
DNS_JSON='{"skipped":true}'
if have dig; then
  dig +short TXT "$DOMAIN" 2>/dev/null | grep -q 'v=spf1' && SPF=true || SPF=false
  dig +short TXT "_dmarc.$DOMAIN" 2>/dev/null | grep -q 'v=DMARC1' && DMARC=true || DMARC=false
  CAA=$(num "$(dig +short CAA "$DOMAIN" 2>/dev/null | wc -l)")
  DNS_JSON="{\"spf\":$SPF,\"dmarc\":$DMARC,\"caa_records\":${CAA:-0}}"
fi

# ── 6. Local project checks ────────────────────────────────────
echo "  [6/6] local project"
PROJ_JSON='{"skipped":true}'
if [[ -n "$PROJECT" && -d "$PROJECT" ]]; then
  # `npm audit` EXITS NON-ZERO when it finds something — which is the normal
  # case — so `... || echo null` appended "null" to perfectly good JSON and the
  # assembled document had a newline in the middle of it. Capture first, judge
  # after: empty or unparseable becomes null, output is never appended to.
  json_or_null() {
    local v; v="$(cat)"
    [[ -n "$v" ]] && printf '%s' "$v" | python3 -c 'import json,sys
raw = sys.stdin.read()
try:
    json.loads(raw); print(raw.strip())
except Exception:
    print("null")' 2>/dev/null || echo null
  }

  NPM_VULN="null"; COMP_VULN="null"
  if have npm && [[ -f "$PROJECT/package.json" ]]; then
    NPM_VULN=$( (cd "$PROJECT" && npm audit --json 2>/dev/null) | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    print(json.dumps(d.get("metadata", {}).get("vulnerabilities", {})))
except Exception:
    pass' 2>/dev/null | json_or_null )
  fi
  if have composer && [[ -f "$PROJECT/composer.json" ]]; then
    COMP_VULN=$( (cd "$PROJECT" && composer audit --format=json 2>/dev/null) | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    print(json.dumps({"advisories": len(d.get("advisories", {}))}))
except Exception:
    pass' 2>/dev/null | json_or_null )
  fi
  WORLD_W=$(num "$(find "$PROJECT" -type f -perm -o+w 2>/dev/null | head -50 | wc -l)")
  ENV_IN_ROOT=$([[ -f "$PROJECT/.env" ]] && echo true || echo false)
  GIT_IN_ROOT=$([[ -d "$PROJECT/.git" ]] && echo true || echo false)
  LOCKFILE=$([[ -f "$PROJECT/package-lock.json" || -f "$PROJECT/composer.lock" || -f "$PROJECT/yarn.lock" ]] && echo true || echo false)
  # The FILE NAMES, not just how many. A count alone reads as "one secret is
  # leaking" when the hit is a fixture in a test file — the person reading the
  # report has to be able to judge it without re-running the grep themselves.
  SECRET_FILES=$(grep -rIlE '(api[_-]?key|secret|password|token)\s*[:=]\s*["'"'"'][A-Za-z0-9_\-]{16,}' \
            "$PROJECT" --include='*.js' --include='*.php' --include='*.py' --include='*.ts' \
            --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=.git 2>/dev/null | head -20 \
            | sed "s|^$PROJECT/||")
  SECRETS=$(num "$(printf '%s' "$SECRET_FILES" | grep -c . )")
  SECRET_LIST=$(printf '%s' "$SECRET_FILES" | python3 -c 'import json,sys; print(json.dumps([l for l in sys.stdin.read().splitlines() if l]))')
  PROJ_JSON="{\"npm_vulnerabilities\":$NPM_VULN,\"composer\":$COMP_VULN,\"world_writable_files\":${WORLD_W:-0},\"env_in_project_root\":$ENV_IN_ROOT,\"git_dir_present\":$GIT_IN_ROOT,\"lockfile_committed\":$LOCKFILE,\"files_with_possible_secrets\":${SECRETS:-0},\"secret_files\":$SECRET_LIST}"
fi

# ── assemble ───────────────────────────────────────────────────
python3 - "$OUT" "$DOMAIN" "$TLS_JSON" "$PATH_JSON" "$DNS_JSON" "$PROJ_JSON" \
  "$TMP/h.txt" "$TMP/body.html" "$REDIR" "$REDIR_CODE" "$FINAL_CODE" "$DIRLIST" \
  "$BASE_CODE" "${BASE_SIZE:-0}" <<'PY'
import json,sys,re,datetime
out,domain,tls,paths,dns,proj,hpath,bpath,redir,rcode,fcode,dirlist,bcode,bsize = sys.argv[1:15]

def loads(fragment):
    """A sub-check that produced something unreadable is skipped, not fatal.

    One malformed fragment used to take the entire scan with it — the run
    finished, printed nothing, and left no file at all."""
    try:
        return json.loads(fragment)
    except Exception:
        return {"skipped": True, "parse_error": True}


def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""

raw = read(hpath)
headers, cookies = {}, []
for line in raw.splitlines():
    if ":" in line and not line.startswith("HTTP/"):
        k, v = line.split(":", 1); k = k.strip().lower(); v = v.strip()
        if k == "set-cookie": cookies.append(v)
        else: headers[k] = v

body = read(bpath)
ext = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
ext_domains = sorted({re.sub(r'^https?://([^/]+).*', r'\1', s) for s in ext if s.startswith("http")})
sri = len(re.findall(r'<script[^>]+integrity=', body, re.I))
mixed = len(re.findall(r'(?:src|href)=["\']http://', body, re.I))
secret_hits = re.findall(r'(?i)(api[_-]?key|apikey|secret|bearer\s|sk_live_|AIza[0-9A-Za-z_\-]{20,})', body)
comments = len(re.findall(r'<!--(?!\[if)(?:(?!-->).){20,}-->', body, re.S))
trackers = sorted({t for t in ["connect.facebook.net","googletagmanager","analytics.tiktok.com",
                               "google-analytics","hotjar","clarity.ms"] if t in body})

cookie_flags = [{"raw": c[:120],
                 "httponly": "httponly" in c.lower(),
                 "secure": "secure" in c.lower(),
                 "samesite": (re.search(r'samesite=(\w+)', c, re.I).group(1)
                              if re.search(r'samesite=(\w+)', c, re.I) else None)} for c in cookies]

json.dump({
  "meta": {"domain": domain, "scanned_at": datetime.datetime.now().isoformat(timespec="seconds"),
           "scanner": "web-security-scan/1.1", "final_status": int(fcode or 0),
           # Nothing answered on 443. Every check below is therefore empty, and
           # the report must say "ยังไม่ตรวจ" rather than score the silence.
           "reachable": bool(raw)},
  "headers": headers,
  "cookies": cookie_flags,
  "http_redirect": {"location": redir, "status": int(rcode or 0)},
  "tls": loads(tls),
  "exposed_paths": loads(paths),
  # What a path that certainly does not exist answers. `soft_404` true means a
  # 200 proves nothing on this site.
  "path_baseline": {"code": int(bcode or 0), "size": int(bsize or 0),
                    "soft_404": int(bcode or 0) == 200 and int(bsize or 0) > 0},
  "directory_listing_hint": dirlist.strip() not in ("0", ""),
  "dns": loads(dns),
  "page": {"external_script_domains": ext_domains, "scripts_with_sri": sri,
           "mixed_content_refs": mixed, "possible_secret_matches": len(secret_hits),
           "html_comments": comments, "trackers_on_load": trackers},
  "project": loads(proj),
}, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("\n✅ เสร็จแล้ว →", out)
print("ขั้นต่อไป: python3 scripts/build_report.py", out, "--out Security_Report.xlsx")
PY
