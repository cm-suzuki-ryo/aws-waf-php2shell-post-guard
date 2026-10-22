#!/usr/bin/env bash
# Checks rule 4 (block-php-upload-progress) and rule 5 (block-oversize-body) against a test ALB.
# Usage: php_upload_progress_test.sh <ALB DNS name>
# The requests only contain the field NAMES the AWS rule looks for, with dummy values. No attack payload is sent.
# TLS verification is disabled (-k) for a self-signed test certificate: use it only against an ALB you own.
set -u
DNS="$1"
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT

mp() { # multipart body: $1 = extra part(s) text
  printf -- '--x\r\nContent-Disposition: form-data; name="a"\r\n\r\nb\r\n%s--x--\r\n' "$1"
}
part() { printf -- '--x\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' "$1" "$2"; }

mp "$(part PHP_SESSION_UPLOAD_PROGRESS dummy)" > "$D/mp-field.bin"
mp "$(part PHP_SESSION_UPLOAD_PROGRESS dummy)$(part PHPSESSID dummy)" > "$D/mp-field-sid.bin"
mp "$(part PHPSESSID dummy)" > "$D/mp-sid-only.bin"
mp "" > "$D/mp-plain.bin"
printf 'PHP_SESSION_UPLOAD_PROGRESS=dummy&PHPSESSID=dummy' > "$D/urlenc-both.bin"
# reserved field placed after ~9 KB of padding (beyond the 8 KB an ALB hands to WAF)
mp "$(part pad "$(head -c 9000 /dev/zero | tr '\0' 'a')")$(part PHP_SESSION_UPLOAD_PROGRESS dummy)" > "$D/mp-field-after-8k.bin"
printf 'a=%s' "$(head -c 7000 /dev/zero | tr '\0' 'a')" > "$D/body-7k.bin"
printf 'a=%s' "$(head -c 9000 /dev/zero | tr '\0' 'a')" > "$D/body-9k.bin"
printf 'a=' > "$D/body-1m.bin"; head -c 1048576 /dev/zero | tr '\0' 'a' >> "$D/body-1m.bin"

t() { # label method content-type cookie body-file
  local label="$1" method="$2" ct="$3" cookie="$4" body="$5" out
  local args=(-sk -m 15 -o "$D/resp" -D - -X "$method" "https://$DNS/")
  [ -n "$ct" ] && args+=(-H "Content-Type: $ct")
  [ -n "$cookie" ] && args+=(-H "Cookie: $cookie")
  [ -n "$body" ] && args+=(--data-binary @"$body")
  out=$(curl "${args[@]}" | tr -d '\r')
  printf '%-46s %s %s x-waf-blocked-by=%s body=%s\n' "$label" "$method" \
    "$(awk 'NR==1{print $2}' <<<"$out")" \
    "$(awk 'tolower($0) ~ /^x-waf-blocked-by/{print $2}' <<<"$out" | head -1 | sed 's/^$/-/')" \
    "$(head -c 90 "$D/resp" | tr -d '\n')"
}
MPCT="multipart/form-data; boundary=x"
FORM="application/x-www-form-urlencoded"
t "01 mp + cookie PHPSESSID + field"              POST "$MPCT" "PHPSESSID=dummy" "$D/mp-field.bin"
t "02 mp + PHPSESSID in body + field"             POST "$MPCT" "" "$D/mp-field-sid.bin"
t "03 mp + field only (no PHPSESSID)"             POST "$MPCT" "" "$D/mp-field.bin"
t "04 mp + cookie PHPSESSID, no field"            POST "$MPCT" "PHPSESSID=dummy" "$D/mp-plain.bin"
t "05 mp + PHPSESSID in body, no field"           POST "$MPCT" "" "$D/mp-sid-only.bin"
t "06 GET + cookie PHPSESSID"                     GET  "" "PHPSESSID=dummy" ""
t "07 PUT + cookie + field"                       PUT  "$MPCT" "PHPSESSID=dummy" "$D/mp-field.bin"
t "08 urlencoded with both names"                 POST "$FORM" "" "$D/urlenc-both.bin"
t "09 cookie phpsessid (lowercase) + field"       POST "$MPCT" "phpsessid=dummy" "$D/mp-field.bin"
t "10 cookie MYSESS (other session.name) + field" POST "$MPCT" "MYSESS=dummy" "$D/mp-field.bin"
t "11 field after 9 KB padding + cookie"          POST "$MPCT" "PHPSESSID=dummy" "$D/mp-field-after-8k.bin"
t "12 benign urlencoded body ~7 KB"               POST "$FORM" "" "$D/body-7k.bin"
t "13 benign urlencoded body ~9 KB"               POST "$FORM" "" "$D/body-9k.bin"
t "14 benign urlencoded body ~1 MB"               POST "$FORM" "" "$D/body-1m.bin"
