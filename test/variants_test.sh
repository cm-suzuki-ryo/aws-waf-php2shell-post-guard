#!/usr/bin/env bash
# Check which Content-Type / HTTP method combinations the WAF rule block-multipart-post stops.
# Usage: variants_test.sh <ALB DNS name>   (TLS verification is off with -k because of the self-signed test certificate)
DNS="$1"
MP=/tmp/mp-body.bin
printf -- '--x\r\nContent-Disposition: form-data; name="a"\r\n\r\nb\r\n--x--\r\n' > "$MP"
t() { # label method content-type body-file
  local label="$1" method="$2" ct="$3" body="$4" out
  out=$(curl -sk -m 10 -o /tmp/body.out -D - -X "$method" -H "Content-Type:$ct" --data-binary @"$body" "https://$DNS/" | tr -d '\r')
  printf '%-34s %s %s x-waf-blocked-by=%s body=%s\n' "$label" "$method" "$(awk 'NR==1{print $2}' <<<"$out")" \
    "$(awk 'tolower($0) ~ /^x-waf-blocked-by/{print $2}' <<<"$out" | head -1 | sed 's/^$/-/')" "$(head -c 100 /tmp/body.out | tr -d '\n')"
}
printf 'a=b' > /tmp/form.bin; printf '{"a":"b"}' > /tmp/json.bin; printf 'hello' > /tmp/text.bin
t "1 standard"                  POST " multipart/form-data; boundary=x" "$MP"
t "2 comma-separated"           POST " multipart/form-data, boundary=x" "$MP"
t "3 mixed case"                POST " Multipart/Form-Data; boundary=x" "$MP"
t "4 many leading spaces"       POST "      multipart/form-data; boundary=x" "$MP"
t "5 leading tab"               POST $'\tmultipart/form-data; boundary=x' "$MP"
t "6 charset before"            POST " multipart/form-data;charset=utf-8;boundary=x" "$MP"
t "7 urlencoded"                POST " application/x-www-form-urlencoded" /tmp/form.bin
t "8 text/plain"                POST " text/plain" /tmp/text.bin
t "9 json"                      POST " application/json" /tmp/json.bin
t "10 multipart/mixed"          POST " multipart/mixed; boundary=x" "$MP"
t "11 PUT multipart"            PUT  " multipart/form-data; boundary=x" "$MP"
t "12 GET multipart header"     GET  " multipart/form-data; boundary=x" /dev/null
