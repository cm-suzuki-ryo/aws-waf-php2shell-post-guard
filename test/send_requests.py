#!/usr/bin/env python3
"""Send GET or multipart/form-data POST requests over HTTPS and print, for each request,
the UTC time, status code, the x-waf-blocked-by response header and the response body.

Usage: send_requests.py <https-url> <get|post> <count> <interval-seconds>

TLS certificate verification is disabled so that it works against a test ALB with a
self-signed certificate. Do not point it at anything you do not own.
The POST body is a harmless form field plus a dummy file; it contains no attack payload.
"""
import sys, time, uuid, ssl, urllib.request, urllib.error
from datetime import datetime, timezone

url, kind, count, interval = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
for i in range(1, count + 1):
    if kind == "post":
        b = uuid.uuid4().hex
        body = (
            f"--{b}\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nhello\r\n"
            f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"dummy.txt\"\r\n"
            f"Content-Type: text/plain\r\n\r\nbaseline test file\r\n--{b}--\r\n"
        ).encode()
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": f"multipart/form-data; boundary={b}"})
    else:
        req = urllib.request.Request(url, method="GET")
    t = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"
    try:
        r = urllib.request.urlopen(req, timeout=10, context=ctx)
        code, hdr, text = r.status, r.headers.get("x-waf-blocked-by", "-"), r.read().decode(errors="replace").strip()
    except urllib.error.HTTPError as e:
        code, hdr, text = e.code, e.headers.get("x-waf-blocked-by", "-"), e.read().decode(errors="replace").strip()
    print(t, i, kind, code, "x-waf-blocked-by=" + hdr, "body=" + text, flush=True)
    time.sleep(interval)
