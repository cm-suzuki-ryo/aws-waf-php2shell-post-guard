# aws-waf-php2shell-post-guard

[日本語](README.ja.md)

An AWS WAF (REGIONAL) CloudFormation sample for an Application Load Balancer.
It puts three rules (four with the optional multipart rule) in one web ACL and can return the name of the rule that stopped a request, so you can see *why* a request got a 403.

| Priority | Rule | Matches | Action |
|---|---|---|---|
| 0 | `block-multipart-post` (optional, `BlockMultipartPost=true`) | `POST` whose `Content-Type` header contains `multipart/form-data`, case-insensitive | Block (or Count) |
| 1 | `block-foreign-post` | `POST` from a country that is not in `AllowedCountries` (default `JP`) | Block (or Count) |
| 2 | `rate-limit-post-ip` | `POST`, counted per source IP (default 10 per 60 s) | Block (or Count) |
| 3 | `rate-limit-post-fingerprint` | `POST`, counted per TLS JA4 fingerprint (default 15 per 60 s) | Block (or Count) |

Optional: associate the web ACL with an ALB, and send web ACL logs to CloudWatch Logs.

> **This is not a fix for php2shell (CVE-2026-109618 / CVE-2026-109619) and it does not stop a single malicious request.**
> It is a sample for testing WAF rules and reading their logs. Apply the PHP update as soon as it is available.
> - GMO Flatt Security says the `session.upload_progress.enabled=0` workaround only mitigates a little, that the attack stays possible, and that the patch is the fix: <https://blog.flatt.tech/entry/php2shell>
> - Sansec says the attack appears to hit PHP itself, before the application code or a store-level shield runs: <https://sansec.io/research/php2shell>
> - The PHP security team announced the release (two critical issues, CVSS v4.0 9.2) without naming CVE IDs or mechanisms: <https://www.php.net/archive/2026.php#2026-10-20-1>. The CVE IDs and the name "php2shell" come from security vendors' reports.
>
> Rate-based rules let requests through until the limit is exceeded (see the measurements below). Rules 0 and 1 are the only rules here that act on the first request. Rule 0 also blocks legitimate multipart forms and file uploads, so it is off by default.

## Deploy

```bash
aws cloudformation deploy \
  --stack-name waf-post-guard \
  --template-file template.yaml \
  --region ap-northeast-1 \
  --parameter-overrides \
      AllowedCountries=JP \
      RuleAction=Count \
      LoadBalancerArn=arn:aws:elasticloadbalancing:REGION:ACCOUNT_ID:loadbalancer/app/NAME/ID
```

Start with `RuleAction=Count` on a real workload and look at the logs before switching to `Block`.
Delete the stack to remove everything it created (the web ACL, the association, the log group).

### Parameters

| Name | Default | Notes |
|---|---|---|
| `WebAclName` | `post-protection-sample` | Also used as the metric name prefix and the log group name (`aws-waf-logs-<name>`). |
| `AllowedCountries` | `JP` | Comma-separated ISO 3166 alpha-2 codes whose `POST` is *not* matched by rule 1. |
| `RuleAction` | `Block` | `Block` or `Count`. Custom responses apply to `Block` only. |
| `ReturnBlockReason` | `true` | `true` returns 403 with the rule name in the body and in the `x-waf-blocked-by` header. **Use `false` in production**: it tells the client which rule and threshold stopped it. |
| `BlockMultipartPost` | `false` | `true` adds rule 0. It blocks every `POST` whose `Content-Type` contains `multipart/form-data`, including legitimate uploads and forms without files. Enable it only for sites that need none. |
| `IpRateLimit` | `10` | Minimum allowed by AWS WAF is 10. |
| `FingerprintRateLimit` | `15` | Counted per JA4 fingerprint, across different IPs. |
| `EvaluationWindowSec` | `60` | `60`, `120`, `300` or `600`. |
| `LoadBalancerArn` | (empty) | Empty creates the web ACL only. See the warning about existing associations below. |
| `EnableLogging` | `true` | Creates a CloudWatch Logs log group and the logging configuration. |
| `LogRetentionInDays` | `7` | |

## Things to know before you use it

- **JA4 needs TLS.** The fingerprint is computed from the TLS Client Hello. The AWS WAF documentation says a request that lacks a component of the aggregation key is left out of the rate-based rule's evaluation, so use an HTTPS listener if you want rule 2 to count. (I did not test an HTTP listener.)
- **Rules 1 and 2 use the source IP the ALB sees.** Behind another proxy or CDN that may be the proxy's address. Consider AWS WAF's forwarded-IP configuration if you need the original client address (not included in this sample).
- **One web ACL per ALB.** When I passed `LoadBalancerArn` for an ALB that already had another web ACL, the stack update succeeded and the new web ACL started receiving the traffic. Check the existing association first.
- **Rate-based rules are approximate.** AWS WAF documents that it applies rate limiting near the limit and does not guarantee an exact match.
- **Cost.** AWS WAF charges for web ACLs, rules and requests, and CloudWatch Logs charges for ingestion and storage. See the AWS pricing pages.

## What I measured (single run each, `ap-northeast-1`, 2026-10-21)

Test ALB with an HTTPS listener (self-signed certificate) returning a fixed 200. Requests were harmless multipart POSTs (a form field and a dummy file), sent from AWS CloudShell sessions and from one workstation in Japan. These are observations from one run, not guarantees.

| Case | Result |
|---|---|
| `POST` from CloudShell in `us-east-1` (country `US`) | 403 on the first request, 3 out of 3. `GET` from the same shell: 200. The WAF log shows `terminatingRuleId: block-foreign-post`, `country: US`, `responseCodeSent: 403`. |
| `POST` from CloudShell in Tokyo (country `JP`) | 200, 3 out of 3. |
| Rule 2 (limit 10 per 60 s), one Tokyo shell, 60 POSTs at 1 per second | 23 passed, then 403 from the 24th, about 14 seconds after the 11th request. The final `GET` was 200. |
| Rule 2 (earlier run, multipart POSTs only), a burst of 30 within about one second | All 30 returned 200. A second burst 45 seconds later returned 403 from the first request. |
| Rule 3 (limit 15 per 60 s; rule 2 limit raised to 50 for this test), Tokyo and Osaka shells sending 30 POSTs each at 1 per second at the same time | 29 + 23 = 52 requests passed before the 403s started. Both shells had the same JA4 fingerprint, and the 403s came from `rate-limit-post-fingerprint`. |

| Rule 0 (`BlockMultipartPost=true`), `curl` from a workstation in Japan | 403 on the first request, with `x-waf-blocked-by: block-multipart-post`, for: standard `multipart/form-data; boundary=x`, the comma-separated form `multipart/form-data, boundary=x`, `Multipart/Form-Data`, and `multipart/form-data;charset=utf-8;boundary=x`. 200 for `application/x-www-form-urlencoded`, `text/plain`, `application/json`, `multipart/mixed`, a `PUT` with a multipart header, and a `GET` with a multipart header. The rule took effect within about 10 seconds of attaching the web ACL (the first check was already a 403; I did not measure it more precisely). Leading spaces and tabs before the value were removed before the web ACL saw the header, so that case was not exercised. |

What this means: a rate-based rule is a throttle, not a gate. Even with a limit of 10, dozens of requests got through before the block took effect.

## What the logs look like

- **WAF log** (CloudWatch Logs): `action`, `terminatingRuleId`, `terminatingRuleType` (`RATE_BASED` for rules 1 and 2), `rateBasedRuleList` (limit, window, key), `httpRequest.country`, `ja4Fingerprint`, `ja3Fingerprint`, `responseCodeSent`.
- **ALB access log**: a request blocked by WAF has `elb_status_code` 403 and `actions_executed` `waf` (an allowed request shows `waf,fixed-response` on my fixed-response listener). Delivery to CloudWatch Logs lagged: some entries were not there a few minutes after the requests.

## Try it

```bash
python3 test/send_requests.py https://<alb-dns-name>/ get 1 0
python3 test/send_requests.py https://<alb-dns-name>/ post 30 1
```

```bash
bash test/variants_test.sh <alb-dns-name>   # Content-Type / method combinations against rule 0
```

`send_requests.py` prints the status code, the `x-waf-blocked-by` header and the response body for each request. It turns off certificate verification, so use it only against a test ALB you own, and keep the ALB's security group limited to your own source IPs while you test.

## License

MIT. See [LICENSE](LICENSE).
