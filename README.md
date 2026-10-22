# aws-waf-php2shell-post-guard

[日本語](README.ja.md)

An AWS WAF (REGIONAL) CloudFormation sample for an Application Load Balancer.
It puts three rules (up to six with the optional ones) in one web ACL and can return the name of the rule that stopped a request, so you can see *why* a request got a 403.

| Priority | Rule | Matches | Action |
|---|---|---|---|
| 0 | `block-multipart-post` (optional, `BlockMultipartPost=true`) | `POST` whose `Content-Type` header contains `multipart/form-data`, case-insensitive | Block (or Count) |
| 1 | `block-foreign-post` | `POST` from a country that is not in `AllowedCountries` (default `JP`) | Block (or Count) |
| 2 | `rate-limit-post-ip` | `POST`, counted per source IP (default 10 per 60 s) | Block (or Count) |
| 3 | `rate-limit-post-fingerprint` | `POST`, counted per TLS JA4 fingerprint (default 15 per 60 s) | Block (or Count) |
| 4 | `block-php-upload-progress` (`BlockPhpUploadProgress`, default `true`) | The custom rule from AWS security bulletin 2026-143-AWS (CVE-2026-109619): `POST`, and `PHPSESSID` in the body or as a cookie name, and `PHP_SESSION_UPLOAD_PROGRESS` in the body | Block (or Count) |
| 5 | `block-oversize-body` (optional, `BlockLargeBody=true`) | Any request whose body is over 8 KB (8,192 bytes), with oversize handling `MATCH` so that bodies larger than the 8 KB an ALB inspects match too. Custom rule from the AWS Security Blog on PHP2Shell mitigations (CVE-2026-109618 compensating control) | Block (or Count) |

Optional: associate the web ACL with an ALB, and send web ACL logs to CloudWatch Logs.

> **This is not a fix for php2shell (CVE-2026-109618 / CVE-2026-109619) and it does not stop a single malicious request.**
> It is a sample for testing WAF rules and reading their logs. Apply the PHP update as soon as it is available.
> - GMO Flatt Security says the `session.upload_progress.enabled=0` workaround only mitigates a little, that the attack stays possible, and that the patch is the fix: <https://blog.flatt.tech/entry/php2shell>
> - Sansec says the attack appears to hit PHP itself, before the application code or a store-level shield runs: <https://sansec.io/research/php2shell>
> - PHP released fixed versions on 2026-10-21 (8.5.12, 8.4.27, 8.3.36, 8.2.35) and says there is no complete mitigation, only the update: <https://www.php.net/archive/2026.php#2026-10-21-5>. AWS security bulletin 2026-143-AWS lists the WAF compensating controls that rules 4 and 5 implement, and also says none of them is complete: <https://aws.amazon.com/security/security-bulletins/2026-143-aws/>
> - AWS Security Blog, "Using AWS WAF to apply mitigations for PHP2Shell RCE vulnerabilities": the WAF rules (session upload progress, multipart, body size cap, rate limit) that rules 4, 5, 0 and 2 correspond to, what AWS WAF cannot cover, and server-side settings to apply alongside: <https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/>
> - Amazon Threat Intelligence saw a php2shell exploitation attempt on 2026-10-17, four days before the public release, and says the flaws are now being broadly exploited. It also advises considering blocking multipart file uploads where you cannot patch yet (after checking the impact on your application) and looking for POST requests with `PHP_SESSION_UPLOAD_PROGRESS`: <https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/>
> - Before the release, the PHP security team announced it (two critical issues, CVSS v4.0 9.2) without naming CVE IDs or mechanisms: <https://www.php.net/archive/2026.php#2026-10-20-1>. The CVE IDs and the name "php2shell" come from security vendors' reports.
>
> Rate-based rules let requests through until the limit is exceeded (see the measurements below). Rules 0, 1, 4 and 5 act on the first request. Rule 0 also blocks legitimate multipart forms and file uploads, so it is off by default.

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
| `BlockPhpUploadProgress` | `true` | `true` adds rule 4 (AWS's `PHP2Shell` rule). Only the first 8 KB of the body is inspected by an ALB. |
| `BlockLargeBody` | `false` | `true` adds rule 5 (`block-oversize-body`). It also blocks legitimate uploads and any POST body over 8 KB, so it is off by default. The managed `SizeRestrictions_BODY` rule in AWS's Core rule set does the same; this sample uses a custom rule so that the 403 can carry the rule name. |
| `IpRateLimit` | `10` | Minimum allowed by AWS WAF is 10. |
| `FingerprintRateLimit` | `15` | Counted per JA4 fingerprint, across different IPs. |
| `EvaluationWindowSec` | `60` | `60`, `120`, `300` or `600`. |
| `LoadBalancerArn` | (empty) | Empty creates the web ACL only. See the warning about existing associations below. |
| `EnableLogging` | `true` | Creates a CloudWatch Logs log group and the logging configuration. |
| `LogRetentionInDays` | `7` | |

## Things to know before you use it

- **JA4 needs TLS.** The fingerprint is computed from the TLS Client Hello. The AWS WAF documentation says a request that lacks a component of the aggregation key is left out of the rate-based rule's evaluation, so use an HTTPS listener if you want rule 2 to count. (I did not test an HTTP listener.)
- **Rules 1 and 2 use the source IP the ALB sees.** Behind another proxy or CDN that may be the proxy's address. Consider AWS WAF's forwarded-IP configuration if you need the original client address (not included in this sample).
- **Rule 0 matches more broadly than PHP does.** In php-src (`main/SAPI.c`, `sapi_read_post_data`, read on `master` on 2026-10-21; other versions not checked), PHP lowercases the `Content-Type`, cuts it at the first `;`, `,` or space, and compares what is left with `multipart/form-data`. Rule 0 lowercases the header and checks whether it *contains* `multipart/form-data`, so it also stops every value PHP treats as multipart (including the comma-separated form) and some that PHP does not. It looks only at the `Content-Type` header; I did not test requests with several `Content-Type` headers or folded headers.
- **Rule 4 is AWS's rule, copied as published; it is a narrow match.** It needs `PHPSESSID` (cookie name, exact and case-sensitive; or anywhere in the body) *and* `PHP_SESSION_UPLOAD_PROGRESS` in the body, with oversize handling `CONTINUE`. In my test (below) a request with a different session cookie name (`session.name` changed), a lowercase `phpsessid` cookie, or the reserved field placed after about 9 KB of other data all passed rule 4. Rule 5 stopped the 9 KB case only because the body was over 8 KB. Rule 4 does not look at `Content-Type`: a urlencoded body with both names is blocked too.
- **Rule 5 is a size cap, not a parser.** `SizeConstraintStatement` on the body with `OversizeHandling: MATCH` blocks every body over 8,192 bytes, including bodies that are larger than the part an ALB passes to AWS WAF. On CloudFront or API Gateway the default inspection limit is 16 KB (raisable to 32, 48 or 64 KB with the web ACL `AssociationConfig`), so adapt the number and the setting if you move the rules there; this template is for ALB (REGIONAL) only. AWS also says a size cap does not catch header amplification, many small part headers that stay under the cap but cost far more memory inside PHP, and that AWS WAF cannot parse the headers inside individual multipart parts. If you already use `AWSManagedRulesCommonRuleSet`, its `SizeRestrictions_BODY` rule does the same job; override a rule that breaks legitimate traffic to Count instead of disabling the group.
- **Rule order.** The AWS blog suggests running the session-upload-progress and multipart rules before the size and rate rules. Here the rate rules (2, 3) have lower priority numbers than rule 4 and 5, so a request that rules 4 or 5 would block is counted by the rate rules first. It is blocked either way; only the attribution and the rate counters differ. I kept the numbers of rules 0 to 3 as published in the article.
- **One web ACL per ALB.** When I passed `LoadBalancerArn` for an ALB that already had another web ACL, the stack update succeeded and the new web ACL started receiving the traffic. Check the existing association first.
- **Rate-based rules are approximate.** AWS WAF documents that it applies rate limiting near the limit and does not guarantee an exact match.
- **Cost.** AWS WAF charges for web ACLs, rules and requests, and CloudWatch Logs charges for ingestion and storage. See the AWS pricing pages.

## Server-side settings that go with these rules

AWS WAF cannot see PHP's memory or configuration, so the part of CVE-2026-109619 that sits below the HTTP layer needs settings on the PHP host. These come from the PHP advisory and the AWS Security Blog above; I did not test them. None of them replaces the PHP update (8.5.12, 8.4.27, 8.3.36, 8.2.35).

- `session.upload_progress.enabled=0` in `php.ini` or the FPM pool/server configuration, and restart every worker. `ini_set()` and `.user.ini` do not work. It blocks the confirmed session paths, not other variants.
- `memory_limit=-1` (so applications cannot override it) and a small `post_max_size` (8M if there are no uploads, 32M if there are) for CVE-2026-109618. Enforce memory bounds with container or cgroup limits, not `RLIMIT_AS` or `RLIMIT_DATA`.
- On PHP 8.5, `fatal_error_backtraces=0`.
- `pm.max_requests=1` if performance allows, so a worker that served one request is recycled before a second request can reuse stale state.
- Turn on error logging and review it for repeated warnings, fatal errors and timeouts on attacker-reachable routes. No errors is not proof of safety.

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

### Rules 4 and 5 (added 2026-10-22, same ALB, `curl` from a workstation in Japan, `test/php_upload_progress_test.sh`)

Requests contain only the field names AWS's rule looks for, with dummy values; no attack payload. Results with `BlockPhpUploadProgress=true`, `BlockLargeBody=true`, `RuleAction=Block`:

| Case | Result |
|---|---|
| multipart POST, cookie `PHPSESSID`, field `PHP_SESSION_UPLOAD_PROGRESS` | 403, `x-waf-blocked-by: block-php-upload-progress` |
| multipart POST, `PHPSESSID` and the reserved field both in the body | 403 |
| urlencoded POST with both names in the body | 403 |
| reserved field only / `PHPSESSID` only (cookie or body) | 200 |
| `GET` with cookie, `PUT` with cookie and field | 200 |
| lowercase `phpsessid` cookie, or another cookie name (`MYSESS`), with the field | 200 |
| reserved field after about 9 KB of padding, cookie `PHPSESSID` | 403 from rule 5 (`x-waf-blocked-by: block-oversize-body`); 200 with `BlockLargeBody=false`, so rule 4 alone did not see the field |
| benign urlencoded body of about 7 KB / about 9 KB / about 1 MB | 200 / 403 from rule 5 / 403 from rule 5 |

With `RuleAction=Count` and `BlockLargeBody=true` every request returned 200; the WAF log recorded the matches of rule 4 and rule 5 as `COUNT`. One run each; the rules took effect within a minute of the stack update. (A first run used the managed `SizeRestrictions_BODY` rule for rule 5 and gave the same allow/block results, except that its 403 had no `x-waf-blocked-by` header.)

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
bash test/php_upload_progress_test.sh <alb-dns-name>   # rules 4 and 5 (field names and body sizes only, no attack payload)
```

`send_requests.py` prints the status code, the `x-waf-blocked-by` header and the response body for each request. It turns off certificate verification, so use it only against a test ALB you own, and keep the ALB's security group limited to your own source IPs while you test.

## License

MIT. See [LICENSE](LICENSE).
