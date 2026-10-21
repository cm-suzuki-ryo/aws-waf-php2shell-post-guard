# aws-waf-php2shell-post-guard

[English](README.md)

ALB向けのAWS WAF(REGIONAL)をまとめて作るCloudFormationサンプルです。
1つのWebACLに3つのルールを入れ、リクエストを止めたルールの名前をレスポンスに返せるので、403の理由が分かります。

| 優先度 | ルール | 対象 | アクション |
|---|---|---|---|
| 0 | `block-foreign-post` | `AllowedCountries`(既定 `JP`)以外の国からの `POST` | Block(または Count) |
| 1 | `rate-limit-post-ip` | `POST` を送信元IPごとに数える(既定 60秒に10回) | Block(または Count) |
| 2 | `rate-limit-post-fingerprint` | `POST` をTLSのJA4フィンガープリントごとに数える(既定 60秒に15回) | Block(または Count) |

オプションで、ALBへの関連付けと、CloudWatch LogsへのWebACLログ出力ができます。

> **これはphp2shell(CVE-2026-109618 / CVE-2026-109619)の修正ではなく、悪意のある単発のリクエストを止めるものでもありません。**
> WAFのルールを試し、ログの見え方を確認するためのサンプルです。PHPの更新が出たら、すぐに適用してください。
> - GMO Flatt Securityは、`session.upload_progress.enabled=0` は「ややの緩和策に留まり」、攻撃は依然として可能と見られ、根本的にはパッチが必要としています: <https://blog.flatt.tech/entry/php2shell>
> - Sansecは、攻撃はアプリケーションのコードやストア向けのシールドより前に、PHP自体を狙うように見えるとしています: <https://sansec.io/research/php2shell>
> - PHPのセキュリティチームは、2件の重大な脆弱性(CVSS v4.0 9.2)の修正リリースを告知していますが、CVE番号や仕組みには触れていません: <https://www.php.net/archive/2026.php#2026-10-20-1>。CVE番号と「php2shell」の名称は、セキュリティベンダーの報告によるものです。
>
> レートベースのルールは、上限を超えるまでリクエストを通します(下の実測を参照)。最初の1回から効くのは、このサンプルではルール0だけです。

## デプロイ

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

実際のワークロードでは、まず `RuleAction=Count` で始め、ログを見てから `Block` に切り替えてください。
スタックを削除すると、作成したものがすべて消えます(WebACL、関連付け、ロググループ)。

### パラメータ

| 名前 | 既定値 | 説明 |
|---|---|---|
| `WebAclName` | `post-protection-sample` | メトリクス名のプレフィックスと、ロググループ名(`aws-waf-logs-<名前>`)にも使います。 |
| `AllowedCountries` | `JP` | ルール0の対象外にする国のISO 3166 alpha-2コード(カンマ区切り)。 |
| `RuleAction` | `Block` | `Block` か `Count`。カスタムレスポンスは `Block` のときだけ有効です。 |
| `ReturnBlockReason` | `true` | `true` だと、403の本文と `x-waf-blocked-by` ヘッダにルール名を入れます。**本番では `false` にしてください。** どのルールと閾値で止まったかを、相手に教えることになります。 |
| `IpRateLimit` | `10` | AWS WAFの最小値は10です。 |
| `FingerprintRateLimit` | `15` | JA4フィンガープリントごとに数えます。IPが違っても合算されます。 |
| `EvaluationWindowSec` | `60` | `60`、`120`、`300`、`600` のいずれか。 |
| `LoadBalancerArn` | (空) | 空ならWebACLだけ作ります。既存の関連付けについては、下の注意を読んでください。 |
| `EnableLogging` | `true` | CloudWatch Logsのロググループとログ出力の設定を作ります。 |
| `LogRetentionInDays` | `7` | |

## 使う前に知っておくこと

- **JA4にはTLSが必要です。** フィンガープリントはTLSのClient Helloから計算されます。AWS WAFのドキュメントでは、集計キーの要素が欠けたリクエストはレートベースルールの評価から外れるとされています。ルール2を効かせたいなら、HTTPSリスナーを使ってください(HTTPリスナーでは試していません)。
- **ルール0と1は、ALBから見える送信元IPで判定します。** 別のプロキシやCDNを経由する場合、そのプロキシのアドレスになる可能性があります。必要なら、AWS WAFの転送IP(Forwarded IP)の設定を検討してください(このサンプルには含めていません)。
- **1つのALBに関連付けられるWebACLは1つです。** すでに別のWebACLが付いているALBの `LoadBalancerArn` を渡したところ、スタックの更新は成功し、新しいWebACLが通信を受けるようになりました。先に既存の関連付けを確認してください。
- **レートベースのルールは厳密ではありません。** AWS WAFは、上限の付近で制限をかけるだけで、正確な一致は保証しないと説明しています。
- **費用。** AWS WAFはWebACL、ルール、リクエストに、CloudWatch Logsは取り込みと保存に課金されます。AWSの料金ページを確認してください。

## 実測したこと(各1回、`ap-northeast-1`、2026-10-21)

HTTPSリスナー(自己署名証明書)で固定の200を返すテスト用ALBを使いました。送ったのは無害なmultipartのPOST(フォーム項目とダミーファイル)で、AWS CloudShellと日本国内の1台のPCから送っています。1回ずつの観測であり、保証ではありません。

| ケース | 結果 |
|---|---|
| `us-east-1` のCloudShell(国 `US`)からの `POST` | 3回とも最初から403。同じシェルからの `GET` は200。WAFログは `terminatingRuleId: block-foreign-post`、`country: US`、`responseCodeSent: 403`。 |
| 東京のCloudShell(国 `JP`)からの `POST` | 3回とも200。 |
| ルール1(60秒に10回)、東京のシェル1つから1秒に1回で60回の `POST` | 23回が通り、24回目から403。11回目の約14秒後でした。最後の `GET` は200。 |
| ルール1(以前の実行、multipartのPOSTのみ対象)、約1秒で30回の連投 | 30回とも200。その45秒後の連投は、1回目から403。 |
| ルール2(60秒に15回。この確認だけルール1を50回に上げた)、東京と大阪のシェルから同時に1秒に1回で各30回の `POST` | 403が始まるまでに、29 + 23 = 52回が通りました。両方のシェルのJA4は同じで、403は `rate-limit-post-fingerprint` によるものでした。 |

分かること: レートベースのルールは、門ではなくスロットルです。上限が10でも、ブロックが効くまでに数十回が通りました。

## ログの見え方

- **WAFログ**(CloudWatch Logs): `action`、`terminatingRuleId`、`terminatingRuleType`(ルール1と2は `RATE_BASED`)、`rateBasedRuleList`(上限、ウィンドウ、キー)、`httpRequest.country`、`ja4Fingerprint`、`ja3Fingerprint`、`responseCodeSent` が出ます。
- **ALBアクセスログ**: WAFで止まったリクエストは、`elb_status_code` が403、`actions_executed` が `waf` でした(固定応答のリスナーで通ったリクエストは `waf,fixed-response`)。CloudWatch Logsへの配信は遅れ、リクエストの数分後でも揃わないことがありました。

## 試す

```bash
python3 test/send_requests.py https://<alb-dns-name>/ get 1 0
python3 test/send_requests.py https://<alb-dns-name>/ post 30 1
```

1リクエストごとに、ステータス、`x-waf-blocked-by` ヘッダ、レスポンス本文を表示します。証明書の検証を無効にしているので、自分のテスト用ALBにだけ使ってください。テスト中は、ALBのセキュリティグループを自分の送信元IPだけに絞ってください。

## ライセンス

MIT。[LICENSE](LICENSE) を参照してください。
