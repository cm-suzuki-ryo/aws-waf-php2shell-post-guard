# aws-waf-php2shell-post-guard

[English](README.md)

ALB向けのAWS WAF(REGIONAL)をまとめて作るCloudFormationサンプルです。
1つのWebACLに3つのルール(任意のルールを入れると最大6つ)を入れ、リクエストを止めたルールの名前をレスポンスに返せるので、403の理由が分かります。

| 優先度 | ルール | 対象 | アクション |
|---|---|---|---|
| 0 | `block-multipart-post`(任意、`BlockMultipartPost=true`) | `Content-Type` ヘッダに `multipart/form-data` を含む `POST`(大文字小文字は区別しない) | Block(または Count) |
| 1 | `block-foreign-post` | `AllowedCountries`(既定 `JP`)以外の国からの `POST` | Block(または Count) |
| 2 | `rate-limit-post-ip` | `POST` を送信元IPごとに数える(既定 60秒に10回) | Block(または Count) |
| 3 | `rate-limit-post-fingerprint` | `POST` をTLSのJA4フィンガープリントごとに数える(既定 60秒に15回) | Block(または Count) |
| 4 | `block-php-upload-progress`(`BlockPhpUploadProgress`、既定 `true`) | AWSセキュリティ速報 2026-143-AWS(CVE-2026-109619)のカスタムルール: `POST` で、ボディまたはCookie名に `PHPSESSID`、かつボディに `PHP_SESSION_UPLOAD_PROGRESS` を含む | Block(または Count) |
| 5 | `aws-crs-size-restrictions-body`(任意、`BlockLargeBody=true`) | AWSマネージドのコアルールセットのうち `SizeRestrictions_BODY` 以外を Count にしたもの: 8KBを超えるリクエストボディ(同じ速報の CVE-2026-109618 向けの補完策) | Block(または Count) |

オプションで、ALBへの関連付けと、CloudWatch LogsへのWebACLログ出力ができます。

> **これはphp2shell(CVE-2026-109618 / CVE-2026-109619)の修正ではなく、悪意のある単発のリクエストを止めるものでもありません。**
> WAFのルールを試し、ログの見え方を確認するためのサンプルです。PHPの更新が出たら、すぐに適用してください。
> - GMO Flatt Securityは、`session.upload_progress.enabled=0` は「ややの緩和策に留まり」、攻撃は依然として可能と見られ、根本的にはパッチが必要としています: <https://blog.flatt.tech/entry/php2shell>
> - Sansecは、攻撃はアプリケーションのコードやストア向けのシールドより前に、PHP自体を狙うように見えるとしています: <https://sansec.io/research/php2shell>
> - PHPは2026-10-21に修正版(8.5.12、8.4.27、8.3.36、8.2.35)をリリースし、完全な緩和策はなく更新だけが安全としています: <https://www.php.net/archive/2026.php#2026-10-21-5>。AWSセキュリティ速報 2026-143-AWS は、ルール4と5が実装するWAFの補完策を挙げつつ、いずれも完全ではないとしています: <https://aws.amazon.com/security/security-bulletins/2026-143-aws/>
> - リリース前に、PHPのセキュリティチームは、2件の重大な脆弱性(CVSS v4.0 9.2)の修正リリースを告知していますが、CVE番号や仕組みには触れていません: <https://www.php.net/archive/2026.php#2026-10-20-1>。CVE番号と「php2shell」の名称は、セキュリティベンダーの報告によるものです。
>
> レートベースのルールは、上限を超えるまでリクエストを通します(下の実測を参照)。最初の1回から効くのは、このサンプルではルール0、1、4、5です。ルール0は、正当なmultipartのフォームやファイルアップロードも止めるため、既定では無効です。

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
| `AllowedCountries` | `JP` | ルール1の対象外にする国のISO 3166 alpha-2コード(カンマ区切り)。 |
| `RuleAction` | `Block` | `Block` か `Count`。カスタムレスポンスは `Block` のときだけ有効です。 |
| `ReturnBlockReason` | `true` | `true` だと、403の本文と `x-waf-blocked-by` ヘッダにルール名を入れます。**本番では `false` にしてください。** どのルールと閾値で止まったかを、相手に教えることになります。 |
| `BlockMultipartPost` | `false` | `true` にするとルール0を追加します。`Content-Type` に `multipart/form-data` を含む `POST` を、正当なアップロードやファイルなしのフォームも含めて、すべて止めます。これらが不要なサイトだけで有効にしてください。 |
| `BlockPhpUploadProgress` | `true` | `true` でルール4(AWSの `PHP2Shell` ルール)を追加します。ALBがWAFに渡すボディは先頭8KBまでです。 |
| `BlockLargeBody` | `false` | `true` でルール5(AWSマネージドのコアルールセット。`SizeRestrictions_BODY` だけ有効、700 WCU)を追加します。正当なアップロードや8KBを超えるPOSTも止めるため、既定は無効です。 |
| `IpRateLimit` | `10` | AWS WAFの最小値は10です。 |
| `FingerprintRateLimit` | `15` | JA4フィンガープリントごとに数えます。IPが違っても合算されます。 |
| `EvaluationWindowSec` | `60` | `60`、`120`、`300`、`600` のいずれか。 |
| `LoadBalancerArn` | (空) | 空ならWebACLだけ作ります。既存の関連付けについては、下の注意を読んでください。 |
| `EnableLogging` | `true` | CloudWatch Logsのロググループとログ出力の設定を作ります。 |
| `LogRetentionInDays` | `7` | |

## 使う前に知っておくこと

- **JA4にはTLSが必要です。** フィンガープリントはTLSのClient Helloから計算されます。AWS WAFのドキュメントでは、集計キーの要素が欠けたリクエストはレートベースルールの評価から外れるとされています。ルール2を効かせたいなら、HTTPSリスナーを使ってください(HTTPリスナーでは試していません)。
- **ルール1と2は、ALBから見える送信元IPで判定します。** 別のプロキシやCDNを経由する場合、そのプロキシのアドレスになる可能性があります。必要なら、AWS WAFの転送IP(Forwarded IP)の設定を検討してください(このサンプルには含めていません)。
- **ルール0は、PHPの判定より広く止まります。** php-src(`main/SAPI.c` の `sapi_read_post_data`。2026-10-21時点の `master` を読んだもので、他のバージョンは確認していません)は、`Content-Type` を小文字にし、最初の `;`、`,`、半角スペースで打ち切って、残りを `multipart/form-data` と比べます。ルール0は、ヘッダを小文字にして `multipart/form-data` を「含む」かを調べるため、PHPが multipart と判定する値(カンマ区切りを含む)はすべて止まり、PHPが判定しない値も一部止まります。見るのは `Content-Type` ヘッダだけで、`Content-Type` が複数あるリクエストや、折り返されたヘッダは試していません。
- **ルール4はAWSが公開したルールをそのまま写したもので、一致の範囲は狭いです。** ボディかCookie名の `PHPSESSID`(Cookie名は完全一致で大文字小文字を区別)と、ボディの `PHP_SESSION_UPLOAD_PROGRESS` の両方が必要で、サイズ超過時の扱いは `CONTINUE` です。下の実測では、セッションCookie名が違う(`session.name` を変更)、小文字の `phpsessid`、予約フィールドが約9KBのデータより後ろにある、のいずれもルール4を通過しました。9KBの場合にルール5が止めたのは、ボディが8KBを超えていたためです。ルール4は `Content-Type` を見ないため、両方の名前を含むurlencodedのボディも止まります。
- **ルール5はマネージドルールグループです。** カスタムレスポンスを返せないため、403に `x-waf-blocked-by` ヘッダは付きません。WAFログでは `terminatingRuleId: aws-crs-size-restrictions-body` になります。CRSの他のルールは Count に上書きしてあり、ログには数えられますが止めません。マネージドルールグループのバージョンは固定していません。
- **1つのALBに関連付けられるWebACLは1つです。** すでに別のWebACLが付いているALBの `LoadBalancerArn` を渡したところ、スタックの更新は成功し、新しいWebACLが通信を受けるようになりました。先に既存の関連付けを確認してください。
- **レートベースのルールは厳密ではありません。** AWS WAFは、上限の付近で制限をかけるだけで、正確な一致は保証しないと説明しています。
- **費用。** AWS WAFはWebACL、ルール、リクエストに、CloudWatch Logsは取り込みと保存に課金されます。AWSの料金ページを確認してください。

## 実測したこと(各1回、`ap-northeast-1`、2026-10-21)

HTTPSリスナー(自己署名証明書)で固定の200を返すテスト用ALBを使いました。送ったのは無害なmultipartのPOST(フォーム項目とダミーファイル)で、AWS CloudShellと日本国内の1台のPCから送っています。1回ずつの観測であり、保証ではありません。

| ケース | 結果 |
|---|---|
| `us-east-1` のCloudShell(国 `US`)からの `POST` | 3回とも最初から403。同じシェルからの `GET` は200。WAFログは `terminatingRuleId: block-foreign-post`、`country: US`、`responseCodeSent: 403`。 |
| 東京のCloudShell(国 `JP`)からの `POST` | 3回とも200。 |
| ルール2(60秒に10回)、東京のシェル1つから1秒に1回で60回の `POST` | 23回が通り、24回目から403。11回目の約14秒後でした。最後の `GET` は200。 |
| ルール2(以前の実行、multipartのPOSTのみ対象)、約1秒で30回の連投 | 30回とも200。その45秒後の連投は、1回目から403。 |
| ルール3(60秒に15回。この確認だけルール2を50回に上げた)、東京と大阪のシェルから同時に1秒に1回で各30回の `POST` | 403が始まるまでに、29 + 23 = 52回が通りました。両方のシェルのJA4は同じで、403は `rate-limit-post-fingerprint` によるものでした。 |

| ルール0(`BlockMultipartPost=true`)、日本国内のPCからcurl | 次の形は、1回目から403で、ヘッダは `x-waf-blocked-by: block-multipart-post`: 標準の `multipart/form-data; boundary=x`、カンマ区切りの `multipart/form-data, boundary=x`、`Multipart/Form-Data`、`multipart/form-data;charset=utf-8;boundary=x`。次の形は200: `application/x-www-form-urlencoded`、`text/plain`、`application/json`、`multipart/mixed`、multipartのヘッダ付きの `PUT`、同じくヘッダ付きの `GET`。WebACLを付けてから約10秒以内に有効になりました(最初の確認がすでに403で、これより短い可能性があります)。値の前の空白やタブは、WebACLがヘッダを受け取る前に除かれていたため、その形は検証できていません。 |

分かること: レートベースのルールは、門ではなくスロットルです。上限が10でも、ブロックが効くまでに数十回が通りました。

### ルール4と5(2026-10-22に追加、同じALB、日本国内の端末から `curl`、`test/php_upload_progress_test.sh`)

リクエストに含めるのはAWSのルールが見るフィールド名とダミーの値だけで、攻撃のペイロードは含みません。`BlockPhpUploadProgress=true`、`BlockLargeBody=true`、`RuleAction=Block` の結果です。

| ケース | 結果 |
|---|---|
| multipartのPOST、Cookie `PHPSESSID`、フィールド `PHP_SESSION_UPLOAD_PROGRESS` | 403、`x-waf-blocked-by: block-php-upload-progress` |
| multipartのPOST、`PHPSESSID` と予約フィールドの両方がボディ内 | 403 |
| 両方の名前をボディに含むurlencodedのPOST | 403 |
| 予約フィールドだけ、または `PHPSESSID` だけ(Cookie、ボディとも) | 200 |
| Cookie付きの `GET`、Cookieとフィールド付きの `PUT` | 200 |
| 小文字の `phpsessid` Cookie、または別のCookie名(`MYSESS`)とフィールド | 200 |
| 約9KBのパディングの後ろに予約フィールド、Cookie `PHPSESSID` | ルール5(`SizeRestrictions_BODY`)で403。`BlockLargeBody=false` では200で、ルール4だけではフィールドが見えていませんでした |
| 約7KB / 約9KB の無害なurlencodedボディ | 200 / ルール5で403 |

`RuleAction=Count`、`BlockLargeBody=true` ではすべて200で、WAFログにはルール4とルール5の一致が `COUNT` として記録されました。各1回の実測で、ルールはスタック更新から1分以内に効きました。

## ログの見え方

- **WAFログ**(CloudWatch Logs): `action`、`terminatingRuleId`、`terminatingRuleType`(ルール1と2は `RATE_BASED`)、`rateBasedRuleList`(上限、ウィンドウ、キー)、`httpRequest.country`、`ja4Fingerprint`、`ja3Fingerprint`、`responseCodeSent` が出ます。
- **ALBアクセスログ**: WAFで止まったリクエストは、`elb_status_code` が403、`actions_executed` が `waf` でした(固定応答のリスナーで通ったリクエストは `waf,fixed-response`)。CloudWatch Logsへの配信は遅れ、リクエストの数分後でも揃わないことがありました。

## 試す

```bash
python3 test/send_requests.py https://<alb-dns-name>/ get 1 0
python3 test/send_requests.py https://<alb-dns-name>/ post 30 1
```

```bash
bash test/variants_test.sh <alb-dns-name>   # ルール0に対する、Content-Typeとメソッドの組み合わせ
```

`send_requests.py` は、1リクエストごとに、ステータス、`x-waf-blocked-by` ヘッダ、レスポンス本文を表示します。証明書の検証を無効にしているので、自分のテスト用ALBにだけ使ってください。テスト中は、ALBのセキュリティグループを自分の送信元IPだけに絞ってください。

## ライセンス

MIT。[LICENSE](LICENSE) を参照してください。
