# tukuyomi-core

tukuyomi-core は、HTTP・HTTPS のリバースプロキシに組み込んだ WAF（Web Application Firewall）である。受け付けたリクエストを、Coraza か ModSecurity v3 で、OWASP Core Rule Set などのルールセットを使って検査し、アップストリームへ転送する。tukuyomi（tukuyomi WAF）から派生し、WAF の機能に特化したシステムを目指している。

## 今の状態

0.1.0 は最初のリリースである。実装済みの範囲と、まだ無いもの・決まっていないことは、[システム概要](docs/detailed-design/00_overview/system-overview.md) の「現在の状態」に書く。全体としての安全性は、まだ評価していない。

実装済みの主なもの:

- HTTP/1.1 と、TLS の上の HTTP/2 の受付と、アップストリームへの転送
- Coraza（Go の検査プロセス）か ModSecurity v3 によるリクエストの検査。ルールセットの世代のインポート、切り替え、検知のみのモード
- IP と国のアクセス制御と、レート制限（全体の設定と、ホストごとの設定）
- ACME（HTTP-01）による証明書の発行と更新
- 管理 API と管理画面（managed 設定の編集と反映、ルールセットの世代の操作、ログの検索、監査ログ）
- ログファイルと、PostgreSQL・MySQL へのログの送信

試したのは、Landlock が有効な Linux の x86_64 だけである。

## 入れ方

- リリースの tarball を使う: [実行ファイルの build と配置](docs/build/binary-deployment.md) の「リリースの tarball」
- ソースから build する: 同じ文書の「build」
- 設定と運用: [運用リファレンス](docs/operations/operator-reference.md)、[管理リファレンス](docs/operations/admin-reference.md)
- 文書の入口: [docs/README.md](docs/README.md)

## ライセンス

BSD 2-Clause License（[LICENSE](LICENSE)）。実行ファイルに入る第三者のソフトウェアとそのライセンスは、[NOTICE](NOTICE) と [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES) に書く。OWASP Core Rule Set は同梱しない（[実行ファイルの build と配置](docs/build/binary-deployment.md) の「CRS の取得」）。
