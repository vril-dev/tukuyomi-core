# 付録C　リリースノート

公開したときのリリースノートの本文を、新しい順にそのまま収めます。

## 0.2.0

### 概要

- **アップストリームごとに、検査エンジンを選べるようになりました。** 0.1.0 では、選択中の 1 つの世代のエンジンが、すべてのリクエストを検査していました。アップストリームの `engine`（`coraza` か `modsecurity`）でエンジンを選べるようになり、書かないアップストリームは `kernel.default_engine`（書かなければ `coraza`）のエンジンで検査します。プロキシは、起動したエンジンごとに検査カーネルを動かし、リクエストは、行き先のアップストリームのエンジンだけで検査します。同じアドレスのサーバーを持つアップストリームは、同じエンジンにします。
- **ルールストアは、エンジンごとに選択中の世代を持ちます。** `rules activate` は、世代を、そのエンジンの選択中の世代にします。`rules list` の `current` の印は、2 行になることがあります。エンジンの選択を解除する `rules deactivate <config> <engine>` を足しました。0.1.0 が書いた `current` は、その世代のエンジンの選択中の世代として読みます。
- **SIGUSR1 は、エンジンを 1 つずつ切り替えます**（デフォルトのエンジンが先で、ほかは名前の順）。選択中の世代があるのに稼働していないエンジンは、起動します。稼働していないエンジンを使うアップストリームがある設定のリロード（SIGHUP、制御ソケットの `reload`）は拒否します。
- **管理 API と管理画面を、エンジンごとに使えるようにしました。** `GET /api/status` は `default_engine` と `engines` を返し、`POST /api/rollback` は `engine` を受け取り、切り替えの履歴の行は `engine` を持ち、ログの検索はエンジンで絞り込めます。画面では、エンジンごとの状態、エンジンの起動、アップストリームのエンジンの選択ができます。0.1.0 のプロキシには、管理プロセスは世代の選択とロールバックを行いません（`409 the proxy does not report its engines`）。
- **エンジンを省いたインポートは、デフォルトのエンジンの世代になります**（`--engine` を付けない `rules import` と、`engine` の無い管理 API のインポート）。
- `/metrics` に、エンジンごとの `tukuyomi_inspector_engine_up` と `tukuyomi_inspector_engine_restarts_total` を足しました。

### 更新の注意

- **管理プロセス、プロキシ、ログ送信プロセスを、同じリリースにそろえてください。** 0.1.0 のログ送信プロセスは、`kernel.default_engine` とアップストリームの `engine` を受け付けないので、入れ替えてから書いてください。
- **0.1.0 で ModSecurity の世代を選択していたとき**は、`kernel` に `"default_engine": "modsecurity"` を書いてください。書かないと、起動と `config check` は `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` で受け付けません。Coraza の世代を選択していたときは、書く必要はありません。
- **0.1.0 に戻すとき:** 0.1.0 は `current` だけを読みます。0.2.0 で何も選択しておらず、新しい設定キーも書いていなければ、0.1.0 の実行ファイルに戻すだけで起動します。0.2.0 で `rules activate` をした後は、運用リファレンスの「バージョンの更新」の手順で戻してください。
- 起動したエンジンごとに検査プロセスが 1 つ動くので、2 つ目のエンジンを起動すると、プロセスが 1 つとその分のメモリが増えます。測った値は、運用リファレンスの「検査エンジンの選択」にあります。

### 検証

- リリースの木で、`--offline --locked` で組んだ全体の試験が通りました（検査カーネル、プロキシの単体の試験 942 件と実プロセスの試験 112 件、ModSecurity の検査プロセス、ログ送信プロセスと DB の試験、clippy と fmt）。管理画面の試験（155 件）も通りました。
- 新しい振る舞いを、release の実行ファイルで確かめました。OWASP Core Rule Set を 2 つのエンジンに入れ、どちらも通常のリクエストを通して SQL インジェクションをブロックし、ログのエンジンがそれぞれのエンジンになること。SIGUSR1 でエンジンを起動するまでリロードが拒否されること。`kernel.default_engine` を `modsecurity` にした設定。0.1.0 のプロキシと新しい管理プロセスの組み合わせ（409 で、何も変わらない）。0.1.0 に戻して、また進めること。
- 4 つの実行ファイルと tarball を作り、チェックサムを確かめ、tarball を 2 回作って byte が同じことを確かめました。release の ModSecurity の検査プロセスは、Core Rule Set の世代で、通常のリクエストを通し、SQL インジェクションをブロックしました。依存は 0.1.0 と同じです。動く環境: Landlock が有効な Linux x86_64（5.13 以上）、glibc 2.39 以上、ModSecurity の検査プロセスには libstdc++ の `GLIBCXX_3.4.29` と `CXXABI_1.3.15`。

**変更の一覧:** https://github.com/vril-dev/tukuyomi-core/compare/v0.1.0...v0.2.0

## 0.1.0

tukuyomi-core の最初のリリースです。HTTP・HTTPS のリバースプロキシに組み込んだ WAF で、受け付けたリクエストを Coraza か ModSecurity v3 で検査し、アップストリームへ転送します。文書は、どれも初期草案です。全体としての安全性は、まだ評価していません。

### できること

- HTTP/1.1 と、TLS の上の HTTP/2 の受付と、アップストリームへの転送
- Coraza（Go の検査プロセス）か ModSecurity v3 によるリクエストの検査。ルールセットの世代のインポート、切り替え、検知のみのモード
- IP と国のアクセス制御と、レート制限（全体の設定と、ホストごとの設定）
- ACME（HTTP-01）による証明書の発行と更新
- 管理 API と管理画面。managed 設定（サイト、アップストリーム、ルート、ポリシー）の編集と、プロキシを止めない反映、ルールセットの世代の操作、ログの検索、監査ログ
- ログファイルと、PostgreSQL・MySQL へのログの送信

実装していないもの（応答の検査、HTTP/3、平文の HTTP/2 など）と、決まっていないことは、[システム概要](https://github.com/vril-dev/tukuyomi-core/blob/v0.1.0/docs/detailed-design/00_overview/system-overview.md) の「現在の状態」にあります。

### 動く環境

- Linux x86_64。Landlock が有効なこと（Linux 5.13 以上）。
- glibc 2.39 以上。ModSecurity の検査プロセスには、さらに libstdc++ の `GLIBCXX_3.4.29` と `CXXABI_1.3.15` が要ります。
- 実行ファイルは Ubuntu 26.04.1 LTS で build しました。

### ファイル

| ファイル | 中身 |
|---|---|
| `tukuyomi-core_v0.1.0_linux_amd64.tar.gz` | 4 つの実行ファイル（`tukuyomi-proxy`、`tukuyomi-inspector`、`tukuyomi-inspector-modsecurity`、`tukuyomi-records-ship`）、`README.md`、`LICENSE`、`NOTICE`、`THIRD-PARTY-LICENSES`、`docs/`、`scripts/fetch-crs.sh` |
| `tukuyomi-core_v0.1.0_linux_amd64.tar.gz.sha256`、`tukuyomi-core_v0.1.0_SHA256SUMS` | tarball の SHA-256 |

```bash
sha256sum -c tukuyomi-core_v0.1.0_linux_amd64.tar.gz.sha256
tar -xzf tukuyomi-core_v0.1.0_linux_amd64.tar.gz
```

入れ方は [実行ファイルの build と配置](https://github.com/vril-dev/tukuyomi-core/blob/v0.1.0/docs/build/binary-deployment.md) にあります。OWASP Core Rule Set は同梱していません（同じ文書の「CRS の取得」）。

### ライセンス

BSD 2-Clause License。実行ファイルに入る第三者のソフトウェアは、`NOTICE` と `THIRD-PARTY-LICENSES` にあります。
