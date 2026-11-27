[English](binary-deployment.md) | [日本語](binary-deployment.ja.md)

# ビルドと配置

この文書では、現在の実装を 1 台の Linux ホストで動かす手順を説明します。
設定キーの意味と範囲、コマンド、シグナル、ログ、監視については、[運用リファレンス](../operations/operator-reference.ja.md) を参照してください。
管理プロセスの設定と API は、[管理リファレンス](../operations/admin-reference.ja.md) にあります。

この文書に出てくるパス（`/opt/tukuyomi-core`、`/etc/tukuyomi-core`、`/var/lib/tukuyomi-core`）と OS ユーザーの名前（`tukuyomi`）は例です。
設定に書くパスはどれも絶対パスにします。
`.`・`..`・空の要素・末尾の `/` を含むパスは受け付けません。

## 構成要素

| 構成要素 | 内容 |
|---|---|
| `tukuyomi-proxy`（Rust、`proxy/`） | HTTP/HTTPS のリクエストを受信して転送します。検査カーネル（`kernel/`、Rust のライブラリ）を組み込み、検査プロセスの起動・停止・再起動を受け持ちます。同じ実行ファイルに、ルールストアのコマンド（`rules`）、証明書のコマンド（`acme renew`）、設定の検証（`config check`）、管理プロセス（`admin`）も入っています |
| `tukuyomi-inspector`（Go、`inspector/`） | Coraza でリクエストを検査します。プロキシが子プロセスとして起動し、引き継いだ Unix ドメインソケットのペアで通信します。待ち受けるポートは持ちません。設定の `kernel.inspector` に指定します |
| `tukuyomi-inspector-modsecurity`（Rust と C++、`inspector-modsecurity/`） | ModSecurity v3（libmodsecurity 3.0.17）でリクエストを検査します。必要になるのは、ModSecurity の世代（`rules import --engine modsecurity`）を使う場合と、デフォルトのエンジンかアップストリームのエンジンに `modsecurity` を指定する場合だけです。使わないホストでは省略できます。プロキシが子プロセスとして起動し、引き継いだ Unix ドメインソケットのペアで通信します。待ち受けるポートは持ちません。設定の `kernel.engines.modsecurity.inspector` に指定します |
| `tukuyomi-records-ship`（Rust、`records-ship/`） | ログ送信プロセスで、プロキシのログファイルの行を PostgreSQL か MySQL のテーブルへ送ります。ログを DB へ送る場合だけ必要で、送らないホストでは省略できます。プロキシとは別のユニットで動き、同じ設定ファイルを読みます。待ち受けるポートは持ちません |
| 管理プロセス | 同じ実行ファイルの `tukuyomi-proxy admin <config>` です。プロキシとは別のユニットで動かします。ループバックアドレスで待ち受け、管理 API と管理画面（実行ファイルに組み込み済み）を提供します。ルールの世代を操作し、制御ソケットを通じてプロキシに切り替えを依頼します |
| 設定ファイル | 1 つの JSON ファイルで、値にデフォルトはありません。省略できると決まっている設定キー（`acme`、`records`、`access`、`rate_limit`、`geo`、`admin` など）を除き、すべて書きます。プロキシと管理プロセスが同じファイルを読みます |
| ルールストア | ルールの世代を置くディレクトリです（設定の `rules.store.dir`）。`rules import` が世代を作り、`rules activate` が使う世代をエンジン（Coraza か ModSecurity）ごとに選択します。管理プロセスも同じ操作をします |
| 検査プロセスの作業ディレクトリ | 起動ごとの一時ディレクトリを作る親ディレクトリです（設定の `kernel.tmp_root`） |
| 証明書と鍵 | TLS のリスナーで使います。`acme renew` で発行・更新するか、運用者が置きます |
| ログのディレクトリ | 標準エラーに出すログのコピーを置くディレクトリです（設定の `records.dir`）。プロキシが書き、管理プロセスとログ送信プロセスが読みます。ログ送信プロセスは、送信済みの位置（`ship.state`）もここに書きます |
| 接続文字列のファイル | ログ送信プロセスが DB に接続するための文字列（パスワードを含む）を書いたファイルです（設定の `records.ship.db_dsn_file`）。ログ送信プロセスだけが読みます |
| 管理データの保存先 | 管理プロセスが、ユーザー、API トークン、監査ログ、切り替えの履歴を置くディレクトリです（設定の `admin.store.dir`） |
| 制御ソケット | プロキシが管理プロセスからの依頼を受ける Unix ドメインソケットです（設定の `admin.control`） |
| 国のデータベース | アクセス制御（`access`）の国の指定に使う、MaxMind DB 形式のファイルです（設定の `geo.country_db`）。運用者が用意します |

検査プロセス、管理プロセス、ログ送信プロセスは、プロキシと同じ OS ユーザーで動きます。

## 必要な環境

- Linux。動作を確認しているのは x86_64 だけです。
- Landlock が有効な Linux。
  - 検査プロセスはルールを読んだ後に、Landlock で自身の権限を制限します（下の「検査プロセスの権限の制限」）。
  - Landlock が無い Linux では、検査プロセスは起動しません（exit 14）。
    プロキシも起動しません（ログは `stop: the kernel failed, engine <engine>: Exit(14)`）。
    `rules import` の事前検証も、管理プロセスのインポートの事前検証も失敗します。
    制限をかけずに動かす設定はありません。
  - Landlock を含む Linux 5.13 以上で、LSM の一覧に `landlock` が入っている必要があります。一覧は `/sys/kernel/security/lsm` で確認できます。
    どのディストリビューションが Landlock をデフォルトで有効にしているかは、確認していません。
  - Linux のバージョンによって、制限できる範囲が違います。
    どの ABI バージョンで制限したかは、外からは分かりません。
    - TCP のバインドと接続まで制限するには、Linux 6.7 以上（Landlock の ABI 4 以上）が必要です。
      それより前のバージョンでは、ファイルだけを制限して動きます。
    - Linux 6.2 より前（ABI 1・2）では、ファイルの切り詰めを禁止できません。
      Linux 6.10 より前（ABI 4 まで）では、デバイスの ioctl を禁止できません。
- ModSecurity の検査プロセスを動かすホストに必要な共有ライブラリは、libstdc++、libgcc_s、libc、libm だけです。
  libmodsecurity、YAJL、PCRE2 は実行ファイルに静的リンクしてあるため、インストールは不要です。
- 常時動くのは、プロキシ 1 つと、起動したエンジンごとに 1 つずつの検査プロセスです。
  管理プロセスとログ送信プロセスは、これとは別のプロセスです。
  - Coraza だけなら検査プロセスは 1 つで、Coraza と ModSecurity の両方を起動すると 2 つになります。
  - エンジンの世代を切り替えている間は、そのエンジンの検査プロセスが一時的に 1 つ増えます。
    切り替えはプロキシ全体で同時に 1 つまでです。
  - 管理プロセスはインポートの事前検証のたびに、検査プロセスを 1 つ起動します。コマンドの `rules import` も同じです。
  - メモリの目安は、[運用リファレンス](../operations/operator-reference.ja.md) の「検査エンジンの選択」を参照してください。
- ビルドに必要なもの:
  - Rust 1.94.1 以上（`proxy/Cargo.toml` の `rust-version`）
  - C コンパイラ（TLS に使う aws-lc-rs が C のコードをビルドします）
  - Go 1.27.2（`inspector/go.mod`）。
    検査プロセスはビルドに使った Go のバージョンを検査カーネルに通知します。
    検査カーネルが受け付けるのは、`go1.27.2` でビルドしたものだけです。
- ModSecurity の検査プロセスをビルドする場合だけ、さらに次のものが必要です。
  - `rustc` 1.94.1 ちょうど（`rustc -vV` の `release:` の行が `1.94.1`）。
    プロキシと違って、別のバージョンでビルドした検査プロセスは検査カーネルが受け付けません（下の「ModSecurity の検査プロセス」）。
  - C と C++ のコンパイラ、make
  - libyajl-dev と libpcre2-dev（静的ライブラリの `libyajl_s.a` と `libpcre2-8.a`）
  - bash、curl、sha256sum、tar（libmodsecurity のダウンロードに使います）。
    アーカイブを `BUILD_MODSECURITY_ARCHIVE_FILE` で渡す場合は、curl は要りません。
- CRS のダウンロードに必要なもの: bash、curl、sha256sum、tar
- ログを DB へ送る場合だけ必要なもの:
  - PostgreSQL か MySQL のサーバー。動作を確認しているのは PostgreSQL 16・18 と MySQL 8.0 です。
  - ログのディレクトリのファイルシステムが、ファイルの作成時刻（`statx` の btime）を返すこと。動作を確認しているのは ext4 だけです。

## リリースの tarball

0.1.0 から、Linux x86_64 用の実行ファイルの tarball を GitHub のリリースで配布しています。
ソースからビルドしない場合は、これを使います。
0.2.1 からは、運用ガイド（ドキュメントを書籍の形にまとめ直したもの）の EPUB と PDF も、日本語版と英語版を同じリリースに付けています。

| ファイル | 内容 |
|---|---|
| `tukuyomi-core_v0.2.1_linux_amd64.tar.gz` | ディレクトリ `tukuyomi-core_v0.2.1_linux_amd64/` の中に、4 つの実行ファイル（上の「構成要素」）、`README.md`、`README.ja.md`、`LICENSE`、`NOTICE`、`THIRD-PARTY-LICENSES`、`docs/`、`scripts/fetch-crs.sh` |
| `tukuyomi-core_v0.2.1_linux_amd64.tar.gz.sha256` | tarball の SHA-256 |
| `tukuyomi-core_v0.2.1_guide_ja.epub`、`tukuyomi-core_v0.2.1_guide_ja.pdf` | 運用ガイドの日本語版（EPUB と PDF） |
| `tukuyomi-core_v0.2.1_guide_en.epub`、`tukuyomi-core_v0.2.1_guide_en.pdf` | 運用ガイドの英語版（EPUB と PDF） |
| `tukuyomi-core_v0.2.1_SHA256SUMS` | tarball と 4 つの本の SHA-256 |

- ダウンロードしたら、展開する前に SHA-256 を確認します。

  ```bash
  sha256sum -c tukuyomi-core_v0.2.1_linux_amd64.tar.gz.sha256
  tar -xzf tukuyomi-core_v0.2.1_linux_amd64.tar.gz
  ```

- 本は tarball に入っていません。
  ダウンロードした本は、`tukuyomi-core_v0.2.1_SHA256SUMS` の行で確認できます（例: ダウンロードしたディレクトリで `sha256sum -c --ignore-missing tukuyomi-core_v0.2.1_SHA256SUMS`）。
- 実行ファイルは Ubuntu 26.04.1 LTS（glibc 2.43、gcc 15.2.0）上で、`rustc` 1.94.1 と Go 1.27.2 を使ってビルドしています。
  動作を確認したのはビルドしたホストだけです。
- `tukuyomi-proxy` が `GLIBC_2.39` のシンボルを使うため、動かすホストには glibc 2.39 以上が必要です。
  ModSecurity の検査プロセスには、さらに libstdc++ の `GLIBCXX_3.4.29` と `CXXABI_1.3.15` のシンボルが必要です。
  これより古い Linux では動きません。その場合は、ソースからビルドしてください（下の「ソースからのビルド」）。
- 検査プロセス（`tukuyomi-inspector`）は静的リンクしてあり、TLS のライブラリ（aws-lc）も実行ファイルに静的リンクしてあります。
- 実行ファイルは、たとえば `/opt/tukuyomi-core/bin/` に置きます。
  その後の手順は、ソースからビルドした場合と同じです（下の「OS ユーザーとディレクトリ」と「初回起動の手順」）。

## ソースからのビルド

`proxy/` でプロキシをビルドすると、検査カーネルも一緒にビルドされます。

```bash
cd proxy && cargo build --release --locked
```

実行ファイルは `proxy/target/release/tukuyomi-proxy` にできます。
管理画面のファイル（`proxy/admin-ui/`）はこのビルドで実行ファイルに組み込まれるので、画面のための別のビルドや配布は必要ありません。

検査プロセスは `inspector/` で cgo を使わずにビルドします。

```bash
cd inspector && CGO_ENABLED=0 go build -mod=readonly -o tukuyomi-inspector .
```

`CGO_ENABLED=0` は必ず指定してください。

- 検査プロセスは Landlock などの設定をすべてのスレッドにかけるため、Go の `syscall.AllThreadsSyscall` を使います。
  cgo を使った実行ファイルではこの呼び出しが `ENOTSUP` を返すため、検査プロセスは起動しません（exit 14）。
- 起動しない理由（`the inspector is built with cgo and cannot restrict every thread`）は、検査プロセスの標準出力・標準エラーには出ません。
  理由が出るのは、`rules import` の `the inspector said:` の行と、SIGUSR1 の切り替えが失敗したときの `reload: the inspector said:` の行だけです。
  プロキシの起動では、`stop: the kernel failed, engine <engine>: Exit(14)` の行だけが出ます。

### ModSecurity の検査プロセス

ModSecurity の世代を使う場合だけビルドするもので、Coraza の世代だけを使うホストには不要です。
まず、libmodsecurity（ModSecurity v3.0.17）を静的ライブラリとして新しいディレクトリ（prefix）にビルドします。
次に、その prefix を指定して検査プロセスをビルドします。

```bash
scripts/build-modsecurity.sh <new-dir>
cd inspector-modsecurity && TUKUYOMI_MODSECURITY_PREFIX=<new-dir> cargo build --release --locked
```

実行ファイルは `inspector-modsecurity/target/release/tukuyomi-inspector-modsecurity` にできます。

`scripts/build-modsecurity.sh` の動作は次のとおりです。

- ダウンロードするバージョン（3.0.17）と配布アーカイブ（`modsecurity-v3.0.17.tar.gz`）の sha256（`f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50`）は、スクリプトの中に固定してあります。引数では変えられません。
- アーカイブは https でだけダウンロードし、固定した sha256 と一致してから中身を読みます。
  GitHub に接続できないホストでは、固定したアーカイブのコピーを `BUILD_MODSECURITY_ARCHIVE_FILE` で渡せます。その場合も、sha256 などの検証は同じように行います。
- 新しいディレクトリには、まだ存在しないパスを指定します。
  相対パスはカレントディレクトリからのパスとして絶対パスに直します。
  その絶対パスは、英数字と `.`・`_`・`+`・`-` だけでできている必要があり、`.` で始まる名前は使えません。
- 新しいディレクトリの親ディレクトリは、すでに存在していて、実行する OS ユーザーが書き込める必要があります。
  スクリプトはその隣に一時ディレクトリを作り、最後に 1 回のリネームで新しいディレクトリを置きます。
- すでにあるディレクトリには手を付けず、途中で失敗した場合は何も残りません。
- ビルドには数分かかります。
- configure はこのスクリプトに固定したフラグで実行します。
  curl、Lua、MaxMind、GeoIP、libxml2、LMDB、ssdeep は使わず、YAJL と PCRE2 だけを使います。
  configure の結果がそうならなければ、エラーで終わります。
  この設定は、外部からルールを取り込む、スクリプトを実行する、データベースを参照する、XML を解析する、といった機能をルールに使わせないための保護の一部です。変えないでください。
- prefix には、`include/`、`lib/libmodsecurity.a`、`include-src/`（libmodsecurity の内部のヘッダー）、`archive.sha256`（固定したアーカイブの sha256 を書いた 1 行）ができます。

次の場合、検査プロセスのビルドはエラーで終わります。

- `TUKUYOMI_MODSECURITY_PREFIX` が無い、または絶対パスでない
- prefix に `include/modsecurity/modsecurity.h`、`include-src/src/variables/variable.h`、`lib/libmodsecurity.a` のどれかが無い
- prefix の `archive.sha256` が読めない、または小文字の 16 進数 64 桁の 1 行でない
- C++ コンパイラが `libpcre2-8.a`（libpcre2-dev）か `libyajl_s.a`（libyajl-dev）を見つけられない

検査プロセスは起動時の最初のメッセージ（HELLO）で、ビルドに使ったコンパイラのバージョン、libmodsecurity のバージョン、アーカイブの sha256 を検査カーネルに通知します。
検査カーネルが受け付けるのは、次の 3 つがすべて一致する ModSecurity の検査プロセスだけです。

| 項目 | 受け付ける値 |
|---|---|
| ビルドに使ったコンパイラ | `rustc 1.94.1` |
| libmodsecurity のバージョン | `v3.0.17` |
| アーカイブの sha256 | 上の `f283b33d…b671a50` |

一致しない場合、検査カーネルは `hello toolchain differs`、`hello engine version differs`、`hello engine source differs` のどれかを出して、その検査プロセスを受け付けません。検査プロセスの再起動もしません。
プロキシの起動では、`stop: the kernel failed, engine <engine>: Hello("<message>")` の行が出ます。
`rules import` では、`rules import: the trial failed: the inspector could not be started (Hello("<message>"))` の行が出ます。

### ログ送信プロセス

ログを DB へ送る場合だけ、`records-ship/` でビルドします。
プロキシのライブラリも一緒にビルドされます。

```bash
cd records-ship && cargo build --release --locked
```

実行ファイルは `records-ship/target/release/tukuyomi-records-ship` にできます。
必要なものはプロキシと同じです（Rust 1.94.1 以上と C コンパイラ）。

### CRS の取得

CRS（OWASP Core Rule Set）は同梱していないので、`scripts/fetch-crs.sh` でダウンロードします。
スクリプトはサービスの OS ユーザーで実行してください。
CRS は Apache License 2.0 で配布されています。
スクリプトが取り出すのはルールのファイルだけで、アーカイブの `LICENSE` は取り出しません。

```bash
sudo -u tukuyomi scripts/fetch-crs.sh /var/lib/tukuyomi-core/crs-4.23.0
```

- ダウンロードするバージョン（4.23.0）と配布アーカイブの sha256 は、スクリプトの中に固定してあります。引数では変えられません。
- アーカイブは https でだけダウンロードし、固定した sha256 と一致してから中身を読みます。
  GitHub に接続できないホストでは、固定したアーカイブのコピーを `FETCH_CRS_ARCHIVE_FILE` で渡せます。その場合も、sha256 などの検証は同じように行います。
- 新しいディレクトリには、次の 4 つだけが入ります。
  - `crs-setup.conf`（`crs-setup.conf.example` のコピー）
  - `crs-setup.conf.example`
  - `rules/*.conf`
  - `rules/*.data`
- スクリプトは `umask 077` で動くので、できたディレクトリとファイルを読めるのは実行した OS ユーザーだけです。
  root で実行すると、サービスの OS ユーザーで実行する `rules import` が読めません。
- 新しいディレクトリの親ディレクトリは、すでに存在していて、実行する OS ユーザーが書き込める必要があります。
  スクリプトはその隣に一時ディレクトリを作ります。
- すでにあるディレクトリには手を付けず、途中で失敗した場合は何も残りません。
- 運用者はインポートの前に `crs-setup.conf` を編集できます。
  たとえば、受け付けるボディの型を追加できます（[運用リファレンス](../operations/operator-reference.ja.md) の「ルールセットと世代」）。

## OS ユーザーとディレクトリ

プロキシは root では動きません。
プロセスの 4 つのユーザー ID（real、effective、saved、file system）のどれかが 0 の場合、起動もすべてのコマンドも、`host check refused` の行を出して拒否します（exit 1）。

- 専用の OS ユーザーを作り、サービスもコマンドもその OS ユーザーで実行してください。たとえば、`sudo -u tukuyomi tukuyomi-proxy ...` とします。
- root で作った鍵を別の OS ユーザーで動くプロキシが読めないため、`acme renew` も root での実行を拒否します。
- 管理プロセス（`admin`）と、その短時間で終わるコマンド（`admin bootstrap`・`admin reset`）も、同じ OS ユーザーで実行します。
  ルールストア、ログのディレクトリ、制御ソケット、managed ストアを使えるのは、その OS ユーザーだけ（0700）だからです。
  別の OS ユーザーで動かすと、どれも使えません。
- ログ送信プロセスも、ログのディレクトリを読んでそこに `ship.state` を書くため、同じ OS ユーザーで動かします。
  ログ送信プロセスも root では動きません。

ディレクトリとファイルの例を次に示します。

| 例 | 設定キー | 所有者と権限 |
|---|---|---|
| `/opt/tukuyomi-core/bin/tukuyomi-proxy`、`/opt/tukuyomi-core/bin/tukuyomi-inspector` | `kernel.inspector`（Coraza の検査プロセスの方） | root。サービスの OS ユーザーが書き換えられない場所に置きます |
| `/opt/tukuyomi-core/bin/tukuyomi-inspector-modsecurity` | `kernel.engines.modsecurity.inspector`（ModSecurity の検査プロセスの方。省略できます） | root。サービスの OS ユーザーが書き換えられない場所に置きます |
| `/opt/tukuyomi-core/bin/tukuyomi-records-ship` | （ログ送信プロセスのユニット。省略できます） | root。サービスの OS ユーザーが書き換えられない場所に置きます |
| `/etc/tukuyomi-core/config.json` | （起動の引数） | root。サービスの OS ユーザーが読める必要があります。サイズは 256 KiB まで |
| `/var/lib/tukuyomi-core/store` | `rules.store.dir` | サービスの OS ユーザー。権限は 0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root` | サービスの OS ユーザー。権限は 0700。setgid は付けません |
| `/var/lib/tukuyomi-core/managed` | `managed.dir`（managed 設定を使う場合） | サービスの OS ユーザー。権限は 0700。中の `versions/`・`files/`・`acme/` などは、コマンド、管理プロセス、`acme renew` が作ります |
| `/var/lib/tukuyomi-core/tls/` | リスナーと管理画面のルート（`admin.route`）が使う証明書の `cert_file`・`key_file` | サービスの OS ユーザー（`acme renew` が書きます）。managed 設定では、ACME のサイトの証明書は managed ストアの `acme/` にあります |
| `/var/lib/tukuyomi-core/acme/account.key` | `acme.account_key_file` | `acme renew` が初回の実行時に作ります（0600） |
| `/var/lib/tukuyomi-core/challenges` | `acme.challenge_dir` | サービスの OS ユーザー。チャレンジ専用のディレクトリにします |
| `/var/lib/tukuyomi-core/records` | `records.dir` | サービスの OS ユーザー。権限は 0700。中の `records.log` などはプロキシが、`ship.state` はログ送信プロセスが、0600 で作ります |
| `/etc/tukuyomi-core/records-db.dsn` | `records.ship.db_dsn_file`（ログ送信プロセスを使う場合） | 所有者はサービスの OS ユーザーで、権限は 0600。設定ファイルと違い、root を所有者にしません（ログ送信プロセスが所有者と権限を検証します） |
| `/var/lib/tukuyomi-core/admin` | `admin.store.dir`（管理データの保存先） | サービスの OS ユーザー。権限は 0700。中の `users/`・`tokens/`・`audit/` などは管理プロセスが作ります |
| `/var/lib/tukuyomi-core/control` | `admin.control` を置くディレクトリ（例のソケットは `/var/lib/tukuyomi-core/control/proxy.sock`） | サービスの OS ユーザー。権限は 0700。ソケットはプロキシが 0600 で作ります。ソケットのパスは 107 バイトまで |
| `/var/lib/tukuyomi-core/crs-4.23.0` | `admin.crs_dir`（管理 API で CRS をインポートする場合） | 「CRS の取得」で作ったディレクトリ。サービスの OS ユーザーが読める必要があります |
| `/etc/tukuyomi-core/country.mmdb` | `geo.country_db` | root。サービスの OS ユーザーが読めて、書き換えられない形にします（0644）。プロキシは所有者と権限を検証しません |

- 設定の `kernel.inspector` は省略できない設定キーなので、ModSecurity の世代だけを使うホストでも書きます。
  `kernel.engines` は、ModSecurity の世代を使う場合だけ書きます。
  書かないと、ModSecurity の世代はインポートも選択もできず、起動時にも受け付けません（[運用リファレンス](../operations/operator-reference.ja.md) の「`kernel`」）。
  `kernel.default_engine` を `modsecurity` にするときも、`kernel.inspector` は書きます。`kernel.engines` も必要です。
- 上の表のディレクトリは、プロキシもコマンドも作りません。先に作っておいてください。
  ディレクトリの中にできるものは、それぞれ次のものが作ります。
  - ルールストアの中のもの（`generations/`、`staging/`、`using/` など）は、コマンドとプロキシ
  - managed ストアの中のものは、コマンド、管理プロセス、`acme renew`
  - 管理データの保存先の中身は、管理プロセス
  - ログファイルと制御ソケットは、プロキシ
- ルールストア、ログのディレクトリ、管理データの保存先、制御ソケットを置くディレクトリ、managed ストア、`challenge_dir` は、別々のディレクトリにします。
  同じディレクトリにすることも、互いの中に置くこともできません（設定を受け付けません）。
  上の表の例は、どれも `/var/lib/tukuyomi-core` の下にある別々のディレクトリです。
  重なりは書いたままのパスで比べます。シンボリックリンクは使わないでください。
- 下の「systemd」にある例のユニットは、`ReadWritePaths=/var/lib/tukuyomi-core` で、この下のディレクトリに書き込めるようにしています。
  managed ストアもこの下に置けば、ユニットを変更する必要はありません。
  別の場所に置く場合は、`ReadWritePaths` に追加してください。
- ルールストア、作業ディレクトリ、ログのディレクトリ、管理データの保存先、制御ソケットを置くディレクトリ、managed ストアについては、次の条件を検証します。
  - シンボリックリンクではないディレクトリであること
  - 所有者がプロセスの OS ユーザーであること
  - グループとその他のユーザーに権限が無いこと
- これらのディレクトリを検証するタイミングは、それぞれ違います。
  - ルールストアは、プロキシの起動、`config check`、`rules` のコマンドで検証し、管理プロセスがルールストアを開くときも検証します。
    条件を満たさなければ、exit 1 で拒否します。
  - managed ストアは、開くたびに検証します（プロキシの起動と設定のリロード、`config check`、`managed` のコマンド、`acme renew`、管理プロセス）。
    条件を満たさなければ、受け付けません（プロキシの起動と `config check` は exit 1）。
  - 作業ディレクトリは、検査プロセスを起動するたびに検証します（プロキシの起動、検査プロセスの再起動、SIGUSR1 の切り替え、`rules import` の事前検証）。
    条件を満たさなければ、検査プロセスを起動しません。
    プロキシの起動では exit 1 で終わり、SIGUSR1 の切り替えでは今の世代が動き続け、検査プロセスの再起動ではプロキシが停止します。
  - ログのディレクトリは、プロキシの起動時に検証します。
    条件を満たさなければ、プロキシは起動しません（exit 1）。
    ログファイルを開き直す前と、ローテーションする前にも検証します。
  - 制御ソケットを置くディレクトリは、プロキシの起動時に検証します。
    条件を満たさなければ、プロキシは起動しません（exit 1）。
  - 管理データの保存先は、管理プロセスの起動と、`admin bootstrap`・`admin reset` で検証します。
    条件を満たさなければ、exit 1 で拒否します。
  - `config check` と `acme renew` は、作業ディレクトリを検証しません。
    `config check` は、ログのディレクトリ、制御ソケットを置くディレクトリ、管理データの保存先も検証しません。
- 上のディレクトリの親ディレクトリは検証しません。
  ほかの OS ユーザーが親ディレクトリの中に名前を作ったり置き換えたりできないようにするのは、運用者の責任です。
- 作業ディレクトリに setgid が付いていると、中に作るディレクトリがその属性を受け継いで権限の検証に失敗し、検査プロセスを起動できません。
- `acme renew` は、証明書・鍵・チャレンジのファイルをそれぞれのディレクトリに一時ファイルとして書いてから置き換えるため、サービスの OS ユーザーがこれらのディレクトリに書き込める必要があります。
  ACME のサイトでは、managed ストアの `acme/` の中に書きます。
- 設定ファイルを読めない OS ユーザーでコマンドを実行すると、設定を読む段階で受け付けません。
  ルールストアや managed ストアの所有者と違う OS ユーザーで実行すると、それぞれを開く段階で受け付けません。

### 国のデータベース

国の指定（全体の `access`、`host_policies` の `access`、ルートの `access` の `deny_countries`・`allow_countries`）を使う場合だけ必要です。

- データベースはプロキシに同梱しておらず、プロキシが取得することもありません。
  MaxMind DB 形式（バージョン 2）のファイルを運用者が用意します。
  使用許諾は、提供元の条件に従って運用者が守ってください。
- 置く場所と権限: 所有者を root にして、サービスの OS ユーザーが読めるが書き換えられないファイル（0644）にします。
  例は `/etc/tukuyomi-core/country.mmdb` です。
  プロキシは所有者と権限を検証せず、中身を `geo.sha256` で検証します。
  シンボリックリンクは受け付けません。
  サイズは 256 MiB までです。
- 設定の全体を読むコマンド（プロキシの起動とリロード、`config check`、`acme renew`、`managed import`・`managed activate`）は、どれもサービスの OS ユーザーでこのファイルの全体を読みます。
  このファイルを読めない OS ユーザーで実行したコマンドは、設定を読む段階で受け付けません。
  `rules` と `admin` のコマンド、管理プロセス、ログ送信プロセスは、このファイルを読みません。
- 国の指定があれば、プロキシは検証したファイルの全体をメモリに保持します。
  ファイルを読むコマンドは、読むたびに全体を検証するので、大きいファイルでは時間とメモリを使います。
- ファイルの SHA-256 を求めて、設定の `geo.sha256` に書きます。
  値が一致しないと、どのコマンドも設定を受け付けません。

  ```bash
  sha256sum /etc/tukuyomi-core/country.mmdb
  ```

- データベースを入れ替えるときは、新しいファイルを別の名前で置き、設定の `geo.country_db` と `geo.sha256` を 1 回の置き換えで書き換えます。
  `config check` で検証してから、プロキシにリロードさせます（`systemctl reload`）。
  プロキシは起動時とリロードのたびにデータベースを読みます。
  管理プロセスはデータベースを読みません。
- 国の判定では、プライベートアドレスや、IPv4 だけのデータベースでの IPv6 アドレスは `UNKNOWN` になります。
  設定キーと国の判定の方法は、[運用リファレンス](../operations/operator-reference.ja.md) の「アクセス制御とレート制限」を参照してください。

## 初回起動の手順

設定ファイルに `managed` を書く場合（managed 設定を使う場合）は、[運用リファレンス](../operations/operator-reference.ja.md) の「managed 設定での初回起動」の手順で進めてください。
その手順では、下の 2〜4 と 7 をそのまま使います。
managed 設定を使うかどうかは、同じ文書の「managed 設定を使うかどうか」を参照して判断してください。

1. 設定ファイルを書きます。
   設定キーの一覧と例は、[運用リファレンス](../operations/operator-reference.ja.md) を参照してください。
   上の表のディレクトリは先に作っておきます。
   国の指定を使う場合は、国のデータベースも置いて、`sha256` を書きます（上の「国のデータベース」）。
2. CRS をダウンロードします（上の「CRS の取得」）。
3. ルールセットをインポートします。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0 --detect-only
   ```

   - インポートでは、事前検証として検査プロセスを 1 つ起動し、決まったリクエストを 3 つ検査します。
     事前検証に通ったときだけ世代が作られ、標準出力に `<fingerprint> created` が出ます。
     同じ内容の世代がすでにある場合は、`already exists` が出ます。
   - `--detect-only` を付けると検知のみの世代になり、ルールに一致したリクエストも通してログに残します。
     最初はこの世代で動かし、誤検知を確認してから、ブロックする世代に切り替えることをおすすめします。
   - ブロックする世代では、事前検証のリクエストが 1 つでもブロックされると事前検証が失敗し、世代は作られません。
     `crs-setup.conf` の設定を厳しくした場合などは、ログを見て設定を直すか、`--accept-block` を付けてください。
   - ModSecurity で検査する世代を作るには、`--engine modsecurity` を付けます。
     設定の `kernel.engines` に検査プロセスを指定しておく必要があります。
     事前検証はそのエンジンの検査プロセスで実行されます。
4. 世代を選択します。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules activate /etc/tukuyomi-core/config.json <fingerprint>
   ```

   - 世代はエンジンごとに選択し、最初に選択するのはデフォルトのエンジンの世代です。
     デフォルトのエンジンは設定の `kernel.default_engine` に書いたエンジンです。`kernel.default_engine` を書かないときは `coraza` になります。
     デフォルトのエンジンに選択中の世代が無いと、プロキシは起動しません。
   - ModSecurity だけで始めるときは、設定の `kernel.default_engine` を `modsecurity` にして、ModSecurity の世代を選択します。
     `kernel.default_engine` を書かずに ModSecurity の世代だけを選択すると、`config check` と起動は、`rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` で拒否されます（exit 1）。
   - エンジンごとの選択の詳細は、[運用リファレンス](../operations/operator-reference.ja.md) の「エンジンごとの選択中の世代」を参照してください。
5. 設定を検証します。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
   ```

   - 問題がなければ、標準出力に `accepted` が出て exit 0 になります。
   - デフォルトのエンジンの世代を選択する前に実行すると、`rules store refused: no generation is chosen` で拒否されます（exit 1）。
     アップストリームのエンジンに選択中の世代が無いときも、同じ文で拒否されます。
     設定そのもののエラーは exit 2 で分かるため、手順 1 の後にも実行できます。
   - `config check` は、アップストリームのサーバー名と、TLS の証明書と鍵のファイルも検証します。
     受け付けられなかった場合も同じ exit 1 になり、どれが原因かは行の先頭（`upstream refused`、`tls refused`）で区別できます。
   - `config check` は検査プロセスを起動しないので、作業ディレクトリ、検査プロセスの実行ファイル、Landlock は検証しません。
6. サービスを起動します（下の「systemd」）。
7. 管理プロセスを使う場合は、そのユニットも起動して（下の「管理プロセスのユニット」）、最初のユーザーを作成します。

   ```bash
   read -r -s -p 'password: ' PW; echo
   printf '%s\n' "$PW" | sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy admin bootstrap /etc/tukuyomi-core/config.json <name>
   unset PW
   ```

   - パスワードは引数には渡さず、標準入力の最初の 1 行から読みます（12〜128 バイト）。
     名前は、`a-z`・`0-9`・`.`・`_`・`-` で 1〜32 バイトです。
   - 作成するユーザーのロールは `owner` です。
     成功すると、`created owner <name>` が出ます。
     管理データの保存先にユーザーが 1 人でもいれば、拒否されます（exit 1）。
   - このコマンドは、管理プロセスの起動の前でも後でも実行できます。
     パスワードを忘れたユーザーには、`admin reset` を使います。
   - 管理 API、ロール、画面については、[管理リファレンス](../operations/admin-reference.ja.md) を参照してください。
8. ログを DB へ送る場合は、DB のユーザーと DB を用意します。
   接続文字列のファイルは、所有者をサービスの OS ユーザーにして、0600 で置きます。
   設定に `records.ship` を書いて、ログ送信プロセスのユニットを起動します（下の「ログ送信プロセスのユニット」）。
   テーブルは、ログ送信プロセスが最初に接続したときに作成します。
   テーブルの権限と接続文字列の形式は、[運用リファレンス](../operations/operator-reference.ja.md) の「ログ送信プロセス」を参照してください。

## systemd

サービスのユニットの例を次に示します。

```ini
[Unit]
Description=tukuyomi-core WAF
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=tukuyomi
Group=tukuyomi
ExecStart=/opt/tukuyomi-core/bin/tukuyomi-proxy /etc/tukuyomi-core/config.json
ExecReload=/opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
KillSignal=SIGTERM
TimeoutStartSec=90
TimeoutStopSec=60
LogRateLimitIntervalSec=0
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tukuyomi-core
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

- `KillMode=mixed` にします。
  - デフォルトの `control-group` では、停止の SIGTERM が検査プロセスにも届きます。
  - 検査プロセスは SIGTERM を処理せずその場で終了するため、プロキシが検査プロセスを順に停止すること（残りの検査を終えて、終了の通知を受けること）ができなくなります。
  - `mixed` では、SIGTERM はプロキシにだけ届き、プロキシは自分で検査プロセスを停止してから終了します。
- `Type=notify` にします。
  プロキシは、起動するすべてのエンジンで検査カーネルの準備ができ、すべてのリスナーをバインドした後で `READY=1` を systemd へ送ります。
  停止の始めには `STOPPING=1` を送ります。
  `systemctl start` と、`After=` でこのユニットの後に並べたユニットは、`READY=1` が届くまで待ちます。
  `Type=simple` では、実行した時点で起動したとみなされます。
  - 通知を送るのはプロキシのメインプロセスだけで、`NotifyAccess` はデフォルト（`main`）のままで問題ありません。
  - `TimeoutStartSec` は、アップストリームの名前解決の時間（`resolve_timeout_ms`）と、検査カーネルの準備を待つ時間（`ready_wait_ms`）の合計より長くします。
    この時間が過ぎても `READY=1` が届かないと、systemd はプロキシを停止します。
- `TimeoutStopSec` は、`stop_wait_ms`、`kill_grace_ms`、ログの書き出しの 200 ms の合計より長くします。
  短いと、systemd が先に SIGKILL を送ります。
  停止の流れは、[運用リファレンス](../operations/operator-reference.ja.md) の「停止」を参照してください。
- `LogRateLimitIntervalSec=0` を指定します。
  journald のレート制限がデフォルトのままだと、リクエストが集中したときに、リクエストのログがジャーナルに入らずに失われます。
- ログはジャーナルに入ります。設定に `records` があれば、同じログがファイルにも書かれます（上の「OS ユーザーとディレクトリ」）。
  保存期間と容量は journald の設定（`/etc/systemd/journald.conf` の `SystemMaxUse`、`MaxRetentionSec` など）で決めます。
  ログにはクライアントのアドレスとパスが入ります。
  ジャーナルを読めるグループ（Ubuntu では `adm`・`systemd-journal`）に入れる OS ユーザーは、最小限にしてください。
  ログの形式は、[運用リファレンス](../operations/operator-reference.ja.md) の「ログ」を参照してください。
- 監視用のリスナー（設定の `status`）を置くと、同じホストの監視プログラムから `/healthz`・`/readyz`・`/metrics` にアクセスできます。
  ロードバランサーの準備状態の確認には、`/readyz` を使います。
- シグナルは、プロキシのメインプロセスにだけ送ってください（`ExecReload` の `$MAINPID`、または `systemctl kill --kill-whom=main`）。
  - `--kill-whom=main` を付けない `systemctl kill` は、検査プロセスにもシグナルを送ります。
  - 検査プロセスは SIGUSR1・SIGUSR2 を無視しますが、SIGTERM・SIGINT・SIGHUP が届くと終了します。
- `systemctl reload` は、2 つの `ExecReload` を順に実行します。
  SIGHUP を送るのは、`config check` が通ったときだけです。
  プロキシは設定ファイルをリロードし、停止せずに新しい設定に切り替えます（[運用リファレンス](../operations/operator-reference.ja.md) の「SIGHUP（設定のリロード）」）。
  - `config check` が受け付けない設定では、SIGHUP は送られず、`systemctl reload` が失敗を返します。
  - `config check` が通ると、`systemctl reload` は SIGHUP を送った時点で成功を返し、リロードの完了は待ちません。
    次の理由で拒否するのは動作中のプロキシだけなので、この場合も `systemctl reload` は成功を返します。
    - 動作中に変更できない設定キーが変わっていること
    - アップストリームのエンジンが稼働していないこと
    - 新しいリスナーをバインドできないこと
  - 結果はログの行と `/metrics` で確認します。
    ログでは、`reload: configuration replaced <SHA-256>` の行と `reload: configuration refused: <reason>` の行を見ます。
    `managed` のある設定では、前者の後に ` managed <version>` が続きます。
    `/metrics` では、`tukuyomi_config_reloads_total` を見ます。
  - 選択中の世代を `config check` が受け付けない間は、`systemctl reload` も拒否されます。
    なお、リロードそのものは世代に触れません。
- 設定を変更する手順: 新しい設定を別の名前のファイルに書いてから、1 回の置き換えで元のファイルと差し替えます。
  次に `systemctl reload tukuyomi-core.service` を実行し、ログの行で結果を確認します。
  動作中に変更できない設定キーを変えたときは、`systemctl restart` で再起動します。
  管理プロセスとログ送信プロセスは設定をリロードしません。それらが読む設定キーを変えたら、そのプロセスを再起動します。
- 入れ替えの順序: SIGHUP を受けると停止していた以前のバージョンから入れ替えるときは、新しい実行ファイルを入れて再起動してから、ユニットの `ExecReload` を変更して `systemctl daemon-reload` を実行します。
  両方を変更してから再起動してもかまいません。
  前のバージョンのまま新しいユニットで `systemctl reload` を実行すると、前のバージョンは SIGHUP で停止します。
  exit 0 で停止するため、`Restart=on-failure` でも再起動しません。
- エンジンごとの選択に対応していない以前のバージョンから入れ替えるときは、管理プロセス、プロキシ、ログ送信プロセスを同じビルドにそろえます。
  手順と入れ替えの順序は、[運用リファレンス](../operations/operator-reference.ja.md) の「バージョンの更新」を参照してください。
- 証明書と鍵だけを読み込み直させるとき（SIGUSR2）は、次のように送ります。

  ```bash
  systemctl kill -s SIGUSR2 --kill-whom=main tukuyomi-core.service
  ```

- ルールの世代の切り替え（SIGUSR1）は、次のように送ります。

  ```bash
  systemctl kill -s SIGUSR1 --kill-whom=main tukuyomi-core.service
  ```

  SIGUSR1 はエンジンを 1 つずつ順に、エンジンごとの選択中の世代へ切り替えます。
  選択中の世代があるのに稼働していないエンジンは、起動します（[運用リファレンス](../operations/operator-reference.ja.md) の「SIGUSR1（世代の切り替え）」）。

- ログのディレクトリ、制御ソケットを置くディレクトリ、管理データの保存先、managed ストアは、`ReadWritePaths` の中に置きます（上の例では `/var/lib/tukuyomi-core` の下）。
  別の場所に置く場合は、`ReadWritePaths` に追加してください。
- ポート 80・443 で待ち受けるには、`CAP_NET_BIND_SERVICE` が必要です。
  ambient ケーパビリティは検査プロセスにも引き継がれますが、検査プロセスは起動時にすべてのケーパビリティを破棄します。
- `LimitNOFILE` は、受け付ける接続（`max_conns`）とアップストリームへの接続を合わせた数より大きくします。
  接続ごとにファイルディスクリプターを使います。
- 設定のエラーなどで起動が拒否されると、`Restart=on-failure` により `RestartSec` ごとに再起動します。
  設定を変更する前に、`config check` で検証してください。

### 管理プロセスのユニット

管理プロセスはプロキシとは別のユニットで動かします。
実行ファイル、設定ファイル、OS ユーザーはプロキシと同じです。
ユニットの例を次に示します。

```ini
# tukuyomi-core-admin.service
[Unit]
Description=tukuyomi-core admin
After=network.target

[Service]
Type=notify
User=tukuyomi
Group=tukuyomi
ExecStart=/opt/tukuyomi-core/bin/tukuyomi-proxy admin /etc/tukuyomi-core/config.json
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=60
LogRateLimitIntervalSec=0
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tukuyomi-core

[Install]
WantedBy=multi-user.target
```

- `Type=notify` にします。
  管理プロセスはリスナーをバインドした後に `READY=1` を送り、停止の始めに `STOPPING=1` を送ります。
- `KillMode=mixed` にします。
  管理プロセスはルールのインポートの事前検証で検査プロセスを起動します。
  停止の SIGTERM がメインプロセスにだけ届けば、管理プロセスは実行中の事前検証を終えて、検査プロセスと作業ディレクトリを片付けます。
- 停止のシグナル（SIGTERM、SIGINT、SIGHUP）を受けると、管理プロセスはリスナーを閉じ、処理中のリクエストを最大 10 秒待ちます。
  `TimeoutStopSec` はこの 10 秒より長くします。
  インポートの事前検証が実行中の場合に備えて、その検査プロセスを停止する時間（`proxy.stop_inspect_ms` と `kernel.kill_grace_ms`）も加えておきます。
- `LogRateLimitIntervalSec=0` を指定します。
  監査ログは標準エラー（ジャーナル）にも出るため、journald のレート制限で失われないようにします。
- 検査プロセスの実行ファイル（`kernel.inspector`）と作業ディレクトリ（`kernel.tmp_root`）は、プロキシと同じものを使います。
  ModSecurity の世代では、実行ファイルは `kernel.engines` の方を使います。
  インポートの事前検証で起動する検査プロセスも、プロキシの場合と同じく、Landlock で自身の権限を制限します。
- 管理プロセスは `admin.listen` のループバックアドレスで、平文の HTTP で待ち受けます。
  1024 以上のポートなら、`AmbientCapabilities` は不要です。
- 管理プロセスは設定ファイルを起動時に 1 回だけ読み、プロキシと違って SIGHUP でリロードしません。
  管理プロセスにとって、SIGHUP は停止のシグナルです。
  設定を変更したら、`config check` で検証してから `systemctl restart` で再起動します。`ExecReload` は置きません。
- プロキシが動作していなくても管理プロセスは起動しますが、その間は、世代の切り替えも managed 設定の反映も依頼できません。
- 外部から使う場合は、プロキシの TLS リスナーのルートから、`admin.listen` のアドレスへ転送します。
  `admin.listen` はアップストリームのサーバーに指定できます。
  `managed` のある設定では、ルートではなく `admin.route` で転送し、`admin.listen` はアップストリームのサーバーには指定できません（[運用リファレンス](../operations/operator-reference.ja.md) の「`admin`」）。
  ルートの書き方は、[管理リファレンス](../operations/admin-reference.ja.md) の「外部からの利用」を参照してください。
  画面と API の使い方は、同じ文書を参照してください。
- ログはジャーナルに入ります。監査ログは、管理データの保存先の `audit/` にも書かれます。

### ログ送信プロセスのユニット

ログを DB へ送る場合は、ログ送信プロセスをプロキシとは別のユニットで動かします。
設定ファイルと OS ユーザーはプロキシと同じです。
ユニットの例を次に示します。

```ini
# tukuyomi-core-records-ship.service
[Unit]
Description=tukuyomi-core records shipper
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=tukuyomi
Group=tukuyomi
ExecStart=/opt/tukuyomi-core/bin/tukuyomi-records-ship /etc/tukuyomi-core/config.json
KillSignal=SIGTERM
TimeoutStopSec=150
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tukuyomi-core

[Install]
WantedBy=multi-user.target
```

- `Type=notify` にします。
  ログ送信プロセスは起動時の検証を終えた後に `READY=1` を送り、停止の始めに `STOPPING=1` を送ります。
  DB には `READY=1` の後に接続します。
  DB に接続できないときは待ってから再試行するので、DB のユニットの後に並べる必要はありません。
- `TimeoutStopSec` は長めにします。
  停止のシグナルは DB の呼び出しが終わるまで処理されないため、停止までに長いと 1〜2 分かかります。
  それより短くて SIGKILL になった場合でも、行と位置は同じトランザクションで DB に入るため、次の起動では続きから送ります。
- ログのディレクトリは、`ReadWritePaths` の中に置きます。ログ送信プロセスがこのディレクトリに `ship.state` を書くためです。
- DB がログインを拒否すると、ログ送信プロセスは exit 1 で終了し、`Restart=on-failure` により `RestartSec` ごとに再起動します。
  接続文字列を直すまで、これを繰り返します。
- DB サーバーの証明書を独自の認証局で発行したときは、その認証局の証明書を入れたファイルを `Environment=SSL_CERT_FILE=<path>` で渡します。
- 設定ファイルと接続文字列のファイルは起動時に 1 回だけ読み、プロキシと違って SIGHUP でリロードしません。
  ログ送信プロセスにとって、SIGHUP は停止のシグナルです。
  変更したら、`systemctl restart` で再起動します。`ExecReload` は置きません。
- ログ送信プロセスはプロキシと同じ設定ファイルを読み、未知の設定キーを含む設定ファイルは受け付けません。
  設定に新しい設定キー（`managed`、`host_policies`、`kernel.default_engine`、アップストリームの `engine` など）を書く前に、ログ送信プロセスの実行ファイルをプロキシと同じビルドのものに入れ替えてください。
  前のビルドのままだと、ログ送信プロセスは次の起動で設定を受け付けず、起動しません（[運用リファレンス](../operations/operator-reference.ja.md) の「ログ送信プロセスの起動」）。
- プロキシが動作していなくても、ログ送信プロセスは起動し、ファイルにあるログを送ります。
  プロキシは `required` のルートへのリクエストを拒否して、ログ送信プロセスが動作していないこと（`ship.state` が 90 秒より古いこと）を示します。
- ログ送信プロセスのログは、ジャーナルに入ります。

### 証明書の更新のタイマー

`acme renew` を毎日実行する例を次に示します。

```ini
# tukuyomi-core-acme.service
[Unit]
Description=tukuyomi-core certificate renewal (ACME)
After=network-online.target tukuyomi-core.service
Wants=network-online.target

[Service]
Type=oneshot
User=tukuyomi
Group=tukuyomi
ExecStart=/opt/tukuyomi-core/bin/tukuyomi-proxy acme renew /etc/tukuyomi-core/config.json
ExecStopPost=+/bin/systemctl kill --kill-whom=main -s SIGUSR2 tukuyomi-core.service
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tukuyomi-core
```

```ini
# tukuyomi-core-acme.timer
[Unit]
Description=Daily tukuyomi-core certificate renewal

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

- コマンドが証明書を書いても、動作中のプロキシはそのことを検知しません。
  このユニットはコマンドの後に SIGUSR2 を送り、プロキシに新しい証明書を読み込ませます。
  - `systemctl reload` を使わないのは、SIGHUP では設定ファイルの全体を読み込むためです。
    タイマーが実行されたときに編集途中の設定を読み込まないように、証明書と鍵だけを読み込む SIGUSR2 を送ります。
- `ExecStopPost` は、コマンドが失敗しても実行されます。
  証明書が 1 つでも `failed` になると、コマンドは exit 1 で終わります。`failed` の証明書のファイルは前のまま残ります。
  その場合も SIGUSR2 は送られるので、更新できたほかの証明書は使われ始めます。
  SIGUSR2 を受けたプロキシは、読み込んだ証明書がすべて検証に通るときだけ入れ替えるので、失敗したときに SIGUSR2 を送っても問題はありません。
- `ExecStopPost` の先頭の `+` は、`systemctl kill` を root で実行するための指定です。
  コマンドそのものは、サービスの OS ユーザーで実行されます。
- `ExecStartPost=+` で SIGUSR2 を送っているユニットは、その行を上の `ExecStopPost=+` の行に変更し、`systemctl daemon-reload` を実行してください。
  `ExecStartPost` はコマンドが exit 0 で終わったときだけ実行されるので、証明書が 1 つ `failed` になるだけで、更新できたほかの証明書も次に SIGUSR2 か SIGHUP を送るまで使われません。
- `acme renew` には、同時実行を防ぐ仕組みがありません。同じ設定で 2 つ同時に実行しないでください。
  systemd のタイマーは重なりませんが、cron などで実行する場合は、重ならないようにしてください。
- ACME のサイトについて、ホストの組み合わせを変更したバージョンを managed 設定で反映したときは、タイマーを待たずに `systemctl start tukuyomi-core-acme.service` でこのサービスを実行してください（[運用リファレンス](../operations/operator-reference.ja.md) の「ACME のサイト」）。
- 初回の発行の手順は、[運用リファレンス](../operations/operator-reference.ja.md) の「ACME」を参照してください。

## 検査プロセスの権限の制限

検査プロセスは起動時に次の順で自身の権限を制限します。

1. ルールの世代を読みます。
   読めなければ、exit 11 で終了します。
   別のエンジンの世代のマニフェストもこの検査プロセスでは読めないので、同じく exit 11 で終了します。
   - Coraza の検査プロセスは、この後はファイルを読みません。
   - ModSecurity の検査プロセスは、起動ごとの一時ディレクトリの中に、検証したファイルをコピーします。
     コピーできなければ、exit 14 で終了します。
     制限をかけた後は、ルールをこのコピーから組み立て、このコピーだけを読みます。
2. Landlock のルールセットを組み立てます。
   - 起動ごとの一時ディレクトリの外のファイルに触れられなくします。一時ディレクトリは作業ディレクトリの中に作ります。
     作業ディレクトリの中のほかのディレクトリにも触れられません。
   - 一時ディレクトリの中で許可するのは、ファイルの作成・書き込み・読み込み・切り詰め・削除だけです。
     ディレクトリの作成と一覧、一時ディレクトリの外へのリネーム、プログラムの実行はできません。
   - Linux 6.7 以上（ABI 4 以上）では、TCP のバインドと接続も禁止します。
3. ケーパビリティを破棄します。
   ambient を空にし、effective・permitted・inheritable を 0 にします。
4. `no_new_privs` を設定します。
5. 最後に Landlock を有効にします。
   この時点から、2 の制限が効きます。

どの制限も、プロセスのすべてのスレッドに元に戻せない形でかけます。
2 から 5 のどれかが失敗すると、検査プロセスは起動しません（exit 14）。
この後、検査プロセスはルールをその世代のエンジン（Coraza か ModSecurity）で検証して組み立て、リクエストの受け付けを始めます。
ルールの検証や組み立てに失敗したときは、exit 11 で終了します。
ModSecurity の検査プロセスは、ライブラリの準備ができないなど、環境に問題があるときは exit 14 で終了します。

制限できないものもあります。

- Landlock は UDP、Unix ドメインソケット、MPTCP のソケット（`IPPROTO_MPTCP` で作るもの）を制限しません。
  検査プロセスは制限をかけた後も、これらを使って外部へ送信したり、1024 以上のポートで待ち受けたりできます。
- MPTCP を使わないホストでは、`net.mptcp.enabled=0` にすると、MPTCP のソケットを作れなくなります。
- Linux の `net.ipv4.ip_unprivileged_port_start` がデフォルトの 1024 のときは、ケーパビリティを破棄するため、1024 未満のポートは使えません。

プロキシ側にはこの制限をかけません。
プロキシは設定・ルールストア・証明書と鍵を読み、リスナーとアップストリームへの接続を持ちます。
管理プロセスも、自身にはこの制限をかけません。
インポートの事前検証で起動する検査プロセスだけが、上の制限をかけます。

## 起動前の検証

プロキシの起動、事前検証で検査プロセスを起動する `rules import`、管理プロセスのコマンド（`admin <config>`、`admin bootstrap`、`admin reset`）では、`/proc` を読んで次の条件も検証し、満たさなければ拒否します。

- SIGCHLD を無視していないこと。
  検査カーネルは子プロセスの終了を自分で待ちます。
- 2 より大きいファイルディスクリプターが、すべて close-on-exec であること。
  検査プロセスに不要なディスクリプターを渡さないためです。

systemd から起動する場合は、どちらの条件も満たされます。
`config check` とほかのコマンドは、root でないことだけを検証します。
