# ビルドと配置

この文書では、現在の実装を 1 台の Linux ホストで動かす手順を説明します。設定キーの意味と範囲、コマンド、シグナル、ログ、監視は [運用リファレンス](../operations/operator-reference.md) を、管理プロセスの設定と API は [管理リファレンス](../operations/admin-reference.md) を参照してください。

この文書に出てくるパス（`/opt/tukuyomi-core`、`/etc/tukuyomi-core`、`/var/lib/tukuyomi-core`）と OS ユーザーの名前（`tukuyomi`）は例です。設定に書くパスは、どれも絶対パスで書きます（`.`・`..`・空の要素・末尾の `/` を含むパスは受け付けません）。

## 構成要素

| 構成要素 | 内容 |
|---|---|
| `tukuyomi-proxy`（Rust、`proxy/`） | HTTP／HTTPS のリクエストを受信して転送します。検査カーネル（`kernel/`、Rust のライブラリ）を組み込み、検査プロセスの起動・停止・再起動を受け持ちます。同じ実行ファイルが、ルールストアのコマンド（`rules`）、証明書のコマンド（`acme renew`）、設定の検証（`config check`）、管理プロセス（`admin`）も持ちます |
| `tukuyomi-inspector`（Go、`inspector/`） | Coraza でリクエストを検査します。プロキシが子プロセスとして起動し、引き継いだ Unix ドメインソケットのペアで通信します。待ち受けるポートは持ちません。設定の `kernel.inspector` に指定します |
| `tukuyomi-inspector-modsecurity`（Rust と C++、`inspector-modsecurity/`） | ModSecurity v3（libmodsecurity 3.0.17）でリクエストを検査します。ModSecurity の世代（`rules import --engine modsecurity`）を使う場合だけ必要で、使わないホストでは省けます。プロキシが子プロセスとして起動し、引き継いだ Unix ドメインソケットのペアで通信します。待ち受けるポートは持ちません。設定の `kernel.engines.modsecurity.inspector` に指定します |
| `tukuyomi-records-ship`（Rust、`records-ship/`） | ログ送信プロセスです。プロキシのログファイルの行を、PostgreSQL か MySQL のテーブルへ送ります。ログを DB へ送る場合だけ必要で、送らないホストでは省けます。プロキシとは別のユニットで動き、同じ設定ファイルを読みます。待ち受けるポートは持ちません |
| 管理プロセス | 同じ実行ファイルの `tukuyomi-proxy admin <config>` です。プロキシとは別のユニットで動かします。ループバックアドレスで待ち受け、管理 API と管理画面（実行ファイルに組み込み済み）を提供します。ルールの世代を操作し、制御ソケットを通じてプロキシに切り替えを依頼します |
| 設定ファイル | 1 つの JSON ファイルです。値にデフォルトはありません。省けると決まっている設定キー（`acme`、`records`、`access`、`rate_limit`、`geo`、`admin` など）のほかは、すべて書きます。プロキシと管理プロセスが同じファイルを読みます |
| ルールストア | ルールセットの世代を置くディレクトリです（設定の `rules.store.dir`）。`rules import` が世代を作り、`rules activate` が使う世代を選択します。管理プロセスも同じ操作をします |
| 検査プロセスの作業ディレクトリ | 起動ごとの一時ディレクトリを作る親ディレクトリです（設定の `kernel.tmp_root`） |
| 証明書と鍵 | TLS のリスナーで使います。`acme renew` で発行・更新するか、運用者が置きます |
| ログのディレクトリ | 標準エラーに出すログの写しを置くディレクトリです（設定の `records.dir`）。プロキシが書き、管理プロセスとログ送信プロセスが読みます。ログ送信プロセスは、送信済みの位置（`ship.state`）もここに書きます |
| 接続文字列のファイル | ログ送信プロセスが DB に接続するための文字列（パスワードを含む）を書いたファイルです（設定の `records.ship.db_dsn_file`）。ログ送信プロセスだけが読みます |
| 管理データの保存先 | 管理プロセスが、ユーザー、API トークン、監査ログ、切り替えの履歴を置くディレクトリです（設定の `admin.store.dir`） |
| 制御ソケット | プロキシが管理プロセスからの依頼を受ける Unix ドメインソケットです（設定の `admin.control`） |
| 国のデータベース | アクセス制御（`access`）の国の指定に使う、MaxMind DB 形式のファイルです（設定の `geo.country_db`）。運用者が用意します |

検査プロセス、管理プロセス、ログ送信プロセスは、プロキシと同じ OS ユーザーで動きます。

## 必要な環境

- Linux。動作を確認しているのは x86_64 だけです。
- Landlock が有効な Linux。
  - 検査プロセスは、ルールを読んだ後に Landlock で自身の権限を制限します（下の「検査プロセスの権限の制限」）。
  - Landlock が無い Linux では、検査プロセスは起動しません（exit 14）。プロキシも起動せず（ログは `stop: the kernel failed: Exit(14)`）、`rules import` の事前検証も、管理プロセスのインポートの事前検証も失敗します。制限をかけずに動かす設定はありません。
  - Landlock を含む Linux 5.13 以上で、LSM の一覧に `landlock` が含まれている必要があります（`/sys/kernel/security/lsm` で確認できます）。どのディストリビューションが Landlock をデフォルトで有効にしているかは確認していません。
  - Linux のバージョンによって、制限できる範囲が違います。どの ABI バージョンで制限したかは、外からは分かりません。
    - TCP のバインドと接続まで制限するには、Linux 6.7 以上（Landlock の ABI 4 以上）が必要です。それより前のバージョンでは、ファイルだけを制限して動きます。
    - Linux 6.2 より前（ABI 1・2）では、ファイルの切り詰めを禁止できません。Linux 6.10 より前（ABI 4 まで）では、デバイスの ioctl を禁止できません。
- ModSecurity の検査プロセスを動かすホストに必要な共有ライブラリは、libstdc++、libgcc_s、libc、libm だけです。libmodsecurity、YAJL、PCRE2 は実行ファイルに静的リンクしてあるので、インストールは不要です。
- ビルドに必要なもの:
  - Rust 1.94.1 以上（`proxy/Cargo.toml` の `rust-version`）
  - C コンパイラ（TLS に使う aws-lc-rs が C のコードをビルドします）
  - Go 1.27.2（`inspector/go.mod`）。検査プロセスは、ビルドに使った Go のバージョンを検査カーネルに通知します。検査カーネルは、`go1.27.2` でビルドしたものだけを受け付けます。
- ModSecurity の検査プロセスをビルドする場合だけ、さらに次のものが必要です。
  - `rustc` 1.94.1 ちょうど（`rustc -vV` の `release:` の行が `1.94.1`）。プロキシと違い、別のバージョンでビルドした検査プロセスは検査カーネルが受け付けません（下の「ModSecurity の検査プロセス」）。
  - C と C++ のコンパイラ、make
  - libyajl-dev と libpcre2-dev（静的ライブラリの `libyajl_s.a` と `libpcre2-8.a`）
  - bash、curl、sha256sum、tar（libmodsecurity の取得に使います。アーカイブを `BUILD_MODSECURITY_ARCHIVE_FILE` で渡す場合、curl は不要です）
- CRS の取得に必要なもの: bash、curl、sha256sum、tar
- ログを DB へ送る場合だけ必要なもの:
  - PostgreSQL か MySQL のサーバー。動作を確認しているのは PostgreSQL 16・18 と MySQL 8.0 です。
  - ログのディレクトリのファイルシステムが、ファイルの作成時刻（`statx` の btime）を返すこと。動作を確認しているのは ext4 だけです。

## リリースの tarball

0.1.0 から、GitHub のリリースで、Linux x86_64 用の実行ファイルの tarball を配布しています。ソースからビルドしない場合は、これを使います。

| ファイル | 内容 |
|---|---|
| `tukuyomi-core_v0.1.0_linux_amd64.tar.gz` | ディレクトリ `tukuyomi-core_v0.1.0_linux_amd64/` の中に、4 つの実行ファイル（上の「構成要素」）、`README.md`、`LICENSE`、`NOTICE`、`THIRD-PARTY-LICENSES`、`docs/`、`scripts/fetch-crs.sh` |
| `tukuyomi-core_v0.1.0_linux_amd64.tar.gz.sha256` | tarball の SHA-256 |
| `tukuyomi-core_v0.1.0_SHA256SUMS` | 上と同じ行 |

- ダウンロードしたら、展開する前に SHA-256 を確認します。

  ```bash
  sha256sum -c tukuyomi-core_v0.1.0_linux_amd64.tar.gz.sha256
  tar -xzf tukuyomi-core_v0.1.0_linux_amd64.tar.gz
  ```

- 実行ファイルは、Ubuntu 26.04.1 LTS（glibc 2.43、gcc 15.2.0）で、`rustc` 1.94.1 と Go 1.27.2 を使ってビルドしました。動作を確認したのは、ビルドしたホストだけです。
- 動かすホストには glibc 2.39 以上が必要です（`tukuyomi-proxy` が `GLIBC_2.39` のシンボルを使います）。ModSecurity の検査プロセスには、さらに libstdc++ の `GLIBCXX_3.4.29` と `CXXABI_1.3.15` のシンボルが必要です。これより古い Linux では動かないので、ソースからビルドしてください（下の「ソースからのビルド」）。
- 検査プロセス（`tukuyomi-inspector`）は静的リンクしてあります。TLS のライブラリ（aws-lc）も、実行ファイルに静的リンクしてあります。
- 実行ファイルは、たとえば `/opt/tukuyomi-core/bin/` に置きます。その後の手順は、ソースからビルドした場合と同じです（下の「OS ユーザーとディレクトリ」と「初回起動の手順」）。

## ソースからのビルド

プロキシは `proxy/` でビルドします。検査カーネルも一緒にビルドされます。

```bash
cd proxy && cargo build --release --locked
```

実行ファイルは `proxy/target/release/tukuyomi-proxy` にできます。管理画面のファイル（`proxy/admin-ui/`）は、このビルドで実行ファイルに組み込まれます。画面のための別のビルドや配布は必要ありません。

検査プロセスは、`inspector/` で cgo を使わずにビルドします。

```bash
cd inspector && CGO_ENABLED=0 go build -mod=readonly -o tukuyomi-inspector .
```

`CGO_ENABLED=0` は必ず指定してください。

- 検査プロセスは、Landlock などの設定をすべてのスレッドにかけるために、Go の `syscall.AllThreadsSyscall` を使います。cgo を使った実行ファイルではこの呼び出しが `ENOTSUP` を返すため、検査プロセスは起動しません（exit 14）。
- 起動しない理由（`the inspector is built with cgo and cannot restrict every thread`）は、検査プロセスの標準出力・標準エラーには出ません。`rules import` の `the inspector said:` の行と、SIGUSR1 の切り替えが失敗したときの `reload: the inspector said:` の行にだけ出ます。プロキシの起動では、`stop: the kernel failed: Exit(14)` の行だけが出ます。

### ModSecurity の検査プロセス

ModSecurity の世代を使う場合だけビルドします。Coraza の世代だけを使うホストには不要です。先に libmodsecurity（ModSecurity v3.0.17）を新しいディレクトリ（prefix）に静的ライブラリとしてビルドし、その prefix を指定して検査プロセスをビルドします。

```bash
scripts/build-modsecurity.sh <new-dir>
cd inspector-modsecurity && TUKUYOMI_MODSECURITY_PREFIX=<new-dir> cargo build --release --locked
```

実行ファイルは `inspector-modsecurity/target/release/tukuyomi-inspector-modsecurity` にできます。

`scripts/build-modsecurity.sh` の動作は次のとおりです。

- 取得するバージョン（3.0.17）と、配布アーカイブ（`modsecurity-v3.0.17.tar.gz`）の sha256（`f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50`）は、スクリプトの中に固定してあります。引数では変えられません。
- アーカイブは https でだけ取得し、固定した sha256 と一致してから中身を読みます。GitHub に接続できないホストでは、固定したアーカイブの写しを `BUILD_MODSECURITY_ARCHIVE_FILE` で渡せます。その場合も、sha256 などの検証は同じです。
- 新しいディレクトリは、まだ存在しない絶対パスで、英数字と `.`・`_`・`+`・`-` だけで書きます。`.` で始まる名前は使えません。相対パスで書いた場合は、カレントディレクトリからのパスとして扱います。
- 新しいディレクトリの親ディレクトリは、既に存在し、実行する OS ユーザーが書き込めることが必要です。スクリプトはその隣に一時ディレクトリを作り、最後に 1 回のリネームで新しいディレクトリを置きます。
- 既にあるディレクトリには触れません。途中で失敗したときは、何も残りません。
- 数分かかります。
- configure は、このスクリプトに固定したフラグで実行します。curl、Lua、MaxMind、GeoIP、libxml2、LMDB、ssdeep は使わず、YAJL と PCRE2 だけを使います。configure の結果がそうならなければ、エラーで終わります。外部からルールを取り込む、スクリプトを実行する、データベースを参照する、XML を解析する、といった機能をルールに使わせないための保護の一部なので、変えないでください。
- prefix には、`include/`、`lib/libmodsecurity.a`、`include-src/`（libmodsecurity の内部のヘッダー）、`archive.sha256`（固定したアーカイブの sha256 を書いた 1 行）ができます。

次の場合、検査プロセスのビルドはエラーで終わります。

- `TUKUYOMI_MODSECURITY_PREFIX` が無い、または絶対パスでない
- prefix に `include/modsecurity/modsecurity.h`、`include-src/src/variables/variable.h`、`lib/libmodsecurity.a` のどれかが無い
- prefix の `archive.sha256` が読めない、または小文字の 16 進数 64 桁の 1 行でない
- C++ コンパイラが `libpcre2-8.a`（libpcre2-dev）か `libyajl_s.a`（libyajl-dev）を見つけられない

検査プロセスは、ビルドに使ったコンパイラのバージョン、libmodsecurity のバージョン、アーカイブの sha256 を、起動時の最初のメッセージ（HELLO）で検査カーネルに通知します。ModSecurity の検査プロセスについて、検査カーネルは次の 3 つがすべて一致するものだけを受け付けます。

| 項目 | 受け付ける値 |
|---|---|
| ビルドに使ったコンパイラ | `rustc 1.94.1` |
| libmodsecurity のバージョン | `v3.0.17` |
| アーカイブの sha256 | 上の `f283b33d…b671a50` |

一致しない場合、検査カーネルは `hello toolchain differs`、`hello engine version differs`、`hello engine source differs` のどれかを出して受け付けず、検査プロセスを再起動しません。プロキシの起動では `stop: the kernel failed: Hello("<message>")` の行が、`rules import` では `rules import: the trial failed: the inspector could not be started (Hello("<message>"))` の行が出ます。

### ログ送信プロセス

ログを DB へ送る場合だけビルドします。`records-ship/` でビルドします。プロキシのライブラリも一緒にビルドされます。

```bash
cd records-ship && cargo build --release --locked
```

実行ファイルは `records-ship/target/release/tukuyomi-records-ship` にできます。必要なものはプロキシと同じです（Rust 1.94.1 以上と C コンパイラ）。

### CRS の取得

CRS（OWASP Core Rule Set）は同梱していません。`scripts/fetch-crs.sh` で取得します。サービスの OS ユーザーで実行してください。CRS は Apache License 2.0 で配布されています。スクリプトはルールのファイルだけを取り出し、アーカイブの `LICENSE` は取り出しません。

```bash
sudo -u tukuyomi scripts/fetch-crs.sh /var/lib/tukuyomi-core/crs-4.23.0
```

- 取得するバージョン（4.23.0）と、配布アーカイブの sha256 は、スクリプトの中に固定してあります。引数では変えられません。
- アーカイブは https でだけ取得し、固定した sha256 と一致してから中身を読みます。GitHub に接続できないホストでは、固定したアーカイブの写しを `FETCH_CRS_ARCHIVE_FILE` で渡せます。その場合も、sha256 などの検証は同じです。
- 新しいディレクトリには、次の 4 つだけが入ります。
  - `crs-setup.conf`（`crs-setup.conf.example` の写し）
  - `crs-setup.conf.example`
  - `rules/*.conf`
  - `rules/*.data`
- スクリプトは `umask 077` で動きます。できたディレクトリとファイルは、実行した OS ユーザーだけが読めます。root で実行すると、サービスの OS ユーザーの `rules import` が読めません。
- 新しいディレクトリの親ディレクトリは、既に存在し、実行する OS ユーザーが書き込めることが必要です。スクリプトはその隣に一時ディレクトリを作ります。
- 既にあるディレクトリには触れません。途中で失敗したときは、何も残りません。
- 運用者は、インポートの前に `crs-setup.conf` を編集できます。たとえば、受け付けるボディの型を追加できます（[運用リファレンス](../operations/operator-reference.md) の「ルールセットと世代」）。

## OS ユーザーとディレクトリ

プロキシは root では動きません。起動もすべてのコマンドも、プロセスの 4 つのユーザー ID（real、effective、saved、file system）のどれかが 0 なら、`host check refused` の行を出して拒否します（exit 1）。

- 専用の OS ユーザーを作り、サービスもコマンドもその OS ユーザーで実行してください。たとえば `sudo -u tukuyomi tukuyomi-proxy ...` とします。
- root で `acme renew` を実行すると、作った鍵を別の OS ユーザーのプロキシが読めないので、これも拒否します。
- 管理プロセス（`admin`）と、その短いコマンド（`admin bootstrap`・`admin reset`）も、同じ OS ユーザーで実行します。ルールストア、ログのディレクトリ、制御ソケット、managed ストアは、その OS ユーザーだけが使える（0700）ためです。別の OS ユーザーで動かすと、どれも使えません。
- ログ送信プロセスも、同じ OS ユーザーで動かします。ログのディレクトリを読み、そこに `ship.state` を書くためです。ログ送信プロセスも root では動きません。

ディレクトリとファイルの例を次に示します。

| 例 | 設定キー | 所有者と権限 |
|---|---|---|
| `/opt/tukuyomi-core/bin/tukuyomi-proxy`、`/opt/tukuyomi-core/bin/tukuyomi-inspector` | `kernel.inspector`（Coraza の検査プロセスの方） | root。サービスの OS ユーザーが書き換えられない場所に置きます |
| `/opt/tukuyomi-core/bin/tukuyomi-inspector-modsecurity` | `kernel.engines.modsecurity.inspector`（ModSecurity の検査プロセスの方。省けます） | root。サービスの OS ユーザーが書き換えられない場所に置きます |
| `/opt/tukuyomi-core/bin/tukuyomi-records-ship` | （ログ送信プロセスのユニット。省けます） | root。サービスの OS ユーザーが書き換えられない場所に置きます |
| `/etc/tukuyomi-core/config.json` | （起動の引数） | root。サービスの OS ユーザーが読めることが必要です。サイズは 256 KiB まで |
| `/var/lib/tukuyomi-core/store` | `rules.store.dir` | サービスの OS ユーザー。権限は 0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root` | サービスの OS ユーザー。権限は 0700。setgid は付けません |
| `/var/lib/tukuyomi-core/managed` | `managed.dir`（managed 設定を使う場合） | サービスの OS ユーザー。権限は 0700。中の `versions/`・`files/`・`acme/` などは、コマンド、管理プロセス、`acme renew` が作ります |
| `/var/lib/tukuyomi-core/tls/` | リスナーと管理画面のルート（`admin.route`）が使う証明書の `cert_file`・`key_file` | サービスの OS ユーザー（`acme renew` が書きます）。managed 設定の ACME のサイトの証明書は、managed ストアの `acme/` にあります |
| `/var/lib/tukuyomi-core/acme/account.key` | `acme.account_key_file` | `acme renew` が初回の実行時に作ります（0600） |
| `/var/lib/tukuyomi-core/challenges` | `acme.challenge_dir` | サービスの OS ユーザー。チャレンジ専用のディレクトリにします |
| `/var/lib/tukuyomi-core/records` | `records.dir` | サービスの OS ユーザー。権限は 0700。中の `records.log` などはプロキシが、`ship.state` はログ送信プロセスが、0600 で作ります |
| `/etc/tukuyomi-core/records-db.dsn` | `records.ship.db_dsn_file`（ログ送信プロセスを使う場合） | 所有者はサービスの OS ユーザーで、権限は 0600。設定ファイルと違い、root を所有者にしません（ログ送信プロセスが所有者と権限を検証します） |
| `/var/lib/tukuyomi-core/admin` | `admin.store.dir`（管理データの保存先） | サービスの OS ユーザー。権限は 0700。中の `users/`・`tokens/`・`audit/` などは管理プロセスが作ります |
| `/var/lib/tukuyomi-core/control` | `admin.control` を置くディレクトリ（例のソケットは `/var/lib/tukuyomi-core/control/proxy.sock`） | サービスの OS ユーザー。権限は 0700。ソケットはプロキシが 0600 で作ります。ソケットのパスは 107 バイトまで |
| `/var/lib/tukuyomi-core/crs-4.23.0` | `admin.crs_dir`（管理 API で CRS をインポートする場合） | 「CRS の取得」で作ったディレクトリ。サービスの OS ユーザーが読めることが必要です |
| `/etc/tukuyomi-core/country.mmdb` | `geo.country_db` | root。サービスの OS ユーザーが読めて、書き換えられない形にします（0644）。プロキシは所有者と権限を検証しません |

- 設定の `kernel.inspector` は、ModSecurity の世代だけを使うホストでも書きます（省けない設定キーです）。`kernel.engines` は、ModSecurity の世代を使う場合だけ書きます。書かないと、ModSecurity の世代はインポートも選択もできず、起動時にも受け付けません（[運用リファレンス](../operations/operator-reference.md) の「`kernel`」）。
- 上の表のディレクトリは、先に作っておいてください。プロキシもコマンドも、これらのディレクトリは作りません。ルールストアの中のもの（`generations/`、`staging/`、`using/` など）はコマンドとプロキシが、managed ストアの中のものはコマンド、管理プロセス、`acme renew` が、管理データの保存先の中身は管理プロセスが、ログファイルと制御ソケットはプロキシが作ります。
- ルールストア、ログのディレクトリ、管理データの保存先、制御ソケットを置くディレクトリ、managed ストア、`challenge_dir` は、別々のディレクトリにします。同じディレクトリにすることも、互いの中に置くこともできません（設定を受け付けません）。上の表の例は、どれも `/var/lib/tukuyomi-core` の下の別々のディレクトリです。重なりは書いたままのパスで比べるので、シンボリックリンクは使わないでください。
- 下の「systemd」の例のユニットは、`ReadWritePaths=/var/lib/tukuyomi-core` で、この下のディレクトリに書き込めるようにしています。managed ストアもこの下に置けば、ユニットを変更する必要はありません。別の場所に置く場合は、`ReadWritePaths` に追加してください。
- ルールストア、作業ディレクトリ、ログのディレクトリ、管理データの保存先、制御ソケットを置くディレクトリ、managed ストアについては、シンボリックリンクでないディレクトリであること、所有者がプロセスの OS ユーザーであること、グループとその他のユーザーの権限が無いことを検証します。検証するタイミングはそれぞれ違います。
  - ルールストアは、プロキシの起動、`config check`、`rules` のコマンドで検証します。管理プロセスがルールストアを開くときも検証します。条件を満たさなければ、exit 1 で拒否します。
  - managed ストアは、開くたびに検証します（プロキシの起動と設定のリロード、`config check`、`managed` のコマンド、`acme renew`、管理プロセス）。条件を満たさなければ受け付けません（プロキシの起動と `config check` は exit 1）。
  - 作業ディレクトリは、検査プロセスを起動するたびに検証します（プロキシの起動、検査プロセスの再起動、SIGUSR1 の切り替え、`rules import` の事前検証）。条件を満たさなければ、検査プロセスを起動しません。プロキシの起動では exit 1 で終わり、SIGUSR1 の切り替えでは今の世代が動き続け、再起動ではプロキシが停止します。
  - ログのディレクトリは、プロキシの起動時に検証します。条件を満たさなければ、プロキシは起動しません（exit 1）。ログファイルを開き直す前と、ローテーションする前にも検証します。
  - 制御ソケットを置くディレクトリは、プロキシの起動時に検証します。条件を満たさなければ、プロキシは起動しません（exit 1）。
  - 管理データの保存先は、管理プロセスの起動と、`admin bootstrap`・`admin reset` で検証します。条件を満たさなければ、exit 1 で拒否します。
  - `config check` と `acme renew` は、作業ディレクトリを検証しません。`config check` は、ログのディレクトリ、制御ソケットを置くディレクトリ、管理データの保存先も検証しません。
- 上のディレクトリの親ディレクトリは検証しません。ほかの OS ユーザーが中に名前を作ったり、置き換えたりできないようにするのは、運用者の責任です。
- 作業ディレクトリに setgid が付いていると、中に作るディレクトリがその属性を受け継いで権限の検証に失敗し、検査プロセスを起動できません。
- `acme renew` は、証明書・鍵・チャレンジのファイルを、それぞれのディレクトリ（ACME のサイトでは managed ストアの `acme/` の中）に一時ファイルとして書いてから置き換えます。サービスの OS ユーザーが、これらのディレクトリに書き込めることが必要です。
- 設定ファイルを読めない OS ユーザーでコマンドを実行すると、設定を読む段階で受け付けません。ルールストアや managed ストアの所有者と違う OS ユーザーで実行すると、それぞれを開く段階で受け付けません。

### 国のデータベース

国の指定（全体の `access`、`host_policies` の `access`、ルートの `access` の `deny_countries`・`allow_countries`）を使う場合だけ必要です。

- データベースはプロキシに同梱しておらず、プロキシが取得することもありません。MaxMind DB 形式（バージョン 2）のファイルを運用者が用意します。使用許諾は、提供元の条件に従って運用者が守ってください。
- 置く場所と権限: 所有者を root にし、サービスの OS ユーザーが読めて書き換えられないファイル（0644）にします。例は `/etc/tukuyomi-core/country.mmdb` です。プロキシは所有者と権限を検証せず、中身を `geo.sha256` で検証します。シンボリックリンクにはしないでください（受け付けません）。サイズは 256 MiB までです。
- 設定の全体を読むコマンド（プロキシの起動とリロード、`config check`、`acme renew`、`managed import`・`managed activate`）は、どれもサービスの OS ユーザーでこのファイルの全体を読みます。このファイルを読めない OS ユーザーで実行したコマンドは、設定を読む段階で受け付けません。`rules` と `admin` のコマンド、管理プロセス、ログ送信プロセスは、このファイルを読みません。
- 国の指定があると、プロキシは、検証したファイルの全体をメモリに保持します。読むコマンドは、読むたびに全体を検証するので、大きいファイルでは時間とメモリを使います。
- ファイルの SHA-256 を求めて、設定の `geo.sha256` に書きます。値が一致しないと、どのコマンドも設定を受け付けません。

  ```bash
  sha256sum /etc/tukuyomi-core/country.mmdb
  ```

- データベースを入れ替えるときは、新しいファイルを別の名前で置き、設定の `geo.country_db` と `geo.sha256` を 1 回の置き換えで書き換えます。`config check` で検証してから、プロキシにリロードさせます（`systemctl reload`）。プロキシは、起動時とリロードのたびにデータベースを読みます。管理プロセスは、データベースを読みません。
- 設定キーと、国の判定の方法（プライベートアドレスや、IPv4 だけのデータベースでの IPv6 アドレスは `UNKNOWN`）は、[運用リファレンス](../operations/operator-reference.md) の「アクセス制御とレート制限」を参照してください。

## 初回起動の手順

設定ファイルに `managed` を書く（managed 設定を使う）場合は、[運用リファレンス](../operations/operator-reference.md) の「managed 設定での初回起動」の手順で進めてください。managed 設定を使うかどうかの判断は、同じ文書の「managed 設定を使うかどうか」を参照してください。その手順では、下の 2〜4 と 7 をそのまま使います。

1. 設定ファイルを書きます。設定キーの一覧と例は、[運用リファレンス](../operations/operator-reference.md) を参照してください。上の表のディレクトリを先に作ります。国の指定を使う場合は、国のデータベースも置き、`sha256` を書きます（上の「国のデータベース」）。
2. CRS を取得します（上の「CRS の取得」）。
3. ルールセットをインポートします。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0 --detect-only
   ```

   - インポートでは、検査プロセスを 1 つ起動し、決まったリクエストを 3 つ検査します（事前検証）。事前検証に通ったときだけ世代になり、標準出力に `<fingerprint> created` が出ます。同じ内容の世代が既にあれば、`already exists` が出ます。
   - `--detect-only` を付けると、検知のみの世代になります。ルールに一致したリクエストも通し、ログに残します。最初はこの形で動かし、誤検知を確認してから遮断の世代に切り替えることをおすすめします。
   - 遮断の世代では、事前検証のリクエストが 1 つでもブロックされると、事前検証に失敗し、世代になりません。`crs-setup.conf` の設定を厳しくした場合などは、ログを見て修正するか、`--accept-block` を付けてください。
   - ModSecurity で検査する世代にするには、`--engine modsecurity` を付けます。設定の `kernel.engines` に検査プロセスを指定する必要があります。事前検証は、そのエンジンの検査プロセスで実行されます。
4. 世代を選択します。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules activate /etc/tukuyomi-core/config.json <fingerprint>
   ```

5. 設定を検証します。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
   ```

   - 通れば、標準出力に `accepted` が出て、exit 0 になります。
   - 世代を選択する前に実行すると、`rules store refused: no generation is chosen` で拒否されます（exit 1）。設定そのもののエラーは exit 2 で分かるので、手順 1 の後にも実行できます。
   - アップストリームのサーバー名と、TLS の証明書と鍵のファイルも検証します。受け付けられなかった場合も同じ exit 1 で、行の先頭（`upstream refused`、`tls refused`）で区別できます。
   - 検査プロセスは起動しないので、作業ディレクトリ、検査プロセスの実行ファイル、Landlock は検証しません。
6. サービスを起動します（下の「systemd」）。
7. 管理プロセスを使う場合は、そのユニットも起動し（下の「管理プロセスのユニット」）、最初のユーザーを作ります。

   ```bash
   read -r -s -p 'password: ' PW; echo
   printf '%s\n' "$PW" | sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy admin bootstrap /etc/tukuyomi-core/config.json <name>
   unset PW
   ```

   - パスワードは、標準入力の最初の 1 行から読みます（12〜128 バイト）。引数には渡しません。名前は、`a-z`・`0-9`・`.`・`_`・`-` で 1〜32 バイトです。
   - 作るユーザーのロールは `owner` です。成功すると `created owner <name>` が出ます。管理データの保存先にユーザーが 1 人でもいれば、拒否されます（exit 1）。
   - 管理プロセスの起動の前でも後でも実行できます。パスワードを忘れたユーザーには `admin reset` を使います。
   - 管理 API、ロール、画面については、[管理リファレンス](../operations/admin-reference.md) を参照してください。
8. ログを DB へ送る場合は、DB のユーザーと DB を用意し、接続文字列のファイルを、所有者をサービスの OS ユーザーにして 0600 で置きます。設定に `records.ship` を書いて、ログ送信プロセスのユニットを起動します（下の「ログ送信プロセスのユニット」）。テーブルは、ログ送信プロセスが最初に接続したときに作ります。テーブルの権限と接続文字列の形式は、[運用リファレンス](../operations/operator-reference.md) の「ログ送信プロセス」を参照してください。

## systemd

サービスのユニットの例を示します。

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
  - 検査プロセスは SIGTERM を処理しないので、その場で終了します。そのため、プロキシが検査プロセスを順に停止すること（残りの検査を終え、終了の通知を受けること）ができません。
  - `mixed` では、SIGTERM はプロキシにだけ届きます。プロキシは、自分で検査プロセスを停止してから終了します。
- `Type=notify` にします。プロキシは、検査カーネルの準備ができてすべてのリスナーをバインドした後に `READY=1` を、停止の始めに `STOPPING=1` を systemd へ送ります。`systemctl start` と、このユニットの後に `After=` で並べたユニットは、そこまで待ちます。`Type=simple` では、実行した時点で起動したと見なされます。
  - 通知を送るのはプロキシのメインプロセスだけです。`NotifyAccess` はデフォルト（`main`）のままで問題ありません。
  - `TimeoutStartSec` は、アップストリームの名前解決の時間（`resolve_timeout_ms`）と、検査カーネルの準備を待つ時間（`ready_wait_ms`）を足した時間より長くします。`READY=1` が届かないと、systemd はこの時間の後にプロキシを停止します。
- `TimeoutStopSec` は、`stop_wait_ms` と `kill_grace_ms` と、ログの書き出しの 200 ms を足した時間より長くします。短いと、systemd が先に SIGKILL を送ります。停止の流れは、[運用リファレンス](../operations/operator-reference.md) の「停止」を参照してください。
- `LogRateLimitIntervalSec=0` を指定します。journald のデフォルトのレート制限では、リクエストが集中したときにリクエストのログがジャーナルに入らずに失われます。
- ログはジャーナルに入ります。設定に `records` があれば、同じログがファイルにも書かれます（上の「OS ユーザーとディレクトリ」）。保存期間と容量は、journald の設定（`/etc/systemd/journald.conf` の `SystemMaxUse`、`MaxRetentionSec` など）で決めます。ログにはクライアントのアドレスとパスが入るので、ジャーナルを読めるグループ（Ubuntu では `adm`・`systemd-journal`）に入れる OS ユーザーは最小限にしてください。ログの形式は、[運用リファレンス](../operations/operator-reference.md) の「ログ」を参照してください。
- 監視用のリスナー（設定の `status`）を置くと、同じホストの監視プログラムから `/healthz`・`/readyz`・`/metrics` にアクセスできます。ロードバランサーの準備状態の確認には `/readyz` を使います。
- シグナルは、プロキシのメインプロセスにだけ送ります（`ExecReload` の `$MAINPID`、または `systemctl kill --kill-whom=main`）。
  - `--kill-whom=main` を付けない `systemctl kill` は、検査プロセスにもシグナルを送ります。
  - 検査プロセスは、SIGUSR1・SIGUSR2 は無視しますが、SIGTERM・SIGINT・SIGHUP が届くと終了します。
- `systemctl reload` は、2 つの `ExecReload` を順に実行します。`config check` が通ったときだけ SIGHUP を送り、プロキシは設定ファイルをリロードして、停止せずに新しい設定に切り替えます（[運用リファレンス](../operations/operator-reference.md) の「SIGHUP（設定のリロード）」）。
  - `config check` が受け付けない設定では、SIGHUP は送られず、`systemctl reload` が失敗を返します。
  - `config check` が通ると、`systemctl reload` は SIGHUP を送った時点で成功を返し、リロードの完了を待ちません。動作中のプロキシだけが拒否する理由（動作中に変更できない設定キーの違い、新しいリスナーのバインド）では、`systemctl reload` は成功を返します。結果は、ログの `reload: configuration replaced <SHA-256>`（`managed` のある設定では、後に ` managed <version>` が続きます）と `reload: configuration refused: <reason>` の行と、`/metrics` の `tukuyomi_config_reloads_total` で確認します。
  - 選択中の世代を `config check` が受け付けない間は、`systemctl reload` も拒否されます（リロードそのものは世代に触れません）。
- 設定を変更する手順: ファイルを書き換え（別の名前に書いてから、1 回の置き換えで差し替えます）、`systemctl reload tukuyomi-core.service` を実行し、ログの行で結果を確認します。動作中に変更できない設定キーを変えたときは、`systemctl restart` で再起動します。管理プロセスとログ送信プロセスは設定をリロードしないので、それらが読む設定キーを変えたら再起動します。
- 入れ替えの順序: SIGHUP を受けると停止していた以前のバージョンから入れ替えるときは、新しい実行ファイルを入れて再起動してから、ユニットの `ExecReload` を変更して `systemctl daemon-reload` を実行します（両方を変更してから再起動してもかまいません）。前のバージョンのまま新しいユニットで `systemctl reload` を実行すると、前のバージョンは SIGHUP で停止します。exit 0 で停止するので、`Restart=on-failure` でも再起動しません。
- 証明書と鍵だけを再読み込みさせる（SIGUSR2）ときは、次のように送ります。

  ```bash
  systemctl kill -s SIGUSR2 --kill-whom=main tukuyomi-core.service
  ```

- ルールセットの世代の切り替え（SIGUSR1）は、次のように送ります。

  ```bash
  systemctl kill -s SIGUSR1 --kill-whom=main tukuyomi-core.service
  ```

- ログのディレクトリ、制御ソケットを置くディレクトリ、管理データの保存先、managed ストアは、`ReadWritePaths` の中に置きます（上の例では `/var/lib/tukuyomi-core` の下）。別の場所に置く場合は、`ReadWritePaths` に追加してください。
- ポート 80・443 で待ち受けるには `CAP_NET_BIND_SERVICE` が必要です。ambient ケーパビリティは検査プロセスにも引き継がれますが、検査プロセスは起動時にすべてのケーパビリティを破棄します。
- `LimitNOFILE` は、受け付ける接続（`max_conns`）とアップストリームへの接続の数を足した値より大きくします。接続ごとにファイルディスクリプターを使います。
- 設定のエラーなどで起動が拒否されると、`Restart=on-failure` により `RestartSec` ごとに再起動します。設定を変更する前に、`config check` で検証してください。

### 管理プロセスのユニット

管理プロセスは、プロキシとは別のユニットで動かします。実行ファイル、設定ファイル、OS ユーザーはプロキシと同じです。ユニットの例を示します。

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

- `Type=notify` にします。管理プロセスは、リスナーをバインドした後に `READY=1` を、停止の始めに `STOPPING=1` を送ります。
- `KillMode=mixed` にします。管理プロセスは、ルールのインポートの事前検証で検査プロセスを起動します。停止の SIGTERM がメインプロセスにだけ届けば、管理プロセスが実行中の事前検証を終えて、検査プロセスと作業ディレクトリを片付けます。
- 管理プロセスは、停止のシグナル（SIGTERM、SIGINT、SIGHUP）を受けると、リスナーを閉じ、処理中のリクエストを最大 10 秒待ちます。`TimeoutStopSec` は、この 10 秒より長くします。インポートの事前検証が実行中の場合に備えて、その検査プロセスを停止する時間（`proxy.stop_inspect_ms` と `kernel.kill_grace_ms`）も足しておきます。
- `LogRateLimitIntervalSec=0` を指定します。監査ログは標準エラー（ジャーナル）にも出るので、journald のレート制限で失われないようにします。
- 検査プロセスの実行ファイル（`kernel.inspector`。ModSecurity の世代では `kernel.engines` の方）と作業ディレクトリ（`kernel.tmp_root`）は、プロキシと同じものを使います。インポートの事前検証で起動する検査プロセスも、プロキシの場合と同じく Landlock で自身の権限を制限します。
- 管理プロセスは、`admin.listen` のループバックアドレスで、平文の HTTP で待ち受けます。1024 以上のポートなら、`AmbientCapabilities` は不要です。
- 管理プロセスは、設定ファイルを起動時に 1 回だけ読みます（プロキシと違い、SIGHUP でリロードしません）。設定を変更したら、`config check` で検証してから、`systemctl restart` で再起動します。`ExecReload` は置きません（管理プロセスにとって SIGHUP は停止のシグナルです）。
- プロキシが動いていなくても、管理プロセスは起動します。その間は、世代の切り替えも managed 設定の反映も依頼できません。
- 外部から使う場合は、プロキシの TLS リスナーのルートから `admin.listen` のアドレスへ転送します。`admin.listen` はアップストリームのサーバーに指定できます。`managed` のある設定では、ルートではなく `admin.route` で転送し、`admin.listen` をアップストリームのサーバーには指定できません（[運用リファレンス](../operations/operator-reference.md) の「`admin`」）。ルートの書き方は [管理リファレンス](../operations/admin-reference.md) の「外部からの利用」を、画面と API の使い方は同じ文書を参照してください。
- ログはジャーナルに入ります。監査ログは、管理データの保存先の `audit/` にも書かれます。

### ログ送信プロセスのユニット

ログを DB へ送る場合は、ログ送信プロセスをプロキシとは別のユニットで動かします。設定ファイルと OS ユーザーはプロキシと同じです。ユニットの例を示します。

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

- `Type=notify` にします。ログ送信プロセスは、起動時の検証を終えた後に `READY=1` を、停止の始めに `STOPPING=1` を送ります。DB には `READY=1` の後に接続します。接続できない DB は待ってから再試行するので、DB のユニットの後に並べる必要はありません。
- `TimeoutStopSec` は長めにします。停止のシグナルは DB の呼び出しが終わるまで処理されないため、停止までに長いと 1〜2 分かかります。それより短くて SIGKILL になっても、行と位置は同じトランザクションで DB に入るので、次の起動では続きから送ります。
- ログのディレクトリ（`ship.state` を書きます）は、`ReadWritePaths` の中に置きます。
- DB がログインを拒否すると、ログ送信プロセスは exit 1 で終了し、`Restart=on-failure` により `RestartSec` ごとに再起動します。接続文字列を直すまで、これを繰り返します。
- DB サーバーの証明書を独自の認証局で発行したときは、その証明書のファイルを `Environment=SSL_CERT_FILE=<path>` で渡します。
- 設定ファイルと接続文字列のファイルは、起動時に 1 回だけ読みます（プロキシと違い、SIGHUP でリロードしません）。変更したら、`systemctl restart` で再起動します。`ExecReload` は置きません（ログ送信プロセスにとって SIGHUP は停止のシグナルです）。
- ログ送信プロセスはプロキシと同じ設定ファイルを読み、未知の設定キーを含む設定ファイルは受け付けません。設定に新しい設定キー（`managed`、`host_policies` など）を書く前に、ログ送信プロセスの実行ファイルをプロキシと同じビルドに入れ替えてください。前のビルドのままだと、ログ送信プロセスは次の起動で設定を受け付けず、起動しません（[運用リファレンス](../operations/operator-reference.md) の「ログ送信プロセスの起動」）。
- プロキシが動いていなくても、ログ送信プロセスは起動し、ファイルにあるログを送ります。プロキシは、ログ送信プロセスが動いていないこと（`ship.state` が 90 秒より古いこと）を、`required` のルートのリクエストを拒否することで示します。
- ログ送信プロセスのログはジャーナルに入ります。

### 証明書の更新のタイマー

`acme renew` を毎日実行する例を示します。

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

- コマンドの後に送る SIGUSR2 で、プロキシが新しい証明書を読み込みます。動作中のプロキシは、コマンドが証明書を書いたことを検知しません。
  - `systemctl reload` を使わないのは、SIGHUP では設定ファイルの全体を読み込むためです。タイマーが実行されたときに編集途中の設定を読み込まないように、証明書と鍵だけを読み込む SIGUSR2 を送ります。
- `ExecStopPost` は、コマンドが失敗しても実行されます。証明書が 1 つでも `failed` になるとコマンドは exit 1 で終わりますが、SIGUSR2 は送られるので、ほかの更新できた証明書は使われ始めます。`failed` の証明書のファイルは前のまま残り、SIGUSR2 は読み込んだ証明書がすべて検証に通るときだけ入れ替えるので、失敗したときに送っても問題ありません。
- `ExecStopPost` の先頭の `+` は、`systemctl kill` を root で実行するための指定です。コマンドそのものは、サービスの OS ユーザーで実行されます。
- `ExecStartPost=+` で SIGUSR2 を送っているユニットは、その行を上の `ExecStopPost=+` の行に変更し、`systemctl daemon-reload` を実行してください。`ExecStartPost` はコマンドが exit 0 で終わったときだけ実行されるので、1 つの `failed` で、ほかの更新できた証明書も、次に SIGUSR2 か SIGHUP を送るまで使われません。
- 同じ設定で `acme renew` を 2 つ同時に実行しないでください。同時実行を防ぐ仕組みはありません。systemd のタイマーは重なりませんが、cron などで実行する場合は重ならないようにしてください。
- managed 設定で、ACME のサイトのホストの組み合わせを変更したバージョンを反映したときは、タイマーを待たずに `systemctl start tukuyomi-core-acme.service` でこのサービスを実行します（[運用リファレンス](../operations/operator-reference.md) の「ACME のサイト」）。
- 初回の発行の手順は、[運用リファレンス](../operations/operator-reference.md) の「ACME」を参照してください。

## 検査プロセスの権限の制限

検査プロセスは、起動時に次の順で自身の権限を制限します。どの制限も、プロセスのすべてのスレッドに、元に戻せない形でかけます。

1. ルールセットの世代を読みます。読めなければ exit 11 で終了します。別のエンジンの世代のマニフェストもこの検査プロセスは読めないので、同じく exit 11 で終了します。
   - Coraza の検査プロセスは、この後はファイルを読みません。
   - ModSecurity の検査プロセスは、検証したファイルを、起動ごとの一時ディレクトリの中に写します（写せなければ exit 14）。制限をかけた後は、ルールをこの写しから組み立て、この写しだけを読みます。
2. Landlock のルールセットを組み立てます。
   - 起動ごとの一時ディレクトリ（作業ディレクトリの中に作ります）の外のファイルに触れられなくします。作業ディレクトリの中のほかのディレクトリにも触れられません。
   - 一時ディレクトリの中で許可するのは、ファイルの作成・書き込み・読み込み・切り詰め・削除だけです。ディレクトリの作成と一覧、一時ディレクトリの外へのリネーム、プログラムの実行はできません。
   - Linux 6.7 以上（ABI 4 以上）では、TCP のバインドと接続も禁止します。
3. ケーパビリティを破棄します（ambient を空にし、effective・permitted・inheritable を 0 にします）。
4. `no_new_privs` を設定します。
5. 最後に Landlock を有効にします。この時点から、2 の制限が効きます。

2 から 5 のどれかが失敗すると、検査プロセスは起動しません（exit 14）。この後、ルールをその世代のエンジン（Coraza か ModSecurity）で検証して組み立て、リクエストの受け付けを始めます。ルールの検証や組み立てに失敗したときは、exit 11 で終了します。ModSecurity の検査プロセスは、ライブラリの準備ができないなどの環境の問題では、exit 14 で終了します。

制限できないものもあります。

- Landlock は、UDP、Unix ドメインソケット、MPTCP のソケット（`IPPROTO_MPTCP` で作るもの）を制限しません。そのため検査プロセスは、これらを使って外部へ送信することや、1024 以上のポートで待ち受けることが、まだできます。
- MPTCP を使わないホストでは、`net.mptcp.enabled=0` にすると MPTCP のソケットを作れなくなります。
- 1024 未満のポートは、ケーパビリティを破棄するので使えません（Linux の `net.ipv4.ip_unprivileged_port_start` がデフォルトの 1024 の場合）。

プロキシ側には、この制限をかけません。プロキシは設定・ルールストア・証明書と鍵を読み、リスナーとアップストリームへの接続を持ちます。管理プロセスも、自身にはこの制限をかけません。インポートの事前検証で起動する検査プロセスだけが、上の制限をかけます。

## 起動前の検証

プロキシの起動、`rules import`（事前検証で検査プロセスを起動します）、管理プロセスのコマンド（`admin <config>`、`admin bootstrap`、`admin reset`）は、`/proc` を読んで次の条件も検証します。条件を満たさなければ拒否します。`config check` とほかのコマンドは、root でないことだけを検証します。

- SIGCHLD を無視していないこと。検査カーネルは、子プロセスの終了を自分で待ちます。
- 2 より大きいファイルディスクリプターが、すべて close-on-exec であること。検査プロセスに不要なディスクリプターを渡さないためです。

systemd から起動する場合は、どちらの条件も満たされます。
