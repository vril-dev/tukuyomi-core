# 実行ファイルの build と配置

この文書は、今の実装を1台の Linux のホストで動かす手順を示す。設定の鍵の意味と範囲、命令、合図、記録、監視は [運用リファレンス](../operations/operator-reference.md) に書く。管理のプロセスの設定と API は [管理リファレンス](../operations/admin-reference.md) に書く。

ここに出てくる置き場の path（`/opt/tukuyomi-core`、`/etc/tukuyomi-core`、`/var/lib/tukuyomi-core`）と利用者の名前（`tukuyomi`）は例である。設定の path は、どれも絶対の path で書く（`.`・`..`・空の要素・末尾の `/` は断られる）。

## 動くもの

| もの | 中身 |
|---|---|
| `tukuyomi-proxy`（Rust、`proxy/`） | HTTP・HTTPS の受付と転送。検査核（`kernel/`、Rust のライブラリ）を組み込み、検査プロセスの起動・停止・再起動を受け持つ。同じ実行ファイルが、ルールの保管場所の命令（`rules`）、証明書の命令（`acme renew`）、設定の確かめ（`config check`）、管理のプロセス（`admin`）も持つ |
| `tukuyomi-inspector`（Go、`inspector/`） | Coraza で要求を検査する。proxy が子のプロセスとして起動し、引き継いだ Unix domain socket の対で話す。待ち受けの port は持たない。設定の `kernel.inspector` に書く |
| `tukuyomi-inspector-modsecurity`（Rust と C++、`inspector-modsecurity/`） | ModSecurity v3（libmodsecurity 3.0.17）で要求を検査する。ModSecurity の世代（`rules import --engine modsecurity`）を使うときだけ要り、使わないホストでは省いてよい。proxy が子のプロセスとして起動し、引き継いだ Unix domain socket の対で話す。待ち受けの port は持たない。設定の `kernel.engines.modsecurity.inspector` に書く |
| `tukuyomi-records-ship`（Rust、`records-ship/`） | 記録の送り手。proxy の記録のファイルの行を、PostgreSQL か MySQL の表へ送る。記録を DB へ送るときだけ要り、送らないホストでは省いてよい。proxy とは別の unit で、同じ設定ファイルを読む。待ち受けの port は持たない |
| 管理のプロセス | 同じ実行ファイルの `tukuyomi-proxy admin <config>`。proxy とは別の unit で動かす。loopback の待ち受けで、管理 API と管理画面（実行ファイルに組み込んである）に答える。ルールの世代の操作と、proxy への切り替えの依頼（制御 socket）をする |
| 設定ファイル | JSON の1つのファイル。値に既定値はない。鍵は、省けると決まったもの（`acme`、`records`、`access`、`rate_limit`、`geo`、`admin` など）のほかは、すべて書く。proxy と管理のプロセスが同じファイルを読む |
| ルールの保管場所 | ルールセットの世代を置くディレクトリ（設定の `rules.store.dir`）。`rules import` が世代を作り、`rules activate` が使う世代を選ぶ。管理のプロセスも同じ操作をする |
| 検査プロセスの作業場所 | 起動ごとの一時のディレクトリを作る親（設定の `kernel.tmp_root`） |
| 証明書と鍵 | TLS の待ち受けのもの。`acme renew` で発行・更新するか、運用者が置く |
| 記録のファイル | 標準エラーに出す記録の写しを置くディレクトリ（設定の `records.dir`）。proxy が書き、管理のプロセスと送り手が読む。送り手は、送った位置（`ship.state`）もここに書く |
| 接続の文字列のファイル | 送り手が DB につなぐ文字列（パスワードを含む）のファイル（設定の `records.ship.db_dsn_file`）。送り手だけが読む |
| 管理の置き場 | 管理のプロセスが利用者・API の token・監査の記録・切り替えの履歴を置くディレクトリ（設定の `admin.store.dir`） |
| 制御 socket | proxy が管理のプロセスの依頼を受ける Unix domain socket（設定の `admin.control`） |
| 国のデータベース | 国の一覧（`access`）が使う、MaxMind DB の形式のファイル（設定の `geo.country_db`）。運用者が用意する |

検査プロセス、管理のプロセス、送り手は、proxy と同じ利用者で動く。

## 要るもの

- Linux。試したのは x86_64 だけである。
- Landlock が有効な Linux。
  - 検査プロセスは、ルールを読んだ後に Landlock で自分を絞る（下の「検査プロセスの絞り」）。
  - Landlock が無い Linux では、検査プロセスは起動を断る（exit 14）。proxy も起動せず（記録は `stop: the kernel failed: Exit(14)`）、`rules import` の試しも、管理のプロセスの取り込みの試しも失敗する。絞らずに動かす設定は無い。
  - 要るのは、Landlock を含む Linux 5.13 以上で、LSM の並びに `landlock` があること（`/sys/kernel/security/lsm` で分かる）。どの distribution の既定で有効かは確かめていない。
  - Linux の版によって、絞れる範囲が違う。どの版で絞ったかは、外からは見えない。
    - TCP の bind と connect まで絞るには、Linux 6.7 以上（Landlock の ABI 4 以上）が要る。それより前の版では、ファイルだけを絞って動く。
    - Linux 6.2 より前（ABI 1・2）では、ファイルの切り詰めを断れない。Linux 6.10 より前（ABI 4 まで）では、デバイスの ioctl を断れない。
- ModSecurity の検査プロセスを動かすホストに要る共有 library は、libstdc++、libgcc_s、libc、libm だけである。libmodsecurity、YAJL、PCRE2 は実行ファイルに静的に入っているので、入れなくてよい。
- build に要るもの。
  - Rust 1.94.1 以上（`proxy/Cargo.toml` の `rust-version`）
  - C の compiler（TLS に使う aws-lc-rs が、C のコードを build する）
  - Go 1.27.2（`inspector/go.mod`）。検査プロセスは、build した Go の版を検査核に知らせる。検査核は、`go1.27.2` のものだけを受け付ける。
- ModSecurity の検査プロセスを build するときだけ、さらに要るもの。
  - `rustc` 1.94.1 ちょうど（`rustc -vV` の `release:` の行が `1.94.1`）。proxy と違い、別の版で build した検査プロセスは検査核が受け付けない（下の「ModSecurity の検査プロセス」）。
  - C と C++ の compiler、make
  - libyajl-dev と libpcre2-dev（静的 library の `libyajl_s.a` と `libpcre2-8.a`）
  - bash、curl、sha256sum、tar（libmodsecurity の取得。archive を `BUILD_MODSECURITY_ARCHIVE_FILE` で渡すなら curl は要らない）
- CRS の取得に要るもの: bash、curl、sha256sum、tar。
- 記録を DB へ送るときだけ要るもの。
  - PostgreSQL か MySQL の server。試したのは PostgreSQL 16・18 と MySQL 8.0 である。
  - 記録のディレクトリのファイルシステムが、ファイルの生まれた時刻（`statx` の btime）を返すこと。試したのは ext4 だけである。

## build

proxy は `proxy/` で build する。検査核は、そこから一緒に build される。

```bash
cd proxy && cargo build --release --locked
```

実行ファイルは `proxy/target/release/tukuyomi-proxy` にできる。管理画面のファイル（`proxy/admin-ui/`）は、この build で実行ファイルに組み込まれる。画面のための build や配布は、別には要らない。

検査プロセスは、`inspector/` で cgo を使わずに build する。

```bash
cd inspector && CGO_ENABLED=0 go build -mod=readonly -o tukuyomi-inspector .
```

`CGO_ENABLED=0` は必ず付ける。

- 検査プロセスは、Landlock などの設定をすべての thread にかけるために、Go の `syscall.AllThreadsSyscall` を使う。cgo を使った実行ファイルでは、この呼び出しが `ENOTSUP` を返すため、検査プロセスは起動を断る（exit 14）。
- 断った理由の文（「cgo で build された」など）は、検査プロセスの標準出力・標準エラーには出ない。`rules import` の `the inspector said:` の行と、SIGUSR1 の切り替えが失敗したときの `reload: the inspector said:` の行にだけ出る。proxy の起動では、`stop: the kernel failed: Exit(14)` の行だけが出る。

### ModSecurity の検査プロセス

ModSecurity の世代を使うときだけ build する。Coraza の世代だけを使うホストには要らない。先に libmodsecurity（ModSecurity v3.0.17）を、新しいディレクトリ（prefix）に静的 library として build し、その prefix を指して検査プロセスを build する。

```bash
scripts/build-modsecurity.sh <新しいディレクトリ>
cd inspector-modsecurity && TUKUYOMI_MODSECURITY_PREFIX=<新しいディレクトリ> cargo build --release --locked
```

実行ファイルは `inspector-modsecurity/target/release/tukuyomi-inspector-modsecurity` にできる。

`scripts/build-modsecurity.sh` は次のとおり動く。

- 取得する版（3.0.17）と、配布の archive（`modsecurity-v3.0.17.tar.gz`）の sha256（`f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50`）は、台本の中に固定してある。引数では変えられない。
- archive は https だけで取り、固定した sha256 と一致してから中を読む。GitHub に届かないホストでは、固定した archive の写しを `BUILD_MODSECURITY_ARCHIVE_FILE` で渡せる。そのときも sha256 などの確かめは同じである。
- 新しいディレクトリは、まだ無い絶対の path で、英数字と `.`・`_`・`+`・`-` だけで書く。`.` で始まる名前は使えない。相対で書くと、今いる場所からの path にする。
- 新しいディレクトリの親は、既にあって、流す利用者が書けること。台本は、その隣に一時のディレクトリを作り、最後に1回の名前の変更で新しいディレクトリを置く。
- 既にあるディレクトリには触らない。途中で失敗したときは何も残らない。
- 数分かかる。
- configure は、台本に固定した flag で流す。curl、Lua、MaxMind、GeoIP、libxml2、LMDB、ssdeep は使わず、YAJL と PCRE2 だけを使う。configure の結果がそうならなければ断る。外から規則を取り込む、スクリプトを実行する、データベースを引く、XML を解析する、といった機能をルールに使わせないための守りの一部なので、変えない。
- prefix には、`include/`、`lib/libmodsecurity.a`、`include-src/`（libmodsecurity の内部の header）、`archive.sha256`（固定した archive の sha256 を書いた1行）ができる。

検査プロセスの build は、次の場合に断る。

- `TUKUYOMI_MODSECURITY_PREFIX` が無い、または絶対の path でない。
- prefix に `include/modsecurity/modsecurity.h`、`include-src/src/variables/variable.h`、`lib/libmodsecurity.a` のどれかが無い。
- prefix の `archive.sha256` が読めない、または小文字の16進数64桁の1行でない。
- C++ の compiler が `libpcre2-8.a`（libpcre2-dev）か `libyajl_s.a`（libyajl-dev）を見つけられない。

検査プロセスは、build した compiler の版、libmodsecurity の版、archive の sha256 を、起動の最初の知らせ（HELLO）で検査核に伝える。検査核は、ModSecurity では次の3つがすべて同じものだけを受け付ける。

| 項目 | 受け付ける値 |
|---|---|
| build した compiler | `rustc 1.94.1` |
| libmodsecurity の版 | `v3.0.17` |
| archive の sha256 | 上の `f283b33d…b671a50` |

違うと、検査核は `hello toolchain differs`、`hello engine version differs`、`hello engine source differs` のどれかで断り、起動し直さない。proxy の起動では `stop: the kernel failed: Hello("<文>")` の行が、`rules import` では `rules import: the trial failed: the inspector could not be started (Hello("<文>"))` の行が出る。

### 記録の送り手

記録を DB へ送るときだけ build する。`records-ship/` で build する。proxy のライブラリも一緒に build される。

```bash
cd records-ship && cargo build --release --locked
```

実行ファイルは `records-ship/target/release/tukuyomi-records-ship` にできる。要るものは proxy と同じである（Rust 1.94.1 以上と C の compiler）。

### CRS の取得

CRS（OWASP Core Rule Set）は同梱しない。`scripts/fetch-crs.sh` で取得する。サービスの利用者で流す。

```bash
sudo -u tukuyomi scripts/fetch-crs.sh /var/lib/tukuyomi-core/crs-4.23.0
```

- 取得する版（4.23.0）と、配布の archive の sha256 は、台本の中に固定してある。引数では変えられない。
- archive は https だけで取り、固定した sha256 と一致してから中を読む。GitHub に届かないホストでは、固定した archive の写しを `FETCH_CRS_ARCHIVE_FILE` で渡せる。そのときも sha256 などの確かめは同じである。
- 新しいディレクトリには、次の4つだけが入る。
  - `crs-setup.conf`（`crs-setup.conf.example` の写し）
  - `crs-setup.conf.example`
  - `rules/*.conf`
  - `rules/*.data`
- 台本は `umask 077` で動く。できたディレクトリとファイルは、流した利用者だけが読める。root で流すと、サービスの利用者の `rules import` が読めない。
- 新しいディレクトリの親は、既にあって、流す利用者が書けること。台本は、その隣に一時のディレクトリを作る。
- 既にあるディレクトリには触らない。途中で失敗したときは何も残らない。
- 運用者は、取り込みの前に `crs-setup.conf` を直してよい。たとえば、受け付ける本文の型を足す（[運用リファレンス](../operations/operator-reference.md) の「ルールセットと世代」）。

## 利用者と置き場

proxy は root では動かない。起動もすべての命令も、プロセスの user id の4つ（real、effective、saved、file system）のどれかが 0 なら `host check refused` の行を出して断る（exit 1）。

- 専用の利用者を作り、サービスも命令もその利用者で流す。たとえば `sudo -u tukuyomi tukuyomi-proxy ...` とする。
- root で `acme renew` を流すと、作った鍵を別の利用者の proxy が読めないので、これも断る。
- 管理のプロセス（`admin`）と、その短い命令（`admin bootstrap`・`admin reset`）も、同じ利用者で流す。ルールの保管場所、記録のディレクトリ、制御 socket は、その利用者だけが使える（0700）ためである。別の利用者で動かすと、どれも使えない。
- 記録の送り手も、同じ利用者で動かす。記録のディレクトリを読み、そこに `ship.state` を書くためである。送り手も root では動かない。

置き場の例を次に示す。

| 例 | 設定の鍵 | 持ち主と権限 |
|---|---|---|
| `/opt/tukuyomi-core/bin/tukuyomi-proxy`、`/opt/tukuyomi-core/bin/tukuyomi-inspector` | `kernel.inspector`（Coraza の検査プロセスの方） | root。サービスの利用者が書き換えられない所に置く |
| `/opt/tukuyomi-core/bin/tukuyomi-inspector-modsecurity` | `kernel.engines.modsecurity.inspector`（ModSecurity の検査プロセスの方。省いてよい） | root。サービスの利用者が書き換えられない所に置く |
| `/opt/tukuyomi-core/bin/tukuyomi-records-ship` | （送り手の unit。省いてよい） | root。サービスの利用者が書き換えられない所に置く |
| `/etc/tukuyomi-core/config.json` | （起動の引数） | root。サービスの利用者が読めること。大きさは 256 KiB まで |
| `/var/lib/tukuyomi-core/store` | `rules.store.dir` | サービスの利用者。権限は 0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root` | サービスの利用者。権限は 0700。setgid は付けない |
| `/var/lib/tukuyomi-core/tls/` | 証明書の `cert_file`・`key_file` | サービスの利用者（`acme renew` が書く） |
| `/var/lib/tukuyomi-core/acme/account.key` | `acme.account_key_file` | `acme renew` が初めての実行のときに作る（0600） |
| `/var/lib/tukuyomi-core/challenges` | `acme.challenge_dir` | サービスの利用者 |
| `/var/lib/tukuyomi-core/records` | `records.dir` | サービスの利用者。権限は 0700。中の `records.log` などは proxy が、`ship.state` は送り手が、0600 で作る |
| `/etc/tukuyomi-core/records-db.dsn` | `records.ship.db_dsn_file`（送り手を使うとき） | サービスの利用者が持ち主で、権限は 0600。設定ファイルと違い、root の持ち物にしない（送り手が、持ち主と権限を確かめる） |
| `/var/lib/tukuyomi-core/admin` | `admin.store.dir` | サービスの利用者。権限は 0700。中の `users/`・`tokens/`・`audit/` などは管理のプロセスが作る |
| `/var/lib/tukuyomi-core/control` | `admin.control` のあるディレクトリ（例の socket は `/var/lib/tukuyomi-core/control/proxy.sock`） | サービスの利用者。権限は 0700。socket は proxy が 0600 で作る。socket の path は 107 バイトまで |
| `/var/lib/tukuyomi-core/crs-4.23.0` | `admin.crs_dir`（管理の API で CRS を取り込むとき） | 「CRS の取得」で作ったディレクトリ。サービスの利用者が読めること |
| `/etc/tukuyomi-core/country.mmdb` | `geo.country_db` | root。サービスの利用者が読めて、書き換えられない形にする（0644）。proxy は持ち主と権限を確かめない |

- 設定の `kernel.inspector` は、ModSecurity の世代だけを使うホストでも書く（省けない鍵である）。`kernel.engines` は、ModSecurity の世代を使うときだけ書く。書かないと、ModSecurity の世代は取り込めず、選べず、起動でも断られる（[運用リファレンス](../operations/operator-reference.md) の「`kernel`」）。
- 上の表のディレクトリは、先に作っておく。proxy も命令も、これらは作らない。保管場所の中のもの（`generations/`、`staging/`、`using/` など）は、命令と proxy が作る。管理の置き場の中のものは管理のプロセスが、記録のファイルと制御 socket は proxy が作る。
- ルールの保管場所、記録のディレクトリ、管理の置き場、制御 socket のあるディレクトリは、別々のディレクトリにする。同じにも、互いの中にも置けない（設定が断られる）。上の表の例は、どれも `/var/lib/tukuyomi-core` の下の別々のディレクトリである。
- 保管場所、作業場所、記録のディレクトリ、管理の置き場、制御 socket のあるディレクトリは、本物のディレクトリ（link ではない）で、持ち主がプロセスの利用者で、group と other の権限が無いことを確かめる。確かめる時が違う。
  - 保管場所は、proxy の起動、`config check`、`rules` の命令で確かめる。管理のプロセスが保管場所を開くときも確かめる。違えば exit 1 で断る。
  - 作業場所は、検査プロセスを起動するたびに確かめる（proxy の起動、検査プロセスの起動し直し、SIGUSR1 の切り替え、`rules import` の試し）。違えば検査プロセスを起動しない。proxy の起動では exit 1 で終わり、SIGUSR1 の切り替えでは今の世代が動き続け、起動し直しでは proxy が止まる。
  - 記録のディレクトリは、proxy の起動のときに確かめる。違えば proxy は起動しない（exit 1）。記録のファイルを開き直す前と、回す前にも確かめる。
  - 制御 socket のあるディレクトリは、proxy の起動のときに確かめる。違えば proxy は起動しない（exit 1）。
  - 管理の置き場は、管理のプロセスの起動と、`admin bootstrap`・`admin reset` で確かめる。違えば exit 1 で断る。
  - `config check` と `acme renew` は、作業場所を確かめない。`config check` は、記録のディレクトリ、制御 socket のあるディレクトリ、管理の置き場も確かめない。
- 上の置き場の親のディレクトリは確かめない。ほかの利用者が中の名前を作ったり差し替えたりできないようにするのは、運用者の受け持ちである。
- 作業場所に setgid が付いていると、中に作るディレクトリがその印を受け継いで権限の確かめに落ち、検査プロセスが起動できない。
- `acme renew` は、証明書・鍵・challenge のファイルを、それぞれの置き場のディレクトリに一時のファイルとして書いてから置き換える。サービスの利用者が、これらのディレクトリに書けること。
- 設定ファイルが読めない利用者で命令を流すと、設定の段で断られる。保管場所の持ち主と違う利用者で流すと、保管場所の段で断られる。

### 国のデータベース

国の一覧（`access` の `deny_countries`・`allow_countries`）を使うときだけ要る。

- データベースは、proxy に同梱せず、proxy は取得もしない。MaxMind DB の形式（版 2）のファイルを、運用者が用意する。使用許諾は、提供元の条件に従って運用者が守る。
- 置く所と権限: root が持ち主で、サービスの利用者が読めて書き換えられないファイル（0644）にする。例は `/etc/tukuyomi-core/country.mmdb` である。proxy は持ち主と権限を確かめず、中身を `geo.sha256` で確かめる。link にはしない（断られる）。大きさは 256 MiB までである。
- 設定の命令（proxy の起動、`config check`、`rules`、`acme renew`、`admin`）は、どれもサービスの利用者でこのファイルの全体を読む。読めない利用者の命令は、設定の段で断られる。
- 国の一覧があれば、proxy と管理のプロセスは、確かめたファイルの全体をメモリに持つ。どの命令も読むたびに全体を確かめるので、大きいファイルでは時間とメモリを使う。
- ファイルの SHA-256 を求めて、設定の `geo.sha256` に書く。値が合わないと、どの命令も設定を断る。

  ```bash
  sha256sum /etc/tukuyomi-core/country.mmdb
  ```

- 替えるときは、新しいファイルを別の名前で置き、設定の `geo.country_db` と `geo.sha256` を1回の置き換えで書き換える。`config check` で確かめてから、proxy に読み直させ（`systemctl reload`）、管理のプロセスを起動し直す。proxy は、起動のときと読み直しのたびにデータベースを読む。管理のプロセスは、起動の後は読み直さない。
- 設定の鍵と、国の決め方（private な address や、IPv4 だけのデータベースの IPv6 は `UNKNOWN`）は [運用リファレンス](../operations/operator-reference.md) の「要求の前の方針」にある。

## 初めて起動する手順

1. 設定ファイルを書く。鍵の一覧と例は [運用リファレンス](../operations/operator-reference.md) にある。置き場のディレクトリ（上の表）を先に作る。国の一覧を使うときは、国のデータベースも置き、`sha256` を書く（上の「国のデータベース」）。
2. CRS を取得する（上の「CRS の取得」）。
3. ルールセットを取り込む。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0 --detect-only
   ```

   - 取り込みでは、検査プロセスを1つ起動して決まった要求を3つ検査する（試し）。試しに通ったときだけ世代になり、標準出力に `<指紋> created` が出る。同じ中身の世代が既にあれば `already exists` が出る。
   - `--detect-only` を付けると、検知だけの世代になる。規則に当たった要求も通して、記録に残す。最初はこの形で動かし、誤検知を見てから遮断の世代に替えるとよい。
   - 遮断の世代では、試しの要求が1つでも遮断されると、試しに落ちて世代にならない。`crs-setup.conf` を強めたときなどは、記録を見て直すか、`--accept-block` を付ける。
   - ModSecurity で検査する世代にするには、`--engine modsecurity` を付ける。設定の `kernel.engines` に検査プロセスが要る。試しは、そのエンジンの検査プロセスで流れる。
4. 世代を選ぶ。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules activate /etc/tukuyomi-core/config.json <指紋>
   ```

5. 設定を確かめる。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
   ```

   - 通れば、標準出力に `accepted` が出て exit 0 になる。
   - 世代を選ぶ前に流すと、`rules store refused: no generation is chosen` で断られる（exit 1）。設定そのものの誤りは exit 2 で分かるので、手順 1 の後にも流せる。
   - 上流の server の名前と、TLS の証明書と鍵のファイルも確かめる。断られたときは、同じ exit 1 で、行の頭（`upstream refused`、`tls refused`）で分かる。
   - 検査プロセスは起動しないので、作業場所、検査プロセスの実行ファイル、Landlock は確かめない。
6. サービスを起動する（下の「systemd」）。
7. 管理のプロセスを使うときは、その unit も起動し（下の「管理のプロセス」）、最初の利用者を作る。

   ```bash
   read -r -s -p 'password: ' PW; echo
   printf '%s\n' "$PW" | sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy admin bootstrap /etc/tukuyomi-core/config.json <名前>
   unset PW
   ```

   - パスワードは、標準入力の最初の1行から読む（12〜128 バイト）。引数には渡さない。名前は 1〜32 バイトの `a-z`・`0-9`・`.`・`_`・`-` である。
   - 作る利用者の役割は `owner` である。成功すると `created owner <名前>` が出る。管理の置き場に利用者が1人でもいれば、断られる（exit 1）。
   - 管理のプロセスの起動の前でも後でも流せる。パスワードを忘れた利用者には `admin reset` を使う。
   - 管理 API、役割、画面は [管理リファレンス](../operations/admin-reference.md) にある。
8. 記録を DB へ送るときは、DB の利用者と DB を用意し、接続の文字列のファイルをサービスの利用者の持ち物の 0600 で置き、設定に `records.ship` を書いて、送り手の unit を起動する（下の「記録の送り手」）。表は、送り手が最初につないだときに作る。表の権限と接続の文字列の形は [運用リファレンス](../operations/operator-reference.md) の「記録の送り手」にある。

## systemd

サービスの unit の例を示す。

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

- `KillMode=mixed` にする。
  - 既定の `control-group` では、停止の SIGTERM が検査プロセスにも届く。
  - 検査プロセスは SIGTERM を扱わないので、その場で終わる。proxy が検査プロセスを順に止めること（検査の残りを終え、終わりの知らせを受ける）ができない。
  - `mixed` では SIGTERM は proxy だけに届く。proxy は自分で検査プロセスを止めてから終わる。
- `Type=notify` にする。proxy は、検査核の準備ができて待ち受けを全部 bind した後に `READY=1` を、停止の始めに `STOPPING=1` を systemd へ送る。`systemctl start` と、この unit の後に `After=` で並べた unit は、そこまで待つ。`Type=simple` では、実行した時点で起動したと見なされる。
  - 知らせを送るのは proxy の主プロセスだけである。`NotifyAccess` は既定（`main`）のままでよい。
  - `TimeoutStartSec` は、上流の名前を引く時間（`resolve_timeout_ms`）と、検査核の準備を待つ時間（`ready_wait_ms`）を足した時間より長くする。`READY=1` が届かないと、systemd はこの時間の後に proxy を止める。
- `TimeoutStopSec` は、`stop_wait_ms` と `kill_grace_ms` と、記録の書き出しの 200 ms を足した時間より長くする。短いと、systemd が先に SIGKILL を送る。停止の流れは [運用リファレンス](../operations/operator-reference.md) の「停止」にある。
- `LogRateLimitIntervalSec=0` を置く。journald の既定の流量の上限では、混んだときに要求の記録が journal に入らずに落ちる。
- 記録は journal に入る。設定に `records` があれば、同じ記録がファイルにも入る（上の「利用者と置き場」）。保存の期間と容量は、journald の設定（`/etc/systemd/journald.conf` の `SystemMaxUse`、`MaxRetentionSec` など）で決める。記録には client の address と path が入るので、journal を読める組（Ubuntu では `adm`・`systemd-journal`）に入れる利用者を絞る。記録の形は [運用リファレンス](../operations/operator-reference.md) の「記録」にある。
- 監視の待ち受け（設定の `status`）を置くと、同じ host の監視の program から `/healthz`・`/readyz`・`/metrics` を引ける。ロードバランサーの準備の確かめには `/readyz` を使う。
- 合図は proxy の主プロセスだけに送る（`ExecReload` の `$MAINPID`、または `systemctl kill --kill-whom=main`）。
  - `--kill-whom=main` を付けない `systemctl kill` は、検査プロセスにも合図を送る。
  - 検査プロセスは、SIGUSR1・SIGUSR2 は無視するが、SIGTERM・SIGINT・SIGHUP が届くと終わる。
- `systemctl reload` は、2つの `ExecReload` を順に流す。`config check` が通ったときだけ SIGHUP を送り、proxy は設定ファイルを読み直して、止まらずに新しい設定に替える（[運用リファレンス](../operations/operator-reference.md) の「SIGHUP（設定の読み直し）」）。
  - `config check` が断る設定では、SIGHUP は送られず、`systemctl reload` が失敗を返す。
  - `config check` が通ると、`systemctl reload` は SIGHUP を送った所で成功を返し、読み直しの終わりを待たない。動いている proxy だけが断る理由（動いている間に変えられない鍵の違い、新しい待ち受けの bind）では、`systemctl reload` は成功を返す。結果は、記録の `reload: configuration replaced <SHA-256>` と `reload: configuration refused: <理由>` の文と、`/metrics` の `tukuyomi_config_reloads_total` で見る。
  - 選んでいる世代を `config check` が断る間は、`systemctl reload` も断られる（読み直しそのものは世代に触れない）。
- 設定を変える手順: ファイルを書き換え（別の名前に書いてから、1回の置き換えで差し替える）、`systemctl reload tukuyomi-core.service` を流し、記録の文で結果を見る。動いている間に変えられない鍵を替えたときは、`systemctl restart` で起動し直す。管理のプロセスと記録の送り手は読み直さないので、それらが読む鍵を替えたら起動し直す。
- 入れ替えの順: SIGHUP で止まる前の版から入れ替えるときは、新しい実行ファイルを入れて起動し直してから、unit の `ExecReload` を替えて `systemctl daemon-reload` を流す（両方を替えてから起動し直してもよい）。前の版のまま新しい unit で `systemctl reload` を流すと、前の版は SIGHUP で止まる。exit 0 で止まるので、`Restart=on-failure` でも起動し直さない。
- 証明書と鍵だけを読ませる（SIGUSR2）ときは、次のように送る。

  ```bash
  systemctl kill -s SIGUSR2 --kill-whom=main tukuyomi-core.service
  ```

- ルールセットの世代の切り替え（SIGUSR1）は、次のように送る。

  ```bash
  systemctl kill -s SIGUSR1 --kill-whom=main tukuyomi-core.service
  ```

- 記録のディレクトリ、制御 socket のあるディレクトリ、管理の置き場は、`ReadWritePaths` の中に置く（上の例は `/var/lib/tukuyomi-core` の下）。別の所に置くときは、`ReadWritePaths` に足す。
- port 80・443 で待ち受けるには `CAP_NET_BIND_SERVICE` が要る。ambient の capability は検査プロセスにも受け継がれるが、検査プロセスは起動のときにすべての capability を捨てる。
- `LimitNOFILE` は、受ける接続（`max_conns`）と上流への接続の数を足したより大きくする。接続ごとに file descriptor を使う。
- 設定の誤りなどで起動が断られると、`Restart=on-failure` により `RestartSec` ごとに起動し直す。設定を変える前に `config check` で確かめる。

### 管理のプロセス

管理のプロセスは、proxy とは別の unit で動かす。同じ実行ファイル、同じ設定ファイル、同じ利用者である。unit の例を示す。

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

- `Type=notify` にする。管理のプロセスは、待ち受けを bind した後に `READY=1` を、停止の始めに `STOPPING=1` を送る。
- `KillMode=mixed` にする。管理のプロセスは、ルールの取り込みの試しで検査プロセスを起動する。停止の SIGTERM が主プロセスにだけ届けば、管理のプロセスが、動いている試しを終えて、検査プロセスと作業場所を片付ける。
- 管理のプロセスは、停止の合図（SIGTERM、SIGINT、SIGHUP）を受けると、待ち受けを閉じ、動いている要求を 10 秒まで待つ。`TimeoutStopSec` は、この 10 秒より長くする。取り込みの試しが動いているときのために、その検査プロセスを止める時間（`proxy.stop_inspect_ms` と `kernel.kill_grace_ms`）も足しておく。
- `LogRateLimitIntervalSec=0` を置く。監査の記録は標準エラー（journal）にも出るので、journald の流量の上限で落ちないようにする。
- 検査プロセスの実行ファイル（`kernel.inspector`。ModSecurity の世代では `kernel.engines` の方）と作業場所（`kernel.tmp_root`）は、proxy と同じものを使う。取り込みの試しの検査プロセスは、proxy と同じに Landlock で自分を絞る。
- 管理のプロセスは、`admin.listen` の loopback の address で、平文の HTTP で待つ。1024 以上の port なら、`AmbientCapabilities` は要らない。
- 管理のプロセスは、設定ファイルを起動のときに1回だけ読む（proxy と違い、SIGHUP で読み直さない）。設定を変えたら、`config check` で確かめてから、`systemctl restart` で起動し直す。`ExecReload` は置かない（管理のプロセスの SIGHUP は、停止である）。
- proxy が動いていなくても、管理のプロセスは起動する。そのあいだは、世代の切り替えを依頼できない。
- 外から使うときは、proxy の TLS の待ち受けの経路から、`admin.listen` の address へ転送する。`admin.listen` は、上流の server にしてよい（[運用リファレンス](../operations/operator-reference.md) の「`admin`」）。経路の書き方は [管理リファレンス](../operations/admin-reference.md) の「外から使う」に、画面と API の使い方は同じ文書にある。
- 記録は journal に入り、監査の記録は管理の置き場の `audit/` にも書く。

### 記録の送り手

記録を DB へ送るときは、送り手を proxy とは別の unit で動かす。同じ設定ファイル、同じ利用者である。unit の例を示す。

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

- `Type=notify` にする。送り手は、起動の確かめを終えた後に `READY=1` を、停止の始めに `STOPPING=1` を送る。DB には `READY=1` の後につなぐ。届かない DB は待って試し直すので、DB の unit の後に並べなくてよい。
- `TimeoutStopSec` は長めにする。止める合図は DB を呼んでいる間は待たされ、止まるまでに長いと1〜2分かかる。それより短くて SIGKILL になっても、行と位置は同じ transaction で DB に入るので、次の起動は続きから送る。
- 記録のディレクトリ（`ship.state` を書く）は、`ReadWritePaths` の中に置く。
- DB がログインを断ると、送り手は exit 1 で終わり、`Restart=on-failure` により `RestartSec` ごとに起動し直す。接続の文字列を直すまで、これを繰り返す。
- DB の server の証明書を自前の認証局で出したときは、その証明書のファイルを `Environment=SSL_CERT_FILE=<path>` で渡す。
- 設定ファイルと接続の文字列のファイルは、起動のときに1回だけ読む（proxy と違い、SIGHUP で読み直さない）。変えたら、`systemctl restart` で起動し直す。`ExecReload` は置かない（送り手の SIGHUP は停止である）。
- proxy が動いていなくても、送り手は起動し、ファイルにある記録を送る。proxy は、送り手が動いていないこと（`ship.state` が 90 秒より古い）を、`required` の経路の要求を断ることで示す。
- 送り手の記録は journal に入る。

### 証明書の更新の timer

`acme renew` を毎日流す例を示す。

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
ExecStartPost=+/bin/systemctl kill --kill-whom=main -s SIGUSR2 tukuyomi-core.service
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

- 命令の後の SIGUSR2 で、proxy が新しい証明書を読む。動いている proxy は、命令が証明書を書いたことに気づかない。
  - `systemctl reload` を使わないのは、SIGHUP が設定ファイル全体を読み直すためである。timer が流れたときに書きかけの設定を拾わないように、証明書と鍵だけを読む SIGUSR2 を送る。
- `ExecStartPost` の先頭の `+` は、`systemctl kill` を root で流すための印である。命令そのものはサービスの利用者で流れる。
- 証明書の1つでも `failed` だと、命令は exit 1 で終わり、`ExecStartPost` は流れない。そのときは、ほかに更新できた証明書も、次に SIGUSR2 か SIGHUP を送るまで使われない。
- 同じ設定で `acme renew` を2つ同時に流してはいけない。止める仕組みが無い。systemd の timer は重ならないが、cron などで流すときは重ならないようにする。
- 初めての発行の手順は [運用リファレンス](../operations/operator-reference.md) の「ACME」にある。

## 検査プロセスの絞り

検査プロセスは、起動のときに次のとおり自分を絞る。どれもプロセスの全部の thread に、元に戻せない形でかける。

1. ルールセットの世代を読む。読めなければ exit 11 で断る。別のエンジンの世代の manifest も、この検査プロセスは読めず、この exit 11 で断る。
   - Coraza の検査プロセスは、この後はファイルを読まない。
   - ModSecurity の検査プロセスは、確かめたファイルを、起動ごとの一時のディレクトリの中に写す（写せなければ exit 14）。絞った後は、ルールをこの写しから組み、この写しだけを読む。
2. Landlock の規則を組む。
   - 起動ごとの一時のディレクトリ（作業場所の中に作る）の外のファイルに触れなくする。作業場所の中のほかのディレクトリにも触れない。
   - 一時のディレクトリの中で許すのは、ファイルを作る・書く・読む・切り詰める・消すことだけである。ディレクトリを作る・一覧する、そこから外への名前の変更、プログラムの実行はできない。
   - Linux 6.7 以上（ABI 4 以上）では、TCP の bind と connect も断る。
3. capability を捨てる（ambient を空にし、effective・permitted・inheritable を 0 にする）。
4. `no_new_privs` を付ける。
5. 最後に Landlock をかける。この時から 2 の制限が効く。

2 から 5 のどれかが失敗したら、検査プロセスは起動を断る（exit 14）。この後で、ルールをその世代のエンジン（Coraza か ModSecurity）で確かめて組み、要求を受け始める。ルールの確かめや組み立てに失敗したときは exit 11 で断る。ModSecurity の検査プロセスは、ライブラリの準備ができないなど、環境の失敗では exit 14 で断る。

絞れないものもある。

- Landlock は、UDP、unix の socket、MPTCP の socket（`IPPROTO_MPTCP` で作るもの）を絞らない。そのため検査プロセスは、これらで外へ送ることや、1024 以上の port で待ち受けることがまだできる。
- MPTCP を使わないホストでは、`net.mptcp.enabled=0` にすれば MPTCP の socket は作れなくなる。
- 1024 未満の port は、capability を捨てるので取れない（Linux の `net.ipv4.ip_unprivileged_port_start` が既定の 1024 のとき）。

proxy の側は、絞りをかけない。proxy は設定・保管場所・証明書と鍵を読み、待ち受けと上流への接続を持つ。管理のプロセスも、自分には絞りをかけない。取り込みの試しで起動する検査プロセスだけが、上の絞りをかける。

## 起動の前の確かめ

proxy の起動、`rules import`（試しで検査プロセスを起動する）、管理のプロセスの命令（`admin <config>`、`admin bootstrap`、`admin reset`）は、`/proc` を読んで次も確かめる。違えば断る。`config check` とほかの命令は、root でないことだけを確かめる。

- SIGCHLD を無視していないこと。検査核は、子のプロセスの終わりを自分で待つ。
- 2 より上の file descriptor が、すべて close-on-exec であること。検査プロセスに余計な descriptor を渡さないため。

systemd から起動するときは、どちらも満たされる。
