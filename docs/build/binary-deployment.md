# 実行ファイルの build と配置

この文書は、今の実装を1台の Linux のホストで動かす手順を示す。設定の鍵の意味と範囲、命令、合図、記録、監視は [運用リファレンス](../operations/operator-reference.md) に書く。

ここに出てくる置き場の path（`/opt/tukuyomi-core`、`/etc/tukuyomi-core`、`/var/lib/tukuyomi-core`）と利用者の名前（`tukuyomi`）は例である。設定の path は、どれも絶対の path で書く（`.`・`..`・空の要素・末尾の `/` は断られる）。

## 動くもの

| もの | 中身 |
|---|---|
| `tukuyomi-proxy`（Rust、`proxy/`） | HTTP・HTTPS の受付と転送。検査核（`kernel/`、Rust のライブラリ）を組み込み、検査プロセスの起動・停止・再起動を受け持つ。同じ実行ファイルが、ルールの保管場所の命令（`rules`）、証明書の命令（`acme renew`）、設定の確かめ（`config check`）も持つ |
| `tukuyomi-inspector`（Go、`inspector/`） | Coraza で要求を検査する。proxy が子のプロセスとして起動し、引き継いだ Unix domain socket の対で話す。待ち受けの port は持たない |
| 設定ファイル | JSON の1つのファイル。値に既定値はない。鍵は、省けると決まったもの（`acme` など）のほかは、すべて書く |
| ルールの保管場所 | ルールセットの世代を置くディレクトリ（設定の `rules.store.dir`）。`rules import` が世代を作り、`rules activate` が使う世代を選ぶ |
| 検査プロセスの作業場所 | 起動ごとの一時のディレクトリを作る親（設定の `kernel.tmp_root`） |
| 証明書と鍵 | TLS の待ち受けのもの。`acme renew` で発行・更新するか、運用者が置く |

検査プロセスは、proxy と同じ利用者で動く。

## 要るもの

- Linux。試したのは x86_64 だけである。
- Landlock が有効な Linux。
  - 検査プロセスは、ルールを読んだ後に Landlock で自分を絞る（下の「検査プロセスの絞り」）。
  - Landlock が無い Linux では、検査プロセスは起動を断る（exit 14）。proxy も起動せず（記録は `stop: the kernel failed: Exit(14)`）、`rules import` の試しも失敗する。絞らずに動かす設定は無い。
  - 要るのは、Landlock を含む Linux 5.13 以上で、LSM の並びに `landlock` があること（`/sys/kernel/security/lsm` で分かる）。どの distribution の既定で有効かは確かめていない。
  - Linux の版によって、絞れる範囲が違う。どの版で絞ったかは、外からは見えない。
    - TCP の bind と connect まで絞るには、Linux 6.7 以上（Landlock の ABI 4 以上）が要る。それより前の版では、ファイルだけを絞って動く。
    - Linux 6.2 より前（ABI 1・2）では、ファイルの切り詰めを断れない。Linux 6.10 より前（ABI 4 まで）では、デバイスの ioctl を断れない。
- build に要るもの。
  - Rust 1.94.1 以上（`proxy/Cargo.toml` の `rust-version`）
  - C の compiler（TLS に使う aws-lc-rs が、C のコードを build する）
  - Go 1.27.2 以上（`inspector/go.mod`）
- CRS の取得に要るもの: bash、curl、sha256sum、tar。

## build

proxy は `proxy/` で build する。検査核は、そこから一緒に build される。

```bash
cd proxy && cargo build --release --locked
```

実行ファイルは `proxy/target/release/tukuyomi-proxy` にできる。

検査プロセスは、`inspector/` で cgo を使わずに build する。

```bash
cd inspector && CGO_ENABLED=0 go build -mod=readonly -o tukuyomi-inspector .
```

`CGO_ENABLED=0` は必ず付ける。

- 検査プロセスは、Landlock などの設定をすべての thread にかけるために、Go の `syscall.AllThreadsSyscall` を使う。cgo を使った実行ファイルでは、この呼び出しが `ENOTSUP` を返すため、検査プロセスは起動を断る（exit 14）。
- 断った理由の文（「cgo で build された」など）は、検査プロセスの標準出力・標準エラーには出ない。`rules import` の `the inspector said:` の行と、SIGUSR1 の切り替えが失敗したときの `reload: the inspector said:` の行にだけ出る。proxy の起動では、`stop: the kernel failed: Exit(14)` の行だけが出る。

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

置き場の例を次に示す。

| 例 | 設定の鍵 | 持ち主と権限 |
|---|---|---|
| `/opt/tukuyomi-core/bin/tukuyomi-proxy`、`/opt/tukuyomi-core/bin/tukuyomi-inspector` | `kernel.inspector`（検査プロセスの方） | root。サービスの利用者が書き換えられない所に置く |
| `/etc/tukuyomi-core/config.json` | （起動の引数） | root。サービスの利用者が読めること。大きさは 256 KiB まで |
| `/var/lib/tukuyomi-core/store` | `rules.store.dir` | サービスの利用者。権限は 0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root` | サービスの利用者。権限は 0700。setgid は付けない |
| `/var/lib/tukuyomi-core/tls/` | 証明書の `cert_file`・`key_file` | サービスの利用者（`acme renew` が書く） |
| `/var/lib/tukuyomi-core/acme/account.key` | `acme.account_key_file` | `acme renew` が初めての実行のときに作る（0600） |
| `/var/lib/tukuyomi-core/challenges` | `acme.challenge_dir` | サービスの利用者 |

- 上の表のディレクトリは、先に作っておく。proxy も命令も、これらは作らない。保管場所の中のもの（`generations/`、`staging/`、`using/` など）は、命令と proxy が作る。
- 保管場所と作業場所は、本物のディレクトリ（link ではない）で、持ち主がプロセスの利用者で、group と other の権限が無いことを確かめる。確かめる時が違う。
  - 保管場所は、proxy の起動、`config check`、`rules` の命令で確かめる。違えば exit 1 で断る。
  - 作業場所は、検査プロセスを起動するたびに確かめる（proxy の起動、検査プロセスの起動し直し、SIGUSR1 の切り替え、`rules import` の試し）。違えば検査プロセスを起動しない。proxy の起動では exit 1 で終わり、SIGUSR1 の切り替えでは今の世代が動き続け、起動し直しでは proxy が止まる。
  - `config check` と `acme renew` は、作業場所を確かめない。
- 上の2つの親のディレクトリは確かめない。ほかの利用者が中の名前を作ったり差し替えたりできないようにするのは、運用者の受け持ちである。
- 作業場所に setgid が付いていると、中に作るディレクトリがその印を受け継いで権限の確かめに落ち、検査プロセスが起動できない。
- `acme renew` は、証明書・鍵・challenge のファイルを、それぞれの置き場のディレクトリに一時のファイルとして書いてから置き換える。サービスの利用者が、これらのディレクトリに書けること。
- 設定ファイルが読めない利用者で命令を流すと、設定の段で断られる。保管場所の持ち主と違う利用者で流すと、保管場所の段で断られる。

## 初めて起動する手順

1. 設定ファイルを書く。鍵の一覧と例は [運用リファレンス](../operations/operator-reference.md) にある。
2. CRS を取得する（上の「CRS の取得」）。
3. ルールセットを取り込む。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0 --detect-only
   ```

   - 取り込みでは、検査プロセスを1つ起動して決まった要求を3つ検査する（試し）。試しに通ったときだけ世代になり、標準出力に `<指紋> created` が出る。同じ中身の世代が既にあれば `already exists` が出る。
   - `--detect-only` を付けると、検知だけの世代になる。規則に当たった要求も通して、記録に残す。最初はこの形で動かし、誤検知を見てから遮断の世代に替えるとよい。
   - 遮断の世代では、試しの要求が1つでも遮断されると、試しに落ちて世代にならない。`crs-setup.conf` を強めたときなどは、記録を見て直すか、`--accept-block` を付ける。
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
ExecReload=/bin/kill -USR2 $MAINPID
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
- 記録は journal に入る。保存の期間と容量は、journald の設定（`/etc/systemd/journald.conf` の `SystemMaxUse`、`MaxRetentionSec` など）で決める。記録には client の address と path が入るので、journal を読める組（Ubuntu では `adm`・`systemd-journal`）に入れる利用者を絞る。記録の形は [運用リファレンス](../operations/operator-reference.md) の「記録」にある。
- 監視の待ち受け（設定の `status`）を置くと、同じ host の監視の program から `/healthz`・`/readyz`・`/metrics` を引ける。ロードバランサーの準備の確かめには `/readyz` を使う。
- 合図は proxy の主プロセスだけに送る（`ExecReload` の `$MAINPID`、または `systemctl kill --kill-whom=main`）。
  - `--kill-whom=main` を付けない `systemctl kill` は、検査プロセスにも合図を送る。
  - 検査プロセスは、SIGUSR1・SIGUSR2 は無視するが、SIGTERM・SIGINT・SIGHUP が届くと終わる。
- proxy は、SIGHUP でも止まる（読み直しではない）。
- `systemctl reload` は SIGUSR2 を送り、証明書と鍵を読み直す。
- ルールセットの世代の切り替え（SIGUSR1）は、次のように送る。

  ```bash
  systemctl kill -s SIGUSR1 --kill-whom=main tukuyomi-core.service
  ```

- port 80・443 で待ち受けるには `CAP_NET_BIND_SERVICE` が要る。ambient の capability は検査プロセスにも受け継がれるが、検査プロセスは起動のときにすべての capability を捨てる。
- `LimitNOFILE` は、受ける接続（`max_conns`）と上流への接続の数を足したより大きくする。接続ごとに file descriptor を使う。
- 設定の誤りなどで起動が断られると、`Restart=on-failure` により `RestartSec` ごとに起動し直す。設定を変える前に `config check` で確かめる。

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
ExecStartPost=+/bin/systemctl reload tukuyomi-core.service
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

- 命令の後の `systemctl reload` で、proxy が新しい証明書を読む。動いている proxy は、命令が証明書を書いたことに気づかない。
- `ExecStartPost` の先頭の `+` は、reload を root で流すための印である。命令そのものはサービスの利用者で流れる。
- 証明書の1つでも `failed` だと、命令は exit 1 で終わり、`ExecStartPost` は流れない。そのときは、ほかに更新できた証明書も、次に reload するまで使われない。
- 同じ設定で `acme renew` を2つ同時に流してはいけない。止める仕組みが無い。systemd の timer は重ならないが、cron などで流すときは重ならないようにする。
- 初めての発行の手順は [運用リファレンス](../operations/operator-reference.md) の「ACME」にある。

## 検査プロセスの絞り

検査プロセスは、起動のときに次のとおり自分を絞る。どれもプロセスの全部の thread に、元に戻せない形でかける。

1. ルールセットの世代を読む（この後はファイルを読まない）。読めなければ exit 11 で断る。
2. Landlock の規則を組む。
   - 起動ごとの一時のディレクトリ（作業場所の中に作る）の外のファイルに触れなくする。作業場所の中のほかのディレクトリにも触れない。
   - 一時のディレクトリの中で許すのは、ファイルを作る・書く・読む・切り詰める・消すことだけである。ディレクトリを作る・一覧する、そこから外への名前の変更、プログラムの実行はできない。
   - Linux 6.7 以上（ABI 4 以上）では、TCP の bind と connect も断る。
3. capability を捨てる（ambient を空にし、effective・permitted・inheritable を 0 にする）。
4. `no_new_privs` を付ける。
5. 最後に Landlock をかける。この時から 2 の制限が効く。

2 から 5 のどれかが失敗したら、検査プロセスは起動を断る（exit 14）。この後で、ルールを Coraza で確かめて組み、要求を受け始める。ルールの確かめや組み立てに失敗したときは exit 11 で断る。

絞れないものもある。

- Landlock は、UDP、unix の socket、MPTCP の socket（`IPPROTO_MPTCP` で作るもの）を絞らない。そのため検査プロセスは、これらで外へ送ることや、1024 以上の port で待ち受けることがまだできる。
- MPTCP を使わないホストでは、`net.mptcp.enabled=0` にすれば MPTCP の socket は作れなくなる。
- 1024 未満の port は、capability を捨てるので取れない（Linux の `net.ipv4.ip_unprivileged_port_start` が既定の 1024 のとき）。

proxy の側は、絞りをかけない。proxy は設定・保管場所・証明書と鍵を読み、待ち受けと上流への接続を持つ。

## 起動の前の確かめ

proxy の起動と `rules import`（試しで検査プロセスを起動する）は、`/proc` を読んで次も確かめる。違えば断る。`config check` とほかの命令は、root でないことだけを確かめる。

- SIGCHLD を無視していないこと。検査核は、子のプロセスの終わりを自分で待つ。
- 2 より上の file descriptor が、すべて close-on-exec であること。検査プロセスに余計な descriptor を渡さないため。

systemd から起動するときは、どちらも満たされる。
