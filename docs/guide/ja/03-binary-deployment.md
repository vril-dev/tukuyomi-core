# 第3章　systemd での配置

第2章では端末から手で起動しましたが、本章では、tukuyomi core を 1 台の Linux ホストで systemd のサービスとして動かし続けるための配置を説明します。
最初の起動の手順は、第2章を参照してください。

この章で分かるのは、次のことです。

- 必要な環境と、実行ファイルの置き場
- OS ユーザーとディレクトリ
- 4 種類のユニット（プロキシ、管理プロセス、ログ送信プロセス、証明書の更新のタイマー）
- 起動前の検証
- `systemctl reload` とシグナルの送り方
- 検査プロセスの権限の制限

## 3.1　配置の全体像

tukuyomi core は、役割の違う複数のプロセスで動きます。
systemd では、プロキシ、管理プロセス、ログ送信プロセスをそれぞれ別のユニットで動かします。
検査プロセスはプロキシが子プロセスとして起動するため、ユニットはありません。

| 構成要素 | 実行ファイル | 必要なとき |
|---|---|---|
| プロキシ | `tukuyomi-proxy` | 常に |
| 検査プロセス（Coraza） | `tukuyomi-inspector` | 設定の `kernel.inspector` に指定します。省略できない設定キーなので、ModSecurity の世代だけを使うホストでも書きます |
| 検査プロセス（ModSecurity） | `tukuyomi-inspector-modsecurity` | ModSecurity の世代を使うとき、またはデフォルトのエンジンかアップストリームのエンジンに `modsecurity` を指定するとき |
| 管理プロセス | `tukuyomi-proxy admin <config>` | 管理 API と管理画面を使うとき |
| ログ送信プロセス | `tukuyomi-records-ship` | ログを PostgreSQL か MySQL へ送るとき |

- プロキシ、管理プロセス、ログ送信プロセスは、同じ設定ファイル（JSON のファイル 1 つ）を読みます。
  どのプロセスも同じ OS ユーザーで動かし、検査プロセスもプロキシと同じ OS ユーザーで動きます。
- 管理プロセスの実行ファイルは、プロキシと同じ `tukuyomi-proxy` です。
- 構成要素の役割は、第1章を参照してください。

## 3.2　必要な環境

必要な環境は次のとおりです。

- **Linux**: 動作を確認しているのは x86_64 だけです。
- **Landlock が有効な Linux**: 検査プロセスはルールを読んだ後に、Landlock で自身の権限を制限します（3.8 を参照してください）。
  - Landlock が無い Linux では、検査プロセスは起動しません（exit 14）。
    プロキシも起動せず、ログには `stop: the kernel failed: Exit(14)` が出ます。
    `rules import` の事前検証も、管理プロセスのインポートの事前検証も失敗します。
    制限をかけずに動かす設定はありません。
  - Linux 5.13 以上で、LSM の一覧に `landlock` が入っている必要があります。一覧は `/sys/kernel/security/lsm` で確認できます。
    どのディストリビューションが Landlock をデフォルトで有効にしているかは、確認していません。
  - 制限できる範囲は Linux のバージョンによって違います。
    TCP のバインドと接続まで制限するには、Linux 6.7 以上（Landlock の ABI 4 以上）が必要です。
    それより前のバージョンでは、ファイルだけを制限して動きます。
- **glibc と libstdc++**: リリースの実行ファイルを使う場合は、glibc 2.39 以上が必要です。
  ModSecurity の検査プロセスには、さらに libstdc++ の `GLIBCXX_3.4.29` と `CXXABI_1.3.15` のシンボルが必要です。
  これより古い Linux では、ソースからビルドします。
- **ModSecurity の検査プロセスが使う共有ライブラリ**: 動かすホストに必要なのは、libstdc++、libgcc_s、libc、libm だけです。
  libmodsecurity、YAJL、PCRE2 は、実行ファイルに静的リンクしてあります。
- **プロセスの数とメモリ**: 常時動くのは、プロキシ 1 つと、起動したエンジンごとの検査プロセス 1 つずつです。
  世代を切り替えている間と、インポートの事前検証の間は、検査プロセスが増えます。
  メモリの目安は、付録A 運用リファレンスの「検査エンジンの選択」を参照してください。
- **ログを DB へ送る場合の DB とファイルシステム**: PostgreSQL か MySQL のサーバーが必要です。動作を確認しているのは PostgreSQL 16・18 と MySQL 8.0 です。
  ログのディレクトリのファイルシステムが、ファイルの作成時刻（`statx` の btime）を返すことも必要です。動作を確認しているのは ext4 だけです。
- **ソースからビルドする場合**: 必要なもの（Rust、C コンパイラ、Go など）は、リポジトリのドキュメント「ビルドと配置」（`docs/build/binary-deployment.ja.md`）の「必要な環境」にあります。
  ドキュメントは `docs/` にあり、英語は `foo.md`、日本語は `foo.ja.md` です。

## 3.3　実行ファイルの置き場

リリースの tarball のダウンロード、SHA-256 の確認、展開、実行ファイルの置き方は、第2章の 2.3 を参照してください。
CRS（OWASP Core Rule Set）は同梱していないので、第2章の 2.6 の手順でダウンロードします。
ここでは、運用で決めることを示します。

- 実行ファイルは所有者を root にして、サービスの OS ユーザーが書き換えられない場所に置きます。たとえば、`/opt/tukuyomi-core/bin/` です。
  ModSecurity の検査プロセス（`tukuyomi-inspector-modsecurity`）とログ送信プロセス（`tukuyomi-records-ship`）を使うときは、同じ場所へ置きます。
- 実行ファイルは、Ubuntu 26.04.1 LTS（glibc 2.43、gcc 15.2.0）で、`rustc` 1.94.1 と Go 1.27.2 を使ってビルドしたものです。
  動作を確認したのは、ビルドしたホストだけです。
- 検査プロセス（`tukuyomi-inspector`）と TLS のライブラリ（aws-lc）は、静的リンクしてあります。
- ソースからビルドする手順は、「ビルドと配置」の「ソースからのビルド」を参照してください。
  検査プロセスは必ず `CGO_ENABLED=0` でビルドします。
  ModSecurity の検査プロセスは、ビルドに使うコンパイラのバージョンも決まっています。
- CRS はサービスの OS ユーザーでダウンロードします。
  root でダウンロードすると、サービスの OS ユーザーで実行する `rules import` がファイルを読めません。

## 3.4　OS ユーザーとディレクトリ

### OS ユーザー

プロキシは root では動きません。
プロセスの 4 つのユーザー ID（real、effective、saved、file system）のどれかが 0 なら、起動もすべてのコマンドも拒否します。
そのときは `host check refused` の行を出して、exit 1 で終わります。

- 専用の OS ユーザーを作り、サービスもコマンドもその OS ユーザーで実行します。たとえば、`sudo -u tukuyomi tukuyomi-proxy ...` とします。
- 管理プロセス（`admin`）と、その短時間で終わるコマンド（`admin bootstrap`・`admin reset`）も、同じ OS ユーザーで実行します。
  ルールストア、ログのディレクトリ、制御ソケット、managed ストアは、その OS ユーザーだけが使える（0700）ためです。
  別の OS ユーザーで動かすと、どれも使えません。
- ログ送信プロセスも、同じ OS ユーザーで動かします。
  ログのディレクトリを読み、そこに `ship.state` を書くためです。
  ログ送信プロセスも root では動きません。
- `acme renew` も、root で実行すると拒否します。
  root で作った鍵は、別の OS ユーザーで動くプロキシが読めないためです。

### ディレクトリとファイル

ディレクトリとファイルの例を次の表に示します。

| 例 | 設定キー | 所有者と権限 |
|---|---|---|
| `/opt/tukuyomi-core/bin/` の実行ファイル | `kernel.inspector`、`kernel.engines.modsecurity.inspector`（省略できます） | root。サービスの OS ユーザーが書き換えられない場所 |
| `/etc/tukuyomi-core/config.json` | （起動の引数） | root。サービスの OS ユーザーが読めること。256 KiB まで |
| `/var/lib/tukuyomi-core/store` | `rules.store.dir` | サービスの OS ユーザー。0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root` | サービスの OS ユーザー。0700。setgid は付けません |
| `/var/lib/tukuyomi-core/managed` | `managed.dir`（managed 設定を使う場合） | サービスの OS ユーザー。0700 |
| `/var/lib/tukuyomi-core/tls/` | `cert_file`・`key_file` | サービスの OS ユーザー（`acme renew` が書きます） |
| `/var/lib/tukuyomi-core/acme/account.key` | `acme.account_key_file` | `acme renew` が初回の実行時に作ります（0600） |
| `/var/lib/tukuyomi-core/challenges` | `acme.challenge_dir` | サービスの OS ユーザー。チャレンジ専用のディレクトリ |
| `/var/lib/tukuyomi-core/records` | `records.dir` | サービスの OS ユーザー。0700 |
| `/etc/tukuyomi-core/records-db.dsn` | `records.ship.db_dsn_file`（ログ送信プロセスを使う場合） | サービスの OS ユーザー。0600。root を所有者にしません |
| `/var/lib/tukuyomi-core/admin` | `admin.store.dir` | サービスの OS ユーザー。0700 |
| `/var/lib/tukuyomi-core/control` | `admin.control` を置くディレクトリ | サービスの OS ユーザー。0700。ソケットのパスは 107 バイトまで |
| `/var/lib/tukuyomi-core/crs-4.23.0` | `admin.crs_dir`（管理 API で CRS をインポートする場合） | 第2章の 2.6 で作ったディレクトリ。サービスの OS ユーザーが読めること |
| `/etc/tukuyomi-core/country.mmdb` | `geo.country_db` | root。0644 |

パスと OS ユーザーの名前は例です。
設定に書くパスはどれも絶対パスにします。

- 表のディレクトリは、プロキシもコマンドも自動では作りません。先に作っておきます。
  ディレクトリの中身は、それぞれ次のものが作ります。
  - ルールストアの中の `generations/`・`staging/`・`using/` など: コマンドとプロキシ
  - ログファイルと制御ソケット: プロキシ
  - 管理データの保存先の中身: 管理プロセス
- ルールストア、ログのディレクトリ、管理データの保存先、制御ソケットを置くディレクトリ、managed ストア、`challenge_dir` は、別々のディレクトリにします。
  同じディレクトリにした設定も、互いの中に置いた設定も受け付けません。
  重なりは書いたままのパスで比べます。シンボリックリンクは使わないでください。
- ルールストア、作業ディレクトリ、ログのディレクトリ、管理データの保存先、制御ソケットを置くディレクトリ、managed ストアは、次の条件を検証します。
  - シンボリックリンクではないこと
  - 所有者がプロセスの OS ユーザーであること
  - グループとその他のユーザーに権限が無いこと
- これらのディレクトリを検証するタイミングはそれぞれ違い、条件を満たさないときの動きも違います（プロキシの起動を拒否するもの、検査プロセスを起動しないものなど）。
  詳しくは、`docs/build/binary-deployment.ja.md` の「OS ユーザーとディレクトリ」を参照してください。
- これらのディレクトリの親ディレクトリは検証しません。
  ほかの OS ユーザーが親ディレクトリの中に名前を作ったり、置き換えたりできないようにするのは、運用者の責任です。
- 作業ディレクトリに setgid が付いていると、中に作るディレクトリがその属性を受け継いで権限の検証に失敗し、検査プロセスを起動できません。
- 設定の `kernel.inspector` は、ModSecurity の世代だけを使うホストでも書きます。
  `kernel.engines` は、ModSecurity の世代を使う場合だけ書きます（付録A 運用リファレンスの「`kernel`」）。

### 国のデータベース

国のデータベースが必要なのは、国の指定（`access` の `deny_countries`・`allow_countries`）を使う場合だけです。
データベースはプロキシに同梱しておらず、プロキシがダウンロードすることもありません。
MaxMind DB 形式（バージョン 2）のファイルを運用者が用意し、上の表のように置きます。
中身は設定の `geo.sha256` に書いた SHA-256 で検証します。
置き方、入れ替えの手順、国の判定は、第6章を参照してください。

## 3.5　systemd のユニット

第2章の初回起動では、設定ファイルを書いて CRS をダウンロードし、ルールセットをインポートして選択します。
その後、`config check` で検証してサービスを起動します。

ここでは、サービスとして動かすためのユニットを示します。
管理プロセスを使う場合は、そのユニットも起動して、最初のユーザーを作ります（第5章）。
ログを DB へ送る場合は、DB のユーザーと DB を用意し、接続文字列のファイルを置きます。
設定に `records.ship` を書いてから、ログ送信プロセスのユニットを起動します（第7章）。

ユニットの例は、プロキシ、管理プロセス、ログ送信プロセス、証明書の更新のタイマーの順に示します。
以降の説明では、プロキシのユニットの名前を `tukuyomi-core.service` とします。

### プロキシのユニット

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

- `Type=notify` にします。
  プロキシが systemd へ `READY=1` を送るのは、起動するすべてのエンジンで検査カーネルの準備ができ、すべてのリスナーをバインドした後です。
  停止の始めには `STOPPING=1` を送ります。
  `systemctl start` と、`After=` でこのユニットの後に並べたユニットは、`READY=1` が届くまで待ちます。
  `Type=simple` では、実行した時点で起動したと見なされます。
  - `TimeoutStartSec` は、アップストリームの名前解決の時間（`resolve_timeout_ms`）と、検査カーネルの準備を待つ時間（`ready_wait_ms`）の合計より長くします。
    この時間が過ぎても `READY=1` が届かないと、systemd はプロキシを停止します。
- `KillMode=mixed` にします。
  デフォルトの `control-group` では、停止の SIGTERM が検査プロセスにも届きます。
  検査プロセスは SIGTERM を処理しないので、その場で終了します。
  プロキシは残りの検査を終えて終了の通知を受ける、という順で検査プロセスを停止できなくなります。
  `mixed` では、SIGTERM はプロキシにだけ届き、プロキシが自分で検査プロセスを停止してから終了します。
- `TimeoutStopSec` は、`stop_wait_ms`、`kill_grace_ms`、ログの書き出しの 200 ms の合計より長くします。
  短いと、停止が終わる前に systemd が SIGKILL を送ります。
  停止の流れは、付録A 運用リファレンスの「停止」を参照してください。
- `LogRateLimitIntervalSec=0` を指定します。
  journald のデフォルトのレート制限のままだと、リクエストが集中したときに、リクエストのログがジャーナルに入らずに失われます。
- ログはジャーナルに入ります。設定に `records` があれば、同じログがファイルにも書かれます。
  保存期間と容量は journald の設定（`/etc/systemd/journald.conf` の `SystemMaxUse`、`MaxRetentionSec` など）で決めます。
  ログにはクライアントのアドレスとパスが入ります。
  ジャーナルを読めるグループ（Ubuntu では `adm`・`systemd-journal`）に入れる OS ユーザーは、最小限にしてください。
  ログの形式は、第7章を参照してください。
- ポート 80・443 で待ち受けるには、`CAP_NET_BIND_SERVICE` が必要です。
  ambient ケーパビリティは検査プロセスにも引き継がれますが、検査プロセスは起動時にすべてのケーパビリティを破棄します。
- `LimitNOFILE` は、受け付ける接続の数（`max_conns`）とアップストリームへの接続の数の合計より大きくします。
  接続ごとにファイルディスクリプターを使うためです。
- ログのディレクトリ、制御ソケットを置くディレクトリ、管理データの保存先、managed ストアは、`ReadWritePaths` の中に置きます（上の例では `/var/lib/tukuyomi-core` の下）。
  別の場所に置く場合は、`ReadWritePaths` に追加してください。
- 設定のエラーなどで起動が拒否されると、`Restart=on-failure` によって `RestartSec` ごとに再起動します。

### 管理プロセスのユニット

管理プロセスはプロキシとは別のユニットで動かします。
実行ファイル、設定ファイル、OS ユーザーはプロキシと同じです。

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
  監査ログは標準エラー（ジャーナル）にも出るので、journald のレート制限で失われないようにします。
- 検査プロセスの実行ファイルと作業ディレクトリは、プロキシと同じものを使います。
  インポートの事前検証で起動する検査プロセスも、プロキシの場合と同じく、Landlock で自身の権限を制限します。
- 管理プロセスは `admin.listen` のループバックアドレスで、平文の HTTP の接続を待ち受けます。
  1024 以上のポートなら、`AmbientCapabilities` は必要ありません。
- 設定ファイルは起動時に 1 回だけ読み、プロキシと違って SIGHUP でリロードしません。
  管理プロセスにとって、SIGHUP は停止のシグナルです。
  設定を変更したら、`config check` で検証してから `systemctl restart` で再起動します。`ExecReload` は置きません。
- プロキシが動作していなくても管理プロセスは起動しますが、その間は、世代の切り替えも managed 設定の反映も依頼できません。
- 外部から使う場合は、プロキシの TLS リスナーから管理プロセスへ転送します。
  ルートの書き方は、付録B 管理リファレンスの「外部からの利用」を参照してください。
  管理画面と managed 設定は第5章で説明します。

### ログ送信プロセスのユニット

ログを DB へ送る場合は、ログ送信プロセスをプロキシとは別のユニットで動かします。
設定ファイルと OS ユーザーはプロキシと同じです。

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
  DB に接続するのは `READY=1` の後です。
  DB に接続できないときは待ってから再試行するので、DB のユニットの後に並べる必要はありません。
- `TimeoutStopSec` は長めにします。
  停止のシグナルは DB の呼び出しが終わるまで処理されないため、停止までに長いと 1〜2 分かかります。
  `TimeoutStopSec` がこれより短く、SIGKILL で止められても、次の起動では続きから送ります。
  ログの行と、どこまで送ったかの位置は、同じトランザクションで DB に入るためです。
- ログのディレクトリは、`ReadWritePaths` の中に置きます。ログ送信プロセスがこのディレクトリに `ship.state` を書くためです。
- DB がログインを拒否すると、ログ送信プロセスは exit 1 で終了します。
  その後は `Restart=on-failure` によって `RestartSec` ごとに再起動し、接続文字列を直すまで、これを繰り返します。
- DB サーバーの証明書を独自の認証局で発行したときは、その認証局の証明書を入れたファイルを `Environment=SSL_CERT_FILE=<path>` で渡します。
- 設定ファイルと接続文字列のファイルは起動時に 1 回だけ読み、SIGHUP でリロードしません。
  変更したら、`systemctl restart` で再起動します。`ExecReload` は置きません。
- ログ送信プロセスはプロキシと同じ設定ファイルを読み、未知の設定キーを含む設定ファイルを受け付けません。
  設定に新しい設定キー（`managed`、`host_policies`、`kernel.default_engine`、アップストリームの `engine` など）を書く前に、ログ送信プロセスの実行ファイルをプロキシと同じビルドのものに入れ替えてください。
- プロキシが動作していなくても、ログ送信プロセスは起動し、ファイルにあるログを送ります。
- テーブルの権限、接続文字列の形式、送信の仕組みは、第7章を参照してください。

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

- コマンドが証明書を書いても、動作中のプロキシはそのことに気付きません。
  このユニットはコマンドの後に SIGUSR2 を送り、新しい証明書を読み込ませます。
  - `systemctl reload` を使わないのは、SIGHUP では設定ファイルの全体を読み込むためです。
    タイマーが動いたときに編集途中の設定を読み込まないよう、証明書と鍵だけを読み込む SIGUSR2 を送ります。
- `ExecStopPost` は、コマンドが失敗しても実行されます。
  証明書が 1 つでも `failed` になると、コマンドは exit 1 で終わります。`failed` の証明書のファイルは前のまま残ります。
  その場合も SIGUSR2 は送られるので、更新できたほかの証明書は使われ始めます。
  SIGUSR2 を受けたプロキシは、読み込んだ証明書がすべて検証に通るときだけ入れ替えるので、失敗したときに SIGUSR2 を送っても問題はありません。
- `ExecStopPost` の先頭の `+` は、`systemctl kill` を root で実行するための指定です。
  `acme renew` そのものは、サービスの OS ユーザーで実行されます。
- `acme renew` には、同時実行を防ぐ仕組みがありません。同じ設定で 2 つ同時に実行しないでください。
  systemd のタイマーは重なりませんが、cron などで実行する場合は、重ならないようにしてください。
- ACME のサイトについて、ホストの組み合わせを変更したバージョンを managed 設定で反映したときは、タイマーを待たずに `systemctl start tukuyomi-core-acme.service` でこのサービスを実行してください。
- 初回の発行の手順は、第8章を参照してください。

## 3.6　起動前の検証

起動の前に行う検証は 2 種類あります。名前が似ているので、区別してください。

### 設定の検証（`config check`）

`config check` は、起動と同じ検証で設定ファイルと選択中の世代を確認するコマンドです。
サービスの OS ユーザーで実行します。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
```

- 問題がなければ、標準出力に `accepted` が出て、exit 0 になります。
- デフォルトのエンジンの世代を選択する前に実行すると、`rules store refused: no generation is chosen` で拒否されます（exit 1）。
  アップストリームのエンジンに選択中の世代が無いときも、同じ文で拒否されます。
  設定ファイルそのものに誤りがある場合は、exit 2 になります。
- アップストリームのサーバー名と、TLS の証明書と鍵のファイルも検証します。受け付けられなかったときも exit 1 です。
  どれで拒否されたかは、行の先頭（`upstream refused`、`tls refused`）で区別できます。
- `config check` は検査プロセスを起動しないので、作業ディレクトリ、検査プロセスの実行ファイル、Landlock は検証しません。
  これらの問題は起動のときに分かります。
- ユニットの `ExecReload` も、この `config check` を使います。

詳しくは、付録A 運用リファレンスの「`config check`」を参照してください。

### 起動前の検証（SIGCHLD とファイルディスクリプター）

プロキシの起動、事前検証で検査プロセスを起動する `rules import`、管理プロセスのコマンド（`admin <config>`、`admin bootstrap`、`admin reset`）では、`/proc` を読んで次の条件も検証し、満たさなければ拒否します。

- **SIGCHLD を無視していないこと**: 検査カーネルは子プロセスの終了を自分で待ちます。
- **2 より大きいファイルディスクリプターが、すべて close-on-exec であること**: 検査プロセスに不要なディスクリプターを渡さないためです。

systemd から起動する場合は、どちらの条件も満たされます。
`config check` とほかのコマンドが検証するのは、root でないことだけです。

## 3.7　設定のリロードとシグナル

プロキシへのシグナルは、プロキシのメインプロセスにだけ送ってください。
ユニットの `ExecReload` では `$MAINPID` が、`systemctl kill` では `--kill-whom=main` が、これに当たります。
`--kill-whom=main` を付けない `systemctl kill` は、検査プロセスにもシグナルを送ってしまいます。
検査プロセスは SIGUSR1・SIGUSR2 を無視しますが、SIGTERM・SIGINT・SIGHUP が届くと終了します。

### `systemctl reload`

`systemctl reload` は、上のユニットにある 2 つの `ExecReload` を順に実行します。
SIGHUP を送るのは、`config check` が通ったときだけです。
SIGHUP を受けたプロキシは設定ファイルをリロードし、停止せずに新しい設定に切り替えます。

- `config check` が受け付けない設定では、SIGHUP は送られず、`systemctl reload` が失敗を返します。
  選択中の世代を `config check` が受け付けない間も、`systemctl reload` は拒否されます。
  なお、リロードそのものは世代に触れません。
- `config check` が通ると、`systemctl reload` は SIGHUP を送った時点で成功を返し、リロードの完了は待ちません。
  成功が返っても、設定が切り替わったとは限りません。
  次の理由で拒否するのは動作中のプロキシだけなので、この場合も `systemctl reload` は成功を返します。
  - 動作中に変更できない設定キーが変わっていること
  - アップストリームのエンジンが稼働していないこと
  - 新しいリスナーをバインドできないこと
- 結果はログの行と `/metrics` で確認します。
  ログでは、`reload: configuration replaced <sha256>` と `reload: configuration refused: <reason>` の行を見ます。
  `managed` のある設定では、前者の後に ` managed <version>` が続きます。
  `/metrics` では、`tukuyomi_config_reloads_total` を見ます。
- 設定を変更するときは、新しい設定を別の名前のファイルに書いてから、1 回の置き換えで元のファイルと差し替えます。
  次に `systemctl reload tukuyomi-core.service` を実行し、ログの行で結果を確認します。
  動作中に変更できない設定キーを変えたときは、`systemctl restart` で再起動します。
  管理プロセスとログ送信プロセスは設定をリロードしません。それらが読む設定キーを変えたら、そのプロセスを再起動します。
- 動作中に変更できる設定キーと、変更できない設定キーの一覧は、付録A 運用リファレンスの「SIGHUP（設定のリロード）」にあります。
- 0.1.0 から更新するときの順序は、第9章の 9.4 を参照してください。

### SIGUSR2 と SIGUSR1

証明書と鍵だけを再読み込みさせるときは、SIGUSR2 を次のように送ります。

```bash
systemctl kill -s SIGUSR2 --kill-whom=main tukuyomi-core.service
```

ACME の更新のタイマー（3.5）も、更新の後に同じ SIGUSR2 を送っています。

ルールの世代を切り替えるときは、SIGUSR1 を次のように送ります。

```bash
systemctl kill -s SIGUSR1 --kill-whom=main tukuyomi-core.service
```

SIGUSR1 を受けたプロキシは、エンジンを 1 つずつ順に、それぞれの選択中の世代へ切り替えます。
選択中の世代があるのに稼働していないエンジンは、このとき起動します（付録A 運用リファレンスの「SIGUSR1（世代の切り替え）」）。
世代の扱いは、第4章を参照してください。

## 3.8　検査プロセスの権限の制限

検査プロセスは起動時に次の順で自身の権限を制限します。

1. ルールの世代を読み、読めなければ exit 11 で終了します。
   別のエンジンの世代のマニフェストも読めないので、同じく exit 11 で終了します。
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
5. 最後に Landlock を有効にし、この時点から 2 の制限が効きます。

どの制限も、プロセスのすべてのスレッドに元に戻せない形でかけます。
2 から 5 のどれかが失敗すると、検査プロセスは起動しません（exit 14）。
制限をかけ終えた後に、ルールをその世代のエンジンで検証して組み立て、リクエストの受け付けを始めます。
ルールの検証や組み立てに失敗したときは、exit 11 で終了します。

一方で、制限できないものもあります。

- Landlock は UDP、Unix ドメインソケット、MPTCP のソケット（`IPPROTO_MPTCP` で作るもの）を制限しません。
  検査プロセスは制限をかけた後も、これらを使って外部へ送信したり、1024 以上のポートで待ち受けたりできます。
- MPTCP を使わないホストでは、`net.mptcp.enabled=0` にすると、MPTCP のソケットを作れなくなります。
- Linux の `net.ipv4.ip_unprivileged_port_start` がデフォルトの 1024 のときは、ケーパビリティを破棄しているので、1024 未満のポートは使えません。

プロキシにはこの制限をかけません。
プロキシは設定・ルールストア・証明書と鍵を読み、リスナーとアップストリームへの接続を持ちます。
管理プロセスも自身にはこの制限をかけず、インポートの事前検証で起動する検査プロセスだけが上の制限をかけます。

## 3.9　運用上の注意

最後に、配置と運用で気を付ける点をまとめます。

- **サービスもコマンドも、専用の OS ユーザーで実行します**: root では動きません。
  3.4 の表のディレクトリは、起動の前に作っておいてください。
- **設定を変更するときは、先に `config check` で検証します**: `systemctl reload` の成功は、設定が切り替わったことを意味しません。結果はログの行で確認してください。
- **シグナルはプロキシのメインプロセスにだけ送ります**: `systemctl kill` では、`--kill-whom=main` を付けて送ってください。
- **管理プロセスとログ送信プロセスは設定をリロードしません**: それらが読む設定キーを変えたら、再起動してください。
- **Landlock が使えない Linux では、検査プロセスもプロキシも起動しません**: 配置の前に、3.2 の条件を確認してください。
