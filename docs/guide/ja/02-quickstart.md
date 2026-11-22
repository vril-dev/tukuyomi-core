# 第2章　クイックスタート

本章では、リリースの tarball を取り、1 台の Linux ホストで手で起動して、通常のリクエストが通ることと、SQL インジェクションのリクエストがブロックされることを、ログで確かめるところまでを通して試します。systemd を使った本番向けの配置は第3章で扱うので、ここでは、手で起動して動作を確かめるところに絞ります。

## 2.1　この章で用意するもの

この章で作る構成は、次のとおりです。

- `curl` のリクエストを、プロキシ（`tukuyomi-proxy`。`127.0.0.1:8000`）が受けます。
- プロキシは、子プロセスとして起動する検査プロセス（Coraza）で、リクエストを検査します。
- ブロックしなかったリクエストを、アップストリームのアプリケーション（`127.0.0.1:8080`）へ転送します。

次のものを用意してください。

- **Linux x86_64 のホスト。** 動作を確認しているのは Landlock が有効な Linux x86_64 だけです。Linux 5.13 以上で、LSM の一覧に `landlock` が含まれている必要があります（`/sys/kernel/security/lsm` で確認できます）。glibc は 2.39 以上が必要です。
- **bash、curl、sha256sum、tar。** CRS の取得に使います。
- **root の権限（`sudo`）。** OS ユーザーとディレクトリの作成と、実行ファイルの配置に使います。tukuyomi core 自身は root では動きません。
- **`127.0.0.1:8080` で HTTP に応答するアプリケーション。** プロキシの転送先（アップストリーム）です。手元にある Web アプリケーションでも、試験用の HTTP サーバーでもかまいません。本書では、これを用意する手順は扱いません。

リリースの実行ファイルは、Ubuntu 26.04.1 LTS（glibc 2.43）でビルドしたもので、動作を確認したのは、ビルドしたホストだけです。古い Linux で動かないときは、ソースからビルドします（リポジトリのドキュメントの「ビルドと配置」の「ソースからのビルド」を参照してください。`docs/build/binary-deployment.ja.md` です）。

## 2.2　手順の流れと仕組み

手順は、次の順に進みます。

1. 実行ファイルを置きます（2.3）。tarball の SHA-256 を確かめてから展開します。
2. OS ユーザーとディレクトリを用意します（2.4）。プロキシは root では動きません。また、設定が指すディレクトリは、プロキシもコマンドも作らないので、先に作っておきます。
3. 設定ファイルを書きます（2.5）。設定の値にデフォルトはないので、必要な設定キーをすべて書きます。
4. CRS を取得します（2.6）。CRS は同梱していません。バージョンとチェックサムを固定したスクリプトで取得します。
5. ルールセットをインポートし、世代として選択します（2.7）。インポートは、ルールセットを検査プロセスで試して（事前検証）、通ったものを世代にします。選択した世代を、起動するプロキシが使います。選択中の世代が無いと、プロキシは起動しません。
6. 設定を検証して、起動します（2.8）。
7. リクエストを送り、ログで確かめます（2.9）。

インポートと選択は、プロキシとは別のコマンドで、動作中のプロキシは、その変更を検知しません。この章は、プロキシを起動する前にすべて済ませます。動作中のプロキシに新しい世代を使わせる方法は、第4章で扱います。

## 2.3　tarball を取り、実行ファイルを置く

リリースの tarball は、GitHub のリリース（<https://github.com/vril-dev/tukuyomi-core/releases>）で配布しています。次の 2 つのファイルを取得します。

- `tukuyomi-core_v0.2.0_linux_amd64.tar.gz`
- `tukuyomi-core_v0.2.0_linux_amd64.tar.gz.sha256`

作業用のディレクトリは、後で `sudo -u tukuyomi` から、展開したスクリプトを実行するので、OS ユーザー `tukuyomi` が読める場所に作ります。ほかのユーザーが先に同じ名前で作れないように、`mktemp -d` で名前を決め、`tukuyomi` が読めるよう 0755 にします。

```bash
d=$(mktemp -d /tmp/tukuyomi-core.XXXXXX) && chmod 0755 "$d" && cd "$d"
```

取得した 2 つのファイルは、このディレクトリに置きます。

ダウンロードしたら、展開する前に SHA-256 を確かめます。

```bash
sha256sum -c tukuyomi-core_v0.2.0_linux_amd64.tar.gz.sha256
tar -xzf tukuyomi-core_v0.2.0_linux_amd64.tar.gz
```

展開すると、ディレクトリ `tukuyomi-core_v0.2.0_linux_amd64/` の中に、4 つの実行ファイルと、`scripts/fetch-crs.sh` などができます。実行ファイルは、サービスの OS ユーザーが書き換えられない場所（所有者は root）に置きます。この章で使うのは、プロキシと、Coraza の検査プロセスの 2 つです。ModSecurity の検査プロセス（`tukuyomi-inspector-modsecurity`）とログ送信プロセス（`tukuyomi-records-ship`）は、使うときに同じ場所へ置きます（第3章）。

```bash
sudo install -d -m 0755 /opt/tukuyomi-core/bin
sudo install -m 0755 tukuyomi-core_v0.2.0_linux_amd64/tukuyomi-proxy \
  tukuyomi-core_v0.2.0_linux_amd64/tukuyomi-inspector /opt/tukuyomi-core/bin/
```

## 2.4　OS ユーザーとディレクトリを用意する

サービスもコマンドも、専用の OS ユーザー `tukuyomi` で実行します。この章の設定ファイルが使うディレクトリは、次のとおりです。

| ディレクトリ | 設定キー | 所有者と権限 |
|---|---|---|
| `/var/lib/tukuyomi-core/store` | `rules.store.dir`（ルールストア） | `tukuyomi`、0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root`（検査プロセスの作業ディレクトリ） | `tukuyomi`、0700。setgid は付けません |
| `/var/lib/tukuyomi-core/records` | `records.dir`（ログのディレクトリ） | `tukuyomi`、0700 |

3 つとも、シンボリックリンクでないディレクトリで、所有者がサービスの OS ユーザーで、グループとその他のユーザーの権限が無いことを、プロキシが検証します。互いに別のディレクトリにします。CRS の取得先（`/var/lib/tukuyomi-core/crs-4.23.0`）は、取得スクリプトが親のディレクトリの中に作るので、親のディレクトリ `/var/lib/tukuyomi-core` を `tukuyomi` が書き込める形にしておきます。

```bash
sudo useradd --system --user-group --home-dir /var/lib/tukuyomi-core --no-create-home --shell /usr/sbin/nologin tukuyomi
sudo install -d -o tukuyomi -g tukuyomi -m 0750 /var/lib/tukuyomi-core
sudo install -d -o tukuyomi -g tukuyomi -m 0700 /var/lib/tukuyomi-core/store /var/lib/tukuyomi-core/tmp /var/lib/tukuyomi-core/records
```

## 2.5　設定ファイルを書く

設定ファイルは、`/etc/tukuyomi-core/config.json` に置きます。所有者は root で、サービスの OS ユーザーが読める権限にします。

```bash
sudo install -d -m 0755 /etc/tukuyomi-core
```

次の内容で、`/etc/tukuyomi-core/config.json` を作ります。付録A 運用リファレンスの「設定ファイル」の「例」から、手で起動して試すのに要らない部分を除いたものです。

- リスナーは、平文の HTTP の 1 つだけにしました（`127.0.0.1:8000`）。例の 80 番と 443 番は、`CAP_NET_BIND_SERVICE` の無い OS ユーザーでは待ち受けられません。TLS の証明書も、まだありません。
- 例に入っていた省ける設定キーのうち、`acme` と `rate_limit` は除きました。`records` は、ログをファイルで確かめるために残しました。
- それ以外は、例の値のままです。値は動かすときの目安で、受け付ける範囲は、付録A 運用リファレンスの「設定ファイル」の表にあります。

```json
{
  "proxy": {
    "listeners": [
      {"address": "127.0.0.1:8000"}
    ],
    "max_conns": 256,
    "max_head_bytes": 8192,
    "max_body": 104857600,
    "inspect_body": 16384,
    "max_body_wire": 209715200,
    "max_buffered_bytes": 33554432,
    "upstream_max_headers": 100,
    "upstream_max_head_bytes": 16384,
    "upstream_head_wire": 65536,
    "drive_slice_ms": 1,
    "ready_wait_ms": 30000,
    "head_read_ms": 10000,
    "body_read_ms": 10000,
    "inspect_wait_ms": 55000,
    "upstream_connect_ms": 2000,
    "upstream_header_ms": 30000,
    "request_total_ms": 60000,
    "response_idle_ms": 30000,
    "conn_total_ms": 3700000,
    "stop_inspect_ms": 10000,
    "stop_wait_ms": 20000,
    "keepalive_timeout_ms": 15000,
    "keepalive_requests": 1000,
    "keepalive_time_ms": 3600000,
    "lingering_time_ms": 30000,
    "lingering_timeout_ms": 5000,
    "lingering_bytes": 262144,
    "trusted_proxies": [],
    "upstream_keepalive": 32,
    "upstream_keepalive_timeout_ms": 30000,
    "upstream_keepalive_requests": 1000
  },
  "forward": {
    "resolve_timeout_ms": 5000,
    "upstreams": {
      "app": {
        "servers": [
          {"address": "127.0.0.1:8080", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}
        ]
      }
    },
    "routes": [],
    "default_upstream": "app"
  },
  "kernel": {
    "inspector": "/opt/tukuyomi-core/bin/tukuyomi-inspector",
    "tmp_root": "/var/lib/tukuyomi-core/tmp",
    "gomaxprocs": 1,
    "gomemlimit": 268435456,
    "slots": 2,
    "wait_queue": 16,
    "records": 64,
    "discard_limit": 8,
    "tick_ms": 20,
    "hello_wait_ms": 20000,
    "frame_io_ms": 1000,
    "verdict_wait_ms": 3000,
    "wait_deadline_ms": 5000,
    "closed_wait_ms": 3000,
    "stop_after_ms": 5000,
    "drain_wait_ms": 3000,
    "exit_wait_ms": 3000,
    "kill_grace_ms": 2000,
    "restarts": 3,
    "restart_window_ms": 60000
  },
  "rules": {
    "store": {"kind": "file", "dir": "/var/lib/tukuyomi-core/store"}
  },
  "records": {
    "dir": "/var/lib/tukuyomi-core/records",
    "file_bytes": 16777216,
    "files": 8
  }
}
```

読み方の要点は次のとおりです。

- `forward.upstreams.app` が、転送先のアプリケーションです。`routes` が空で `default_upstream` が `app` なので、どのリクエストも、行き先のアップストリームは `app` になります（ブロックされたリクエストは転送しません）。
- `kernel.inspector` は、Coraza の検査プロセスの実行ファイルです。ModSecurity の世代だけを使うホストでも省けない設定キーです。
- アップストリームのサーバーのアドレスに、リスナーのアドレスは書けません（受け付けません）。リスナーとアップストリームは、ポートを変えてあります。
- `records` があると、標準エラーに出すログの行を、`records.dir` のファイル `records.log` にも書きます。起動の最初の行のうち、ログファイルを開く前に出る行（`start: configuration accepted` や `start: rules …` の行）は、標準エラーだけに出ます。

設定そのもののエラーは、CRS の取得の前に `config check` で分かります。この時点では世代を選択していないので、受け付けられた設定でも、`config check: rules store refused: no generation is chosen` の行を出して exit 1 になります。設定そのもののエラーは exit 2 です。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
```

## 2.6　CRS を取得する

CRS（OWASP Core Rule Set）は、同梱していません。展開したディレクトリの `scripts/fetch-crs.sh` で取得します。次のコマンドは、2.3 で `cd` した作業用のディレクトリで実行します。**サービスの OS ユーザーで実行してください。** root で実行すると、できたファイルを `tukuyomi` の `rules import` が読めません。

```bash
sudo -u tukuyomi tukuyomi-core_v0.2.0_linux_amd64/scripts/fetch-crs.sh /var/lib/tukuyomi-core/crs-4.23.0
```

- 取得するバージョン（4.23.0）と、配布アーカイブの SHA-256 は、スクリプトの中に固定してあります。引数では変えられません。アーカイブは https でだけ取得し、固定した SHA-256 と一致してから、中身を読みます。
- 引数のディレクトリは、まだ存在しない新しいディレクトリです。既にあるディレクトリには触れません。途中で失敗したときは、何も残りません。
- 新しいディレクトリには、`crs-setup.conf`、`crs-setup.conf.example`、`rules/*.conf`、`rules/*.data` の 4 つだけが入ります。`crs-setup.conf` は、インポートの前に編集できます（第4章）。この章では、そのまま使います。
- GitHub に接続できないホストでは、固定したアーカイブの写しを、環境変数 `FETCH_CRS_ARCHIVE_FILE` で渡せます。その場合も、SHA-256 などの検証は同じです。
- `Permission denied` になるときは、展開したディレクトリと、そこまでの親のディレクトリを `tukuyomi` が読める権限にしてください。

## 2.7　最初の世代をインポートして選択する

取得した CRS を、ルールセットの世代としてインポートします。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0
```

- インポートでは、検査プロセスを 1 つ起動し、決まったリクエストを 3 つ検査します（事前検証）。通ったときだけ世代になり、標準出力に `<fingerprint> created` が出ます。`<fingerprint>` は世代のフィンガープリント（64 桁の 16 進数）です。同じ内容の世代が既にあれば、`already exists` が出ます。
- **この章では、ブロックする世代（遮断の世代）にします。** SQL インジェクションがブロックされることを確かめるためです。本番での最初のインポートは、`--detect-only` を付けた検知のみの世代にして、誤検知を確認してから遮断の世代に切り替えることを、ドキュメントはおすすめしています（第4章）。
- 遮断の世代では、事前検証のリクエストが 1 つでもブロックされると、事前検証に失敗し、世代になりません。`crs-setup.conf` の設定を厳しくした場合などは、ログを見て修正するか、`--accept-block` を付けてください。
- インポートのオプションは、付録A 運用リファレンスの「`rules`」を参照してください。

インポートした世代を選択します。`<fingerprint>` は、上で出た値です。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules activate /etc/tukuyomi-core/config.json <fingerprint>
```

成功すると、`<fingerprint> current` が出ます。世代の一覧は、`rules list` で見られます。

世代は、エンジンごとに選択します。最初に選択するのは、デフォルトのエンジン（`kernel.default_engine` を書かなければ `coraza`）の世代です。デフォルトのエンジンに選択中の世代が無いと、プロキシは起動しません。

## 2.8　設定を検証して起動する

起動の前に、設定を検証します。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
```

通れば、標準出力に `accepted` が出て、exit 0 になります。`config check` は検査プロセスを起動しないので、作業ディレクトリ、検査プロセスの実行ファイル、Landlock は検証しません。これらの問題は、次の起動で分かります。

続けて、プロキシを起動します。この章では、systemd を使わずに、端末の前面で動かします。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy /etc/tukuyomi-core/config.json
```

ログは、標準エラーに 1 行 1 件の JSON で出ます。準備ができると `start: the kernel is ready`、リスナーが待ち受けを始めると `start: listening` の行が出ます（`type` が `line` のログです）。`start: listening` が出たら、起動は完了です。この端末は、そのままにしておきます。以降のコマンドは、別の端末で実行します。

## 2.9　リクエストを送り、ログで確かめる

別の端末で、2 つのリクエストを送ります。`-H 'Host: example.com'` で、`Host` ヘッダーに名前を指定します。

通常のリクエストです。

```bash
curl -i -H 'Host: example.com' http://127.0.0.1:8000/
```

アップストリームの応答が返ります。応答のヘッダーには、プロキシが付ける `X-Request-ID` が入ります。

SQL インジェクションのリクエストです。クエリは `id=1' OR '1'='1` を URL エンコードしたものです。

```bash
curl -i -H 'Host: example.com' 'http://127.0.0.1:8000/item?id=1%27%20OR%20%271%27%3D%271'
```

こちらは、プロキシが 403 で応答します。ボディは空です。アップストリームには転送されないので、アップストリームのアクセスログにも出ません。

結果は、ログファイルで確かめます。ログファイルは、`tukuyomi` と root だけが読めます。

```bash
sudo -u tukuyomi grep '"type":"request"' /var/lib/tukuyomi-core/records/records.log
```

リクエストのログは、1 件が 1 行の JSON です。見る項目は次のとおりです。

| 項目 | 通常のリクエスト | SQL インジェクションのリクエスト |
|---|---|---|
| `class` | `forwarded` | `blocked` |
| `reason` | `forwarded` | `blocked by a rule` |
| `status` | アップストリームが返したステータスコード | 403 |
| `mode`、`engine` | `block`、`coraza` | `block`、`coraza` |
| `rule` | ルールに一致しなければ、ありません | ブロックしたルールの ID |

- `generation` は、世代のフィンガープリントの先頭 16 桁です。2.7 で選択した世代のものと同じになります。
- クエリは、ログに記録しません。2 つのリクエストは、`path` と、応答の `X-Request-ID` の値と同じ `id` で見分けます。
- ログの項目の全体は、付録A 運用リファレンスの「リクエストのログ（`request`）」を参照してください。

検知のみの世代でインポートしていた場合は、SQL インジェクションのリクエストもアップストリームへ転送されます。ログは `class` が `forwarded`、`reason` が `detected by a rule` になり、`rule` に一致したルールの ID が入ります（付録A 運用リファレンスの「検知のみのモード」）。

## 2.10　停止する

別の端末から、プロキシのメインプロセスに SIGTERM を送ります。シグナルは、プロキシのメインプロセスだけに送ります（付録A 運用リファレンスの「シグナル」）。検査プロセスは、SIGTERM・SIGINT・SIGHUP が届くと終了するので、プロキシの PID を指定して送ります。

```bash
sudo kill -TERM $(pgrep -u tukuyomi -x tukuyomi-proxy)
```

プロキシは、新しい接続とリクエストの受け付けを止め、処理中のリクエストを処理してから、検査プロセスを停止して終了します。ログの最後に `stop: kernel ...` で始まる行が出て、終了コードは、検査プロセスの終了と作業ディレクトリの削除まで確認できたときだけ 0 になります。停止の流れは、付録A 運用リファレンスの「停止」を参照してください。

## 2.11　うまくいかないとき

| 症状 | 原因と対処 |
|---|---|
| `host check refused` の行が出て、exit 1 になる | root で実行しています。`sudo -u tukuyomi` で、サービスの OS ユーザーとして実行してください |
| `config check` が exit 2 になる | 設定ファイルを受け付けていません。範囲や関係のエラーは、違反した設定キーの名前が出ます（例: `max_conns is out of range`）。形のエラー（JSON でない、未知の設定キー、型の違い）は、どの設定キーかは示しません |
| `config check` やプロキシの起動が `rules store refused: no generation is chosen` で exit 1 になる | デフォルトのエンジンの世代を選択していません。2.7 の `rules activate` を実行してください |
| `rules import` が CRS のディレクトリを読めない | `fetch-crs.sh` を root で実行すると、できたファイルは root だけが読めます。そのディレクトリを消して、`tukuyomi` で取得し直してください |
| `rules import` の事前検証が失敗する | Landlock が使えない Linux では、検査プロセスが起動せず、事前検証が失敗します。遮断の世代では、事前検証のリクエストがブロックされても失敗します（`--accept-block`） |
| プロキシが `stop: the kernel failed: Exit(14)` で停止する | Landlock が使えない Linux では、検査プロセスが起動しません。Linux 5.13 以上で、LSM の一覧に `landlock` があるか確かめてください |
| ディレクトリのエラーで起動も `rules import` も受け付けられない | 2.4 の表のディレクトリを、`tukuyomi` が所有し、0700 にしてください。シンボリックリンクにはできません。プロキシもコマンドも、これらのディレクトリは作りません |
| リスナーをバインドできず、起動が止まる | 同じアドレスとポートを使っているプロセスがあります。1 つでもバインドできないと、プロキシはどのリスナーも使わずに停止します |
| 通常のリクエストが 502 になる | アップストリームの `127.0.0.1:8080` に接続できていません。アップストリームを起動してください。ログは `class` が `failed` になります |

起動前の検証には、SIGCHLD を無視していないことと、2 より大きいファイルディスクリプターがすべて close-on-exec であることの 2 つもあります。systemd から起動すれば、どちらも満たされます。手で起動して拒否されたときは、シェルが SIGCHLD を無視していないか、ファイルディスクリプターを引き継いでいないかを確かめてください。起動の順序と終了コードの全体は、付録A 運用リファレンスの「起動」と「`config check`」にあります。

## 2.12　この構成で気を付けること

- **この構成は、動くことを確かめるためのものです。** リスナーはループバックアドレスだけ、プロトコルは平文の HTTP で、プロセスは端末に結び付いています。本番では、systemd のユニットで動かします。ポート 80 と 443 で待ち受けるには `CAP_NET_BIND_SERVICE` が必要で、ユニットで与えます（第3章）。TLS の証明書は、ファイルを置くか、ACME で発行します（第8章）。
- **この章の世代は、遮断の世代です。** 本番の最初のインポートは、検知のみの世代にして、誤検知を確認してから切り替える進め方が、ドキュメントのおすすめです（第4章）。この章の世代は検査除外のルートを持たないので、このまま第5章の管理画面へ進むと、管理画面のリクエストが遮断の世代でブロックされることがあります。管理画面を使うときは、検査除外のルートを最初の世代に入れます（第4章 4.6、第5章 5.4）。
- **ログは、標準エラーに出て、`records` があれば `records.dir` のファイルにも書かれます。** 起動の最初の行のうち、ログファイルを開く前に出る行は、標準エラーだけに出ます。ログにはクライアントのアドレスとパスが入るので、読めるユーザーは最小限にしてください（第7章）。
- **管理画面と、ログの DB への送信は、この章では用意していません。** 管理プロセスは第5章、ログ送信プロセスは第7章で扱います。
- **名前は、ドキュメントの配置の例（第3章）と同じにしてあります。** OS ユーザー、ディレクトリ、実行ファイルの置き場です。

第3章では、ここで手で起動したものを、systemd のユニットで動かす形にします。あわせて、管理プロセスとログ送信プロセスのユニット、証明書の更新のタイマー、起動前の検証、検査プロセスの権限の制限を説明します。
