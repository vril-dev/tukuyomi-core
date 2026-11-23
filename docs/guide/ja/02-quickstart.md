# 第2章　クイックスタート

本章では、リリースの tarball をダウンロードして、1 台の Linux ホストで tukuyomi core を起動します。
通常のリクエストが通ることと、SQL インジェクションのリクエストがブロックされることをログで確認するところまでが、この章のゴールです。

systemd を使った本番向けの配置は第3章で扱い、この章ではコマンドを手で実行して、まず実際に動かしてみることを目的にします。

## 2.1　この章で作る構成と、用意するもの

この章で作るのは、次のような小さな構成です。

- プロキシ（`tukuyomi-proxy`）は `127.0.0.1:8000` で、`curl` から送ったリクエストを受けます。
- プロキシは検査プロセス（Coraza）を子プロセスとして起動し、リクエストを検査させます。
- ブロックしなかったリクエストだけをアップストリームのアプリケーション（`127.0.0.1:8080`）へ転送します。

始める前に、次のものを用意してください。

- **Linux x86_64 のホスト**: 動作を確認しているのは、Landlock が有効な Linux x86_64 だけです。
  Linux 5.13 以上で、LSM の一覧に `landlock` が入っている必要があります。一覧は `/sys/kernel/security/lsm` で確認できます。
  glibc は 2.39 以上が必要です。
- **bash、curl、sha256sum、tar**: CRS のダウンロードに使います。
- **root の権限（`sudo`）**: OS ユーザーとディレクトリの作成、実行ファイルの配置に使います。tukuyomi core 自身は root では動きません。
- **`127.0.0.1:8080` で HTTP に応答するアプリケーション**: プロキシの転送先（アップストリーム）です。
  手元の Web アプリケーションでも、試験用の HTTP サーバーでもかまいません。用意の仕方は本書では扱いません。

リリースの実行ファイルは Ubuntu 26.04.1 LTS（glibc 2.43）でビルドしたもので、動作を確認したのはビルドしたホストだけです。
古い Linux で動かない場合は、ソースからビルドしてください。
手順は、リポジトリのドキュメント「ビルドと配置」（`docs/build/binary-deployment.ja.md`）の「ソースからのビルド」にあります。

## 2.2　全体の流れ

具体的なコマンドに入る前に、何をどの順番で用意するのかを見ておきます。

1. **実行ファイルを置く**（2.3）: tarball の SHA-256 を確認してから展開します。
2. **OS ユーザーとディレクトリを用意する**（2.4）: プロキシは root では動かないので、専用の OS ユーザーを作ります。
   設定で指定するディレクトリは、プロキシもコマンドも自動では作らないため、先に作っておきます。
3. **設定ファイルを書く**（2.5）: 設定の値にはデフォルトが無いので、必要な設定キーをすべて書きます。
4. **CRS をダウンロードする**（2.6）: CRS は同梱していないので、バージョンとチェックサムを固定したスクリプトでダウンロードします。
5. **ルールセットをインポートし、世代として選択する**（2.7）: インポートでは、ルールセットを検査プロセスで実際に試し（事前検証）、通ったものだけが「世代」になります。
   起動したプロキシは選択した世代で検査します。
   選択中の世代が無いと、プロキシは起動しません。
6. **設定を検証して、起動する**（2.8）
7. **リクエストを送り、ログで確認する**（2.9）

インポートと選択はプロキシとは別のコマンドです。
これらのコマンドで世代が変わっても、動作中のプロキシは気付きません。
そこでこの章では、プロキシを起動する前に世代の用意をすべて済ませます。
動作中のプロキシに新しい世代を使わせる方法は、第4章で説明します。

## 2.3　tarball をダウンロードして、実行ファイルを置く

リリースの tarball は GitHub のリリース（<https://github.com/vril-dev/tukuyomi-core/releases>）で配布しています。
ダウンロードするのは、次の 2 つのファイルです。

- `tukuyomi-core_v0.2.0_linux_amd64.tar.gz`
- `tukuyomi-core_v0.2.0_linux_amd64.tar.gz.sha256`

まず、作業用のディレクトリを作ります。
展開したスクリプトを後で `sudo -u tukuyomi` で実行するので、このディレクトリは OS ユーザー `tukuyomi` から読めなければなりません。
ほかのユーザーに同じ名前のディレクトリを先に作られないように、名前は `mktemp -d` で決めます。
`tukuyomi` が読めるように、権限は 0755 にします。

```bash
d=$(mktemp -d /tmp/tukuyomi-core.XXXXXX) && chmod 0755 "$d" && cd "$d"
```

このディレクトリに、ダウンロードした 2 つのファイルを置きます。
展開する前に、SHA-256 を確認してください。

```bash
sha256sum -c tukuyomi-core_v0.2.0_linux_amd64.tar.gz.sha256
tar -xzf tukuyomi-core_v0.2.0_linux_amd64.tar.gz
```

展開すると、`tukuyomi-core_v0.2.0_linux_amd64/` に 4 つの実行ファイルや `scripts/fetch-crs.sh` などができます。

実行ファイルは所有者を root にして、サービスの OS ユーザーが書き換えられない場所に置きます。
この章で使うのは、プロキシと Coraza の検査プロセスの 2 つだけです。
ModSecurity の検査プロセス（`tukuyomi-inspector-modsecurity`）とログ送信プロセス（`tukuyomi-records-ship`）は、使うときに同じ場所へ置きます（第3章）。

```bash
sudo install -d -m 0755 /opt/tukuyomi-core/bin
sudo install -m 0755 tukuyomi-core_v0.2.0_linux_amd64/tukuyomi-proxy \
  tukuyomi-core_v0.2.0_linux_amd64/tukuyomi-inspector /opt/tukuyomi-core/bin/
```

## 2.4　OS ユーザーとディレクトリを用意する

サービスもコマンドも専用の OS ユーザー `tukuyomi` で実行します。
この章の設定ファイルが使うディレクトリは、次の 3 つです。

| ディレクトリ | 設定キー | 所有者と権限 |
|---|---|---|
| `/var/lib/tukuyomi-core/store` | `rules.store.dir`（ルールストア） | `tukuyomi`、0700 |
| `/var/lib/tukuyomi-core/tmp` | `kernel.tmp_root`（検査プロセスの作業ディレクトリ） | `tukuyomi`、0700。setgid は付けません |
| `/var/lib/tukuyomi-core/records` | `records.dir`（ログのディレクトリ） | `tukuyomi`、0700 |

プロキシはこの 3 つについて、次の点を検証します。

- シンボリックリンクではないこと
- 所有者がサービスの OS ユーザーであること
- グループとその他のユーザーに権限が無いこと

表の 3 つのディレクトリはそれぞれ別にしてください。

CRS のダウンロード先（`/var/lib/tukuyomi-core/crs-4.23.0`）は、スクリプトが親ディレクトリの中に作ります。
親ディレクトリ `/var/lib/tukuyomi-core` は、`tukuyomi` が書き込めるようにしておきます。

```bash
sudo useradd --system --user-group --home-dir /var/lib/tukuyomi-core --no-create-home --shell /usr/sbin/nologin tukuyomi
sudo install -d -o tukuyomi -g tukuyomi -m 0750 /var/lib/tukuyomi-core
sudo install -d -o tukuyomi -g tukuyomi -m 0700 /var/lib/tukuyomi-core/store /var/lib/tukuyomi-core/tmp /var/lib/tukuyomi-core/records
```

## 2.5　設定ファイルを書く

設定ファイルは `/etc/tukuyomi-core/config.json` に置き、所有者を root にして、サービスの OS ユーザーが読めるようにします。

```bash
sudo install -d -m 0755 /etc/tukuyomi-core
```

ここで作る設定ファイルは、付録A 運用リファレンスの「設定ファイル」にある「例」から、手で起動して試すのに要らない部分を除いたものです。
例との違いは次のとおりです。

- リスナーは平文の HTTP で待ち受ける `127.0.0.1:8000` の 1 つだけにしました。
  例にある 80 番と 443 番のポートは、`CAP_NET_BIND_SERVICE` を持たない OS ユーザーでは待ち受けられません。TLS の証明書もまだありません。
- 例に入っていた省略できる設定キーのうち、`acme` と `rate_limit` は外し、`records` はログをファイルで確認するために残しています。
- ほかの値は例のままです。
  どれも動かすときの目安で、受け付ける範囲は、付録A 運用リファレンスの「設定ファイル」の表にあります。

次の内容で `/etc/tukuyomi-core/config.json` を作成します。

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

設定キーは多く見えますが、この章で意識するのは次の 4 点だけです。

- **転送先**: `forward.upstreams.app` は、プロキシがリクエストを転送するアプリケーションです。
  `routes` が空で、`default_upstream` が `app` なので、リクエストはすべて `app` 宛てになります。ブロックしたリクエストは転送しません。
- **検査プロセス**: `kernel.inspector` は、Coraza の検査プロセスの実行ファイルです。
  ModSecurity の世代だけを使うホストでも、この設定キーは省略できません。
- **アドレス**: アップストリームのサーバーにはリスナーと同じアドレスを書けないので、リスナーとアップストリームでポートを分けています。
- **ログ**: `records` を書くと、標準エラーに出るログの行が `records.dir` の `records.log` にも書かれます。
  ただし、ログファイルを開く前に出る起動の最初の行は、標準エラーにだけ出ます。たとえば、`start: configuration accepted` や `start: rules …` の行です。

ここで一度 `config check` を実行しておくと、設定ファイルの誤りを CRS のダウンロード前に見つけられます。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
```

この時点ではまだ世代を選択していないので、設定ファイルに問題がなくても、`config check: rules store refused: no generation is chosen` の行が出て exit 1 になります。これは想定どおりの結果です。
設定ファイルそのものに誤りがある場合は、exit 2 になります。

## 2.6　CRS をダウンロードする

CRS（OWASP Core Rule Set）は同梱していないので、展開したディレクトリにある `scripts/fetch-crs.sh` でダウンロードします。

**必ずサービスの OS ユーザーで実行してください。**
root で実行すると、できたファイルを `tukuyomi` で実行する `rules import` が読めません。

2.3 で移動した作業用のディレクトリで、次のコマンドを実行します。

```bash
sudo -u tukuyomi tukuyomi-core_v0.2.0_linux_amd64/scripts/fetch-crs.sh /var/lib/tukuyomi-core/crs-4.23.0
```

このスクリプトについて、知っておくとよい点は次のとおりです。

- ダウンロードする CRS のバージョン（4.23.0）とアーカイブの SHA-256 は、スクリプトの中に固定してあり、引数では変えられません。
  アーカイブは https でだけダウンロードし、SHA-256 が一致してから中身を読みます。
- 引数には、まだ存在しないディレクトリを指定します。すでにあるディレクトリには手を付けません。
  途中で失敗した場合は、何も残りません。
- できたディレクトリには、`crs-setup.conf`、`crs-setup.conf.example`、`rules/*.conf`、`rules/*.data` の 4 種類だけが入ります。
  `crs-setup.conf` はインポートの前に編集できますが（第4章）、この章ではそのまま使います。
- GitHub に接続できないホストでは、固定したアーカイブのコピーを環境変数 `FETCH_CRS_ARCHIVE_FILE` で渡せます。その場合も、SHA-256 などの検証は同じように行います。
- `Permission denied` になる場合は、展開したディレクトリと、そこまでの親のディレクトリを `tukuyomi` が読めるようにしてください。

## 2.7　最初の世代をインポートして選択する

ダウンロードした CRS をルールの世代としてインポートします。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0
```

インポートでは、事前検証として検査プロセスを 1 つ起動し、決まったリクエストを 3 つ検査します。
事前検証に通ったときだけ世代が作られ、標準出力に `<fingerprint> created` が出ます。`<fingerprint>` は世代のフィンガープリント（64 桁の 16 進数）です。
同じ内容の世代がすでにある場合は、`already exists` が出ます。

この章では、SQL インジェクションがブロックされることを確認するために、リクエストをブロックする世代を作ります。
ドキュメントでは、本番で最初にインポートするときは、`--detect-only` を付けて検知のみの世代にすることをおすすめしています。
誤検知を確認してから、ブロックする世代に切り替えます（第4章）。

ブロックする世代では、事前検証のリクエストが 1 つでもブロックされると事前検証が失敗し、世代は作られません。
`crs-setup.conf` の設定を厳しくした場合などは、ログを見て設定を直すか、`--accept-block` を付けてください。
インポートのオプションの一覧は、付録A 運用リファレンスの「`rules`」にあります。

インポートできたら、`<fingerprint>` に上で出た値を指定して、その世代を選択します。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules activate /etc/tukuyomi-core/config.json <fingerprint>
```

成功すると、`<fingerprint> current` が出ます。
世代の一覧は `rules list` で確認できます。

世代は検査エンジンごとに選択し、最初に選択するのはデフォルトのエンジンの世代です。
`kernel.default_engine` を書いていなければ、デフォルトのエンジンは `coraza` です。
デフォルトのエンジンに選択中の世代が無いと、プロキシは起動しません。

## 2.8　設定を検証して起動する

起動する前に、もう一度設定を検証します。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
```

問題がなければ、標準出力に `accepted` が出て exit 0 になります。
`config check` は検査プロセスを起動しないので、作業ディレクトリ、検査プロセスの実行ファイル、Landlock の問題はここでは分かりません。これらは次の起動で初めて分かります。

続けて、プロキシを起動します。この章では systemd を使わず、端末で直接動かします。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy /etc/tukuyomi-core/config.json
```

ログは標準エラーに 1 行 1 件の JSON で出ます。
検査カーネルの準備ができると `start: the kernel is ready` の行が、リスナーが待ち受けを始めると `start: listening` の行が出ます。どちらも `type` が `line` のログです。
`start: listening` が出れば、起動は完了です。

この端末はそのままにして、ここからのコマンドは別の端末で実行します。

## 2.9　リクエストを送って、ログで確認する

別の端末から、リクエストを 2 つ送ります。
`-H 'Host: example.com'` で、`Host` ヘッダーにホスト名を指定しています。

1 つ目は通常のリクエストです。

```bash
curl -i -H 'Host: example.com' http://127.0.0.1:8000/
```

アップストリームの応答が返ってきます。
応答のヘッダーには、プロキシが付けた `X-Request-ID` が入っています。

2 つ目は SQL インジェクションのリクエストで、クエリは `id=1' OR '1'='1` を URL エンコードしたものです。

```bash
curl -i -H 'Host: example.com' 'http://127.0.0.1:8000/item?id=1%27%20OR%20%271%27%3D%271'
```

こちらはプロキシが 403 を返し、ボディは空です。
アップストリームには転送されないので、アップストリームのアクセスログにも残りません。

結果はログファイルで確認します。ログファイルを読めるのは、`tukuyomi` と root だけです。

```bash
sudo -u tukuyomi grep '"type":"request"' /var/lib/tukuyomi-core/records/records.log
```

リクエストのログは 1 件が 1 行の JSON です。
注目するのは、次の項目です。

| 項目 | 通常のリクエスト | SQL インジェクションのリクエスト |
|---|---|---|
| `class` | `forwarded` | `blocked` |
| `reason` | `forwarded` | `blocked by a rule` |
| `status` | アップストリームが返したステータスコード | 403 |
| `mode`、`engine` | `block`、`coraza` | `block`、`coraza` |
| `rule` | ルールに一致しなければ、この項目はありません | ブロックしたルールの ID |

- `generation` は世代のフィンガープリントの先頭 16 桁で、2.7 で選択した世代と同じ値になります。
- クエリはログに記録しません。
  2 つのリクエストは `path` と `id` で見分けます。`id` は応答の `X-Request-ID` と同じ値です。
- ログの項目の一覧は、付録A 運用リファレンスの「リクエストのログ（`request`）」にあります。

もし検知のみの世代でインポートしていた場合は、SQL インジェクションのリクエストもアップストリームへ転送されます。
そのときのログは、`class` が `forwarded`、`reason` が `detected by a rule` になります。
`rule` には一致したルールの ID が入ります（付録A 運用リファレンスの「検知のみのモード」）。

## 2.10　停止する

別の端末から、プロキシのメインプロセスに SIGTERM を送ります。
検査プロセスは SIGTERM・SIGINT・SIGHUP が届くと終了してしまいます。
シグナルは必ずプロキシのメインプロセスにだけ送ってください（付録A 運用リファレンスの「シグナル」）。
次のコマンドでは、プロキシの PID を指定して送ります。

```bash
sudo kill -TERM $(pgrep -u tukuyomi -x tukuyomi-proxy)
```

プロキシは新しい接続とリクエストの受け付けをやめ、処理中のリクエストを処理してから、検査プロセスを止めて終了します。
ログの最後には `stop: kernel ...` で始まる行が出ます。
終了コードが 0 になるのは、検査プロセスの終了と作業ディレクトリの削除まで確認できたときだけです。
停止の詳しい流れは、付録A 運用リファレンスの「停止」にあります。

## 2.11　うまくいかないとき

| 症状 | 原因と対処 |
|---|---|
| `host check refused` の行が出て、exit 1 になる | root で実行しています。`sudo -u tukuyomi` を付けて、サービスの OS ユーザーで実行してください |
| `config check` が exit 2 になる | 設定ファイルに誤りがあります。値の範囲や設定キーどうしの関係の誤りは、該当する設定キーの名前が出ます（例: `max_conns is out of range`）。形の誤り（JSON でない、未知の設定キー、型の違い）は、どの設定キーかを示しません |
| `config check` やプロキシの起動が、`rules store refused: no generation is chosen` で exit 1 になる | デフォルトのエンジンの世代を選択していません。2.7 の `rules activate` を実行してください |
| `rules import` が CRS のディレクトリを読めない | `fetch-crs.sh` を root で実行すると、できたファイルは root しか読めません。そのディレクトリを削除し、`tukuyomi` でダウンロードし直してください |
| `rules import` の事前検証が失敗する | Landlock を使えない Linux では検査プロセスが起動しないため、事前検証は失敗します。ブロックする世代では、事前検証のリクエストがブロックされた場合も失敗します。この場合は、ログを見て設定を直すか、`--accept-block` を付けてください |
| プロキシが `stop: the kernel failed: Exit(14)` で止まる | Landlock を使えない Linux では、検査プロセスが起動しません。Linux 5.13 以上で、LSM の一覧に `landlock` があるかを確認してください |
| ディレクトリのエラーで、起動も `rules import` も失敗する | 2.4 の表のディレクトリは、プロキシもコマンドも自動では作りません。シンボリックリンクは使えません。これらのディレクトリは、所有者 `tukuyomi`、権限 0700 にしてください |
| リスナーをバインドできず、起動が止まる | ほかのプロセスが同じアドレスとポートを使っています。1 つでもバインドできないリスナーがあると、プロキシはどのリスナーも使わずに停止します |
| 通常のリクエストが 502 になる | アップストリームの `127.0.0.1:8080` に接続できていません。アップストリームを起動してください。このときのログは、`class` が `failed` になります |

起動前の検証には、ほかに SIGCHLD を無視していないことと、2 より大きいファイルディスクリプターがすべて close-on-exec になっていることの 2 つがあります。systemd から起動すれば、どちらも満たされます。
手で起動して拒否された場合は、シェルが SIGCHLD を無視していないか、ファイルディスクリプターを引き継いでいないかを確認してください。
起動の順序と終了コードの全体は、付録A 運用リファレンスの「起動」と「`config check`」にあります。

## 2.12　この構成で気を付けること

- **これは動作を確認するための構成です**: リスナーはループバックアドレスだけ、プロトコルは平文の HTTP で、プロセスは端末につながったままです。
  本番では systemd のユニットで動かします。
  ポート 80 と 443 で待ち受けるには、`CAP_NET_BIND_SERVICE` が必要です。この権限はユニットで与えます（第3章）。
  TLS の証明書は、ファイルを置くか、ACME で発行します（第8章）。
- **この章の世代はブロックする世代です**: ドキュメントでは、本番で最初にインポートするときは、検知のみの世代で誤検知を確認してから切り替える進め方をおすすめしています（第4章）。
  この章の世代には検査除外のルートが無いので、このまま第5章の管理画面に進むと、管理画面へのリクエストがブロックされることがあります。
  管理画面を使う場合は、最初の世代に検査除外のルートを入れておいてください（第4章 4.6、第5章 5.4）。
- **ログは標準エラーに出て、`records` があればファイルにも書かれます**: ログファイルを開く前に出る起動の最初の行は、標準エラーにだけ出ます。
  ログにはクライアントのアドレスとパスが入るので、読めるユーザーは最小限にしてください（第7章）。
- **管理画面と、ログの DB への送信は、この章では用意していません**: 管理プロセスは第5章、ログ送信プロセスは第7章で扱います。
- **名前は第3章の配置の例と同じにしてあります**: 対象は OS ユーザー、ディレクトリ、実行ファイルの置き場です。

次の第3章では、ここで手で起動したプロキシを systemd のユニットで動かす形に移します。
あわせて、管理プロセスとログ送信プロセスのユニット、証明書の更新のタイマー、起動前の検証、検査プロセスの権限の制限を説明します。
