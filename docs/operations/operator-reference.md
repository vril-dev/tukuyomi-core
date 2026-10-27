# 運用リファレンス

この文書は、今の実装の命令、合図、設定ファイルの鍵、ルールセットの扱い、要求の扱い、記録、監視を、引いて使える形でまとめる。置き方と systemd の例は [実行ファイルの build と配置](../build/binary-deployment.md) に書く。

例の path と名前（`/etc/tukuyomi-core/config.json`、利用者 `tukuyomi`、`example.com` など）は例である。

## 命令

どの命令も、`tukuyomi-proxy` の1つの実行ファイルで流す。設定ファイルは、絶対の path で渡す（`.`・`..`・空の要素・末尾の `/` は断られる）。

root では、どの命令も流れない。プロセスの user id の4つ（real、effective、saved、file system）のどれかが 0 なら、`host check refused` の行を出して断る（exit 1）。サービスの利用者で流す（例: `sudo -u tukuyomi ...`）。

### 起動

```text
tukuyomi-proxy <config>
```

- 起動は、次の順に進む。
  1. 起動の前の確かめ（root でないこと、SIGCHLD、file descriptor）
  2. 設定ファイル
  3. 上流の server の名前の解決と、上流の組の CA のファイル
  4. TLS の待ち受けの証明書と鍵
  5. ルールの保管場所と、選んだ世代
  6. 監視の待ち受け（設定に `status` があるとき）の bind
  7. 検査核の起動と、検査プロセスの準備
  8. 待ち受けの bind
- 監視の待ち受けは、検査プロセスより前に bind する。bind できなければ、検査プロセスを起動せずに止まる（exit 1）。
- 待ち受けは、検査核の準備ができてから、全部を bind する。1つでも bind できなければ、どれも使わずに止まる。
- 合図を扱う処理は、5 の後に入る。それより前（名前の解決は最長 `resolve_timeout_ms` かかる）に届いた合図は、どれも proxy をそのまま終わらせる。
- 記録には、準備ができると `start: the kernel is ready`、待ち受けを始めると `start: listening` の文が出る（`line` の記録。下の「記録」）。
- 環境に `NOTIFY_SOCKET` があれば、待ち受けを全部 bind した後に `READY=1` を送る（下の「systemd への知らせ」）。
- exit code は次のとおり。

| exit code | 意味 |
|---|---|
| 0 | 合図で止まり、検査核の停止（検査プロセスの終わりと作業場所の削除）まで確かめられた |
| 1 | ほかの終わり方。root での起動、起動の前の確かめの失敗、引けない上流の名前、使えない CA のファイル、断られた証明書や鍵、断られた保管場所や世代、bind できない監視の待ち受けも含む（このときは何も起動していない） |
| 2 | 引数の誤り、または設定ファイルが断られた |

### `config check`

```text
tukuyomi-proxy config check <config>
```

- 起動と同じ確かめを、選んだ世代と検査核の設定まで流す（上の 2〜5 と、検査核の設定の値）。起動の前の確かめ（上の 1）は、root でないことだけを見る。
  - 通れば、標準出力に `accepted` の1行が出て exit 0 になる。
  - ほかの行は標準エラーに出て、`config check:` で始まる。引数の誤りのときだけ `config:` で始まり、使い方の行が続く。
  - exit code は起動と同じである。
- 確かめないもの:
  - SIGCHLD と file descriptor（上の 1 のうち、root でないこと以外）
  - 作業場所（`kernel.tmp_root`）。検査プロセスを起動するときに確かめる
  - 検査プロセスの実行ファイルが起動できること、Landlock が使えること
  - ルールが Coraza で組めること（起動のときに確かめる。ルールは `rules import` が試してから世代にする）
  - 待ち受けの port を bind できること
  - systemd の設定
- この命令が書くものは1つだけである。起動と同じく、選んだ世代を使う印を保管場所の `using/` に作る（まだ無いとき）。命令が終われば、印の lock は外れる。
- サービスと同じ利用者で流す。別の利用者では、保管場所の持ち主の確かめや、鍵のファイルの読みで断られる。

### `rules`

```text
tukuyomi-proxy rules import <config> [--crs <dir>] [--crs-off <name>]... [--rules <file>]... [--data <file>]... [--routes <file>] [--accept-block] [--detect-only]
tukuyomi-proxy rules activate <config> <fingerprint>
tukuyomi-proxy rules remove <config> <fingerprint>
tukuyomi-proxy rules list <config>
```

どれも短い命令で、動いている proxy とは別のプロセスである。動いている proxy は、命令がしたことに気づかない。新しい世代を使わせるには、SIGUSR1 を送る（下の「合図」）。

| 命令 | すること | 標準出力 |
|---|---|---|
| `import` | 入力からルールセットを作って保管場所に置き、試しに通れば世代にする。世代を選びはしない | `<指紋> created`、`<指紋> already exists`、`<指紋> recreated, the stored copy was broken` |
| `activate` | 世代を選ぶ。後で起動する proxy と、SIGUSR1 を受けた proxy がそれを使う | `<指紋> current` |
| `remove` | 選ばれていない世代で、どの proxy も使っていないものを消す | `<指紋> removed` |
| `list` | 世代の一覧 | 指紋、作った時刻（epoch からの秒）、mode（`block`・`detect`、manifest が読めなければ `unknown`）、bypass の経路があれば `routes` と数、選ばれた世代に `current` |

`import` の入力は次のとおりである。option の path は、命令を流す場所からの相対でも書ける。

| option | 中身 |
|---|---|
| `--crs <dir>` | `scripts/fetch-crs.sh` で取得した CRS のディレクトリ。`crs-setup.conf`（と任意の `crs-setup.conf.example`）と `rules/` の `.conf`・`.data`・`.example` だけを持つこと。ほかのもの（隠しファイル、`plugins` などのディレクトリ、ほかの拡張子、link）があれば断る |
| `--crs-off <name>` | `crs/rules/` の `.conf` のうち、読み込まないもの。何度でも書ける。`--crs` が要る |
| `--rules <file>` | 運用者のルールのファイル。何度でも書け、CRS の後に書いた順に読み込む |
| `--data <file>` | 運用者のルールが読むデータのファイル。ルールセットに入るが、ルールとしては読み込まない |
| `--routes <file>` | 検査しない経路（bypass）のファイル（下の「検査しない経路」） |
| `--accept-block` | 試しの要求が遮断されても、試しを失敗にしない（当たった規則は出る） |
| `--detect-only` | 検知だけの世代にする（下の「検知だけのモード」） |

- 読み込む順は、`crs/crs-setup.conf`、`crs/rules/` の `.conf`（名前のバイトの順）、運用者のルールのファイル（書いた順）である。
- `--rules` と `--data` のファイルは、ディレクトリを除いた名前で、ルールセットの `rules/<名前>` に入る。
  - 名前は 1〜128 文字の英数字・`.`・`_`・`-` で、`.` で始めない。
  - 同じ名前は、`--rules` と `--data` をまたいでも断る。
  - 入力のファイルが link のときと、`--crs` のディレクトリが link のときも断る。
- 1つのファイルは 2 MiB まで、ルールセット全体は 128 ファイル・8 MiB までである。ディレクトリは 1024 項目まで見る。manifest は 64 KiB までで、ファイルの一覧と検査しない経路がそれを分け合う。
- ルールが読めるファイル（`@pmFromFile` など）は、ルールセットの中のファイルだけである。ルールには、ルールセットの中の path（`rules/<名前>` など）で書く。
- 試し: 検査プロセスを1つ起動し、決まった3つの要求（`GET /`、form の本文 `a=b` の `POST /`、JSON の本文 `{"a":"b"}` の `POST /`）を検査する。
  - 検査プロセスが `ready_wait` の中に準備でき、どの要求も `inspect_wait` の中に許可され、検査プロセスがきれいに終われば、試しに通る。
  - 遮断の世代では、試しの要求が1つでも遮断されると失敗にする（`--accept-block` を付けたときを除く）。検知だけの世代では、規則に当たっても失敗にしない。
  - 試しは、ルールセットが起動し、普通の形の要求を通すことを示すだけで、ルールが正しいことは示さない。
- 試しの間に SIGINT（Ctrl-C）か SIGTERM を受けると、試しを止め、検査プロセスと作業場所を片付けて、世代を作らずに終わる。試しの後は、この2つの合図で命令は止まらない。
- `import` は検査プロセスを起動するので、起動の前の確かめ（[実行ファイルの build と配置](../build/binary-deployment.md) の「起動の前の確かめ」）も流す。

exit code は、0 が成功、1 がほかの終わり方（断られた保管場所や入力、失敗した試し、使用中の保管場所、`list` で manifest が読めない世代や選んだ世代が無い保管場所、root での実行）、2 が引数の誤りか断られた設定ファイルである。

### `acme renew`

```text
tukuyomi-proxy acme renew <config>
```

- `acme` を持つ証明書を、設定の順に見る。次のどれかに当たる証明書を、新しい鍵で注文し直す（期限が来たもの）。
  - 証明書か鍵のファイルが読めない
  - 鍵が証明書に合わない
  - 証明書がすべての host を含まない
  - 有効期間の終わりまでが `renew_before_days` 日より短い（ちょうどその日数は短くない）
- 期限が来ていない証明書は `valid` である。
- 期限が来た証明書が1つでもあれば、account の鍵を読むか作り、CA に account を作るか見つける。account は、CA の利用規約に同意し、`contact_email` を連絡先にして作る。
- 命令全体（CA の応答と待ちを含む）は `timeout_ms` までである。時間が尽きたとき、まだ更新できていない期限の来た証明書は、その後のものも含めて `failed` になる。期限が来ていない証明書は `valid` のままである。
- 結果は、`acme` を持つ証明書ごとに標準出力に1行出る。形は `<待ち受けの番号>.<証明書の番号> renewed|valid|failed` である。
  - どちらも 1 から数える。待ち受けの番号は `proxy.listeners` の並びの位置で、TLS でない待ち受けも数える。
  - `failed` の証明書は、ファイルを前のまま残す。
- CA から受けたものは、問題の文書の `type` だけを記録に出す。
- SIGINT と SIGTERM で、challenge のファイルを消してすぐ終わる。
- 動いている proxy は、新しい証明書に気づかない。命令の後に SIGUSR2 を送る（`systemctl reload`）。
- exit code は次のとおりである。
  - 0: すべてが `renewed` か `valid`
  - 1: 1つでも `failed`、止められた、流せない、root で流した
  - 2: 引数の誤り、断られた設定ファイル、`acme` を持つ証明書が無い設定ファイル

手順は下の「ACME」にある。

## 合図

合図は proxy の主プロセスだけに送る。検査プロセスは、SIGUSR1・SIGUSR2 は無視するが、SIGTERM・SIGINT・SIGHUP が届くと終わる。systemd では `systemctl reload`（unit の `ExecReload` が主プロセスに SIGUSR2 を送るとき）か `systemctl kill --kill-whom=main` を使う。

| 合図 | すること |
|---|---|
| SIGTERM、SIGINT、SIGHUP | 止まる（下の「停止」） |
| SIGUSR1 | ルールの保管場所が今選んでいる世代へ切り替える |
| SIGUSR2 | すべての TLS の待ち受けの証明書と鍵のファイルを読み直す |

### SIGUSR1（世代の切り替え）

- proxy は保管場所を読み、選ばれた世代で新しい検査核と検査プロセスを起動する。新しい方の準備ができたら、新しい要求をそちらへ回す。
  - 古い方は、持っている要求を `stop_inspect` まで検査してから止まる。
  - 新しい方が起動に失敗するか、`ready_wait` の中に準備できなければ、古い方がそのまま検査を続ける。
- 検査しない経路の表は、新しい世代が要求を受け始めるときに一緒に入れ替わる。
- 切り替えの間は検査プロセスが2つになり、メモリもおよそ2倍になる。CRS 4.23.0 で測った検査プロセスは、1つ約 52 MB だった。
- 合図の処理が入ってから待ち受けを bind するまでの間、切り替えの途中、停止の間に受けた SIGUSR1 は、記録に文を1つ出すだけで何もしない。今と同じ世代が選ばれているときも、その旨の文を出すだけである。
- 使っている間、proxy は世代の印（保管場所の `using/<指紋>`）に共有の lock を持つ。そのため `rules remove` は、使用中の世代を消せない。

### SIGUSR2（証明書の読み直し）

- 読み直したすべての証明書と鍵が確かめに通ったときだけ、まとめて入れ替える（確かめの中身は下の `proxy.listeners` の `cert_file`・`key_file`）。入れ替えた後に始まる handshake から、新しいものを使う。開いている接続は、今のものを使い続ける。
- 1つでも通らなければ、どれも入れ替えず、どれが通らなかったかの文を記録に出す。
- `acme` を持つ証明書でファイルが無いものは、断る理由にならない。行を出して handshake から外し、ファイルができた後の SIGUSR2 で使い始める。動いている間にファイルを消してから SIGUSR2 を送ると、その証明書も handshake から外れ、その host への接続は失敗する。
- 上流の組の CA のファイルは、SIGUSR2 では読み直さない。
- 合図の処理が入ってから待ち受けを bind するまでの間と、停止の間に受けた SIGUSR2 は、記録に文を1つ出すだけである。SIGUSR1 とは関係しない。

### 読み直さないもの

次のものは起動のときに読み、proxy を起動し直すまでそのままである。

- 上流の組と経路（設定の `forward`）
- 上流の server の名前を引いた address
- 上流の組の CA のファイル
- 待ち受けと、その証明書の host

## 停止

最初の止める理由（合図、起動か driver の失敗）の時刻を t0 とする。

1. 待ち受けを閉じ、新しい要求を断る。次の要求を待っている接続は閉じる。`/readyz` は 503 `stopping` になり、`NOTIFY_SOCKET` があれば `STOPPING=1` を送る。
2. 検査は `t0 + stop_inspect` までに終える。
3. 接続は `t0 + stop_wait` まで待ち、残りは打ち切る。WebSocket の tunnel は停止では終わらず、このときに打ち切られる。この後に監視の待ち受けを閉じる。
4. 検査核の終わりを `t0 + stop_wait + kill_grace` まで待つ。
5. 記録を最長 200 ms 書き出して終わる。

最後に `stop: kernel ..., bye ..., exit_confirmed ..., dir_removed ..., held_left ..., waiting_left ..., results ..., retired_clean ...` の文が出る。検査核の終わりが確かめられなかったときは、代わりに `stop: the driver stopped: ...` か `stop: the driver gave no end` が出る。

- `bye true` は、検査プロセスが終わりの知らせを送ってから終わったことを示す。
- exit code が 0 になるのは、止めた理由が失敗でなく、止めた検査核（切り替えで前に止めたものも含む）のすべてで、検査プロセスの終わりと作業場所の削除が確かめられたときだけである。

## 設定ファイル

### 全体の形

```text
{"proxy": {..}, "forward": {..}, "kernel": {..}, "rules": {"store": {..}}, "acme": {..}, "status": {..}}
```

- `acme` と `status` は省いてよい（下のそれぞれの節）。

- UTF-8 の JSON の1つの object で、256 KiB までである。
- 値に既定値は無い。省いてよいと書いた鍵のほかは、すべて書く。
- 知らない鍵、同じ鍵の重複、型の違う値、object の代わりの配列は断る。省いてよい鍵に `null` を書くことも断る（省くか、値を書く）。
- 断るときの文は、誤りの種類ごとに決まった英語の1文で、ファイルの値を含まない。
  - 形の誤り（JSON でない、鍵が無い・知らない・重複、型の違い）は、どの鍵かを言わない。
  - 範囲と関係の誤りは、破った決まりの鍵の名前を言う（例: `max_conns is out of range`）。
  - 値は決まった順に確かめ、最初に破った決まりを返す。
- 設定の中の path は、どれも絶対の path で、`.`・`..`・空の要素・末尾の `/` を含まない形で書く。
- 時間は、名前が `_ms` で終わる鍵に、ミリ秒の整数で書く。
- バイト数の鍵の 1 KiB は 1024、1 MiB は 1048576 である。
- `acme` は、`acme` を持つ証明書があるときだけ書き、そのときは必ず書く。

### 例

TLS の待ち受け（HTTP/2 と ACME の証明書）、https への redirect の待ち受け、1つの上流の組の例を示す。値は動かすときの目安で、受け入れる範囲は下の表にある。

```json
{
  "proxy": {
    "listeners": [
      {"address": "0.0.0.0:80", "redirect": {"https_port": 443}},
      {
        "address": "0.0.0.0:443",
        "tls": {
          "min_version": "1.2",
          "certificates": [
            {
              "cert_file": "/var/lib/tukuyomi-core/tls/www.pem",
              "key_file": "/var/lib/tukuyomi-core/tls/www.key",
              "hosts": ["www.example.com"],
              "acme": {"renew_before_days": 30}
            }
          ],
          "http2": {
            "max_streams": 128,
            "stream_window": 65535,
            "connection_window": 262144,
            "max_header_list": 32768,
            "send_buffer": 16384
          }
        }
      }
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
  "acme": {
    "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "contact_email": "admin@example.com",
    "account_key_file": "/var/lib/tukuyomi-core/acme/account.key",
    "challenge_dir": "/var/lib/tukuyomi-core/challenges",
    "ca_file": "/etc/tukuyomi-core/acme-roots.pem",
    "timeout_ms": 300000
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
  }
}
```

### `proxy`: 接続と大きさ

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `listeners` | 1〜8 個 | 待ち受け（下の `proxy.listeners`） |
| `max_conns` | 1〜65536 | 同時に持つ client の接続の数。すべての待ち受けで合わせて数える |
| `max_head_bytes` | 1024〜32768 | 要求の head のバイト数の上限。超えると 431（request line が終わらないまま上限に達したときは 414） |
| `max_body` | 1 KiB〜4 GiB | 要求の本文の上限（ほどいた後の長さ）。超えると 413。検査する経路の gzip の本文は、`inspect_body` までである（下の「本文と予算」）。検査しない経路の gzip の本文はほどかないので、送られたままの長さで数える |
| `inspect_body` | 1 KiB〜1 MiB、かつ `max_body` 以下 | 本文の先頭から検査するバイト数。これより長い本文は、残りを検査せずに流す |
| `max_body_wire` | `max_body` 〜 `2 × max_body + 4 MiB` | chunked の本文の、回線の上のバイト数の上限（chunk の枠を含む）。超えると 413 |
| `max_buffered_bytes` | `2 × inspect_body + 24 KiB + 32 KiB` 〜 4 GiB | 要求がためるバイトの予算の合計（下の「本文と予算」）。尽きると 503 |
| `upstream_max_headers` | 1〜1024 | 上流の応答の head の field の数の上限 |
| `upstream_max_head_bytes` | 8192〜1 MiB | 上流の応答の head のバイト数の上限。上流の接続の読みの buffer の大きさにもなる |
| `upstream_head_wire` | `2 × upstream_max_head_bytes` 〜 4 MiB | 上流から最後の応答の head まで（1xx を含む）に読むバイト数の上限 |
| `trusted_proxies` | 0〜256 個の network | `X-Forwarded-For` を信じる相手（下の「client の address」）。空なら、相手がいつも client。host の部分が 0 の `address/prefix` で書く（`10.1.2.3/24` や、prefix の無い address は断る） |
| `upstream_keepalive` | 0〜1024 | 上流の組ごとに、使い回しを待つ接続の数（組の server すべてで合わせて）。0 なら、応答の後に閉じる |
| `upstream_keepalive_requests` | 1〜1000000 | 上流への1本の接続で送る要求の数の上限 |
| `keepalive_requests` | 1〜1000000 | client の1本の接続で受ける要求の数の上限。最後の要求の応答で閉じる。HTTP/2 では目安である（下の `http2`） |
| `lingering_bytes` | 1〜4 MiB | 接続を閉じる前に、読んで捨てるバイト数の上限 |

### `proxy`: 時間

範囲は、どれも 1 ms〜3600 s である。ただし、`keepalive_timeout_ms` は 0 も取り、`conn_total_ms` は 24 時間まで取る。

| 鍵 | 意味 |
|---|---|
| `drive_slice_ms` | 検査の driver が1回で検査核を回す時間。新しい要求は回の間に受けるので、ほかの要求があるときに新しい要求が待つ最長になる。推す値は 1 |
| `ready_wait_ms` | 検査核の準備を待つ時間（起動、世代の切り替え、`rules import` の試し） |
| `head_read_ms` | 要求の head を読み終える時間。最初の head は accept から数え（TLS の handshake を含む）、後の head は最初のバイトから数える。HTTP/2 の header block は、`HEADERS` の frame の最初のバイトから数える |
| `body_read_ms` | 本文の先頭（`inspect_body` まで、または本文全体）を、head の終わりから読み終える時間。それより長い本文の残りは、読みと読みの間がこれを超えると切る |
| `inspect_wait_ms` | 要求が検査の結果を待つ時間 |
| `upstream_connect_ms` | 上流への接続を作る時間（TLS の handshake を含む） |
| `upstream_header_ms` | 要求を上流へ送り始めてから、応答の head を受けるまでの時間。送る時間を含む。本文を流す要求では、最後のかけらを上流の接続へ渡したときから数える |
| `request_total_ms` | 要求の始めから、応答の head までの時間の上限。本文を受ける時間と検査の時間も含む。応答の本文を流す時間は含まない。接続の最初の要求は accept から（TLS の handshake を含む）、後の要求は、最初のバイトと前の応答のうち遅い方から数える |
| `response_idle_ms` | 上流への接続が黙っていてよい時間と、client が受け取らない時間の上限。応答の本文の間だけでなく、上流の応答の head を待つ間にも効く（本文を流す要求の、本文を渡し終えるまでは除く）。そのため、本文をためる要求では、`upstream_header_ms` をこれより長くしても効かない |
| `conn_total_ms` | client の1本の接続の時間の上限（accept から）。`stream` を持つ経路の応答だけは、これを越えて続けられる |
| `stop_inspect_ms` | 停止で、検査を終えるまでの時間（下の「停止」） |
| `stop_wait_ms` | 停止で、接続の終わりを待つ時間 |
| `keepalive_timeout_ms` | 応答の後に、次の要求を待つ時間。0 なら、応答のたびに閉じる |
| `keepalive_time_ms` | 接続を使い回せる時間（accept から）。この後に答える要求の応答で閉じる |
| `lingering_time_ms` | 接続を閉じる前に、client がまだ送るものを読んで捨てる時間の上限 |
| `lingering_timeout_ms` | 同じく、次の読みを待つ時間の上限。HTTP/2 では、`GOAWAY` の後に client を待つ時間と、stream の無い接続を残す時間にもなる |
| `upstream_keepalive_timeout_ms` | 上流への接続が、使い回しを待つ時間 |

### `proxy.listeners`

1つの待ち受けは `{"address", "tls"?, "redirect"?}` である。

- `address`: IP の literal と port（IPv6 は `[..]:port`）。port 0 は断る。
- どちらも無いとき: 普通の待ち受け。HTTP で受け、上流へ転送する。
- `tls` があるとき: TLS を終えてから同じことをする。
- `redirect` があるとき: すべての要求に https への redirect（308）か 404 で答え、何も転送しない。
- `tls` と `redirect` は一緒に書けない。
- 待ち受けの間の決まり:
  - 普通の待ち受けか `tls` の待ち受けが、少なくとも1つ要る。
  - `redirect` の待ち受けがあるなら、`tls` の待ち受けも要る。
  - 2つの待ち受けで同じ address は書けない。片方が `0.0.0.0` や `::` で、もう片方と同じ port のものも書けない。

`tls` は `{"min_version", "certificates", "http2"?}` である。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `min_version` | `"1.2"`、`"1.3"` | 受ける TLS の最も古い版。TLS 1.3 はいつも受ける |
| `certificates` | 1〜16 個 | `{"cert_file", "key_file", "hosts", "acme"?}` |
| `cert_file`、`key_file` | 絶対の path、3840 バイトまで | 証明書の chain と秘密鍵のファイル。起動のときと SIGUSR2 で読む |
| `hosts` | 1〜64 個 | 証明書が受け持つ名前（小文字の英字・数字・`-`・`.`）か、`*.` と名前。IP の literal は書けない。1つの待ち受けの中で同じ host は1回だけ |
| `acme` | `{"renew_before_days"}`（1〜60） | `acme renew` で発行・更新する証明書の印。host に `*.` は書けない。ファイルは起動のときに無くてもよい |
| `http2` | object | HTTP/2 を受ける（下の `http2`）。無ければ HTTP/1.1 だけ |

- `cert_file` と `key_file` は、起動のときと SIGUSR2 で、次を確かめる。
  - どちらも 1 MiB までの普通のファイルである。
  - 証明書のファイルは PEM の証明書を 1〜10 枚持ち、先頭が host の証明書である。鍵のファイルは鍵をちょうど1つ持つ。
  - 鍵が先頭の証明書と対になり、先頭の証明書が `hosts` のすべてを受け持つ。
  - 有効期間は確かめない。
- handshake では、client が送った server name で、`hosts` から証明書を選ぶ。名前が、wildcard より先に当たる。server name の無い handshake と、合う host の無い handshake は失敗する。
- `*.` と名前は、名前の前のちょうど1つの label に当たる（`*.a.example` は `www.a.example` に当たり、`a.example` と `x.y.a.example` には当たらない）。英字の大小は区別しない。
- TLS の接続の要求は、`Host` が handshake で使った証明書の host に入っていなければ 421 で答える（経路を引く前）。

`http2` の5つの鍵は、すべて書く。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `max_streams` | 1〜256 | client が同時に開ける stream の数 |
| `stream_window` | 65535〜1 MiB | stream の受信の window |
| `connection_window` | 65535〜4 MiB | 接続の受信の window |
| `max_header_list` | 1 KiB〜`4 × max_head_bytes` | 要求の field を展開した後の大きさ |
| `send_buffer` | 1 KiB〜1 MiB | stream ごとに、送るのを待つ応答のバイト数 |

- 1本の接続が持てる量にも、上限がある。
  - `connection_window + max_streams × (send_buffer + 32 KiB)` は 16 MiB まで。
  - stream ごとに `max_header_list` と `upstream_max_head_bytes` を足しても、16 MiB まで。
- この量は `max_buffered_bytes` に入らない。接続ごとにこれだけ持てるので、全体では `max_conns` 倍になる。たとえば上の例の値では、1本あたり約 12.3 MiB で、256 本なら約 3 GiB になりうる。`max_conns` と合わせて決める。
- HTTP/2 では、`keepalive_requests` と `keepalive_time_ms` は目安である。
  - 接続を閉じる知らせ（`GOAWAY`）の前に client が同じ書き込みで送った stream は、受け付け済みになる。
  - `GOAWAY` の後も、`lingering_timeout_ms` の間は新しい stream を受ける。
- HTTP/2 は TLS の待ち受けで、client が handshake で `h2` を選んだときだけ話す。平文の HTTP/2（h2c）は話さない。

`redirect` は `{"https_port"}`（1〜65535）である。

- redirect の先は `https://<Host の名前>:<https_port><target>` で、target は受けたままである。`https_port` が 443 なら port は書かない。`Host` に書かれた port は使わない。
- redirect するのは、`Host` がどれかの TLS の待ち受けの証明書の host に入り、かつ経路（または既定の組）が要求に当たるときだけである。
- `Host` が IP の literal のとき、読めないとき、そうして受け持たない名前のときは 404 になる。
- 本文は読まない。
- ACME の challenge の要求には、redirect より先に答える（下の「ACME」）。

### `forward`

```text
{"resolve_timeout_ms", "upstreams": {"<名前>": {..}}, "routes": [..], "default_upstream"}
```

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `resolve_timeout_ms` | 1 ms〜3600 s | 起動のときに、上流の server の名前を引き終える時間 |
| `upstreams` | 1〜64 組 | 組の名前（1〜64 文字の英字・数字・`-`・`_`）から `{"servers", "tls"?}` へ |
| `routes` | 0〜1024 個 | 要求の `Host` と path から組を選ぶ経路 |
| `default_upstream` | 組の名前か空の文字列 | どの経路にも当たらない要求の組。空なら、そうした要求は 404 |

server は `{"address", "weight", "max_fails", "fail_timeout_ms", "backup"}` で、すべての鍵を書く。1つの組に 1〜64 個書ける。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `address` | IP の literal と port、または名前と port（`name:port`） | 名前は、小文字の英字・数字・`-`・`_`・`.` で 253 バイトまで。各 label は 1〜63 バイトで、最後の label は英字で始まる。port は 1〜65535 で、先頭に 0 を付けない。IP の literal には、未指定の address（`0.0.0.0`、`::`）、multicast の address、待ち受けの address（待ち受けが未指定の address なら、その port の loopback）は書けない |
| `weight` | 1〜100 | 重み |
| `max_fails` | 0〜100 | `fail_timeout_ms` の中にこの回数失敗したら、server を `fail_timeout_ms` の間外す。0 なら数えない |
| `fail_timeout_ms` | 1 ms〜3600 s | 上の失敗を数える時間と、外す時間 |
| `backup` | true、false | ほかのどの server も使えないときだけ使う |

- 名前は起動のときに1回だけ引き、その後は引き直さない（SIGUSR1 でも引き直さない）。
  - 名前の address が変わったら（コンテナの名前など）、proxy の起動し直しが要る。
  - 名前の address はどれも、書いた server と同じ値を持つ、組の server になる。名前を引いた後で、組の server は 64 個までである。
  - 名前が引けないとき、address が無いとき、未指定・multicast・待ち受けの address を指すとき、時間の中に引き終わらないときは、起動しない。
- server は、使える server の中から、重みに合わせて順に選ぶ（smooth weighted round robin）。
- 組の server が1つだけなら、外さない。組のどの server も使えないときは、何も試さずに 502 にする。
- 次のときは、server の失敗として数える。
  - 接続を断られた・切られた、届かない、`upstream_connect_ms` の中につながらない（TLS の handshake の失敗も含む）
  - 要求を送れない、`upstream_header_ms` の中に応答の head が来ない、head の途中で切れた
- 読めない応答、大きすぎる応答、上流が返した状態コードは、server の失敗にしない。
- 使い回しを待っていた接続で要求を送れなかったときは、server の失敗に数えない（server が待ちの間に閉じただけかもしれない）。2回送っても害の無い method は、同じ server への新しい接続で1回だけ送り直す。ほかの method は送り直さず、502 にする。
- 失敗の後に次の server へ回すのは、次の2つのときだけである。
  - 接続が作れなかった（何も送っていない）
  - 2回送っても害の無い method（GET、HEAD、OPTIONS、PUT、DELETE、TRACE）
- 本文を流す要求は、接続が作れなかったときのほかは、送り直さない。
- 次のときは、server の失敗にせず、ほかの server へも回さない。
  - 要求の時間（`request_total_ms`）が尽きて切れた段。遅い client が server を組から外せないようにするため。
  - proxy 自身が接続を作れない（file descriptor や port が尽きたなど）。503 で答える。

組の `tls` は `{"ca_file", "server_name"?}` である。

- 組のすべての server へ、TLS でつなぐ。server の証明書は必ず確かめ、確かめを外す設定は無い。
- `ca_file` は、信じる root の証明書を持つ PEM のファイルである。絶対の path で 3840 バイトまで、ファイルは 1 MiB までで、1〜100 枚を持つ。起動のときに1回だけ読む。
- `server_name` は、小文字の名前で、TLS が使える形であること。あれば、server をその名前で確かめる。無ければ、書いた名前で確かめる。IP の literal で書いた server は、その address で確かめる。
- 上流へは TLS 1.2 と 1.3 で、ALPN は `http/1.1` だけである（上流へ HTTP/2 は話さない）。client の証明書は送らない。

経路は `{"host"?, "path"?, "upstream", "access"?, "rewrite"?, "stream"?, "max_body"?}` である。

| 鍵 | 意味 |
|---|---|
| `host` | 小文字の名前と、任意で `:port`（`*.` と port を含めて 253 バイトまで）。port を書けばその port だけに、書かなければどの port にも当たる。`*.` で始めると、前の1つ以上の label に当たる |
| `path` | `/` で始まる 1〜255 バイトの path。`/` で終われば、それで始まる path すべてに当たり、そうでなければその path だけに当たる。使えるバイトは英数字と `-._~!$&'()*+,=:@/%` で、`%` の後は16進数2桁。読み方が複数ある形（下の「`access` を使うときの注意」）は書けない |
| `upstream` | 組の名前 |
| `access` | `{"deny_cidrs"?, "allow_cidrs"?}`。それぞれ 256 個までの network |
| `rewrite` | 上流へ送る要求と、返す応答の書き換え（下） |
| `stream` | `{"idle_ms", "total_ms", "websocket"}`。3つとも書く（下の「長い応答と WebSocket」） |
| `max_body` | その経路の本文の上限。`proxy.max_body` 以下で、下げることしかできない。0 なら本文を受けない |

- 経路は、要求の `Host` と、target の最初の `?` までを、受けたバイトのまま比べる。
  - デコードや整形はしない。path の英字の大小は区別する。
  - host の英字の大小は区別せず、名前の末尾の `.` は1つ落とす。
- 同じ `host` と `path` の経路は、2つ書けない。
- 読み方が複数ある path の target（下の「`access` を使うときの注意」に挙げた形）は、`path` を持つ経路には当たらない。host だけの経路か、既定の組へ回る。
- 当たる経路のうち、最も詳しいものを使う。
  - 先に host で決める。名前が wildcard より先、長い wildcard が短いものより先、port のある経路が無いものより先、host のある経路が無いものより先である。
  - 次に path で決める。その path だけの経路が接頭辞より先、長い接頭辞が短いものより先、path のある経路が無いものより先である。
- 既定の組には、`access`・`rewrite`・`stream`・`max_body` は無い。
- 経路を引いた後、本文を読む前と検査の前に、次を答える。
  - どの経路にも当たらず既定の組も無い: 404
  - `access` に断られた client: 403
  - `Content-Length` が経路の `max_body` を超える: 413
- `access`: client の address（下の「client の address」）が `deny_cidrs` に入れば断る。`allow_cidrs` が空でなく、そこに入らなければ断る。

`access` を使うときの注意:

- 経路は受けたバイトで引くが、上流のアプリケーションは別の綴りを同じ path と読むことがある（`/priv%61te/x` を `/private/x` と読むなど）。そのため、どれかの経路が `access` を持つ間は、要求は「その要求と取り違えられうる経路」すべての `access` に通らなければならない。
- どれかの経路が `access` を持つ間は、次の要求は、`Host` が当たる経路（host を持たない経路を含む）のどれかの `access` の外の client には 403 になる。
  - path（`?` より前）が読み方を複数持つ target。`\`、`;`、`//`、`.` か `..` の段、`%2e`・`%2f`・`%5c`・`%00`・`%25`（大小どちらも）を含むもの、escape を置き換えると別の escape になるもの（`%2%65` など）
  - 読めない `Host`（すべての経路が対象になる）
- `access` を持つ経路の path は、escape を大文字で書き、そのまま書けるバイトを escape にしない形（正規の形）で書く。
- どれかの経路が `access` を持つなら、どの経路の `host` にも port は書けない。
- 末尾の `/` は足すだけで取らない。完全一致の経路 `/admin` の制限は `/admin/` には効かないので、上流が同じに扱うなら両方を書く。
- path の英字の大小は区別する。大小を区別しない上流では、制限は書いた綴りにだけ効く。

`rewrite` は `{"host"?, "path"?, "query"?, "request_headers"?, "response_headers"?}` である。

- `host`: 上流へ送る `Host`。経路の `host` と同じ形で、wildcard は書けない。
- `path`: 経路の path の置き換え。`path` を持つ経路にだけ書ける。経路の path が `/` で終わるなら、その後の target（query を含む）をそのまま新しい path の後ろに付ける。新しい path も `/` で終わる。そうでなければ path を置き換え、query は残す。
- `query`: `{"remove"?, "remove_prefixes"?, "set"?, "add"?}`。名前の比較は ASCII の大小を区別しない。名前の後ろに `[` が続く項目（`debug[]` など）も同じ名前とする。
- `request_headers`・`response_headers`: `{"remove"?, "set"?, "add"?}`。`remove` は名前の一覧、`set` と `add` は `{"name", "value"}` の一覧である。`set` は同じ名前の field をすべて外して1つ入れ、`add` は後ろに足す。
- query、要求の field、応答の field は、それぞれ 32 項目まで書ける。
- 要求の field では、次のものは書けない。
  - `_` を含む名前
  - 接続に属する field（`Connection`、`Keep-Alive`、`Transfer-Encoding`、`Upgrade` など）
  - client の address を伝える field（`X-Forwarded-For`、`X-Forwarded-Proto`、`X-Real-IP`、`Forwarded` など）
  - `Host`、`X-Forwarded-Host`、`X-Request-ID`
  - 本文の長さと型を伝える field（`Content-Length`、`Content-Type`、`Content-Encoding`）
- 応答の field では、接続に属する field、`Set-Cookie`、`X-Request-ID`、本文の長さと型と範囲を伝える field（`Content-Length`、`Content-Type`、`Content-Encoding`、`Content-Range`）は書けない。proxy が自分で作る答えは書き換えない。
- 書き換えの順は、要求の field、`Host`、target（path、次に query）である。`X-Forwarded-Host` は、その前に client が送った `Host` から作る。
- 書き換えは、経路を引いて検査した後に1回だけする。そのため、WAF の規則と除外、検査しない経路、`access` は、公開側（書き換えの前）の path と `Host` で書く。2つの公開の接頭辞が同じ内部の path に入るときも、片方の公開の path に向けた規則は、もう片方には効かない。
- form の本文の引数は、`query` の書き換えの対象ではない。
- 書き換えられない要求（新しい target が長すぎるなど）は送らない。server の失敗にもしない。

#### 長い応答と WebSocket（`stream`）

- `total_ms`（1 ms〜24 時間）: 応答の head の後、接続を少なくともこの時間は続ける。WebSocket の tunnel は、101 から `total_ms` で必ず終わる。
- `idle_ms`（1 ms〜`total_ms`）: 上流が黙っていてよい時間。
- `websocket`: WebSocket の握手を通すか。
- `stream` を持つ経路の応答は、その接続の最後の応答になる。接続の終わりは、もとの終わり（accept から `conn_total_ms`）と、応答の head から `total_ms` の後のうち、遅い方になる。`total_ms` が接続の残りの時間より短くても、応答はそこでは切れない。
- WebSocket の握手の GET は、ほかの要求と同じく検査する（検査しない経路なら検査しない）。101 の後の WebSocket の frame は検査せず、写すだけである。
- 握手の前に、tunnel の分の予算（16 KiB）を取る。取れなければ、何も送らずに 503 で答える。
- tunnel は次のときに終わる。
  - 両方の向きが終わった
  - 上流が `idle_ms` の間何も送らない。どちらかへの書き込みが `response_idle_ms` の間進まない（両方の向きが開いている間は、client は黙っていてよい）
  - 片方の向きが終わってから `idle_ms` の中に、もう片方が終わらない（その間にどれだけ動いていても終わる）
  - 101 から `total_ms` が過ぎた
  - 読み書きが失敗した、上流の接続を引き継げない、101 を client へ送れない
  - 停止で接続が打ち切られた
- WebSocket を通さない経路への `Upgrade` の要求（`Upgrade: h2c` も含む）は、tunnel にしない。`Upgrade` を外して普通の要求として転送し、応答の後に閉じる。上流が頼んでいない 101 を返したら 502 にする。
- `CONNECT` は 400 で断る。

### client の address

- `trusted_proxies` に入る相手からの要求では、その `X-Forwarded-For` の行を、1つの一覧として右から左へ読む。
  - 信じる proxy の address は飛ばし、最初の、信じる proxy でない address を client とする。
  - すべてが信じる proxy なら、いちばん左を client とする。
  - IP の literal でない項目があれば、そこで読むのをやめ、相手を client とする。
- 信じない相手からの要求では、相手が client である。その `X-Forwarded-For` などの申告は捨てる。
- この client の address を、検査、`access`、記録に使う。

上流へ送る要求には、次の field を付ける。

| field | 中身 |
|---|---|
| `X-Forwarded-For` | 信じる相手からの要求: 受けた行に相手の address を足したもの。ほか: 相手の address だけ |
| `X-Forwarded-Proto` | 信じる相手が `http` か `https` ちょうどを送ったときはそれ。ほか: 待ち受けの scheme（TLS の待ち受けは `https`、ほかは `http`） |
| `X-Forwarded-Host` | client が書いた `Host`（相手を問わない） |
| `X-Request-ID` | 要求の番号（下の「記録」の `id`）。client が送ったものは、相手を問わず捨てて置き換える |

### `kernel`

検査核と検査プロセスの設定である。時間は、どれも 1 ms〜3600 s の範囲で書く。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `inspector` | 絶対の path | 検査プロセスの実行ファイル |
| `tmp_root` | 絶対の path、3840 バイトまで | 起動ごとの作業場所を作る親。本物のディレクトリで、持ち主が proxy の利用者、group と other の権限が無く、setgid が無いこと |
| `gomaxprocs` | 1〜65535 | 検査プロセスの `GOMAXPROCS` |
| `gomemlimit` | 1〜9223372036854775807（バイト） | 検査プロセスの `GOMEMLIMIT` |
| `slots` | 1〜4 | 同時に検査する要求の数 |
| `wait_queue` | 1 以上、`max_conns` 以下 | 検査の枠を待つ要求の数 |
| `records` | `slots + wait_queue` 以上 | 同時に持つ要求の記録の数 |
| `discard_limit` | `u32` の最大値より小さい | 検査プロセスの1回の起動で捨ててよい応答の数。超えると接続の誤りとする |
| `tick_ms` | 1 s まで、ほかのどの時間以下 | 1歩の待ちの最長 |
| `hello_wait_ms` | | 検査プロセスの起動から、最初の知らせ（HELLO）までの時間 |
| `frame_io_ms` | | 1つの frame の書き込みと、最初のバイトの後の読みの時間 |
| `verdict_wait_ms` | | 検査プロセスが判定を返すまでの時間 |
| `wait_deadline_ms` | | 要求が検査プロセスに渡るまでの時間 |
| `closed_wait_ms` | | 要求を閉じてから、閉じた知らせまでの時間 |
| `stop_after_ms` | | 判定を待つのをやめた（`verdict_wait_ms` が過ぎた）とき、または終わりの知らせを渡したときから、検査の枠が返らないままこの時間が過ぎると、検査プロセスを止める |
| `drain_wait_ms` | | 終わりの合図から、検査プロセスの終わりの知らせ（BYE）までの時間 |
| `exit_wait_ms` | | 終わりの知らせの後に、検査プロセスが自分で終わるのを待つ時間 |
| `kill_grace_ms` | | SIGKILL の後、終わりが見えるまでの時間 |
| `restarts` | 0〜1000 | `restart_window_ms` の中で起動し直してよい回数。0 なら起動し直さない |
| `restart_window_ms` | | 起動し直しの回数を数える窓 |

- 検査プロセスの起動し直しには、窓の中の回数の上限がある。上限に達したら窓が空くまで起動し直さず、その間に待つ要求は 503 になる。
- ルールの誤りなど、決まって失敗する理由では起動し直さない。要求を渡している検査核が止まると、proxy も止まる（`stop: the kernel failed`）。

### `rules.store`

- `{"kind": "file", "dir"}` と書く。`kind` は今は `file` だけである。
- `dir` は絶対の path で 3840 バイトまでである。本物のディレクトリで、持ち主が proxy の利用者、group と other の権限が無いこと。

### `acme`

`acme` を持つ証明書があるときだけ書き、そのときはすべての鍵を書く。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `directory_url` | `https://` の URL、2048 バイトまで | CA の ACME の directory |
| `contact_email` | 254 バイトまで | CA に届ける連絡先。形だけを確かめる |
| `account_key_file` | 絶対の path | ACME の account の鍵。無ければ命令が作る（0600） |
| `challenge_dir` | 絶対の path | challenge のファイルを置くディレクトリ |
| `ca_file` | 絶対の path | CA の server 証明書を確かめる root（上流の組の `ca_file` と同じ形。1〜100 枚） |
| `timeout_ms` | 1 ms〜600 s | 命令全体の時間 |

- `account_key_file`、`ca_file`、`acme` を持つ証明書の `cert_file`・`key_file` は、すべて別のファイルにする。`acme` を持たない証明書の `cert_file`・`key_file` も、これらのどれとも別のファイルにする。
- `challenge_dir` の直下に、これらのファイルや、ほかの証明書の `cert_file`・`key_file` を置かない。
- 普通の待ち受けか redirect の待ち受けが、少なくとも1つ要る（CA は平文の HTTP で challenge を取りに来る）。

### `status`

監視の待ち受け（下の「監視」）を置くときだけ書く。省けば、監視の待ち受けは無い。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `listen` | loopback の IP（`127.0.0.0/8` か `::1`）と port（0 は不可） | 監視の待ち受けの address |

- 答えに認証が無いので、同じ host の監視の program から使う。`::ffff:127.0.0.1` の形は loopback と見なさない。
- 待ち受け（`proxy.listeners`）と重ならない（待ち受けどうしと同じ決まり。`0.0.0.0`・`::` と同じ port も重なる）。
- 上流の server（書いた address も、名前を引いた address も）は、この address にできない。待ち受けの address と同じく断る。
- 待ち受けの数（1〜8）にも、「普通か TLS の待ち受けが少なくとも1つ」にも数えない。

### 値どうしの関係

起動と `config check` は、値の範囲のほかに、次の関係を確かめる。

| 関係 | 理由 |
|---|---|
| `inspect_body ≤ max_body` | 検査するのは本文の先頭 |
| `max_body ≤ max_body_wire ≤ 2 × max_body + 4 MiB` | chunked の本文は、枠の分も回線に載る |
| `max_buffered_bytes ≥ 2 × inspect_body + 24 KiB + 32 KiB` | 1つの要求がためる最大: 検査する先頭、検査核の写し、field、流している途中のかけら |
| `routes[].max_body ≤ max_body` | 経路は下げるだけ |
| `http2.max_header_list ≤ 4 × max_head_bytes` | 展開した後の field の大きさ |
| `connection_window + max_streams × (send_buffer + 32 KiB) ≤ 16 MiB` | 1本の HTTP/2 の接続が持てる量 |
| 上に `max_streams × (max_header_list + upstream_max_head_bytes)` を足しても 16 MiB 以下 | 同上（stream ごとの field と、上流から読むかけら） |
| `upstream_head_wire ≥ 2 × upstream_max_head_bytes` | 上流の head の読み |
| `drive_slice ≤ tick` | driver の1回は、検査核の1歩より短い |
| `ready_wait ≥ hello_wait` | 準備の待ちは、検査プロセスの最初の知らせの待ちを含む |
| `head_read ≤ request_total`、`body_read ≤ request_total` | 要求の時間の中の段 |
| `inspect_wait ≥ wait_deadline + 2 × verdict_wait + 18 × (drive_slice + frame_io)` | 1つの検査に要る最短の時間 |
| `inspect_wait ≤ request_total` | 要求の時間の中の段 |
| `upstream_connect + upstream_header < request_total` | 上流とのやり取りの2つの段は、要求の時間の中で終わる。`upstream_header` は、`response_idle` より長くしても、本文をためる要求では効かない（上の `response_idle_ms`） |
| `request_total ≤ conn_total`、`response_idle ≤ conn_total`、`keepalive_timeout ≤ conn_total` | 接続の時間の中の段 |
| `upstream_keepalive_timeout ≤ response_idle` | 使い回しを待つ接続も、読みの idle の上限に掛かる |
| `keepalive_time + request_total ≤ conn_total` | `keepalive_time` の前に始まった要求は、接続の時間の中に応答の head を受ける |
| `lingering_timeout ≤ lingering_time` | 閉じる前の読み |
| `stop_inspect < stop_wait`、`stop_inspect + kill_grace < stop_wait` | 停止の段の順 |
| `wait_queue ≤ max_conns` | 1つの接続が持つ検査は1つ |
| `records ≥ slots + wait_queue` | 検査核の記録 |
| `tick ≤ 1 s`、`tick` はほかの検査核のどの時間以下 | 検査核の1歩 |

- 時間の関係は `_ms` を外した名前で書いた。

## 本文と予算

- 推す値は、`max_body` が 100 MiB、`inspect_body` が 16 KiB である。`inspect_body` は、検査の重さを測ってから決め直す予定である。
  - 1 vCPU のホストでは、1 MiB 近い JSON の検査に約 7 秒かかった。
  - 検査の時間が `verdict_wait_ms` を超えると、要求は 503 になる。検査プロセスは、503 を返した後も、その検査が終わるまで CPU を使う。
  - さらに `stop_after_ms` を超えると、検査プロセスは止められて起動し直す。その間はほかの要求も 503 になり、起動し直しの回数（`restarts`）も使う。
- 本文が `inspect_body` で終わるなら、全体をためて検査し、検査した形で転送する。
- 長い本文は、先頭の `inspect_body` バイトだけを検査する。許されたら、残りを client が送るとおりに上流へ流す（ためない）。
  - 先頭より後ろは検査しない。
  - 流す本文は、client が使った枠（長さか chunked）のまま送る。
- 検査しない経路の本文は、`inspect_body` で終わればためて転送し、長ければ同じく流す。
- gzip の本文:
  - 検査する経路: 全体をためてほどく。gzip のままの長さも、ほどいた長さも、`inspect_body`（経路の `max_body` がそれより小さければ、その値）までで、どちらかが超えれば 413。gzip として読めない本文、gzip の後ろに続くバイト、空の gzip の本文は 400。ほどいた本文を `Content-Encoding` 無しで検査し、そのまま転送する。
  - 検査しない経路: ほどかない。ほかの本文と同じに扱い、上限は gzip のままの長さで数える。
- chunked の本文を流している途中で `max_body` を超えたときは、413 は返せない（上流へ送り始めている）。上流への要求を切り、client の接続を閉じ、記録に理由を書く。
- 予算（`max_buffered_bytes`）:
  - 本文を流す1つの要求が持つのは、検査の間は、先頭の `inspect_body`、検査核の写し（先頭と field）、流すための小さな buffer（32 KiB）である。判定が出た後は、先頭の `inspect_body` と 32 KiB の buffer だけになる。本文の長さでは増えない。検査しない経路には、検査核の写しは無い。
  - 同時に進む要求の数だけ要るので、予算は、同時に来ると見込む最大の数に合わせて決める。
  - 予算の外にも、上流の接続の読みの buffer（`upstream_max_head_bytes` まで）に、流している本文が入る。本文の長さでは増えないが、同時に流す要求の数だけ増える。
  - HTTP/2 の window と buffer も予算の外である（上の `http2`）。
- 大きな送信の時間:
  - `request_total_ms` は、本文を受け終えて応答の head が来るまでを含む。たとえば 100 MiB を 60 秒（`request_total_ms` 60000）で受けるには、約 14 Mbit/s が要る。大きな送信を受けるなら、回線の速さに合わせて大きくする。
  - `upstream_header_ms` は、本文の最後のかけらを上流へ渡してから数える。上流が大きな送信を長く処理するなら、大きくする。
  - 本文を流している間、client の読みと読みの間は `body_read_ms` までである。

## ルールセットと世代

- 世代は、`rules import` が作るルールセットの一式で、指紋（manifest の sha256）で呼ぶ。作った後は変えない。
- 保管場所の中身:
  - `generations/<指紋>/`: 世代
  - `current`: 選んだ世代
  - `using/<指紋>`: 使用中の印
  - `staging/`: 取り込みの途中
  - `lock`: 命令の lock
- 命令は一度に1つだけ保管場所を変えられる。途中で止まった命令の残りは、次の命令が片付ける。
- 指紋が捕まえるのは、事故による壊れと取り違えと、動いている proxy が覚えている指紋と中身が違う起動である。同じ利用者のプロセス（検査プロセスも同じ利用者）が保管場所を書き換えることは防がない。起動し直しをまたいだ認証でもない。
- 起動の後に使っている世代のファイルが壊れると、検査プロセスの次の起動し直しが失敗する（ファイルが manifest と違えば exit 11、manifest が替われば指紋の不一致）。そのとき、検査核は決まった失敗として止まり、proxy も止まる。

### 検知だけのモード

- `rules import --detect-only` で作った世代は、規則に当たった要求も通す。要求の記録は class `forwarded`、reason `detected by a rule` で、`rule` に当たった規則の id が入る。
- 遮断の世代と同じルールのファイルで、遮断するかどうかだけが違う。最初はこの形で動かし、誤検知を見て除外を足してから、遮断の世代を取り込み直すとよい。
- 検知だけの世代でも、下の「検査プロセスが足す決まり」の規則は遮断する。
- 検知だけの世代は、ルールの前と後に印の規則（id 4000010、4000011）を足す。運用者の規則でこれを消したり飛ばしたりすると、その要求は検査できないとして 503 になる。黙って遮断や素通しにはならない。

### 検査プロセスが足す決まり

運用者のルールの後に、検査プロセスが次を足す。運用者のルールで替えることはできない。

- 検査の engine は On、本文は読む、本文の上限を超えたら断る、JSON の入れ子は 64 段まで。
- 規則の id 4000001〜4000003（本文の解析の失敗、引数の数の上限、URI の解析の失敗で遮断する）は、すべての世代で検査プロセスが使う。4000010・4000011 は、検知だけの世代で使う。運用者の規則で同じ id を使うと、その世代のルールセットは組めない。遮断の世代では 4000010・4000011 を使っても組めるが、検知だけの世代に取り込み直せなくなるので、使わない。
- 次のものを含むルールは断る。判定は文字の並びだけで、大小を区別せず、`msg` の中の語にも当たる。
  - `Include`、`SecIgnoreRuleCompilationErrors`（引数が `Off` でも）
  - 名前が `SecAuditLog`・`SecDebugLog`・`SecUpload` で始まる指示
  - `ctl:ruleEngine`・`ctl:requestBodyAccess`・`ctl:requestBodyLimit`
  - `@inspectFile`・`@rbl`・`setenv:`
  - 変数の名前 `reserved_body_cut`
- 運用者の規則が本文の処理（`ctl:requestBodyProcessor` など）を替えたり、上の規則を実行時に外したりして、検査が終わったと確かめられない要求は、503 になる。

### 運用者に任せていること

- `ctl:ruleRemoveById`、`SecRuleRemoveById` などで遮断の規則をわざと外すことは、運用者の方針として断らない。
- ただし `SecRuleRemoveByMsg` は、前に `SecMarker` があると Coraza が異常終了し、ルールセットが組めない（exit 11）。CRS は `SecMarker` を多く使うので、CRS と一緒には使えない。
- 取り込みと検査プロセスが捕まえるのは、marker の事故（無い marker や前にある marker への `skipAfter`、名前の打ち違い）だけである。
- Coraza の推奨の設定にある、`REQBODY_ERROR`・`MULTIPART_STRICT_ERROR` を見る規則（200002、200003）を運用者が足すと、先頭で切った本文も遮断する。本文の途中で切ると、解析が失敗することがあるためである。
  - 検査プロセスの規則 4000001 は、切った本文の解析の失敗では遮断しない。
  - CRS 4.23.0 には、これに当たる規則は無い。
- CRS の既定は、`application/<名前>+json` の本文を遮断する。受けるなら、取り込みの前に `crs-setup.conf` で受け付ける型に足す。

### 検査しない経路

`rules import --routes <file>` のファイルは、次の形の JSON の配列である。

```json
[
  {"host": "app.example.com", "path": "/api/uploads", "action": "bypass"}
]
```

- `host` は省ける。ほかの鍵は取らない。`action` は `bypass` だけである。
- 経路に当たる要求は検査せず、上流へ転送する。
  - proxy が自分でする確かめ（head、本文の型、本文の大きさの上限）は、その前にする。
  - 上流は、検査しない経路ではなく、`forward` の経路か既定の組で選ぶ。そこで 404・403・421 になる要求は、検査しない経路に当たっても答えは変わらない。
  - 検査の枠を取らないので、検査が混んでいるときや、検査プロセスが止まっているときも通る。
- `path` と `host` の形と当たり方は、`forward` の経路と同じである。ほかに次の決まりがある。
  - `path` は `/` だけにはできない（すべての要求の検査を外してしまう）。2〜255 バイトで書く。
  - `host` に wildcard は書けない。
  - 1つの世代で 256 個までで、host と path の同じ組は書けない。
- `host` を持つ検査しない経路は、末尾が `.` の `Host`（`app.example.com.`）には当たらず、検査する。上流がそれを別の host と読むかもしれないためである。`host` を持たない経路は、末尾が `.` の `Host` にも当たる。
- path が読み方を複数持つ要求（「`access` を使うときの注意」に挙げた形）は、検査しない経路に当たらず、検査する。
- 経路は世代の manifest に入り、指紋の一部になる。動いている proxy は、世代の切り替えで経路を替える。

## 要求の扱い

### head の確かめ

要求の head は、HTTP の解析の前に次の順に確かめ、最初に破った決まりで答える。ただし、field が 64 個を超える head は、1・2 より先に 431 になる。

1. 行の終わりは CRLF だけ。head は空の行で始まらない。
2. method は 1〜32 バイトの token で、`CONNECT` ではない。target は `/` で始まり、1〜4096 バイトで、`#` を持たない。path に `<`・`>`・`` ` ``、query に `"`・`<`・`>` を持たない。版は `HTTP/1.1` か `HTTP/1.0`。target が長すぎれば 414。
3. field は 64 個まで。名前は 1〜256 バイト、値は 4096 バイトまで、名前と値の合計は 24 KiB まで。値に HTAB のほかの制御文字を持たない。超えれば 431。
4. 空でない `Host` がちょうど1つ。
5. `Transfer-Encoding` と `Content-Length` を一緒に持たない。`Transfer-Encoding` は `chunked` ちょうどの1行で、`HTTP/1.0` の要求は持たない。`Content-Length` は数字の1行で、本文の上限を超えない（超えれば 413）。
6. `Expect` は無いか、`100-continue` ちょうどの1行。違えば 417。
7. `Connection` は token の一覧で、`host`、`content-length`、`content-type`、`content-encoding` を挙げない。
8. `Content-Encoding` は無いか、`gzip` ちょうどの1行。違えば 415。空でない本文は、`Content-Type` をちょうど1つ持ち、それは次のどれかである（`;` より前を、大小を区別せずに比べる）。違えば 415。
   - `application/x-www-form-urlencoded`
   - `multipart/form-data`
   - `application/json`
   - `application/<名前>+json`（名前は 1〜122 バイトの英数字・`.`・`-`）

ほかの違反は 400 になる。断るときの応答は本文が無い。

- HTTP/1.1 の接続の最初の要求では、応答を返して接続を閉じる。
- 2つ目からの要求の head を断るときは、応答を返さない。前の応答を送り終えてから接続を閉じ、記録は class `closed`、status 0 の接続の記録になる。
- HTTP/2 の stream の field も、HTTP/1.1 の head の形に書き直してから、同じ決まりで確かめる。断るときは、その stream にだけ応答を返し、接続は続ける。

- 名前に `_` を含む field は、検査もせず転送もしない。上流の多くのサーバーは `X_Forwarded_For` と `X-Forwarded-For` を同じ変数に読むので、client がその名前で proxy の付ける address を装えないようにするため。
- `Expect: 100-continue` は受けるが、検査する形にも、上流へ送る要求にも入れない。proxy は、本文を読み始めるときに 100 を返す。
- 要求の trailer は受けない（400）。
- HTTP/1.1 の接続では、次の要求がその接続の最後の要求になる。
  - chunked の要求、`Upgrade` を持つ要求
  - HTTP/1.0 の要求（応答も HTTP/1.0 で返す）
  - `Connection: close` の要求
  - 本文を読み終えないまま答えた要求（本文を持ったまま 403・404・421 で断った要求など）
- 前の要求の後の、次の head の前の空の行は、2つまで捨てる。

### 転送の前に外すもの

接続に属する field（`Connection` とそれが挙げるもの、`Keep-Alive`、`TE`、`Transfer-Encoding`、`Upgrade`、`Expect` など）と `Proxy-Authorization` は外す。その後に上の「client の address」の field を付けるので、client が名前を挙げて外させることはできない。上流の応答の trailer は、client へ送らない。

### 答え

| 状態 | とき |
|---|---|
| 規則の状態コード | 規則が遮断した（200〜599 の外なら 500） |
| 400、408、413、414、415、417、431 | head か本文が断られた |
| 403 | 経路の `access` に断られた |
| 404 | 当たる経路も既定の組も無い。redirect しない `Host` |
| 421 | `Host` が TLS の証明書に入っていない |
| 502 | 上流につながらない、上流の応答の誤り、上流の時間切れ、組のどの server も使えない |
| 503 | 検査できない（検査プロセスが使えない、検査の待ちが満ちた・時間切れ）、予算が尽きた、要求の時間が尽きた、proxy 自身が上流への接続を作れない |
| 500 | proxy の中の不整合（記録に `internal fault` の行も出る） |

proxy が自分で作る答えは、本文が空で `Content-Length: 0` を持つ（204・304 は `Content-Length` を持たない）。ACME の challenge の 200 は、そのファイルを本文に持つ。

proxy が返すすべての応答（上流の応答、遮断、head の拒否、redirect も含む）は、要求の番号を `X-Request-ID` に1つ持つ。上流の応答に同じ名前の field があれば置き換える。番号は、その要求の記録の `id` と同じなので、断られた人が番号を伝えれば記録を引ける。

## 記録

記録は、標準エラーに1行1件の JSON で出る（systemd では journal）。短い命令（`config check`・`rules`・`acme`）の出力は、人が読む文の行のままである。

どの記録も、次の2つの項目で始まる。値の無い項目は書かない（`null` にしない）。

| 項目 | 中身 |
|---|---|
| `ts` | 記録した時刻。UTC の RFC 3339 で ms まで（例: `2026-10-27T03:53:27.123Z`） |
| `type` | `request`、`connection`、`tunnel`、`line`、`dropped` のどれか |

### 要求の記録（`request`）

client へ答えを書いた要求ごとに1件出る。head の拒否、redirect、ACME の challenge の答えも含む。応答を送り終えたとき（または切れたとき）に書くので、長い応答の記録は応答の終わりに出る。

```text
{"ts":"2026-10-27T03:53:27.123Z","type":"request","id":"0186af5443bddbd9-1","conn":1,"listener":0,"proto":"h1","tls":false,"client":"192.0.2.10","method":"GET","host":"example.com","path":"/q","class":"blocked","status":403,"reason":"blocked by a rule","ms":3,"mode":"block","generation":"2f3bda9b9ca7db60","rule":949110,"rules":[941100,941110],"severity":2,"score":10,"sent":0}
```

| 項目 | 中身 |
|---|---|
| `id` | 要求の番号。応答の `X-Request-ID` と、上流へ送る `X-Request-ID` と同じ。起動ごとの乱数の16桁と、要求ごとの通し番号を `-` でつないだもの。HTTP/2 では stream ごとに1つ |
| `conn` | 接続の番号 |
| `listener` | 受けた待ち受けの番号（設定の `listeners` の順で、0 から） |
| `proto` | `h1` か `h2` |
| `tls` | TLS の待ち受けか |
| `client` | 上の「client の address」で決めた address。head を読む前の答えでは、接続の相手の address |
| `method`、`host`、`path` | 要求の method、`Host`（HTTP/2 では `:authority`）、target の `?` より前（受けたまま）。head の確かめに通らなかった要求には無い |
| `cut` | 上限で切った項目の名前の一覧（例: `["path"]`） |
| `class` | 下の表 |
| `status` | 答えた状態コード（何も答えなかったときは 0） |
| `reason` | 決まった英語の語句（例: `malformed request head`、`body over the limit`、`inspection queue full`、`upstream connection failed`） |
| `ms` | かかった時間（ミリ秒） |
| `upstream`、`server` | 上流の組の名前と、最後に試した server の address（試していなければ `server` は無い） |
| `mode`、`generation` | 判定したルールの世代のモード（`block` か `detect`）と、世代の指紋の先頭16桁。検査しなかった要求には無い |
| `rule` | 遮断した規則、または検知だけのモードで当たった規則の id |
| `rules` | ほかに当たった規則の id。評価の順に16個まで。記録しない規則（`nolog`）と、検査プロセスが足す決まり（4000001〜4000011）は入らない |
| `rules_more` | 16個より多く当たったとき `true` |
| `severity` | 当たった規則の重さのうち、いちばん重いもの（0 が最も重い。規則の `severity` の数） |
| `score` | CRS の inbound の anomaly score（`tx.blocking_inbound_anomaly_score`）。0 のときと、CRS の無いルールセットでは無い |
| `body` | 本文の長さ。`Content-Length` があればそれ、無ければそれまでに読んだバイト数（gzip の本文は gzip のままの長さ）。本文の無い要求、経路で断った要求、本文の先頭を読み終えられなかった要求には無い |
| `inspected` | 先頭だけを検査して残りを流した要求の、検査したバイト数。検査しない経路で流した本文には無い |
| `sent` | client へ送った応答の本文のバイト数 |

`class` は次のどれかである。

| class | とき |
|---|---|
| `forwarded` | 上流の応答を返した |
| `blocked` | 規則が遮断した |
| `rejected` | head か本文が断られた。経路で断った 403・404・421 と、redirect の待ち受けの 404 も含む |
| `redirected` | https へ redirect した |
| `answered` | ACME の challenge に答えた |
| `failed` | こちらの理由で答えられなかった（混んでいる、検査できない、上流の失敗） |
| `closed` | 何も答えなかった |

`forwarded` の `reason` は次のどれかになる。

- `forwarded`: 検査で許した
- `detected by a rule`: 検知だけのモードで規則に当たった
- `bypassed by a route`: 検査しない経路
- `closed while the response was sent`: 応答を送り終える前に切れた

要求から来る文字（`method`、`host`、`path`）は、0x21〜0x7e の外のバイトと `"`・`\` を `%XX`（大文字の16進）にしてから、`method` は 32、`host` は 255、`path` は 1024 バイトで切る。`%XX` の途中では切らない。受けた `%` はそのままなので、受けた `%80` とバイトの 0x80 は同じ `%80` になる。

query、本文、`Host` のほかの field（`User-Agent`、`Cookie` など）、規則に一致した値と変数の名前、規則の `msg` は記録しない。path に秘密の値を入れる作りのサイトでは、その値が記録に残る。

### ほかの記録

| type | 項目 | とき |
|---|---|---|
| `connection` | `conn`、`listener`、`client`、`class`、`status`、`reason`、`ms`、`streams` | 答えを書かずに終わった接続（要求の前に閉じた、2つ目からの head を断った、TLS の handshake に失敗したなど）と、HTTP/2 の接続の終わり（`streams` は受けた stream の数） |
| `tunnel` | `id`（tunnel を開いた要求の番号）、`conn`、`client`、`upstream`、`server`、`end`、`ms`、`to_upstream`、`from_upstream` | WebSocket の tunnel が終わった（動く前に終わったときも出る）。`end` は `closed`（両方の向きが終わった）、`idle`、`total`、`error`、`stop`（停止で打ち切った）のどれか。バイト数は handshake の後に各向きで読んだ量 |
| `line` | `line` | 下の表の文。512 バイトまでで、長い文は切る。制御文字は空白にする |
| `dropped` | `count` | 書けずに捨てた記録の数（前の `dropped` の記録の後に捨てた分） |

`line` の文は次のとおり。

| 文 | とき |
|---|---|
| `start: ...` | 起動の各段（`start: rules generation <指紋>`、`start: rules mode <block か detect>`、`start: the kernel is ready`、`start: listening` など） |
| `reload: ...` | SIGUSR1・SIGUSR2 を受けたこと、切り替えと証明書の入れ替えの結果 |
| `driver: inspector incarnation changed, inc <回>, restarts <回>` | 検査プロセスが起動し直した |
| `conn <番号>: internal fault: <理由>` | proxy の中の不整合 |
| `notify: <知らせ> not sent ...` | systemd への知らせを送れなかった |
| `stop: ...` | 停止の理由と、最後の停止の結果 |

### 書けないとき

- 記録は 1024 件の待ち行列に入れ、書くのは1つの thread だけである。要求の処理と停止は、書き込みを待たない。
- 待ち行列が満ちたときは、その記録を捨てて数え、書けるようになってから `dropped` の記録を1件出す。標準エラーを読む側が止まると、こうなる。
- 書き込みの失敗（`/dev/full` など）は、その記録を失い、別に数える。
- どちらの数も、監視の `/metrics` で見られる（`tukuyomi_records_dropped_total`、`tukuyomi_record_write_errors_total`）。標準エラーが詰まっている間は、記録では知らせられない。
- 1件は 4 KiB 未満で、切らない（項目の上限からこの大きさを超えない）。

### 記録を読める人

記録には、client の address と path が入る。journal を読める利用者（root と、Ubuntu では `adm`・`systemd-journal` の組の利用者）は、それを読める。組に入れる人を絞る。保存の期間と容量は journald の設定で決める（[実行ファイルの build と配置](../build/binary-deployment.md) の「systemd」）。

## 監視

設定に `status` を書くと、その loopback の address で次の3つに答える。答えに認証は無い。

| 要求 | 答え |
|---|---|
| `GET /healthz` | 200 `ok`。proxy が答えられることだけを示す |
| `GET /readyz` | 準備ができていれば 200 `ready`。でなければ 503 と理由の語: `starting`（待ち受けを bind する前）、`inspector down`（検査プロセスが動いていない。起動し直しの間も含む）、`stopping`（停止が始まった後） |
| `GET /metrics` | 200 と、下の表の数（Prometheus の text の形、`text/plain; version=0.0.4`） |

- 準備ができているのは、検査プロセスが動いていて、待ち受けを全部 bind し、停止が始まっていないときである。世代の切り替えの間は、古い世代が答えるので準備ができたままである。
- `HEAD` は、同じ状態コードで本文を返さない。ほかの method は 405、ほかの target（query の付いたものも）は 404、HTTP/1.1 でない要求と、4 KiB に収まらない head は 400 で答える。
- 1つの接続で1つの要求に答え、答えたら閉じる。同時に答える接続は 8 つまでで、転送の `max_conns` とは別に数える。それを超えた接続は、受けてすぐ閉じる。head を待つのは 2 秒、答えを書くのは 2 秒までである。
- 監視の要求は、検査も転送もせず、記録もしない。
- 監視の待ち受けは、検査プロセスより前に bind し、停止の 3 の後に閉じる。それまで `/healthz` は 200 を返す。

### 数（`/metrics`）

数は proxy のメモリの中にあり、起動し直すと 0 から数える。label の値は、決まった語か、設定の名前だけである（要求から来る値は label にしない）。

| 名前 | 型 | label | 中身 |
|---|---|---|---|
| `tukuyomi_requests_total` | counter | `class` | 要求の記録の数（`class` は記録と同じ7つ） |
| `tukuyomi_waf_rule_hits_total` | counter | `decision`（`block`、`detect`） | 規則が遮断した要求と、検知だけのモードで規則に当たった要求 |
| `tukuyomi_uninspectable_total` | counter | `reason` | 検査できなかった要求（`invalid`、`queue_full`、`unavailable`、`wait_deadline`、`verdict_deadline`、`inspector_lost`、`protocol`、`inspector_error`、`not_created`、`cancelled`） |
| `tukuyomi_connections_accepted_total` | counter | | 受けた接続 |
| `tukuyomi_connections_open` | gauge | | 開いている接続 |
| `tukuyomi_connection_permit_waits_total` | counter | | 受付が接続の枠を待った回数（`max_conns` に届いた回数の目安） |
| `tukuyomi_tls_handshake_failures_total` | counter | | TLS の handshake の失敗と時間切れ |
| `tukuyomi_body_buffer_bytes` | gauge | | 本文などをためている予算のバイト数（`max_buffered_bytes` のうち使っている分） |
| `tukuyomi_inspections_waiting` | gauge | | 検査の待ちの席を持っている要求（`wait_queue` のうち使っている分） |
| `tukuyomi_inspector_up` | gauge | | 要求を受けている検査核の準備ができていれば 1、でなければ 0 |
| `tukuyomi_inspector_restarts_total` | counter | | 検査プロセスの起動し直し |
| `tukuyomi_rules_generation_info` | gauge | `generation`（指紋の先頭16桁）、`mode` | 要求を受けている世代。値はいつも 1 |
| `tukuyomi_rules_switches_total` | counter | `result`（`switched`、`refused`、`failed`） | SIGUSR1 による世代の切り替え |
| `tukuyomi_certificate_reloads_total` | counter | `result`（`replaced`、`refused`） | SIGUSR2 による証明書の読み直し |
| `tukuyomi_upstream_failures_total` | counter | `group` | 上流の組の server の失敗 |
| `tukuyomi_records_dropped_total` | counter | | 捨てた記録（上の「書けないとき」） |
| `tukuyomi_record_write_errors_total` | counter | | 書き込みに失敗した記録 |
| `tukuyomi_start_time_seconds` | gauge | | 起動した時刻（Unix 時間の秒） |

### systemd への知らせ

環境に `NOTIFY_SOCKET` があれば、待ち受けを全部 bind した後に `READY=1` を、停止が始まったときに `STOPPING=1` を、その socket へ1回ずつ送る。

- `NOTIFY_SOCKET` は、絶対の path か、`@` で始まる名前（Linux の abstract の名前）である。ほかの値なら `start:` の文を1行出し、知らせを送らずに動く。
- 送れなかったときは `notify:` の文を1行出すだけで、動きは変えない。待たずに送るので、受ける側が読まなくても proxy は止まらない。
- 検査プロセスの環境は空なので、検査プロセスは知らせを送らない。
- unit を `Type=notify` にすると、`systemctl start` は検査核の準備と待ち受けの bind まで待つ（[実行ファイルの build と配置](../build/binary-deployment.md) の「systemd」）。

## ACME

`acme renew` は、HTTP-01 の challenge だけで、証明書を発行・更新する（RFC 8555）。

### 要るもの

- CA は、証明書の名前の port 80 へ、平文の HTTP で challenge を取りに来る。port 80 で普通の待ち受けか redirect の待ち受けを持つ。
  - proxy は port の番号を確かめない。
- 普通の待ち受けと redirect の待ち受けは、次の要求に、経路・`access`・検査・転送・redirect より先に答える。TLS の待ち受けは答えない。
  - method が `GET` か `HEAD`
  - target が `/.well-known/acme-challenge/<token>` で、後ろに何も無い（query や escape も無い）。token は 1〜128 文字の英数字・`-`・`_` である
  - `Host` が `acme` を持つ証明書の host（大小を区別せず、port と末尾の `.` は見ない）
- 上の形でない要求は challenge として扱わず、ほかの要求と同じに経路と検査へ回る。
- 答えは、`challenge_dir` の `<token>` のファイル（1 KiB までの普通のファイル）を本文にした 200 か、404 である。link はたどらない。
- `ca_file` には、CA の API の server 証明書を出した root だけを入れる。100 枚までなので、OS の root の束をそのまま使うことはできない。

### 初めての発行

1. 設定に `acme` と、`acme` を持つ証明書を書く。証明書のファイルはまだ無くてよい。
   - proxy は、行を出してその証明書を handshake から外したまま起動する。
   - 試すときは、CA の試験用の directory（Let's Encrypt なら staging）を `directory_url` に書く。
2. proxy を起動する。
3. サービスの利用者で `acme renew` を流す。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy acme renew /etc/tukuyomi-core/config.json
   ```

   `2.1 renewed` のような行が出る。
4. `systemctl reload tukuyomi-core.service`（SIGUSR2）で、proxy が証明書を使い始める。
5. 試験用の CA で通ったら、本番の CA へ替える。
   - 試験用の CA の証明書は、期限が来ていないので、そのままでは置き換わらない（`valid`）。その証明書の `cert_file` と `key_file` を消す。
   - `directory_url` を本番の CA のものに替える。CA の API の server 証明書の root が違うなら、`ca_file` も替える。
   - もう一度 `acme renew` を流してから、SIGUSR2 を送る。ファイルを消してから `acme renew` が終わるまでの間に SIGUSR2 を送ると（ほかの `systemctl reload` も含む）、その証明書は handshake から外れる。この順を守れば、その間も proxy は読み込み済みの証明書を使い続ける。
   - `directory_url`・`ca_file`・`contact_email` など、`acme` の多くの鍵は命令だけが読むので、proxy の起動し直しは要らない。`challenge_dir` と、`acme` を持つ証明書の host は proxy も起動のときに読むので、替えたときは起動し直す。
6. 毎日の timer を置く（[実行ファイルの build と配置](../build/binary-deployment.md) の「証明書の更新の timer」）。

### 注意

- 同じ設定で `acme renew` を2つ同時に流さない。止める仕組みが無い。
- 命令の後に SIGUSR2 を送らないと、新しい証明書は使われない。
- 鍵と証明書は別のファイルに書いて同期してから、鍵、証明書の順に置き換える。
  - 2つの置き換えの間で止まると、鍵が証明書に合わない組が残る。動いている proxy は、SIGUSR2 でその組を断って今のものを使い続け、次の命令が作り直す。ただし、その間に proxy を起動すると、その組を断って起動しない（exit 1）。
- `cert_file`・`key_file`・`challenge_dir` の置かれたディレクトリに、サービスの利用者が書けること（[実行ファイルの build と配置](../build/binary-deployment.md) の「利用者と置き場」）。
  - 鍵は 0600、証明書は 0644 で書く（umask の分は引かれる）。
