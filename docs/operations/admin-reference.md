# 管理リファレンス

この文書は、今の実装の管理のプロセス、設定の `admin`、管理 API、管理画面を、引いて使える形でまとめる。proxy の設定と命令は [運用リファレンス](operator-reference.md)、置き方と systemd の例は [実行ファイルの build と配置](../build/binary-deployment.md) に書く。

例の path と名前（`/etc/tukuyomi-core/config.json`、利用者 `tukuyomi`、`admin.example.com`、`192.0.2.0/24` など）は例である。

## 構成

管理のプロセスは、`tukuyomi-proxy` と同じ実行ファイルの `admin` 命令で動く、proxy とは別のプロセスである。ブラウザで開く管理画面と、プログラムが使う管理 API に答える。

| もの | 中身 |
|---|---|
| 管理のプロセス | `tukuyomi-proxy admin <config>`。TLS を持たない loopback の待ち受けで、管理画面と管理 API に答える |
| 管理画面 | 実行ファイルに埋め込んだ画面（日本語と英語）。管理のプロセスが配る |
| 管理の置き場 | 設定の `admin.store.dir`。利用者、API token、監査、切り替えの履歴を置くディレクトリ |
| 制御 socket | 設定の `admin.control`。proxy が作る Unix domain socket。管理のプロセスが proxy の状態を問い、世代の切り替えを依頼する（proxy 側は [運用リファレンス](operator-reference.md) の「制御 socket」） |
| 記録のファイル | 設定の `records.dir`。proxy が記録の写しを置く。管理のプロセスが読み出す（[運用リファレンス](operator-reference.md) の「記録のファイル（`records`）」） |

- 管理のプロセスと proxy は、同じ設定ファイルを読む。どちらも起動のときに1回だけ読み、読み直さない。
  - proxy が `admin` から使う鍵は `listen` と `control` だけである。ほかの鍵は、同じファイルを両方が受け入れるか両方が断るように、proxy も範囲を確かめるだけである。
  - `admin` の鍵を変えたら、管理のプロセスを起動し直す。`listen` と `control` を変えたときは、proxy も起動し直す。
- 管理のプロセスは、proxy が止まっていても動く。止まっている間も、世代と記録の読み出し、取り込み、利用者の管理は使える。proxy に依頼する世代の切り替えと戻しだけは、proxy に届かなければ断る（下の「世代の操作」）。
- 設定に `admin` が無ければ、管理のプロセスは起動せず（exit 2）、proxy は制御 socket を作らない。

## 管理のプロセス

### `admin`

```text
tukuyomi-proxy admin <config>
```

- 設定ファイルは絶対の path で渡す（[運用リファレンス](operator-reference.md) の「命令」と同じ決まり）。
- 起動は次の順に進む。
  1. 起動の前の確かめ（root でないこと、SIGCHLD、file descriptor。proxy と同じで、中身は [実行ファイルの build と配置](../build/binary-deployment.md) の「起動の前の確かめ」）
  2. 設定ファイル
  3. 管理の置き場を開き、`process.lock` の lock を取る
  4. 監査の記録を開く
  5. 待ち受けの bind
- 待ち受けを bind すると、`admin: listening` の行を出し、環境に `NOTIFY_SOCKET` があれば `READY=1` を送る。
- 1つの管理の置き場で動く管理のプロセスは1つだけである。`process.lock` を持っている間、ほかの管理のプロセスは同じ置き場で起動できない（exit 1）。2つのプロセスが、同じ時間枠の確認コードや同じ回復コードを、それぞれ1回ずつ受け入れてしまうのを防ぐためである。
- proxy と同じ利用者で流す。ルールの保管場所、管理の置き場、記録のファイルを置くディレクトリは、どれも持ち主がその利用者で、group と other の権限が無いディレクトリでなければ使わない。制御 socket のあるディレクトリは、proxy が socket を作るときに同じ確かめをする。取り込みの試しは検査プロセスを起動するので、設定の `kernel`（検査プロセスの実行ファイルと作業場所）も proxy と同じ値を使う。
- exit code は次のとおり。

| exit code | 意味 |
|---|---|
| 0 | 合図で止まった |
| 1 | ほかの終わり方。root での起動、起動の前の確かめの失敗、使えない管理の置き場（別の管理のプロセスが使っているときを含む）、開けない監査の記録、bind できない `admin.listen` |
| 2 | 引数の誤り、断られた設定ファイル、`admin` の無い設定ファイル |

### `admin bootstrap`

```text
tukuyomi-proxy admin bootstrap <config> <name>
```

最初の利用者（役割は `owner`）を作る。管理の置き場に利用者が1人もいないときだけ作れる。

- パスワードは標準入力の最初の1行から読む。引数には渡さない。例:

  ```bash
  read -r -s -p 'password: ' PW; echo
  printf '%s\n' "$PW" | sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy admin bootstrap /etc/tukuyomi-core/config.json alice
  unset PW
  ```

- 名前は 1〜32 バイトの小文字の英字・数字・`.`・`_`・`-` で、パスワードは 12〜128 バイトの UTF-8 である。
- 成功すると、標準出力に `created owner <name>` が出て exit 0 になる。ほかの行は標準エラーに出て、`admin bootstrap:` で始まる。
- 監査の行（action `create`、`auth` が `bootstrap`、操作者と送り元は無し）を、利用者を作る前に書く。書けなければ利用者を作らない。この行は標準エラーに JSON のまま出る。
- 管理のプロセスが動いていなくても流せる。

### `admin reset`

```text
tukuyomi-proxy admin reset <config> <name>
```

締め出された利用者（たとえば、パスワードと第二要素を両方失った唯一の owner）のために、パスワードを決め直す。

- パスワードの読み方、名前とパスワードの決まり、標準エラーの行、監査の行の書き方は `admin bootstrap` と同じである。監査の行は action `reset`、`auth` が `reset` で、対象が利用者の名前になる。
- 成功すると、標準出力に `reset password of <name>` が出て exit 0 になる。
- 利用者に次のことをする。
  - パスワードを入力のものにし、次のログインで変えさせる。
  - 第二要素と回復コードを外す。
  - この利用者の session を終わらせ、API token をすべて無効にする。token のファイルを消せなかったときは、その旨の行を標準エラーに出すが、token は無効のままで、exit 0 になる。
  - 締め出しと失敗の数を、数え直しにする。
- 無効にした利用者は、有効には戻さない。無効の利用者を使えるようにするには、owner が `PUT /api/users/<名前>` で有効にする。
- 管理のプロセスが動いている間も流せる。変更は、置き場の lock の中で、読んだ利用者がそのままのときだけ書く。別の書き込みと重なったときは、`the admin store is in use by another process` か `the user was changed since it was read` で断られる（exit 1）。もう一度流す。

`bootstrap` と `reset` の exit code と標準エラーの主な行は次のとおり。

| exit code | とき | 標準エラーの行（`admin bootstrap:` か `admin reset:` の後） |
|---|---|---|
| 0 | 成功 | （標準出力に上の語） |
| 1 | root での実行、起動の前の確かめの失敗 | `host check refused: ...` |
| 1 | パスワードが読めない | `the password is not 12 to 128 bytes`、`the password line is too long`、`the password is not UTF-8` |
| 1 | 使えない管理の置き場、書けない監査の記録 | `admin store refused: ...`、`audit log refused: ...`、`the audit log cannot be written` |
| 1 | 利用者がすでにいる（`bootstrap`）、利用者がいない（`reset`） | `the store has a user already`、`the user is not in the store` |
| 2 | 設定が断られた、`admin` が無い | `configuration refused: ...` |
| 2 | 名前の誤り | `the name is not 1 to 32 bytes of a-z, 0-9, '.', '_' and '-'` |
| 2 | 引数の誤り | （`admin:` で始まる行に、使い方の行が続く） |

### 待ち受け

管理のプロセスは、`admin.listen` の loopback の address で、HTTP/1.1 に答える。TLS は持たない（外から使うときは、proxy の TLS の待ち受けを通す。下の「外から使う」）。

| 項目 | 値 |
|---|---|
| 同時の接続 | 32。超えた接続は、受けてすぐ閉じる |
| 1つの接続 | 要求を1つ受け、答えて閉じる（`Connection: close`）。次の要求は待たない |
| head | 8 KiB まで、field は 64 個まで。10 秒の中に読み終える |
| 本文 | 64 KiB まで。30 秒の中に読み終える |
| 取り込みの本文 | 12 MiB まで。取り込みを使える利用者（operator 以上で、session か token が生きていて、状態に制限されていない）にだけ読む。それ以外では読まずに、確かめの 400・401・403・429・503 で断る（cookie と token の両方は 400、token の回数を使い切った client は 429、置き場を読めないときは 503） |
| 答えを作る時間 | 30 秒。取り込み、世代の選択、戻しは下の「長い答え」の時間 |
| 接続の寿命 | head と本文と答えの時間の合計まで |

- `Content-Length` が上限を超える要求は、資格を見る前に、本文を読まずに 413 で答える。head の誤りや上限超えは、HTTP の部品が自分の答えを返すか、何も返さない。
- 本文を読む API は、`Content-Type` が `application/json` でなければ 415 になる。JSON の形が違う本文、その API が知らない鍵を持つ本文は 400 になる。
- `HEAD` は `GET` として扱う。表に無い path は 404、表にある path の別の method は 405（`Allow` を付ける）になる。

長い答え: 取り込み（試しを含む）、世代の選択、戻しは時間がかかる。答えを作る時間は、次の長い方に 7 秒を足した時間である（`proxy` の時間の鍵を使う）。尽きた要求は 503 `unavailable` になる。

- 取り込み: `ready_wait_ms + 3 × inspect_wait_ms + stop_inspect_ms`
- 選択と戻し: `ready_wait_ms + stop_inspect_ms + 14 秒`

運用リファレンスの例の値（`ready_wait_ms` 30000、`inspect_wait_ms` 55000、`stop_inspect_ms` 10000）では、上限は約 212 秒である。普通に終わる取り込みは、これよりずっと短い。

### 停止と systemd

- SIGTERM、SIGINT、SIGHUP で止まる。`admin: stop: <合図>` の行を出し、`NOTIFY_SOCKET` があれば `STOPPING=1` を送る。
  1. 動いている取り込みの試しを失敗として終わらせる（検査プロセスと作業場所を片付ける）。
  2. 待ち受けを閉じる。
  3. 処理中の要求に最長 10 秒を与え、残った接続は打ち切る。
  4. exit 0 で終わる。
- `NOTIFY_SOCKET` の決まりは proxy と同じである（[運用リファレンス](operator-reference.md) の「systemd への知らせ」）。扱う合図はこの3つだけで、SIGUSR1 と SIGUSR2 は扱わない（送ると既定の動きでプロセスが終わる）。
- session、締め出しの数、設定中の第二要素の秘密はメモリだけにあるので、起動し直すと全員がログインし直す。API token、利用者、監査、切り替えの履歴は置き場に残る。

systemd の unit は、proxy の unit（[実行ファイルの build と配置](../build/binary-deployment.md) の「systemd」）に合わせて作る。管理のプロセスの違いは次のとおりである。

- `ExecStart` は `tukuyomi-proxy admin <config>`、`User` と `Group` は proxy と同じにする。
- `Type=notify` にする。待ち受けを bind した後に `READY=1` を送る。
- `KillMode=mixed` にする。既定の `control-group` では、取り込みの試しの検査プロセスにも SIGTERM が届き、管理のプロセスが検査プロセスを順に止められない（理由は proxy と同じ）。
- `TimeoutStopSec` は、停止の待ちの 10 秒より長くする。取り込みの試しが動いているときのために、その検査プロセスを止める時間（`proxy.stop_inspect_ms` と `kernel.kill_grace_ms`）も足しておく。
- `admin.listen` の port が 1024 以上なら、`AmbientCapabilities` は要らない。`ReadWritePaths` には、ルールの保管場所、管理の置き場、`kernel.tmp_root`、制御 socket のあるディレクトリを含める。
- `LogRateLimitIntervalSec=0` にする。監査の行は標準エラー（journal）にも出るので、journald の流量の上限で落ちないようにする。
- proxy の unit と順序を付ける必要は無い。

記録は、proxy と同じく標準エラーに1行1件の JSON で出る（[運用リファレンス](operator-reference.md) の「記録」）。`admin:` で始まる文の `line` と、監査の行の `audit` を出す。`audit` は proxy の記録のファイル（`records.dir`）には入らない。

## 設定 `admin`

```json
"admin": {
  "listen": "127.0.0.1:9100",
  "control": "/var/lib/tukuyomi-core/control/proxy.sock",
  "store": {"kind": "file", "dir": "/var/lib/tukuyomi-core/admin"},
  "origin": "https://admin.example.com",
  "trusted_proxies": ["127.0.0.1/32"],
  "mfa": "required",
  "session_idle_ms": 1800000,
  "session_total_ms": 43200000,
  "crs_dir": "/var/lib/tukuyomi-core/crs-4.23.0"
},
"records": {"dir": "/var/lib/tukuyomi-core/records", "file_bytes": 16777216, "files": 8}
```

`admin` と `records` は、設定ファイルの一番上の object（`proxy`、`forward`、`kernel` などと並ぶ）である。どちらも省いてよい。`admin` を書くときは、`crs_dir` のほかのすべての鍵を書く。知らない鍵、重複、型の違いを断る決まりは、[運用リファレンス](operator-reference.md) の「設定ファイル」と同じである。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `listen` | loopback の IP（`127.0.0.0/8` か `::1`）と port（0 は不可） | 管理のプロセスの待ち受けの address。`::ffff:127.0.0.1` の形は loopback と見なさない |
| `control` | 絶対の path、107 バイトまで | 制御 socket のファイル |
| `store` | `{"kind": "file", "dir"}` | 管理の置き場。`kind` は今は `file` だけ。`dir` は絶対の path で 3840 バイトまで |
| `origin` | `https://` と host（任意で `:port`） | 管理画面を開く URL の origin。経路の `host` と同じ形（小文字の名前）で、wildcard、path、query、末尾の `/` は書けない。`POST` などの変更の `Origin` と比べる |
| `trusted_proxies` | 0〜256 個の network | 管理のプロセスの client の address を、`X-Forwarded-For` から決めるときに信じる相手。host の部分が 0 の `address/prefix` で書く。読み方は proxy と同じ（[運用リファレンス](operator-reference.md) の「client の address」） |
| `mfa` | `"optional"`、`"required"` | 第二要素を求めるか。`required` は、第二要素を持たない利用者に設定だけをさせる（下の「ログインと第二要素」） |
| `session_idle_ms` | 1 分〜24 時間 | session が使われないまま続く時間 |
| `session_total_ms` | `session_idle_ms` 〜 7 日 | session が続く時間の上限 |
| `crs_dir` | 絶対の path、3840 バイトまで。省いてよい | 取り込みで使える CRS のディレクトリ。`scripts/fetch-crs.sh` で取得したもの（[実行ファイルの build と配置](../build/binary-deployment.md) の「CRS の取得」）。省くと、取り込みで CRS を使えない |

- `listen` は、待ち受け（`proxy.listeners`）と `status.listen` のどれとも重ならない。重なりの決まりは待ち受けどうしと同じで、同じ address と port、または片方が `0.0.0.0` や `::` で port が同じものである。
- 上流の server の address には、`admin.listen` を書ける（待ち受けと `status.listen` は書けない）。proxy の経路を通して外から使うためである（下の「外から使う」）。
- ディレクトリは互いに離す。ルールの保管場所（`rules.store.dir`）、`records.dir`（あるとき）、`admin.store.dir`、`admin.control` のあるディレクトリは、どれも同じにならず、互いの中にもならない。`admin.control` そのものも、前の3つの中にならない。
- `admin.store.dir` と、`admin.control` のあるディレクトリは、先に作っておく。持ち主が proxy の利用者で、group と other の権限が無い（0700）本物のディレクトリであること。管理のプロセスは、その中に `users/`、`tokens/`、`audit/` を作る。
- `config check` は、`admin` と `records` の鍵と値の関係を確かめる。管理の置き場、制御 socket、記録のファイルを開けるかは、確かめない。

管理の置き場の中身（ファイルは 0600、ディレクトリは 0700）:

| 置き場 | 中身 |
|---|---|
| `users/<名前>.json` | 利用者。パスワードの hash、第二要素の秘密、回復コードの hash を含む。最大 1000 人 |
| `tokens/<id>.json` | API token。token の秘密の SHA-256 だけを持つ。持ち主ごとに 50 個まで |
| `audit/` | 監査（`audit.log` と、回した古いファイル） |
| `activations.log` | 切り替えの履歴 |
| `lock`、`process.lock` | 書き込みの lock と、管理のプロセスの lock |

### 制御 socket

proxy は、設定に `admin` があると、起動のときに `admin.control` の制御 socket を作る。作り方、使える人、依頼と答えの形は [運用リファレンス](operator-reference.md) の「制御 socket」に書く。管理のプロセスの側の扱いは次のとおりである。

- 状態の問い: 接続は 2 秒、答えは 2 秒待つ。proxy が接続を受けて何も答えずに閉じる（同時の接続の上限に達している）ときは、250 ms 後に1回だけ問い直し、それでも同じなら「proxy が処理中」とする（`GET /api/status` では、`reachable` が `true` で `proxy` が `null`）。
- socket が無い、誰も受けない、答えが決まった形でない、時間内に答えが無いときは、どれも「proxy に届かない」になる。
- 切り替えの依頼は、`ready_wait_ms + 7 秒` まで待つ。proxy 自身が答えを待つ時間は `ready_wait_ms + 5 秒` で、管理のプロセスの待ちは 2 秒長い。
- proxy が `busy` と答えたとき、または依頼を読まずに閉じたときは、管理のプロセスが 250 ms ごとに状態を問う。
  - proxy が、依頼した世代を使い始めれば `switched` とする。
  - 切り替えの途中でない状態が、依頼した世代でないまま2回続けば `failed` とする。
  - `stop_inspect_ms + 7 秒` が過ぎても `failed` とする。
  - 途中で届かなくなれば `unconfirmed` とする。

結果の扱いは、下の「世代の操作」にある。

### 記録のファイル

`GET /api/records` は、proxy が書く記録のファイル（`records.dir`）を読む。ファイルの名前、大きさ、回し方は [運用リファレンス](operator-reference.md) の「記録のファイル（`records`）」に書く。

- 設定に `records` が無いと、この API は 404 になる。
- 管理のプロセスは、proxy と同じ利用者としてファイルを読む。ディレクトリが、持ち主が違う、group か other の権限がある、本物のディレクトリでない、のどれかなら読まない（503）。
- 記録のファイルには client の address と path が入る。管理 API では viewer 以上が読めるので、viewer の役割を渡す人を考えて決める。

## 外から使う

管理のプロセスは TLS を持たないので、proxy の TLS の待ち受けに、管理用の Host の経路を作って使う。cookie は `Secure` で出るので、管理画面は https でしか使えない。

```json
"forward": {
  "upstreams": {
    "app": {"servers": [{"address": "127.0.0.1:8080", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}]},
    "admin": {"servers": [{"address": "127.0.0.1:9100", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}]}
  },
  "routes": [
    {"host": "admin.example.com", "upstream": "admin", "access": {"allow_cidrs": ["192.0.2.0/24"]}}
  ],
  "default_upstream": "app"
}
```

（`forward` の他の鍵は省いた。`admin.listen` が `127.0.0.1:9100` の例である。）

- 証明書: `admin.example.com` を `hosts` に持つ証明書を、TLS の待ち受けに置く。持たない名前の handshake は失敗する。
- 上流の組: server の address に `admin.listen` を書く。
- `access`: `allow_cidrs` で、管理を使う人の address に絞る。client の address の決め方と、`access` を使うときの注意は [運用リファレンス](operator-reference.md) の「client の address」と「`access` を使うときの注意」にある。どれかの経路が `access` を持つと、どの経路の `host` にも port を書けない。
- 全体の `access` と `rate_limit` は、経路を引く前に、この Host の要求にも掛かる（[運用リファレンス](operator-reference.md) の「要求の前の方針」）。管理を使う人の数と速さに合わせて決める。
- 平文の待ち受けに、この Host を通さない。経路は待ち受けを問わずに引かれるので、`redirect` でない平文の待ち受けがあると、パスワードが暗号化されずに流れうる。平文の待ち受けは `redirect` にする。
- `admin.trusted_proxies`: proxy が管理のプロセスに接続する元の address（同じ host なら `127.0.0.1/32`）を書く。書かないと、すべての client が proxy の address になり、ログインの試行の制限（client ごと）が全員で共有され、監査の `client` がどれも proxy の address になる。
- `admin.origin`: ブラウザで開く URL の origin と一字一句同じにする（port が 443 のときは書かない）。違うと、ログインを含む変更が 403 になる。

### 取り込みの経路を検査しない

`POST /api/generations`（取り込み）の本文は、ルールのファイルを含む大きな JSON である。これを検査の対象にすると、ルールの検査が取り込みを遮断することがある。この path は、世代の検査しない経路（[運用リファレンス](operator-reference.md) の「検査しない経路」）にする。

```json
[
  {"host": "admin.example.com", "path": "/api/generations", "action": "bypass"}
]
```

- `path` は `/` で終わらないので、この path だけに当たる。`/api/generations/<指紋>`（世代の読み出しと削除）は、検査される。
- 検査しない経路は世代の一部である。どの世代にも同じ経路を入れ続ける。入れ忘れた世代を選ぶと、その世代からは取り込みが検査される。
- この経路が効くのは、入れた世代が使われてからである。最初にこの経路を入れる世代は、命令で取り込む（`rules import ... --routes <file>`）。管理画面の取り込みも、同じ形の JSON を入力できる。

### 本文の大きさ

- 取り込みの本文は 12 MiB まで届く。`proxy.max_body` を 12 MiB（12582912）以上にする。経路の `max_body` は `proxy.max_body` を下げることしかできないので、ほかの経路を絞りたいなら、そちらの経路に小さい `max_body` を書く。
- 検査しない経路の長い本文は、ためずに流す（[運用リファレンス](operator-reference.md) の「本文と予算」）ので、12 MiB の取り込みが `max_buffered_bytes` を使い切ることはない。

### 長い答えと時間

- 取り込み、世代の選択、戻しは、数十秒以上かかることがある（時間の上限は「待ち受け」の「長い答え」）。proxy の時間の鍵は経路ごとに変えられない。応答の head を待つ時間は、`upstream_header_ms`、`response_idle_ms`、`request_total_ms` のうち先に尽きたもので切れる（[運用リファレンス](operator-reference.md) の「`proxy`: 時間」と「値どうしの関係」）。本文を流す要求（検査しない経路の取り込みなど）では、応答の head が来るまで `response_idle_ms` は効かない。
- 切れると、proxy は client に 502（`request_total_ms` では 503）を返す。管理のプロセスは処理を続け、取り込み、選択、戻しは最後まで進む。proxy の切断では止まらない。
- 管理画面は、本文に `result` を持たない 502 と 504 を「結果が分からない」として扱い、画面ごとに、状態と履歴、または世代の一覧を読み直して見せる。`result` を持つ答え（`failed` の 502、`unreachable` と `unconfirmed` の 503 を含む）は、その語で読む。`result` を持たない 503 は「変更を断った」と読むので、`request_total_ms` は、本文を受ける時間と検査の時間に `upstream_header_ms` を足した時間より十分に長くしておく。API を直接使う側も、同じ答えのときは `GET /api/status` と `GET /api/history`（取り込みなら `GET /api/generations`）で確かめる。
- 時間の鍵は、取り込みと切り替えに要る時間を測ってから決める。`upstream_header_ms` を長くすると、ほかの Host の上流が遅いときも長く待つ。

## 利用者と役割

利用者は名前、役割、パスワードを持つ。名前は 1〜32 バイトの小文字の英字・数字・`.`・`_`・`-`、パスワードは 12〜128 バイトの UTF-8 である（日本語の文字は1文字が3バイト）。パスワードは PBKDF2-HMAC-SHA256（600000 回、salt 16 バイト）の hash で置く。

| 役割 | できること |
|---|---|
| `viewer` | 状態、世代の一覧と中身、切り替えの履歴、記録を読む。自分のパスワード、第二要素、API token を扱う |
| `operator` | viewer のすべて。加えて、監査を読む。ルールの取り込み、世代の選択、戻し、削除をする |
| `owner` | operator のすべて。加えて、利用者を作り、役割と有効・無効を変え、ほかの人のパスワードと第二要素を初期化し、全員の API token を見て削除する |

- 最初の owner は `admin bootstrap` で作る。以後の利用者は、owner が `POST /api/users` で作る。1000 人まで作れる。1000 人に達すると、作成は 409 `the store has too many users` で断る。利用者は消せないので、上限は無効にした利用者も数える。
- 利用者を消す API は無い。使わなくなった利用者は無効にする。無効にした利用者は、ログインできず、session と API token が使えなくなる。有効にし直しても、消えた API token は戻らない。
- owner が作った利用者と、owner が `POST /api/users/<名前>/password` でパスワードを決めた利用者は、次のログインで、自分のパスワードに変えるまで、ほかの API を使えない。
- owner の自分自身への操作と、owner がいなくなる操作は断る。
  - 自分の役割を下げる、自分を無効にする: 403
  - 自分のパスワードと第二要素の初期化: 403（アカウントの API で変える）
  - 有効な owner が1人もいなくなる変更: 409
- 利用者の管理は、管理のプロセスの中で1つずつ進む。2人の owner が同時に互いを下げて、owner がいなくなることはない。
- 役割と状態の変更（役割を変える、無効にする、有効にする、パスワードを決める、第二要素を外す）は、その利用者の session を終わらせる。役割を下げることと無効にすることとパスワードを決めることは、API token も無効にする。
- 役割も有効・無効も変わらない `PUT /api/users/<名前>` は、何も変えずに 200 でその利用者を返す。session は終わらせず、監査にも書かない。

## ログインと第二要素

ログインは `POST /api/login`（`{"name", "password"}`）で始まる。答えの `mfa` が次の段を示す。

| `mfa` | 意味 | 次 |
|---|---|---|
| `off` | session が使える | API を使う。`must_change` が `true` なら、パスワードを変える |
| `verify` | 第二要素の確認コードが要る | `POST /api/login/mfa` |
| `setup` | `admin.mfa` が `required` で、第二要素が未設定 | 第二要素を設定する |

session は、状態によって使える API が決まる。状態に合わない API は、403 と次の決まった文で断る。

| 状態 | とき | 使える API | 断るときの `error` |
|---|---|---|---|
| 確認待ち | パスワードが合い、第二要素を持つ利用者。5 分で終わる | `POST /api/login/mfa`、`POST /api/logout` | `second factor required` |
| パスワードの変更待ち | owner が作った、または owner か `admin reset` がパスワードを決めた | `PUT /api/account/password`、`GET /api/session`、`POST /api/logout` | `password change required` |
| 第二要素の設定待ち | `admin.mfa` が `required` で、第二要素が未設定 | `POST /api/account/mfa/setup`、`POST /api/account/mfa/confirm`、`GET /api/session`、`POST /api/logout` | `second factor setup required` |
| 通常 | 上のどれでもない | 役割が許すすべての API | |

- 変更待ちと設定待ちが重なるときは、両方の API を使える。
- `GET /api/session` は、状態（`state`: `active`、`must_change`、`mfa_setup`）、残りの時間、残りの回復コードの数を答える。確認待ちの session は 403 になる。

第二要素（管理画面では二要素認証、MFA）:

- 時刻に基づく1回限りのパスワード（RFC 6238）で、HMAC-SHA1、6 桁、30 秒ごとの時間枠で作る。今の枠の前後1つの枠の確認コードも受け入れる。使った枠は覚えていて、その枠と、それより前の枠の確認コードは断る。
- 設定:
  1. `POST /api/account/mfa/setup`（`{"password"}`）が、秘密（20 バイトの乱数）を base32 の文字列（`secret`）と `otpauth://` の address（`uri`）で返す。秘密は session のメモリに 10 分だけ置く。
  2. `POST /api/account/mfa/confirm`（`{"code"}`）が、認証アプリの確認コードで確かめ、第二要素を有効にし、回復コードを返す。この利用者のほかの session は終わり、新しい session と CSRF token が返る。
- 設定の開始と確定を断るとき: すでに第二要素がある利用者は、どちらも 409 `mfa is set already` で断る。確定は、設定を始めていない、または 10 分を過ぎたときも、409 `mfa setup was not started or has run out` で断る。確認コードが合わないときは 403 `the code is wrong` である。
- 回復コードは 10 個で、1個は 16 文字（大文字の `A`〜`Z` と `2`〜`7`）、1回だけ使える。設定のとき1回だけ返し、置き場には SHA-256 だけを置く。使い切る前に作り直すには、第二要素を外して設定し直す。`admin.mfa` が `required` のときは、自分では外せない。owner に `DELETE /api/users/<名前>/mfa` で外してもらう（owner 自身の分は、ほかの owner に外してもらうか、`admin reset` を使う）。
- ログインの確認は `POST /api/login/mfa` に `{"code"}`（6 桁）か `{"recovery"}`（回復コード。大文字で送る）の一方を送る。合うと、確認待ちの session が終わり、新しい session（新しい id と CSRF token）が返る。
- 外す: `DELETE /api/account/mfa`（`{"password", "code"}`。`code` は確認コードか回復コード）。`admin.mfa` が `required` のときは 403 `mfa is required` で断る。owner は、ほかの人の第二要素を `DELETE /api/users/<名前>/mfa` で外せる。
- `required` のとき、第二要素を持たない利用者の API token は使えない。
- 第二要素の秘密は、利用者のファイルに、そのまま置く（確認コードを計算するのに秘密そのものが要るため）。置き場のディレクトリを 0700 にして守る。

## 締め出しと試行の制限

| 対象 | 決まり |
|---|---|
| 利用者ごと | 続けて 5 回失敗すると、15 分締め出す。締め出しの間の試行も失敗に数え、15 分を数え直す。成功すると数を消す |
| client ごと | 1 分に 30 回まで試せる。超えた試行は、hash を計算する前に 429 `too many tries` で断り、利用者の失敗には数えない |

- 利用者ごとの失敗に数えるのは、ログインのパスワードの誤り、ログインの確認コード（`POST /api/login/mfa`）の誤り、第二要素の解除の確認コードの誤り、パスワードを確かめる API（パスワードの変更、第二要素の設定と解除、token の作成）のパスワードの誤りである。無効の利用者や締め出し中の利用者のログインも、その利用者の失敗に数える。確認コードを持つ利用者は、パスワードが合っても数を消さない。確認コードが合ったときに消す。パスワードを知る人が、ログインのたびに数を消して確認コードを試し続けられないようにするためである。第二要素の設定の確定（`POST /api/account/mfa/confirm`）の確認コードの誤りは、利用者の失敗にも client の回数にも数えず、監査にも書かない。答えは 403 `the code is wrong` である。
- client ごとの回数に数えるのは、ログイン、ログインの確認コード、パスワードを確かめる API（上と同じ）、合わない API token である。正しい API token の要求と、第二要素の設定の確定は数えない。ログインは、成功した試行も数える。回数を使い切った client の API token の要求は、token が正しくても、token を見る前に 429 `too many tries` で断る。
- 最大 4096 の client を覚える。表が1分以内に試した client で満ちているときは、ほかの client を受けない。
- ログインは、知らない名前、無効な利用者、締め出し中の利用者、パスワードの誤りのどれでも、同じ答え（401 `invalid credentials`）にする。知らない名前や締め出し中でも hash を1回計算するので、かかる時間でも見分けられない。ログインの確認コードの誤りも、同じ 401 `invalid credentials` で答える。ほかの API の誤りは 403 で、パスワードは `the password is wrong`（パスワードの変更は `the current password is wrong`）、確認コードは `the code is wrong` である。
- 理由は監査にだけ書く（`unknown user`、`disabled`、`locked`、`wrong password`、`wrong code`）。知らない名前は書かない。名前の欄に打ったパスワードが記録に出ないようにするためである。
- 締め出しの数と client の回数は、管理のプロセスのメモリにだけある。起動し直すと消える。
- 利用者が変わると（`admin reset`、owner の操作、パスワードの変更、第二要素の設定と解除）、締め出しは解け、次の失敗から数え直す。

## session

- ログインが通ると、session を作り、cookie `tukuyomi_admin` を返す。cookie の値は、32 バイトの乱数を base64url にした 43 文字である。

  ```text
  Set-Cookie: tukuyomi_admin=<43 文字>; Secure; HttpOnly; SameSite=Strict; Path=/
  ```

  有効期限は付けない（ブラウザを閉じると消える）。ログアウトでは `Max-Age=0` の cookie を返して消す。
- 管理のプロセスは、session を id の SHA-256 で覚え、id そのものは持たない。監査の `session` には、その SHA-256 の先頭 8 桁だけを書く。
- session ごとに、CSRF token（別の 32 バイトの乱数、43 文字）を持つ。ログインの答えと `GET /api/session` で返す。
- session が終わるとき:
  - `admin.session_idle_ms` の間、使われなかった（要求ごとに数え直す）
  - 作ってから `admin.session_total_ms` が過ぎた
  - ログアウトした
  - その利用者のパスワード、役割、有効・無効、第二要素が変わった（`admin reset` と、別の管理のプロセスの操作を含む）。パスワードと第二要素を自分で変えたときは、その要求に新しい session を返し、ほかの session を終わらせる
  - 利用者が無効になった
  - 管理のプロセスを起動し直した
- 1人の利用者が持てる session は、確認待ちと通常のそれぞれで 16 個までである。17 個目を作ると、いちばん古いものを終わらせ、監査に `logout`（reason `too many sessions`）を書く。確認待ちを繰り返しても、通常の session は終わらない。全体では 1024 個まで持ち、満ちると新しい session を作れない（ログインは 503）。
- 1つの要求は、session の cookie か API token のどちらかを持つ。両方あると 400 になる。`Authorization` の field が Bearer でなくても、session の cookie と並ぶと 400 になるので、管理画面の前に Basic 認証などの HTTP の認証をかけると、ログインの後の要求は 400 になる。cookie が2回ある要求は、session を持たないものとして 401 にする。

## CSRF と Origin

`GET` と `HEAD` 以外の要求（変更）には、次の2つの確かめがある。

- `Origin`: field があれば、`admin.origin` と一字一句同じで、1つだけであること。違うと 403 `forbidden`。field が無い要求（プログラムからの要求）は通る。ログインの要求にも適用する。
- `X-CSRF-Token`: session の要求では、その session の CSRF token と同じ値を、1つだけ付けること（一定の時間で比べる）。違うか無いと 403 `forbidden`。API token の要求には要らない（cookie を使わないため）。

確かめの順は、「答えの形」の「管理 API の確かめの順」にある。

- 管理画面は、CSRF token をメモリにだけ置き、変更の要求ごとに付ける。ページを開き直すと `GET /api/session` で受け取り直す。確認待ちの session は `GET /api/session` が 403 になり CSRF token を受け取れないので、ページを開き直すとログインからやり直しになる。
- `Origin` の違いと CSRF の違いで断った要求は、利用者が分かっているときに監査に書く（reason `origin`、`csrf`）。

## API の token

プログラムが管理 API を使うための token である。

- 形は `tkc_<16 桁の 16 進数>_<43 文字>`。前の部分が token の id で、後ろが秘密（32 バイトの乱数の base64url）である。作ったときに1回だけ全体を返す。管理の置き場には秘密の SHA-256 だけを置く。
- `Authorization: Bearer <token>` で送る。session の cookie とは一緒に送れない（400）。
- 作る: `POST /api/account/tokens`（`{"name", "role", "days", "password"}`）。session の利用者が自分のために作り、今のパスワードを求める。
  - `name`: 1〜64 バイトの印字できる ASCII
  - `role`: 自分の役割以下。上の役割は 403 `the role is above the role of the user` で断る
  - `days`: 1〜365。作った時刻からこの日数で終わる
  - 1人が持てるのは 50 個まで（超えると 409 `the user has too many tokens`）。50 個の数には、期限が切れた token も入る。期限が切れた token は自動では消えないので、`DELETE /api/account/tokens/<id>` で消す
  - 答えは token の情報（`id`、`owner`、`name`、`role`、`created`、`expires`、`expired`、`last_used`。時刻はミリ秒の epoch）に、`token`（全体の文字列）を足したもの
- 使える API: 状態、世代、取り込み、選択、戻し、削除、履歴、記録、監査（下の「API の path の一覧」で「token」が ○ のもの）。アカウントの API と、利用者の管理の API には使えない（403）。owner の token で、ほかの人のパスワードや第二要素を初期化して、その人としてログインできてしまうのを防ぐためである。
- 要求の役割は token の役割である（持ち主の役割以下）。CSRF の token は要らない。変更の要求の `Origin` は、あれば `admin.origin` と同じであること。
- 使うたびに、次を確かめる。
  - 形が正しく、置き場にその id があり、秘密の SHA-256 が合う
  - 持ち主がいて、無効でなく、役割が token の役割以上である
  - token が、持ち主の「この時刻より前に作った token は無効」の時刻より後に作られている
  - 期限が過ぎていない
  - `admin.mfa` が `required` なら、持ち主が第二要素を持つ
- 無効になるとき（ファイルを消せなくても、上の確かめで通らなくなる）:
  - 期限が来た、または削除した（`DELETE /api/account/tokens/<id>`、owner は `DELETE /api/tokens/<id>`）
  - 持ち主が無効になった
  - 持ち主の役割が下がった（持ち主のすべての token が無効になる）
  - 持ち主のパスワードが変わった（自分で変えたとき、owner が決めたとき、`admin reset`）
- 合わない token は、client ごとの試行の回数（上の「締め出しと試行の制限」）に数える。監査には書かない。誰でも送れる要求で、監査を埋められないようにするためである。
- 最後に使った時刻（`last_used`）は、10 分に1回までしか書かない。書けなくても要求は通る。
- 使い方の例（`$TOKEN` に token を入れる）:

  ```bash
  curl -sS -H "Authorization: Bearer $TOKEN" https://admin.example.com/api/status
  curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"generation":"<切り替え先の指紋>","expect":"<今選ばれている指紋>"}' \
    https://admin.example.com/api/activate
  ```

## 監査

管理のプロセスは、ログイン、変更、断った要求を、監査の行として残す。

| 項目 | 中身 |
|---|---|
| `ts`、`type` | 記録と同じ。`type` は `audit` |
| `id` | 要求の番号（`X-Request-ID`）。命令（`admin bootstrap`、`admin reset`）の行には無い |
| `actor` | 確かめた利用者の名前。確かめられなかったときは無い。要求の header からは取らない |
| `session` | session の id の SHA-256 の先頭 8 桁。id そのものは書かない |
| `auth` | session でないときの入り方。`token:<id>`、`bootstrap`、`reset` |
| `client` | client の address。命令の行には無い |
| `action` | 操作（下の表） |
| `target` | 操作の対象（利用者の名前、token の id、世代の指紋）。知らない名前のログインには無い |
| `result` | `ok`、`denied`（断った）、`failed`（試したが失敗した） |
| `reason` | 決まった語（`wrong password`、`locked`、`expect`、`store` など） |
| `before`、`after` | 変更の前と後。役割、有効・無効、世代の指紋 |

パスワード、token、確認コード、回復コード、秘密、cookie は書かない。

| action | とき |
|---|---|
| `login` | ログインの成功（`ok`）と失敗（`denied`。reason は `unknown user`、`wrong password`、`locked`、`disabled`）。session を作れないとき（`failed`、`no session`）。第二要素を持つ利用者のパスワードが合ったときの reason は `second factor pending` |
| `mfa` | 確認コードの成功と失敗（`wrong code`、`locked`）。回復コードの成功は reason `recovery code` |
| `lock` | 利用者を締め出した（reason `too many failures`） |
| `logout` | ログアウト。session が多すぎて終わらせたときは reason `too many sessions` |
| `password`、`mfa_setup`、`mfa_confirm`、`mfa_disable` | 自分のパスワード、第二要素の設定の開始・確定・解除。パスワードや確認コードの誤りは `denied`（`wrong password`、`wrong code`、`locked`）。ただし、`mfa_confirm` の確認コードの誤りは行を書かない |
| `token_create`、`token_revoke` | token の作成（`after` が役割）と削除 |
| `user_create`、`role`、`disable`、`enable`、`user_password`、`user_mfa` | owner の利用者の管理 |
| `import`、`activate`、`rollback`、`remove` | 世代の操作（下の「世代の操作」） |
| `create`、`reset` | 命令 `admin bootstrap`、`admin reset` |
| API ごとの action | 断った API の名前で、`denied` の行を書く（下の注）。名前は、上の世代の操作の action のほかに、`status`、`generations`、`generation`（世代1つの読み出し）、`history`、`records`、`audit`、`session`、`users`、`user_update`（`PUT /api/users/<名前>`）、`tokens` である |

- API ごとの確かめで断った要求は、利用者が分かっていれば `denied` の行を書く。reason は `origin`、`csrf`、`token`（token が使えない API）、`role`、`state`、`second factor pending`、`password change`、`second factor setup` である。
- 利用者が分からない段で断った要求は書かない。session も token も無い、合わない token、client の回数を超えたログイン、`Origin` が違うログイン、path が無いなどである。誰でも送れる要求で、古い行を押し出せないようにするためである。
- 世代の操作の行は、`target` に対象の世代の指紋を書く。`activate` と `rollback` の `ok` の行は、`before` に選ばれていた世代、`after` に依頼した世代も書く。`ok` の行は変更の前に書くので、成功の印ではない。終わり方は、後に続く `failed` の行と、切り替えの履歴で見る。`failed` の reason は、`expect`、`store`、`refused`、`failed`、`unconfirmed`、`history`（履歴の行を書けなかった）で、取り込みは `store` と `trial` である。変更の前に断ったときは `denied` で、reason は `expect`、`busy`、`unreachable` である。削除は、選ばれている世代が `chosen`、戻しの先が `rollback target` である。

書き方:

- 変更は、監査の行を先に書いてから行う。行を書けない（ディスクが満ちている、など）と、変更はせず、503 `unavailable` で断る。行はディスクに同期してから、標準エラーにも出す。
- 例外はログアウトである。権利を取り上げる操作なので、行を書けなくても session を終わらせる。
- 変更が失敗したときは、後から `failed` の行を書く（書けなくても答えは変えない）。
- 置き場は `admin.store.dir` の `audit/audit.log` で、1行1件の JSON である。1つのファイルが 16 MiB を超えるなら次のファイルに移り、8 ファイル（`audit.log`、`audit.1.log` から `audit.7.log`）を残す。同じ行を標準エラー（journal）にも出す。
- `GET /api/audit`（operator 以上、token 可）は、最新の 200 行を新しい順に `{"entries": [...]}` で返す。ファイルの終わりから読み、足りなければ古いファイルを読む。1つのファイルは終わりの 1 MiB までを読み、ファイルがそれより大きいときは、古いファイルを読まずにそこで終える。読めない行は飛ばす。

## 世代の操作

世代の一覧と中身は viewer が読める。取り込み、選択、戻し、削除は operator 以上である。

### 一覧と中身

- `GET /api/status`: 次を返す。
  - `current`: ルールの保管場所が選んでいる世代の指紋（無ければ `null`）
  - `reachable`: proxy に届くか。同時の接続の上限で答えられない proxy は、届くとする
  - `proxy`: proxy の状態（`generation`、`mode`、`phase`、`switching`、`ready`）。読めなければ `null`
  - `rollback_to`: 今戻しを依頼したら選ぶ世代（無ければ `null`）
  - `crs`: `{"available", "files"}`。`admin.crs_dir` があるか、取り込みで外せる CRS の `.conf` の名前
- `GET /api/generations`: `{"reachable", "generations"}`。新しい順に、各世代の `fingerprint`、`made`（作った時刻。epoch からの秒）、`mode`（`block`、`detect`、manifest が読めなければ `unknown`）、`routes`（検査しない経路の数）、`current`（保管場所が選んでいる）、`serving`（proxy が使っている）を返す。
- `GET /api/generations/<指紋>`: 上に加えて、`load`（読み込む順）、`files`（`path`、`size`、`sha256`）を返す。`routes` は、ここでは数でなく経路の配列（`host`、`path`、`action`）である。経路が `host` を持たないときは、`host` は付かない。保管場所に無い世代は 404。

「選ばれている」世代と「使っている」世代は別である。保管場所が選んでいても、proxy が切り替えに失敗していれば、使っていない。管理画面は、切り替えの途中ではないのに2つが違うときに、警告を出す。

### 取り込み

`POST /api/generations`（operator 以上、token 可）は、`rules import` と同じ順に、世代を作る。ファイルを集める、保管場所に仮に置く、検査プロセスで試す、試しに通れば世代にする。世代は選ばない。

本文は JSON の object で、鍵はすべて省いてよい。

| 鍵 | 中身 |
|---|---|
| `rules` | ルールのファイル。`{"name", "data"}` の配列で、書いた順に読み込む。`name` はディレクトリを除いた名前（`--rules` と同じ決まり）、`data` は標準の base64（padding つき） |
| `data` | データのファイル。形は `rules` と同じ（`--data` に当たる） |
| `crs` | `true` で `admin.crs_dir` の CRS を使う。要求では path を指定できない。`admin.crs_dir` が無いと 400 |
| `crs_off` | 読み込まない CRS の `.conf` の名前の配列（`--crs-off` に当たる） |
| `routes` | 検査しない経路の配列（`--routes` のファイルと同じ形） |
| `detect_only` | `true` で検知だけの世代にする |
| `accept_block` | `true` で、試しの要求が遮断されても失敗にしない |

- 上限と名前の決まりは `rules import` と同じである（[運用リファレンス](operator-reference.md) の「`rules`」）。ファイルは 128 個、1つ 2 MiB、全体 8 MiB まで。2 MiB を超えるファイルは、デコードする前に断る。
- 試しは `rules import` と同じで、管理のプロセスが検査プロセスを1つ起動し、決まった3つの要求（`GET /`、form の `POST /`、JSON の `POST /`）を検査する。`kernel` の値と、`proxy` の `ready_wait_ms`・`inspect_wait_ms`・`stop_inspect_ms`・`drive_slice_ms` を使う。
- 取り込み、選択、戻し、削除は、管理のプロセスの中で1つずつ進む。ほかの変更が進んでいるときは、待たずに 409 `a change of the rules is under way`。命令や別のプロセスが保管場所の lock を持っているときは、409 `the rules store is in use by another command`。

答え:

| 状態コード | とき | 本文 |
|---|---|---|
| 200 | 世代を作れた | `{"fingerprint", "result", "trial"}`。`result` は `created`、`existing`（同じ世代が既にあった）、`repaired`（壊れていた同じ指紋の世代を作り直した） |
| 400 | 入力が断られた | `{"error"}`。入力のファイルの名前があれば `subject` に付く（0x20〜0x7e の外のバイトは `\xNN`、128 バイトまで） |
| 409 | 保管場所が断った、ほかの変更が進んでいる | `{"error"}` |
| 422 | 試しが失敗した。世代は作らない | `{"error": "the trial failed", "trial": {..}}` |
| 500 | 試しを流せない | `{"error"}` |
| 503 | 監査の行を書けない | `{"error": "unavailable"}` |

`trial` は、通ったとき `{"passed": true, "accepted": [..]}`、失敗したとき `{"passed": false, "failure": <文>}` で、検査プロセスの出力があれば、`passed` の値に関わらず `detail`（512 バイトまで）が付く。試しの要求がすべて通っても、検査プロセスか作業場所が片付かなかったときは、`passed` が `false`、`failure` が `the inspector did not stop cleanly; a process or a directory may be left behind` になり、422 で世代は作らない。このときは、ホストにプロセスやディレクトリが残っていないか確かめる。`accepted` は、試しで受け入れた遮断（`{"kind": "block", "probe", "rule", "phase", "status"}`）と検知（`{"kind": "detected", "probe", "rule", "status"}`）である。`probe` は試しの要求の名前（`GET /`、`POST / with a urlencoded body`、`POST / with a JSON body`）である。

### 選択と戻し

`POST /api/activate`（`{"generation", "expect"}`）と `POST /api/rollback`（`{"expect"}`）は、保管場所の選ぶ世代を変え、proxy を切り替えさせる。operator 以上で、token 可である。

- 指紋は 64 桁の小文字の 16 進数。違うと 400 `a generation is not 64 lowercase hexadecimal digits`。
- `expect` は、画面で見た「今選ばれている世代」である。画面を見た後に別の人や命令が選び直していれば、古い画面で選び直して上書きするのを防ぐため、409 で断る。
- 保管場所に選ばれている世代が無いと、`expect` が合わないので選べない。最初の世代は命令（`rules activate`）で選ぶ。画面も、選ばれている世代が無いときは選択を出さず、`rules activate` を案内する。
- `generation` に今選ばれている世代を指定すると、保管場所の選ぶ世代は変わらず、proxy だけを切り替えさせる（管理画面の「プロキシを切り替える」）。

進み方:

1. 世代が保管場所にあること（`activate`。無ければ 404 `no such generation`）。戻しは、戻しの先を決める（下）。
2. 保管場所が選んでいる世代が `expect` と同じこと。違えば 409（変更なし。履歴には書かない。監査に `denied`、reason `expect`）。
3. proxy の状態を問う。
   - 届かない: 503 `the proxy cannot be reached`。保管場所は変えず、履歴に `unreachable` を書く（監査にも `denied`、reason `unreachable`）。
   - 接続を受けて何も答えずに閉じる（同時の接続の上限）: 503 `the proxy is busy`。保管場所は変えず、履歴には書かない（監査に `denied`、reason `busy`）。
4. 監査の行を書く（書けなければ 503 `unavailable` で、変更しない）。
5. 保管場所が世代を選ぶ。選ぶのは lock の中で、`expect` をもう一度確かめる。別のプロセスがこの間に選んでいれば、上書きせずに 409 とする。
6. proxy に切り替えを依頼し、終わりを待つ（上の「制御 socket」）。
7. 履歴に1行書き、答える。

答え（本文は `{"result", "from", "generation", "chosen"}`。失敗では `error` も付く）:

| `result` | 状態コード | 意味 | `chosen` |
|---|---|---|---|
| `switched` | 200 | proxy は今その世代を使っている | `true` |
| `unchanged` | 200 | proxy はすでにその世代を使っていた | `true` |
| `refused` | 409 | proxy が断った（`the proxy refused the switch`）。proxy が `expect` の違いを見つけたときも含む | `true` |
| `failed` | 502 | proxy は切り替えなかった（`the proxy did not switch`）。時間内に切り替わらなかったときも含む | `true` |
| `unreachable` | 503 | proxy に届かない。保管場所は変えていない | `false` |
| `unconfirmed` | 503 | 保管場所は変えたが、proxy が結果を答えなかった（`the proxy did not say how the switch ended`） | `true` |

- `chosen` は「保管場所が今その世代を選んでいる」かどうかである。
- 切り替えが `refused`、`failed`、`unconfirmed` に終わっても、保管場所は元に戻さない。`refused` と `failed` では、proxy は前の世代を使い続ける。`unconfirmed` では、proxy がどちらの世代を使っているか分からないので、`GET /api/status` の `proxy.generation` で確かめる。proxy を起動し直すと、保管場所が選んでいる世代で始まる。その世代を使わないなら、前の世代を選び直す。
- 履歴に行を書けなかったときは、答えに `"history": "not written"` が付く。
- `result` と `chosen` を持つのは、上の表の6つの場合だけである。ほかの失敗の本文は `{"error": <文>}` だけである。`expect` が合わない 409（`the chosen generation is not the one that was expected`）、`the proxy is busy` の 503、戻しの先が決まらない 409、保管場所そのものが選択を断った 409 がそれに当たる。この中で履歴に行（`refused`）を書くのは、保管場所そのものが選択を断ったときだけである。

戻しの先:

- 履歴の中で、結果が `switched` で、`from` と `to` が違う、最も新しい行の `from` である。
- ただし、その行の `to` が、保管場所が今選んでいる世代のときだけ。切り替えが失敗した後や、命令で世代を選んだ後は、履歴の終わりが選ばれた世代と合わないので、戻せない（409 `the history does not end at the chosen generation`）。`switched` の行が無いときは 409 `there is no switch to go back from`。
- 戻しの先の世代が保管場所に無ければ 409 `the generation to go back to is not in the store`。
- 戻しも履歴に `rollback` として入る。続けてもう一度戻すと、元の世代に戻る。

### 削除

`DELETE /api/generations/<指紋>`（operator 以上、token 可）は、世代を保管場所から消す。元に戻せない。次の世代は消さず、409 で断る。

| 世代 | `error` |
|---|---|
| 保管場所が選んでいる世代 | `the generation is the one the rules store chooses` |
| 戻しの先の世代 | `the generation is the target of a rollback` |
| proxy が使っている世代 | `the generation is used by a running proxy` |

保管場所に無い世代は 404 である。ほかの変更が進んでいるときは、409 `a change of the rules is under way`（この管理のプロセスの中）か `the rules store is in use by another command`（命令や別のプロセスが保管場所の lock を持っている）で断る。削除の確かめの後に命令が世代を選んだときは、409 `the generation is the current one` になる。成功すると `{"removed": <指紋>}` を返す。

## 切り替えの履歴

`GET /api/history`（viewer 以上、token 可）は、世代の選択と戻しの履歴を、新しい順に 200 行まで `{"entries": [...]}` で返す。

| 項目 | 中身 |
|---|---|
| `ts` | 時刻（UTC の RFC 3339 で ms まで） |
| `actor` | 切り替えを依頼した利用者の名前 |
| `from` | 依頼の前に保管場所が選んでいた世代 |
| `to` | 依頼した世代（戻しでは戻しの先） |
| `kind` | `activate`、`rollback` |
| `result` | 結果の語（下の注） |

`result` は、「選択と戻し」の答えの `result`（`switched`、`unchanged`、`refused`、`failed`、`unreachable`、`unconfirmed`）と同じ6つで、意味も同じである。

- 履歴は `admin.store.dir` の `activations.log` に追記する。1行を書き終えて同期してから答える。回転させず、消えもしない。読み戻すのは終わりの 1 MiB（約 4000 行）までで、それより古い行は戻しの先の判断にも使われない。
- 管理画面と管理 API で依頼した切り替えだけが入る。命令（`rules activate`）と SIGUSR1 による選択と切り替えは入らない。
- 履歴に書くのは、proxy に届かなかったときと、監査の行を書いた後の結果（保管場所が選択を断ったときと、proxy の答え）だけである。入力の誤り、世代が無い、戻しの先が決まらない、ほかの変更が進んでいる、`expect` が古い、proxy が同時の接続の上限で状態の問いに答えなかった、監査の行を書けなかった、のときは書かない。

## 記録の読み出し

`GET /api/records`（viewer 以上、token 可）は、`records.dir` のファイルを新しい行から読み、条件に合う行を返す。行は書かれたままの JSON の object で、要求から来た文字（`path` など）は `%XX` の形のままである（[運用リファレンス](operator-reference.md) の「記録」）。鍵の順は変わりうる。

条件（query）は次のとおり。どれも1回まで、値は `%XX` で書ける（デコードの後に 128 バイトまで）。

| 条件 | 形 |
|---|---|
| `from`、`to` | 初めと終わりの時刻。UTC の RFC 3339 で、`Z` で終わる。秒の小数は 9 桁まで（ms に切る）か、無し |
| `type` | `request`、`connection`、`tunnel`、`line`、`audit`、`dropped` |
| `class` | 要求の記録の分類（1〜32 文字の小文字・数字・`_`・`-`） |
| `status` | 状態コード（1〜3 桁の数字） |
| `rule` | 規則の id。判定した規則か、ほかに当たった規則の中にあるもの |
| `id` | 要求の番号 |
| `client` | IP の address |
| `generation` | 世代の指紋。先頭 16 桁か 64 桁（記録には先頭 16 桁だけがある） |
| `file`、`offset`、`inode` | 続きの位置。3つがそろって初めて使える |

- `audit` の記録は、管理のプロセスの標準エラーと監査の置き場に出るもので、proxy の記録のファイルには入らない。`type=audit` で探しても、このファイルからは出ない。監査は `GET /api/audit` で読む。
- 1回に返すのは 500 行まで、読むのは 256 MiB までである。どちらかに届いて、まだ記録が残るときは、答えの `next` に続きの位置が入る。読む量の上限で、条件に合う行を見つける前に読みが止まると、`records` が空でも `next` が入る。`next` が `null` になるまで続けて読む。
- 答えは `{"records": [..], "next": null か {"file", "offset", "inode"}}` である。`inode` は文字列で返す。続きを読むには、同じ条件に `next` の3つの値を足す。
- 続きの位置は、ファイルの番号と、その中の位置、ファイルの inode で決まる。記録のファイルの回転で番号が変わっても、inode でファイルを探す。ファイルが回転で消えた、または位置が行の終わりでなくなったときは、409 `the continuation names no place in the record files any more` になる。最初から読み直す。
- 読む順は新しい行からで、`from` より古い行に出会うと、そこで読みを終える。書いている途中で改行が無い最後の行、`ts` を持たない行、長すぎる行は、返さない。
- 失敗:
  - 設定に `records` が無い: 404 `records are not configured`
  - 条件の誤り（知らない条件、同じ条件が2回、値の形の誤り、続きの位置の3つがそろわない）: 400。文は決まった英語の1文
  - 記録のファイルのディレクトリが、持ち主・権限の確かめを通らない: 503。文は確かめの文
  - ファイルを読めない: 503 `unavailable`

## 管理画面

管理画面は、管理のプロセスが配る。ブラウザで `https://admin.example.com/`（`admin.origin`）を開く。

- ファイルは `proxy/admin-ui/` にあり、実行ファイルに埋め込む。管理のプロセスと管理画面は、いつも同じ版である。ホストのファイルは読まない。
- 配る path は、`GET /`（ページ）と `GET /ui/<名前>`（スタイルシート、script、icon の14個）だけである。session は要らない（ファイルに秘密は無い）。`GET` と `HEAD` 以外は 405、表に無い名前は API の表に回って 404 になる。
- ファイルの答えの header:

| header | 値 |
|---|---|
| `Cache-Control` | `no-store` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'` |
| `Referrer-Policy` | `same-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Permissions-Policy` | `accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()` |

- 画面の script は、文字列から markup を作れない（Trusted Types）。画面が自分の script と style と icon を読み、自分の API を呼ぶ以外は、何もできない。
- API の答えの `Referrer-Policy` は `no-referrer`、画面のファイルの答えは `same-origin` である。

言語と保存:

- 言語は日本語と英語である。選んだ言語を覚えていればそれを、無ければブラウザの言語（`ja` で始まれば日本語、`en` で始まれば英語）を、どちらでもなければ英語を使う。上の帯で切り替えられる。
- 表示（自動、明るい、暗い）も選べる。ブラウザの storage（`localStorage`）に置くのは、この言語と表示の2つだけである。パスワード、確認コード、回復コード、API token、CSRF token、第二要素の秘密は、どれも画面のメモリにだけ置く。一度しか返さないもの（回復コード、token、設定中の秘密）も、画面を離れると捨てる。URL と履歴にも入れない。
- 第二要素の QR コードは、画面の中で描く（外には何も送らない）。

使える画面は役割で決まる。

| 画面 | 役割 | すること |
|---|---|---|
| 状態 | viewer 以上 | proxy の状態、選ばれた世代と使っている世代、戻しの先を表示する。切り替えの途中ではないのに2つの世代が違うときは、帯に警告を出す。途中のときは、状態の画面にその旨だけを出す |
| 世代 | viewer 以上 | 世代の一覧と中身を見る。operator 以上は、選択、proxy の切り替え（選ばれているのに使われていない世代）、削除ができる。選ばれた世代、使われている世代、戻しの先は削除できない |
| 取り込み | operator 以上 | ブラウザでファイルを選び、CRS の使用と外すファイル、検査しない経路、検知だけを指定して取り込む。上限をブラウザでも数える。試しで遮断されたら、確認を経て「遮断を受け入れて取り込む」ができる。新しい世代は選ばれない |
| 履歴 | viewer 以上 | 切り替えの履歴。operator 以上は、「前の世代に戻す」ができる |
| 記録 | viewer 以上 | 条件を指定して記録を探し、ページごとに新しい方・古い方へ進む。要求から来た文字は、`%XX` の形のまま表示する。行の詳細で「%XX を読み取った文字も見る」を選ぶと、読み取った文字も見せる |
| 監査 | operator 以上 | 最新の 200 件 |
| アカウント | viewer 以上 | パスワードの変更、第二要素の設定と解除、API token の作成と削除 |
| 利用者 | owner | 利用者の一覧、作成、役割の変更、無効・有効、パスワードと第二要素の初期化、全員の token の一覧と削除 |

- 選択と戻しは、先に確認を出し、変更前と変更後の世代を見せる。削除は、消す世代の指紋・作った時刻・モードを見せて確認する。取り込みは確認なしで送り、試しの遮断を受け入れて取り込み直すときだけ確認を出す。実行中は、ほかの変更を始められない。
- 結果が分からないとき（本文に `result` が無い 502 と 504、接続が切れた）は、選択と戻しでは状態と履歴を、取り込みでは世代の一覧の新しい方3つを、削除では世代の一覧を読み直して見せる。
- どの画面も自動では読み直さない。最新にするには「読み直す」を使う。
- ログインの後、パスワードの変更待ちと設定待ちのときは、その画面だけを出す。
- 画面は、ブラウザの `fetch` で管理 API を呼ぶ。API の答えの文（`error`）は、画面が言語ごとの文に置き換える。

## API の path の一覧

「token」の列は、API token で使えるかである。「状態」の列は、使える session の状態である（通常は、状態の制限が無いこと）。

| method | path | 最小の役割 | token | 状態 | すること |
|---|---|---|---|---|---|
| POST | `/api/login` | （不要） | × | | ログイン。`{"name", "password"}` |
| POST | `/api/login/mfa` | viewer | × | 確認待ち | 第二要素の確認。`{"code"}` か `{"recovery"}` |
| POST | `/api/logout` | viewer | × | どの状態でも | ログアウト |
| GET | `/api/session` | viewer | × | 確認待ち以外 | session の情報 |
| PUT | `/api/account/password` | viewer | × | 通常、変更待ち | パスワードの変更。`{"current", "new"}` |
| POST | `/api/account/mfa/setup` | viewer | × | 通常、設定待ち | 第二要素の設定の開始。`{"password"}` |
| POST | `/api/account/mfa/confirm` | viewer | × | 通常、設定待ち | 設定の確定。`{"code"}` |
| DELETE | `/api/account/mfa` | viewer | × | 通常、設定待ち | 第二要素を外す。`{"password", "code"}` |
| GET | `/api/account/tokens` | viewer | × | 通常 | 自分の token の一覧 |
| POST | `/api/account/tokens` | viewer | × | 通常 | token の作成 |
| DELETE | `/api/account/tokens/<id>` | viewer | × | 通常 | 自分の token の削除。ほかの人の token は 404 |
| GET | `/api/status` | viewer | ○ | 通常 | proxy と世代の状態 |
| GET | `/api/generations` | viewer | ○ | 通常 | 世代の一覧 |
| GET | `/api/generations/<指紋>` | viewer | ○ | 通常 | 世代の中身 |
| POST | `/api/generations` | operator | ○ | 通常 | 取り込み |
| DELETE | `/api/generations/<指紋>` | operator | ○ | 通常 | 世代の削除 |
| POST | `/api/activate` | operator | ○ | 通常 | 世代の選択と proxy の切り替え |
| POST | `/api/rollback` | operator | ○ | 通常 | 前の世代へ戻す |
| GET | `/api/history` | viewer | ○ | 通常 | 切り替えの履歴 |
| GET | `/api/records` | viewer | ○ | 通常 | 記録の読み出し |
| GET | `/api/audit` | operator | ○ | 通常 | 監査の最新 200 行 |
| GET | `/api/users` | owner | × | 通常 | 利用者の一覧 |
| POST | `/api/users` | owner | × | 通常 | 利用者の作成。`{"name", "role", "password"}` |
| PUT | `/api/users/<名前>` | owner | × | 通常 | 役割か有効・無効の変更。`{"role"}` か `{"disabled"}` のどちらか1つ |
| POST | `/api/users/<名前>/password` | owner | × | 通常 | ほかの利用者のパスワードを決める。`{"password"}` |
| DELETE | `/api/users/<名前>/mfa` | owner | × | 通常 | ほかの利用者の第二要素を外す |
| GET | `/api/tokens` | owner | × | 通常 | 全員の token の一覧 |
| DELETE | `/api/tokens/<id>` | owner | × | 通常 | 全員の token の削除 |

- 「通常」の API は、パスワードの変更待ちと設定待ちの session では使えない。
- 主な答えの本文（時刻は、利用者と token ではミリ秒の epoch、世代の `made` では秒の epoch、履歴と監査の `ts` では RFC 3339）:
  - `POST /api/login`、`POST /api/login/mfa`: `{"name", "role", "csrf", "mfa", "must_change"}` と cookie
  - `GET /api/session`: `{"name", "role", "csrf", "mfa", "recovery_left", "must_change", "state", "idle_expires_in_ms", "total_expires_in_ms"}`。`mfa` は第二要素を持つか
  - `PUT /api/account/password`、`DELETE /api/account/mfa`: `{"csrf"}` と新しい cookie。ほかの session は終わる。パスワードの変更では API token がすべて消える
  - `POST /api/account/mfa/setup`: `{"secret", "uri"}`。`POST /api/account/mfa/confirm`: `{"csrf", "recovery"}` と新しい cookie
  - `GET /api/users`: `{"users": [..]}`（`name`、`role`、`disabled`、`mfa`、`must_change`、`created`、`changed`）。`POST /api/users` と `PUT /api/users/<名前>` は、その利用者を返す
  - `GET /api/account/tokens`、`GET /api/tokens`: `{"tokens": [..]}`（新しい順。秘密は含まない）

## 答えの形

### 答え

- 答えはどれも JSON で、次の header を持つ（管理画面のファイルは別である。上の「管理画面」）: `Content-Type: application/json`、`Cache-Control: no-store`、`X-Content-Type-Options: nosniff`、`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`、`Referrer-Policy: no-referrer`、`X-Request-ID`（要求の番号）。
- 要求の番号は、`admin.trusted_proxies` に入る相手からの要求が持つ `X-Request-ID` が、proxy の付ける形（16 桁の小文字の 16 進数、`-`、1〜16 桁の数字）のときはそれである。そうでなければ、管理のプロセスが同じ形の番号を作る。proxy を通した要求は、proxy の記録の `id` と監査の `id` が同じになる。
- 失敗の答えは `{"error": "<文>"}` である。文は、誤りの種類ごとに決まった英語の1文で、要求の値は含まない（入力のファイルの名前だけは、取り込みの 400 の `subject` に別の項目で付く）。取り込みの 422 は `trial` も、世代の選択と戻しの失敗は上の表の項目も持つ。管理画面は、この文を言語ごとの文に置き換える。

### 状態コード

| 状態コード | とき | 主な `error` |
|---|---|---|
| 400 | 本文が JSON の object でない、その API が知らない鍵がある、cookie と token の両方がある、入力の誤り | `bad request`、API ごとの文 |
| 401 | session も token も無い、終わった、利用者が変わった、無効の token。ログインの誤り | `unauthorized`、`invalid credentials` |
| 403 | `Origin`・CSRF・役割・状態・token が使えない API で断った。パスワードや確認コードの誤り。ほかの断り | `forbidden`、`second factor required`、`password change required`、`second factor setup required`、`the password is wrong`、`the current password is wrong`、`the code is wrong`、`mfa is required` |
| 404 | 表に無い path、無い世代・利用者・token、`records` が無い設定 | `not found`、`no such generation`、`records are not configured` |
| 405 | path にその method が無い。`Allow` を付ける（`GET` があれば `HEAD` も挙げる） | `method not allowed` |
| 408 | 本文が 30 秒の中に届かない | `request timeout` |
| 409 | 別の変更と重なった、状態に合わない、数の上限 | `conflict`、`the name is taken`、`the store has too many users`、`the user has too many tokens`、`the last enabled owner stays`、`the user was changed since it was read`、世代の操作の文 |
| 413 | 本文が上限を超える | `payload too large` |
| 415 | 本文を読む API に、`application/json` でない `Content-Type` | `unsupported media type` |
| 422 | 取り込みの試しの失敗 | `the trial failed` |
| 429 | client の回数を超えた | `too many tries` |
| 500 | 管理のプロセスの中の不整合、保管場所を読めない | `internal error`、保管場所の文 |
| 502 | proxy が切り替えなかった | `the proxy did not switch` |
| 503 | 置き場や監査の行を読み書きできない、時間が尽きた、proxy に届かない | `unavailable`、`the proxy cannot be reached`、`the proxy is busy`、`the proxy did not say how the switch ended` |

### 管理 API の確かめの順

最初に破った確かめで答える。

1. path（表に無ければ 404）と method（無ければ 405）
2. 最小の役割を持つ API は、資格（session の cookie か `Authorization: Bearer`）。両方あれば 400、どちらも無い、または合わなければ 401、token の回数を使い切った client は 429
3. 変更では `Origin`（403）と、session なら `X-CSRF-Token`（403）
4. token が使えない API に token（403）
5. session の状態（403。固定の文）
6. 役割（403）

3 から 6 で断った要求は、利用者が分かっているので、監査に書く。その後、その API が本文を読むなら、`Content-Type`（415）と JSON の形（400）を確かめる。
