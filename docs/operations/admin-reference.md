# 管理リファレンス

この文書は、今の実装の管理のプロセス、設定の `admin`、管理 API、管理画面を、引いて使える形でまとめる。proxy の設定と命令は [運用リファレンス](operator-reference.md)、置き方と systemd の例は [ビルドと配置](../build/binary-deployment.md) に書く。

例の path と名前（`/etc/tukuyomi-core/config.json`、利用者 `tukuyomi`、`admin.example.com`、`192.0.2.0/24` など）は例である。

## 構成

管理のプロセスは、`tukuyomi-proxy` と同じ実行ファイルの `admin` 命令で動く、proxy とは別のプロセスである。ブラウザで開く管理画面と、プログラムが使う管理 API に答える。

| もの | 中身 |
|---|---|
| 管理のプロセス | `tukuyomi-proxy admin <config>`。TLS を持たない loopback の待ち受けで、管理画面と管理 API に答える |
| 管理画面 | 実行ファイルに埋め込んだ画面（日本語と英語）。管理のプロセスが配る |
| 管理の置き場 | 設定の `admin.store.dir`。利用者、API token、監査、切り替えの履歴、設定の変更履歴を置くディレクトリ |
| 制御 socket | 設定の `admin.control`。proxy が作る Unix domain socket。管理のプロセスが proxy の状態を問い、世代の切り替えと、managed 設定のバージョンでの設定の読み直しを依頼する（proxy 側は [運用リファレンス](operator-reference.md) の「制御ソケット」） |
| 記録のファイル | 設定の `records.dir`。proxy が記録の写しを置く。管理のプロセスが読み出す（[運用リファレンス](operator-reference.md) の「記録のファイル（`records`）」） |
| managed ストア | 設定の `managed.dir`（`managed` のある設定だけ）。managed 設定のバージョンと、バージョンが使う証明書などのファイルを置くディレクトリ。管理のプロセスがバージョンを保存し、削除する。proxy は読むだけである（[運用リファレンス](operator-reference.md) の「managed ストアとバージョン」） |

- 管理のプロセスと proxy は、同じ設定ファイルを読む。管理のプロセスは、`admin` などの値を起動のときに1回だけ読み、読み直さない。ただし、設定ファイルの値を見る `GET /api/config` と、managed 設定の検証と変更では、そのたびに設定ファイルを読み直す（下の「managed 設定の操作」）。proxy は SIGHUP で読み直すが、`admin` は動いている間に変えられない鍵である（[運用リファレンス](operator-reference.md) の「SIGHUP（設定のリロード）」）。
  - proxy が `admin` から使う鍵は `listen` と `control`、managed のある設定では `route` である。`route` は proxy だけが使い、管理のプロセスは使わない。ほかの鍵は、同じファイルを両方が受け入れるか両方が断るように、proxy も範囲を確かめるだけである。
  - `admin` の鍵を変えたら、管理のプロセスを起動し直す。proxy は、`admin` の違う設定の読み直しを断るので、proxy も起動し直す。`admin.route` を変えたときの proxy の扱いは、[運用リファレンス](operator-reference.md) の「`admin`」と「SIGHUP（設定のリロード）」にある。
- 管理のプロセスは、proxy が止まっていても動く。止まっている間も、世代と記録の読み出し、取り込み、利用者の管理、managed 設定のバージョンの読み出し・検証・削除は使える。proxy に依頼する世代の切り替えと戻し、managed 設定の反映は、proxy に届かなければ断る。managed 設定の「保存して反映」の操作では、そのときバージョンも保存しない（下の「世代の操作」と「managed 設定の操作」）。
- 設定に `admin` が無ければ、管理のプロセスは起動せず（exit 2）、proxy は制御 socket を作らない。

## 管理のプロセス

### `admin`

```text
tukuyomi-proxy admin <config>
```

- 設定ファイルは絶対の path で渡す（[運用リファレンス](operator-reference.md) の「命令」と同じ決まり）。
- 起動は次の順に進む。
  1. 起動の前の確かめ（root でないこと、SIGCHLD、file descriptor。proxy と同じで、中身は [ビルドと配置](../build/binary-deployment.md) の「起動の前の確かめ」）
  2. 設定ファイル
  3. 管理の置き場を開き、`process.lock` の lock を取る
  4. 監査の記録を開く
  5. 待ち受けの bind
- 待ち受けを bind すると、`admin: listening` の行を出し、環境に `NOTIFY_SOCKET` があれば `READY=1` を送る。
- 1つの管理の置き場で動く管理のプロセスは1つだけである。`process.lock` を持っている間、ほかの管理のプロセスは同じ置き場で起動できない（exit 1）。2つのプロセスが、同じ時間枠の確認コードや同じ回復コードを、それぞれ1回ずつ受け入れてしまうのを防ぐためである。
- proxy と同じ利用者で流す。ルールの保管場所、管理の置き場、記録のファイルを置くディレクトリ、managed ストア（`managed.dir`）は、どれも持ち主がその利用者で、group と other の権限が無いディレクトリでなければ使わない。制御 socket のあるディレクトリは、proxy が socket を作るときに同じ確かめをする。取り込みの試しは検査プロセスを起動するので、設定の `kernel`（検査プロセスの実行ファイルと作業場所）も proxy と同じ値を使う。
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
| 取り込み、`POST /api/managed/check`、`POST /api/managed/apply` の本文 | 12 MiB まで。その API を使える利用者（operator 以上で、session か token が生きていて、状態に制限されていない）にだけ読む。それ以外では読まずに、確かめの 400・401・403・429・503 で断る（cookie と token の両方は 400、token の回数を使い切った client は 429、置き場を読めないときは 503） |
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
- session、締め出しの数、設定中の第二要素の秘密、managed 設定の反映の処理はメモリだけにあるので、起動し直すと全員がログインし直し、反映の処理も残らない。API token、利用者、監査、切り替えの履歴、設定の変更履歴は置き場に残る。

systemd の unit は、proxy の unit（[ビルドと配置](../build/binary-deployment.md) の「systemd」）に合わせて作る。管理のプロセスの違いは次のとおりである。

- `ExecStart` は `tukuyomi-proxy admin <config>`、`User` と `Group` は proxy と同じにする。
- `Type=notify` にする。待ち受けを bind した後に `READY=1` を送る。
- `KillMode=mixed` にする。既定の `control-group` では、取り込みの試しの検査プロセスにも SIGTERM が届き、管理のプロセスが検査プロセスを順に止められない（理由は proxy と同じ）。
- `TimeoutStopSec` は、停止の待ちの 10 秒より長くする。取り込みの試しが動いているときのために、その検査プロセスを止める時間（`proxy.stop_inspect_ms` と `kernel.kill_grace_ms`）も足しておく。
- `admin.listen` の port が 1024 以上なら、`AmbientCapabilities` は要らない。`ReadWritePaths` には、ルールの保管場所、管理の置き場、`kernel.tmp_root`、制御 socket のあるディレクトリ、managed ストア（`managed.dir` があるとき）を含める。
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

`admin` と `records` は、設定ファイルの一番上の object（`proxy`、`forward`、`kernel` などと並ぶ）である。どちらも省いてよい。`admin` を書くときは、`crs_dir` と `route` のほかのすべての鍵を書く。`route` は、`managed` のある設定では必ず書き、`managed` の無い設定では書けない。知らない鍵、重複、型の違いを断る決まりは、[運用リファレンス](operator-reference.md) の「設定ファイル」と同じである。

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
| `crs_dir` | 絶対の path、3840 バイトまで。省いてよい | 取り込みで使える CRS のディレクトリ。`scripts/fetch-crs.sh` で取得したもの（[ビルドと配置](../build/binary-deployment.md) の「CRS の取得」）。省くと、取り込みで CRS を使えない |
| `route` | `managed` のある設定だけ。そのときは必須 | 管理画面のルート（host、証明書、`access`）。proxy だけが使う。形と決まりは [運用リファレンス](operator-reference.md) の「`admin`」、使い方は下の「managed のある設定の管理画面のルート」 |

- `listen` は、待ち受け（`proxy.listeners`）と `status.listen` のどれとも重ならない。重なりの決まりは待ち受けどうしと同じで、同じ address と port、または片方が `0.0.0.0` や `::` で port が同じものである。
- 上流の server の address には、`admin.listen` を書ける（待ち受けと `status.listen` は書けない）。proxy の経路を通して外から使うためである（下の「外から使う」）。
- ディレクトリは互いに離す。ルールの保管場所（`rules.store.dir`）、`records.dir`（あるとき）、`admin.store.dir`、`admin.control` のあるディレクトリ、`managed.dir`（あるとき）、`acme.challenge_dir`（あるとき）は、どれも同じにならず、互いの中にもならない。`admin.control` そのものも、ルールの保管場所、`records.dir`、`admin.store.dir` の中にならない。
- `admin.route.host` を変えると、ブラウザで開く URL も変わるので、`admin.origin` も新しい host に合わせ（下の「外から使う」）、管理のプロセスを起動し直す。管理のプロセスは、`admin.origin` を起動のときにだけ読む。proxy の側の扱いは、[運用リファレンス](operator-reference.md) の「`admin`」にある。
- `admin.store.dir` と、`admin.control` のあるディレクトリは、先に作っておく。持ち主が proxy の利用者で、group と other の権限が無い（0700）本物のディレクトリであること。管理のプロセスは、その中に `users/`、`tokens/`、`audit/` を作る。
- `config check` は、`admin` と `records` の鍵と値の関係を確かめる。管理の置き場、制御 socket、記録のファイルを開けるかは、確かめない。

管理の置き場の中身（ファイルは 0600、ディレクトリは 0700）:

| 置き場 | 中身 |
|---|---|
| `users/<名前>.json` | 利用者。パスワードの hash、第二要素の秘密、回復コードの hash を含む。最大 1000 人 |
| `tokens/<id>.json` | API token。token の秘密の SHA-256 だけを持つ。持ち主ごとに 50 個まで |
| `audit/` | 監査（`audit.log` と、回した古いファイル） |
| `activations.log` | 切り替えの履歴 |
| `managed.log` | 設定の変更履歴（下の「設定の変更履歴」） |
| `lock`、`process.lock` | 書き込みの lock と、管理のプロセスの lock |

### 制御ソケット

プロキシは、設定に `admin` があると、起動のときに `admin.control` の制御ソケットを作る。作り方、使える人、依頼と応答の形は [運用リファレンス](operator-reference.md) の「制御ソケット」に書く。管理プロセスの側の扱いは次のとおりである。

- 状態の問い合わせ: 接続は 2 秒、応答は 2 秒待つ。プロキシが接続を受けて何も応答せずに閉じる（同時の接続の上限に達している）ときは、250 ms 後に1回だけ問い合わせ直し、それでも同じなら「プロキシが処理中」とする（`GET /api/status` では、`reachable` が `true` で `proxy` が `null`）。
- 状態の問い合わせと世代の切り替えの依頼では、ソケットが無い、誰も受けない、応答が決まった形でない、時間内に応答が無いときは、どれも「プロキシに接続できない」になる。
- 世代の切り替えの依頼は、`ready_wait_ms + 7 秒` まで待つ。プロキシ自身が応答を待つ時間は `ready_wait_ms + 5 秒` で、管理プロセスの待ちは 2 秒長い。
- プロキシが切り替えの依頼に `busy` と応答したとき、または依頼を読まずに閉じたときは、管理プロセスが 250 ms ごとに状態を問い合わせる。
  - プロキシが、依頼した世代を使い始めれば `switched` とする。
  - 切り替えの途中でない状態が、依頼した世代でないまま2回続けば `failed` とする。
  - `stop_inspect_ms + 7 秒` が過ぎても `failed` とする。
  - 途中で接続できなくなれば `unconfirmed` とする。
- managed 設定のバージョンでのリロードの依頼（`reload`）は、アップストリームのサーバーの名前の解決にかかりうる時間（プロキシが状態で返す `forward.resolve_timeout_ms`。返さない古いプロキシでは、管理プロセスが読んだ設定ファイルの値）に 7 秒を加えた時間まで待つ。プロキシ自身が待つ時間より 2 秒長い。
- プロキシが証明書（`tls`）で拒否したときは、1 秒後に1回だけ依頼し直す。証明書の更新（`acme renew`）がファイルを書き換えている瞬間に読んだ証明書は、その瞬間だけ拒否されるためである。
- `reload` の依頼では、ソケットが無い、誰も受けない、応答が決まった形でない、時間内に応答が無い、何も応答せずに閉じられた、プロキシが `busy`（`reload under way`）と応答した、のどれも、結果が分からないとして扱う。依頼が届いて、リロードが続いていることがあるためである。管理プロセスは、待った時間と同じだけ、250 ms ごとにプロキシの状態を問い合わせ、リロード中でなくなるのを待つ。
  - プロキシが依頼したバージョンを使っていて、設定を切り替えたリロードの数（`config_reloads` の `replaced`）が依頼の前より増えていれば、反映済みとする。
  - そうでなければ `failed` とする。
  - 途中で接続できなくなったとき、時間の終わりにまだリロード中か、まだ問い合わせに応答できないときは、`unconfirmed` とする。

結果の扱いは、下の「世代の操作」と「managed 設定の操作」にある。反映の順と、反映が途中で止まったときの扱いは、[運用リファレンス](operator-reference.md) の「反映」に書く。

### ログファイル

`GET /api/records` は、プロキシが書くログファイル（`records.dir`）を読む。ファイルの名前、サイズ、ローテーションは [運用リファレンス](operator-reference.md) の「記録のファイル（`records`）」に書く。

- 設定に `records` が無いと、この API は 404 になる。
- 管理プロセスは、プロキシと同じ OS ユーザーとしてファイルを読む。ディレクトリが、所有者が違う、group か other の権限がある、ディレクトリでない（シンボリックリンクは使えない）、のどれかなら読まない（503）。
- ログファイルにはクライアントのアドレスとパスが入る。管理 API では viewer 以上が読めるので、viewer のロールを渡す人を考えて決める。

## 外から使う

管理プロセスは TLS を持たないので、プロキシの TLS のリスナーを通して使う。cookie は `Secure` で出るので、管理画面は https でしか使えない。通し方は、設定ファイルに `managed` があるかどうかで違う。

- `managed` の無い設定: 管理用の Host のルートを `forward.routes` に書く（下の例）。
- `managed` のある設定: 管理画面のルートを `admin.route` に書く（[運用リファレンス](operator-reference.md) の「全体の形」と「`admin`」、下の「managed のある設定の管理画面のルート」）。

`managed` の無い設定の例:

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

（`forward` のほかの設定キーは省いた。`admin.listen` が `127.0.0.1:9100` の例である。）

- 証明書: `admin.example.com` を `hosts` に持つ証明書を、TLS のリスナーに置く。持たない名前の handshake は失敗する。
- アップストリーム: サーバーのアドレスに `admin.listen` を書く。
- `access`: `allow_cidrs` で、管理画面を使う人のアドレスに絞る。クライアントのアドレスの決め方と、`access` を使うときの注意は [運用リファレンス](operator-reference.md) の「client の address」と「`access` を使うときの注意」にある。どれかのルートが `access` を持つと、どのルートの `host` にもポートを書けない。
- 全体の設定（全体のアクセス制御とレート制限）とホストごとの設定は、ルートを引く前に、この Host のリクエストにも掛かる（[運用リファレンス](operator-reference.md) の「リクエストの前のポリシー」）。管理画面を使う人の数と速さに合わせて決める。
- 平文のリスナーに、この Host を通さない。ルートはリスナーを問わずに引かれるので、`redirect` でない平文のリスナーがあると、パスワードが暗号化されずに流れうる。平文のリスナーは `redirect` にする。

次の 2 つは、どちらの設定でも書く。

- `admin.trusted_proxies`: プロキシが管理プロセスに接続する元のアドレス（同じホストなら `127.0.0.1/32`）を書く。書かないと、すべてのクライアントがプロキシのアドレスになり、ログインの試行の制限（クライアントごと）が全員で共有され、監査ログの `client` がどれもプロキシのアドレスになる。
- `admin.origin`: ブラウザで開く URL の origin と一字一句同じにする（ポートが 443 のときは書かない）。違うと、ログインを含む変更が 403 になる。

### managed のある設定の管理画面のルート

`managed` のある設定では、管理画面のルートを設定ファイルの `admin.route` に書き、プロキシがこのルートを自分で作る。設定キーの形、証明書と `access`、全体の設定とホストごとの設定が掛からないこと、managed 設定のバージョンに書けないホストは [運用リファレンス](operator-reference.md) の「`admin`」に、リクエストを受けてからの扱いは同じく「リクエストの検証の順」に書く。ボディの上限は下の「ボディの大きさ」にある。

管理画面のルートのリクエストも、ほかのルートと同じく、稼働中の世代で検査される。管理画面で managed 設定を編集するには、`POST /api/managed/check`（検証）と `POST /api/managed/apply`（「保存して反映」の操作）を検査除外のルートにする。この 2 つのリクエストのボディは、証明書チェーンと秘密鍵の PEM や多くのルートを含む、最大 12 MiB の JSON で、検査の対象にすると、ルールがブロックすることがある。ルールのインポートのパス（下の「取り込みの経路を検査しない」）と一緒に、1 つの `--routes` のファイルに書ける。

```json
[
  {"host": "admin.example.com", "path": "/api/generations", "action": "bypass"},
  {"host": "admin.example.com", "path": "/api/managed/check", "action": "bypass"},
  {"host": "admin.example.com", "path": "/api/managed/apply", "action": "bypass"}
]
```

- `path` は `/` で終わらないので、そのパスだけに当たる。ほかの `/api/managed` のパスは、検査される。
- 検査除外のルートは世代の一部である。どの世代にも同じルートを入れ続ける。入れ忘れた世代を選ぶと、その世代からは `check` と `apply` のボディが検査される。
- 検査除外のルートが無い世代で、ルールが `check` か `apply` のリクエストを 403 でブロックすると、管理画面は「プロキシか WAF がリクエストを拒否しました。PEM のファイルや多くのルートを含むリクエストボディは、WAF にブロックされることがあります。/api/managed/check と /api/managed/apply を検査の対象から除外する設定を確認してください。」と出す。

### 取り込みの経路を検査しない

`POST /api/generations`（取り込み）の本文は、ルールのファイルを含む大きな JSON である。これを検査の対象にすると、ルールの検査が取り込みを遮断することがある。この path は、世代の検査しない経路（[運用リファレンス](operator-reference.md) の「検査しない経路」）にする。

```json
[
  {"host": "admin.example.com", "path": "/api/generations", "action": "bypass"}
]
```

- `path` は `/` で終わらないので、この path だけに当たる。`/api/generations/<指紋>`（世代の読み出しと削除）は、検査される。
- 検査しない経路は世代の一部である。どの世代にも同じ経路を入れ続ける。入れ忘れた世代を選ぶと、その世代からは取り込みが検査される。
- この経路が効くのは、入れた世代が使われてからである。最初にこの経路を入れる世代は、命令で取り込む（`rules import ... --routes <file>`）。管理画面の取り込みでも、ホストとパスを表の行に書いて入れられる（送る本文は同じ形の JSON である）。

### 管理の Host の CRS の調整

管理の Host を CRS で検査すると、CRS の既定の設定は、管理画面の次の要求を遮断する。どちらも、管理の Host にだけ効く調整で通す。調整の後も、ほかの Host の検査は変わらない。

- PUT と DELETE: CRS が既定で許す method は `GET`・`HEAD`・`POST`・`OPTIONS` だけで、ほかの method は規則 911100 で遮断される。管理 API は、パスワードの変更、役割と有効・無効の変更、第二要素の解除、API token と世代の削除に PUT と DELETE を使う。調整が無いと、新しい利用者は最初のパスワードの変更ができず、ログインを終えられない。
- パスワードの欄: CRS は JSON の本文の値も検査する。記号の並びによっては、正しいパスワードが SQL injection と判定され、ログインやパスワードの変更が遮断される（規則 942100 など）。

method の調整は、CRS のディレクトリの `crs-setup.conf` の終わりに足してから、世代を取り込む。運用者のルールのファイルは CRS の規則の後に読み込まれる（[運用リファレンス](operator-reference.md) の「`rules`」）ので、そこに書いても、method の規則より後になって効かない。管理画面の取り込みで CRS を使うときは、`admin.crs_dir` の `crs-setup.conf` に足す。

```text
SecRule REQUEST_HEADERS:Host "@rx ^admin\.example\.com(?::[0-9]{1,5})?$" \
    "id:1000100,phase:1,pass,nolog,t:none,t:lowercase,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT DELETE'"
```

パスワードの欄の調整は、運用者のルールのファイルに書き、取り込みで `--rules`（管理画面では「ルールのファイル」）に渡す。phase 1 の規則なので、CRS の後に読み込まれても、本文を検査する CRS の規則より先に効く。

```text
SecRule REQUEST_HEADERS:Host "@rx ^admin\.example\.com(?::[0-9]{1,5})?$" \
    "id:1000101,phase:1,pass,nolog,t:none,t:lowercase,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.password,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.current,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.new"
```

- `admin\.example\.com` は、`admin.origin` の host に替える。`.` は `\.` と書く。
- 外すのはパスワードの3つの欄（`password`、`current`、`new`）だけである。名前の欄、token の名前、query などは、調整の後も検査される。攻撃に似た名前は遮断されるので、別の名前にする。
- 規則の id は、ほかの規則と重ならない値にする（検査プロセスが使う id は、[運用リファレンス](operator-reference.md) の「検査プロセスが足す決まり」にある）。
- 調整を入れた世代は、管理の Host の PUT と DELETE、記号を含むパスワードでのログインを試してから選ぶ。遮断された要求は、画面に出る要求の番号で記録を探すと、`rules` で規則の id が分かる。

### ボディの大きさ

- ルールのインポート（`POST /api/generations`）と、managed 設定の `POST /api/managed/check`・`POST /api/managed/apply` のリクエストボディは、12 MiB まで届く。`proxy.max_body` を 12 MiB（12582912）以上にする。ルートの `max_body` は `proxy.max_body` を下げることしかできないので、ほかのルートを絞りたいなら、そちらのルートに小さい `max_body` を書く。管理画面のルート（`admin.route`）には `max_body` が無いので、`proxy.max_body` が上限になる。
- 検査除外のルートの長いボディは、ためずに流す（[運用リファレンス](operator-reference.md) の「本文と予算」）ので、12 MiB のボディが `max_buffered_bytes` を使い切ることはない。
- 管理画面は、検証のリクエストボディが 12 MiB を超えるか、ファイルが 192 件を超えるときは、送らずにその旨を出す。設定ファイルの `proxy.max_body`（`GET /api/config` で読む）より大きいだけのときは、送ったうえで、検証の結果と一緒に「送信するリクエストボディが、設定ファイルの proxy.max_body より大きくなります。プロキシを経由して接続しているときは拒否されます。」と出す。プロキシがボディの上限で拒否した 413 には、「リクエストボディがプロキシの上限（proxy.max_body）を超えました。」と出す。

### 長い答えと時間

- 取り込み、世代の選択、戻しは、数十秒以上かかることがある（時間の上限は「待ち受け」の「長い答え」）。proxy の時間の鍵は経路ごとに変えられない。応答の head を待つ時間は、`upstream_header_ms`、`response_idle_ms`、`request_total_ms` のうち先に尽きたもので切れる（[運用リファレンス](operator-reference.md) の「`proxy`: 時間」と「値どうしの関係」）。本文を流す要求（検査しない経路の取り込みなど）では、応答の head が来るまで `response_idle_ms` は効かない。
- 切れると、proxy は client に 502（`request_total_ms` では 503）を返す。管理のプロセスは処理を続け、取り込み、選択、戻しは最後まで進む。proxy の切断では止まらない。
- 管理画面は、本文に `result` を持たない 502 と 504 を「結果が分からない」として扱い、画面ごとに、状態と履歴、または世代の一覧を読み直して見せる。`result` を持つ答え（`failed` の 502、`unreachable` と `unconfirmed` の 503 を含む）は、その語で読む。`result` を持たない 503 は「変更を断った」と読むので、`request_total_ms` は、本文を受ける時間と検査の時間に `upstream_header_ms` を足した時間より十分に長くしておく。API を直接使う側も、同じ答えのときは `GET /api/status` と `GET /api/history`（取り込みなら `GET /api/generations`）で確かめる。
- 時間の鍵は、取り込みと切り替えに要る時間を測ってから決める。`upstream_header_ms` を長くすると、ほかの Host の上流が遅いときも長く待つ。

## 利用者と役割

利用者は名前、役割、パスワードを持つ。名前は 1〜32 バイトの小文字の英字・数字・`.`・`_`・`-`、パスワードは 12〜128 バイトの UTF-8 である（日本語の文字は1文字が3バイト）。パスワードは PBKDF2-HMAC-SHA256（600000 回、salt 16 バイト）の hash で置く。

| 役割 | できること |
|---|---|
| `viewer` | 状態、世代の一覧と中身、切り替えの履歴、記録を読む。managed 設定の状態、バージョンの一覧、反映の処理、設定の変更履歴を読む。自分のパスワード、第二要素、API token を扱う |
| `operator` | viewer のすべて。加えて、監査を読む。ルールの取り込み、世代の選択、戻し、削除をする。managed 設定のバージョンの中身と証明書の情報、設定ファイルの値を読み、検証、保存して反映、名前で反映、戻し、削除をする |
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
- 使える API: 状態、世代、取り込み、選択、戻し、削除、履歴、記録、監査、managed 設定と設定ファイルの値（下の「API の path の一覧」で「トークン」が ○ のもの）。アカウントの API と、利用者の管理の API には使えない（403）。owner の token で、ほかの人のパスワードや第二要素を初期化して、その人としてログインできてしまうのを防ぐためである。
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

管理プロセスは、ログイン、変更、拒否したリクエストを、監査ログの行として残す。

| 項目 | 中身 |
|---|---|
| `ts`、`type` | ログと同じ。`type` は `audit` |
| `id` | リクエスト ID（`X-Request-ID`）。コマンド（`admin bootstrap`、`admin reset`）の行には無い |
| `actor` | 検証したユーザーの名前。検証できなかったときは無い。リクエストヘッダーからは取らない |
| `session` | セッション ID の SHA-256 の先頭 8 桁。ID そのものは書かない |
| `auth` | セッションでないときの入り方。`token:<id>`、`bootstrap`、`reset` |
| `client` | クライアントのアドレス。コマンドの行には無い |
| `action` | 操作（下の表） |
| `target` | 操作の対象（ユーザーの名前、API トークンの ID、世代のフィンガープリント、managed 設定のバージョンの名前）。知らない名前のログインには無い |
| `result` | `ok`、`denied`（拒否した）、`failed`（試したが失敗した） |
| `reason` | 決まった語（`wrong password`、`locked`、`expect`、`store` など） |
| `before`、`after` | 変更の前と後。ロール、有効・無効、世代のフィンガープリント、managed 設定のバージョンの名前 |

パスワード、API トークン、認証コード、リカバリーコード、二要素認証のセットアップキー、cookie は書かない。

| action | とき |
|---|---|
| `login` | ログインの成功（`ok`）と失敗（`denied`。reason は `unknown user`、`wrong password`、`locked`、`disabled`）。セッションを作れないとき（`failed`、`no session`）。二要素認証を設定したユーザーのパスワードが合ったときの reason は `second factor pending` |
| `mfa` | 認証コードの成功と失敗（`wrong code`、`locked`）。リカバリーコードの成功は reason `recovery code` |
| `lock` | ユーザーをロックアウトした（reason `too many failures`） |
| `logout` | ログアウト。セッションが多すぎて終わらせたときは reason `too many sessions` |
| `password`、`mfa_setup`、`mfa_confirm`、`mfa_disable` | 自分のパスワード、二要素認証の設定の開始・確定・無効化。パスワードや認証コードのエラーは `denied`（`wrong password`、`wrong code`、`locked`）。ただし、`mfa_confirm` の認証コードのエラーは行を書かない |
| `token_create`、`token_revoke` | API トークンの作成（`after` がロール）と削除 |
| `user_create`、`role`、`disable`、`enable`、`user_password`、`user_mfa` | owner のユーザーの管理 |
| `import`、`activate`、`rollback`、`remove` | 世代の操作（下の「世代の操作」） |
| `managed-import` | `POST /api/managed/apply`（「保存して反映」の操作）で、バージョンを保存する前（下の「managed 設定の操作」の「保存して反映」） |
| `managed-apply`、`managed-activate`、`managed-rollback` | managed 設定の「保存して反映」「名前で反映」「ロールバック」の操作（下の「managed 設定の操作」） |
| `managed-remove` | managed 設定のバージョンの削除 |
| `create`、`reset` | コマンド `admin bootstrap`、`admin reset` |
| API ごとの action | 拒否した API の名前で、`denied` の行を書く（下の注）。名前は、上の世代の操作と managed 設定の action のほかに、`status`、`generations`、`generation`（世代1つの読み出し）、`history`、`records`、`audit`、`session`、`users`、`user_update`（`PUT /api/users/<name>`）、`tokens`、`managed`（`GET /api/managed`）、`managed-versions`、`managed-version`（バージョン1つの読み出し）、`managed-job`、`managed-history`、`managed-check`、`managed-certificates`、`config`（`GET /api/config`）である |

- API ごとの検証で拒否したリクエストは、ユーザーが分かっていれば `denied` の行を書く。reason は `origin`、`csrf`、`token`（API トークンが使えない API）、`role`、`state`、`second factor pending`、`password change`、`second factor setup` である。
- ユーザーが分からない段で拒否したリクエストは書かない。セッションも API トークンも無い、合わない API トークン、クライアントの回数を超えたログイン、`Origin` が違うログイン、パスが無いなどである。誰でも送れるリクエストで、古い行を押し出せないようにするためである。
- 世代の操作の行は、`target` に対象の世代のフィンガープリントを書く。`activate` と `rollback` の `ok` の行は、`before` に選択中だった世代、`after` に依頼した世代も書く。`ok` の行は変更の前に書くので、成功の印ではない。終わり方は、後に続く `failed` の行と、切り替えの履歴で見る。`failed` の reason は、`expect`、`store`、`refused`、`failed`、`unconfirmed`、`history`（履歴の行を書けなかった）で、インポートは `store` と `trial` である。変更の前に拒否したときは `denied` で、reason は `expect`、`engine`、`busy`、`unreachable` である。削除は、選択中の世代が `chosen`、ロールバック先が `rollback target` である。
- managed 設定の行は、`target` に対象のバージョンの名前を書く。`managed-apply`、`managed-activate`、`managed-rollback` の `ok` の行は、反映の処理がプロキシに依頼する前に書き、`before` に変更前、`after` に変更後のバージョンを書く。成功の印ではないので、終わり方は、後に続く行と設定の変更履歴で見る。
  - 変更の前に拒否したときは `denied` で、reason は `managed`、`configuration`、`expect`、`unreachable`、`busy`、`unmanaged` と、反映の処理の結果の語（`current changed`、`no version`、`store`）である。
  - 変更の前の行を書いた後に失敗したときは `failed` で、reason は反映の処理の結果の語（`refused`、`busy`、`error`、`failed`、`unconfirmed`、`not recorded`）と `history`（設定の変更履歴の行を書けなかった）である。反映の処理を始められなかったときも `failed` で、reason は `time`、`stopping`、`thread` である。
  - `managed-import` の失敗の reason は `store`、`version`、`configuration` である。削除は、拒否が `managed`、`configuration`、`chosen`（選択中のバージョン）、`rollback target`（ロールバック先）、失敗が `store` である。
  - 検証と、読むだけの API は、変更でないので、入口で拒否したときのほかは行を書かない。

書き方:

- 変更は、監査ログの行を先に書いてから行う。行を書けない（ディスクが満ちている、など）と、変更はせず、503 `unavailable` で拒否する。行はディスクに同期してから、標準エラーにも出す。
- 例外はログアウトである。権利を取り上げる操作なので、行を書けなくてもセッションを終わらせる。
- 変更が失敗したときは、後から `failed` の行を書く（書けなくても応答は変えない）。
- 保存先は `admin.store.dir` の `audit/audit.log` で、1行1件の JSON である。1つのファイルが 16 MiB を超えるなら次のファイルに移り、8 ファイル（`audit.log`、`audit.1.log` から `audit.7.log`）を残す。同じ行を標準エラー（journal）にも出す。
- `GET /api/audit`（operator 以上、API トークン可）は、最新の 200 行を新しい順に `{"entries": [...]}` で返す。ファイルの終わりから読み、足りなければ古いファイルを読む。1つのファイルは終わりの 1 MiB までを読み、ファイルがそれより大きいときは、古いファイルを読まずにそこで終える。読めない行は飛ばす。

## 世代の操作

世代の一覧と中身は viewer が読める。取り込み、選択、戻し、削除は operator 以上である。

### 一覧と中身

- `GET /api/status`: 次を返す。
  - `current`: ルールの保管場所が選んでいる世代の指紋（無ければ `null`）
  - `reachable`: proxy に届くか。同時の接続の上限で答えられない proxy は、届くとする
  - `proxy`: proxy の状態（`generation`、`mode`、`engine`、`phase`、`switching`、`reloading`、`ready`）と数（`uptime_ms`、`requests`、`blocked`、`policy_refused`、`upstream_failures`、`config`、`managed`、`resolve_timeout_ms`、`config_reloads`）。proxy の答えのままで、読めなければ `null`。`reloading` と数は前の版の proxy が送らないので、送られなかったものはそれぞれ `null` になる（答えは断らない）。`reloading` は、設定の読み直しの途中かである。数の中身は次のとおりで、詳しくは [運用リファレンス](operator-reference.md) の「制御ソケット」にある
    - `uptime_ms`: proxy が起動してからのミリ秒
    - `requests`: 要求の数（記録の7つの `class` のすべて）
    - `blocked`: 規則が遮断した要求の数
    - `policy_refused`: 全体の `access` と `rate_limit`、ホストごとの設定が断った要求の数
    - `upstream_failures`: 効いている設定の、上流の組の server の失敗の数。設定の読み直しで設定が替わると、0 から数え直す
    - `config`: 効いている設定ファイルの SHA-256（64 桁の小文字の 16 進数）
    - `managed`: 効いている managed 設定のバージョンの名前（64 桁の小文字の 16 進数）。`managed` の無い設定では `null`
    - `resolve_timeout_ms`: 効いている設定の `forward.resolve_timeout_ms`
    - `config_reloads`: SIGHUP と制御 socket の `reload` による設定の読み直しの数。`{"replaced", "refused"}`（替えた数と断った数）
  - `rollback_to`: 今戻しを依頼したら選ぶ世代（無ければ `null`）
  - `crs`: `{"available", "files"}`。`admin.crs_dir` があるか、取り込みで外せる CRS の `.conf` の名前
- `GET /api/generations`: `{"reachable", "generations"}`。新しい順に、各世代の `fingerprint`、`made`（作った時刻。epoch からの秒）、`mode`（`block`、`detect`、manifest が読めなければ `unknown`）、`engine`（`coraza`、`modsecurity`、manifest が読めなければ `unknown`）、`routes`（検査しない経路の数）、`current`（保管場所が選んでいる）、`serving`（proxy が使っている）を返す。
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
| `engine` | 検査のエンジンの名前（`--engine` に当たる）。`coraza` か `modsecurity`（小文字）。省けば `coraza` |
| `detect_only` | `true` で検知だけの世代にする |
| `accept_block` | `true` で、試しの要求が遮断されても失敗にしない |

- 上限と名前の決まりは `rules import` と同じである（[運用リファレンス](operator-reference.md) の「`rules`」）。ファイルは 128 個、1つ 2 MiB、全体 8 MiB まで。2 MiB を超えるファイルは、デコードする前に断る。
- `engine` がエンジンの名前でないときと、そのエンジンが使えないときは、ファイルを集める前に 400 で断る。何も仮に置かず、試しも流さない。文は次のどちらかである。
  - `engine is not the name of an engine (coraza or modsecurity)`
  - `kernel.engines has no inspector for the engine of the generation`（設定に、そのエンジンの検査プロセスが無い）
- 試しは `rules import` と同じで、管理のプロセスが検査プロセスを1つ起動し、決まった3つの要求（`GET /`、form の `POST /`、JSON の `POST /`）を検査する。検査プロセスは、`engine` のエンジンのもの（`coraza` は `kernel.inspector`、`modsecurity` は `kernel.engines`）である。`kernel` の値と、`proxy` の `ready_wait_ms`・`inspect_wait_ms`・`stop_inspect_ms`・`drive_slice_ms` を使う。
- 取り込み、選択、戻し、削除は、管理のプロセスの中で1つずつ進む。ほかの変更が進んでいるときは、待たずに 409 `a change of the rules is under way`。命令や別のプロセスが保管場所の lock を持っているときは、409 `the rules store is in use by another command`。

答え:

| 状態コード | とき | 本文 |
|---|---|---|
| 200 | 世代を作れた | `{"fingerprint", "result", "trial"}`。`result` は `created`、`existing`（同じ世代が既にあった）、`repaired`（壊れていた同じ指紋の世代を作り直した） |
| 400 | 入力が断られた（使えないエンジンも含む） | `{"error"}`。入力のファイルの名前があれば `subject` に付く（0x20〜0x7e の外のバイトは `\xNN`、128 バイトまで） |
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
- `generation` に今選ばれている世代を指定すると、保管場所の選ぶ世代は変わらず、proxy だけを切り替えさせる（管理画面の「プロキシに反映する」）。

進み方:

1. 世代が保管場所にあること（`activate`。無ければ 404 `no such generation`）。戻しは、戻しの先を決める（下）。
2. 保管場所が選んでいる世代が `expect` と同じこと。違えば 409（変更なし。履歴には書かない。監査に `denied`、reason `expect`）。
3. 切り替える先の世代のエンジンが使えること。使えなければ、`{"error": <文>}` の 409（変更なし。履歴には書かない。監査に `denied`、reason `engine`）。文は、上の「取り込み」の 400 の `kernel.engines has no inspector for the engine of the generation` と同じである。manifest が読めない世代は、ここでは断らず、保管場所が世代を選ぶ段で断る。
4. proxy の状態を問う。
   - 届かない: 503 `the proxy cannot be reached`。保管場所は変えず、履歴に `unreachable` を書く（監査にも `denied`、reason `unreachable`）。
   - 接続を受けて何も答えずに閉じる（同時の接続の上限）: 503 `the proxy is busy`。保管場所は変えず、履歴には書かない（監査に `denied`、reason `busy`）。
5. 監査の行を書く（書けなければ 503 `unavailable` で、変更しない）。
6. 保管場所が世代を選ぶ。選ぶのは lock の中で、`expect` をもう一度確かめる。別のプロセスがこの間に選んでいれば、上書きせずに 409 とする。
7. proxy に切り替えを依頼し、終わりを待つ（上の「制御ソケット」）。
8. 履歴に1行書き、答える。

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
- `result` と `chosen` を持つのは、上の表の6つの場合だけである。ほかの失敗の本文は `{"error": <文>}` だけである。`expect` が合わない 409（`the chosen generation is not the one that was expected`）、`the proxy is busy` の 503、戻しの先が決まらない 409、世代のエンジンが使えない 409、保管場所そのものが選択を断った 409 がそれに当たる。この中で履歴に行（`refused`）を書くのは、保管場所そのものが選択を断ったときだけである。

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

## managed 設定の操作

managed 設定は、サイトと証明書、アップストリーム、ルート、デフォルトのアップストリーム、全体のアクセス制御とレート制限、ホストごとの設定を、設定ファイルとは別の managed ストアにバージョンとして置き、管理画面と管理 API から変更する設定である。managed 設定を使うかどうか、managed ストアとバージョンの形、コマンド、反映の順は、[運用リファレンス](operator-reference.md) の「managed 設定」に書く。ここには管理 API の操作を書く。

- 状態、バージョンの一覧、反映の処理、設定の変更履歴は viewer が読める。バージョンの中身、証明書の情報、設定ファイルの値、検証、保存して反映、名前で反映、ロールバック、削除は operator 以上である。どれも API トークンで使える。
- バージョンの中身と設定ファイルの値を operator 以上にするのは、ルートの書き換え（`rewrite`）に、アップストリームの認証の値などの秘密を書けるためである。
- この API が使えるのは、管理プロセスが起動したときに、設定ファイルに `managed` があったときだけである。無かったときは、`GET /api/managed` は `{"managed": false}` を返し、`GET /api/config` はあるときと同じに使え、ほかは 409 `the configuration has no managed object` で拒否する。
- managed ストアは、管理プロセスの起動のときに `managed.dir` が指したディレクトリで、リクエストのたびに開く。開けないときは、500 と managed ストアの文で応答する。検証と変更では設定ファイルを再読み込みし、`managed.dir` が起動のときと違えば 409 `the managed object of the configuration names another directory than at the start` で拒否する。`managed` の有る無しと `managed.dir` を変えたら、管理プロセスを再起動する。

### 状態と一覧

- `GET /api/managed`: 次を返す。
  - `managed`: `true`
  - `current`: managed ストアの選択中のバージョン（無ければ `null`）
  - `serving`: プロキシが制御ソケットで応答した、稼働中のバージョン（状態を読めないとき、プロキシが `managed` の無い設定で動いているときは `null`）
  - `reachable`: プロキシに接続できるか。同時の接続の上限で問い合わせに応答できないプロキシは、接続できるとする
  - `reloading`: プロキシが設定をリロード中か（分からなければ `null`）
  - `rollback_to`: 今ロールバックを依頼したら反映するバージョン（無ければ `null`。下の「名前で反映とロールバック」）
  - `job`: 最後の反映の処理（無ければ `null`。下の「反映の処理」）

  設定の変更履歴を読めないときは 503 になる。
- `GET /api/managed/versions`: `{"reachable", "versions"}`。新しい順に、各バージョンの `name`（バージョンの名前。SHA-256 の 64 桁の小文字の 16 進数）、`made`（バージョンのファイルの更新時刻。epoch からの秒）、`current`（選択中か）、`serving`（稼働中か）を返す。
- `GET /api/managed/versions/<version>`（operator 以上）: 上の 4 つに加えて、`version`（managed ストアにあるとおりのバージョンの JSON）を返す。バージョンはファイルを SHA-256 だけで名指し、どの応答もファイルの中身を持たない。managed ストアに無いバージョンは 404、中身が名前と合わないバージョンは 500 になる。

「選択中」のバージョンと「稼働中」のバージョンは別である。反映が途中で止まったときや、コマンドがバージョンを選択したときは、2 つが違うことがある。どちらかのバージョンをもう一度反映すると、2 つはそろう。管理画面は、2 つが違うときに通知と、そろえる 2 つの操作を出す（下の「管理画面」）。

### 証明書の情報

`GET /api/managed/certificates/<version>`（operator 以上）は、バージョンのサイトごとに、managed ストアにある証明書の状態を、バージョンの順に返す。応答は `{"name", "sites"}` で、サイトごとに次のキーを持つ。

| キー | 中身 |
|---|---|
| `name` | サイトの名前 |
| `kind` | `files`（証明書チェーンと秘密鍵のファイル）、`acme`。どちらの形でもなければ `null` |
| `chain`、`key` | `files` のサイトの、証明書チェーンと秘密鍵のファイルの名前（SHA-256）。中身は返さない |
| `hosts` | `acme` のサイトのホスト。読める形のときだけ |
| `state` | 下の表 |
| `not_after`、`expired` | 証明書チェーンの最初の証明書の有効期限（epoch からの秒）と、サーバーの時計で期限切れか。有効期限を読み取れたときだけ |
| `names`、`more` | 証明書に含まれるホスト名（DNS 名、100 個まで）と、ほかの名前の数。名前も読み取れたときだけ。`[]` は、証明書に DNS 名が無いこと |

`state` は、次のうち最初に当たるものである。

| `state` | 意味 |
|---|---|
| `unreadable` | 証明書チェーンか秘密鍵のファイルを読めない（シンボリックリンク、1 MiB 以下の通常のファイルでない、`files` のサイトで中身が名前と合わない、など）。どちらの形でもない証明書も、これになる |
| `missing` | `files` のサイトで、証明書チェーンか秘密鍵のファイルが managed ストアに無い |
| `waiting` | `acme` のサイトで、まだ発行されていない（`acme renew` が書く証明書チェーンか秘密鍵が無い） |
| `unparsed` | 証明書チェーンの最初の証明書から、名前か有効期限を読み取れない |
| `present` | `files` のサイトで、証明書チェーンを読め、秘密鍵のファイルがある |
| `issued` | `acme` のサイトで、証明書チェーンを読め、秘密鍵のファイルがある |

- 応答は、ディスクにある証明書のもので、プロキシがメモリに持つ証明書ではない。`acme renew` の後は、プロキシが証明書を再読み込みする（SIGUSR2）まで、2 つは違う。バージョンは、稼働中のものでなくてよい。
- `present` と `issued` は、ファイルがあり、証明書チェーンを読めることだけを言う。秘密鍵の中身、証明書チェーンと秘密鍵が対になるか、証明書がサイトのホストを含むかは見ない。どのサイトも `present` のバージョンを、プロキシが拒否することはある。
- プロキシは証明書の有効期限を確認せず、期限切れの証明書もそのまま使う。`check` と `apply` の検証も、有効期限を確認しない。
- この API は、変更の権利もロックも取らず、プロキシに問い合わせず、監査ログに書かない。

### 設定ファイルの値

`GET /api/config`（operator 以上）は、設定ファイルの今の値を返す。設定ファイルに `managed` があっても無くても使える。

- 設定ファイルをリクエストのたびに再読み込みし、設定ファイルの検証をすべて通ったときだけ応答する。読めないときと受け付けないときは、409 と決まった文で応答する。
- 応答は `{"sha256", "managed", ...}` である。`sha256` はファイルの SHA-256（プロキシが読み込むと `/api/status` の `proxy.config` に出る値）、`managed` は設定ファイルに `managed` があるか、残りは設定ファイルの設定キーを、設定ファイルと同じ名前と形で並べたものである。
- 決まった一覧にある設定キーだけを出す。パスの値（証明書、秘密鍵、CA のファイル、ディレクトリ、検査プロセス、ソケット、データベースのファイル）は、書かれていれば `true`、無ければ `null` で返し、パスの文字は返さない。
- operator 以上にするのは、ルートの書き換えに秘密を書けること、サーバーとリスナーのアドレスが入ることのためである。

### 検証

`POST /api/managed/check`（operator 以上）は、バージョンを `POST /api/managed/apply` と同じに検証し、何も保存しない。画面が、保存する前に、エラーをその欄に出すためのものである。

- ボディは `{"version", "files", "expect"}` で、`POST /api/managed/apply` と同じ形である（下の「保存して反映」）。`expect` は省いてよく、あっても形を見ない。
- 進み方（最初に拒否した段で応答する）:
  1. 検証の席。ほかのリクエストが持っていれば 503 `a check of a managed version is under way`。管理プロセスが起動したときに `managed` が無かったときは、すぐに 409。
  2. ボディ、ファイル、バージョンの形。拒否は 400（文と場所）。
  3. 設定ファイルを再読み込みする。`managed` が無いとき、`managed.dir` が起動のときと違うとき、受け付けないときは 409。
  4. managed ストアを開く。開けなければ 500。
  5. バージョンとファイルを、設定ファイルと、リクエストのファイルと managed ストアのファイルで検証する。拒否は 400（文と場所）。
- 応答は 200 `{"version"}` で、保存すればそのバージョンになる名前である。
- 変更の権利を取らず、プロキシに問い合わせず、managed ストアに何も置かず、監査ログにも書かない。選択中のバージョンが無い managed ストア（コマンドで最初のバージョンを作る前）でも検証できる。
- 検証の席: `check` と `apply` のバージョンの検証は、管理プロセスの中で同時に 1 つだけ流す。12 MiB のボディと managed ストアのファイルをもう一度読むので、メモリを多く使うためである。

### 保存して反映

`POST /api/managed/apply`（operator 以上）は、バージョンを managed ストアに保存し、稼働中のプロキシに反映する。ボディは JSON の object で、3 つのキーがどれも要る。

| キー | 中身 |
|---|---|
| `expect` | 画面で見た選択中のバージョン（64 桁の小文字の 16 進数） |
| `version` | 保存するバージョン。managed ストアのバージョンの形（ファイルを SHA-256 で名指し、パスを持たない）で、書き方は問わない。保存するときは 1 つの決まった書き方にし、その SHA-256 がバージョンの名前になる |
| `files` | バージョンと一緒に保存するファイル（証明書チェーン、秘密鍵、CA のファイルの PEM の文字）の配列 |

- `files` は 192 個まで、1 つ 1 MiB まで。同じファイルを 2 回送れず、どのファイルもバージョンが名指すものであること。バージョンが名指してリクエストに無いファイルは、managed ストアに無ければならない。
- ファイルの中身は、応答、監査ログ、設定の変更履歴に書かない。

進み方（最初に拒否した段で応答する）:

1. 検証の席。ほかのリクエストが持っていれば 503。監査ログには書かない。
2. ボディ。JSON の形が違うとき、ファイルが多すぎるか大きすぎるとき、バージョンの形が違うとき（設定キーの重複、知らない設定キー、無い設定キー、型の違い）、`expect` が 64 桁の小文字の 16 進数でないときは 400。監査ログには書かない。
3. 変更の権利、設定ファイルの再読み込み、managed ストアと `expect`、プロキシの状態（下の「名前で反映とロールバック」の 1〜4 と同じ）。プロキシがバージョンを受けられないときは、何も保存しない。
4. バージョンを、設定ファイルとファイルで検証する（`managed import` と同じ検証。国のデータベースは読まず、プロキシが反映のときに読む）。拒否は 400（文と場所）。監査ログには書かない。
5. 監査ログに `managed-import` の行（対象はバージョンの名前）を書く。書けなければ 503 で、何も保存しない。
6. ファイルとバージョンを、managed ストアのロックの中で置く。コマンドがロックを持っていれば 409 `the managed store is in use by another command`、ほかの managed ストアの拒否も 409。managed ストアのファイルと合わせて読んだバージョンが拒否されれば 400（場所なし）、設定ファイルが拒否されれば 409。どれも監査ログに失敗（`store`、`version`、`configuration`）を書く。
7. 反映の処理を始める（下の「名前で反映とロールバック」の 6）。保存したが反映の処理を始められなかったバージョンは、managed ストアに残る。害は無い。

応答は 202 で、`version`（バージョンの名前）、`placed`（保存の結果。`created`、同じバージョンが既にあった `existing`、壊れた写しを置き換えた `recreated`）、`job`（始めた反映の処理）を持つ。

### 名前で反映とロールバック

`POST /api/managed/activate`（`{"expect", "version"}`）は managed ストアのバージョンを名前で、`POST /api/managed/rollback`（`{"expect"}`）はロールバック先のバージョンを、稼働中のプロキシに反映する。operator 以上で、API トークンでも使える。

- `expect` と `version` は 64 桁の小文字の 16 進数である。違うと 400 `a version is not 64 lowercase hexadecimal digits`。
- `expect` は、画面で見た選択中のバージョンである。画面を見た後にほかのユーザーかコマンドが選択し直していれば、古い画面から上書きしないよう、409 で拒否する。
- 選択中のバージョンが無い managed ストアでは、`expect` が合わないので反映できない。最初のバージョンは、コマンド（`managed import` と `managed activate`）で作って選択する（[運用リファレンス](operator-reference.md) の「managed で初めて起動する」）。

進み方（上の「保存して反映」の 3 も同じ。最初に拒否した段で応答する）:

1. 変更の権利。管理プロセスの中で、変更は反映の処理の終わりまで含めて 1 つずつ進む。ほかの変更（バージョンの削除を含む）が進んでいれば 409 `a change of the managed configuration is under way`、管理プロセスが停止中なら 503。監査ログには書かない。
2. 設定ファイルを再読み込みする。`managed` が無いとき（管理プロセスの起動のときに無かったときも）、`managed.dir` が起動のときと違うとき、受け付けないときは 409。監査ログに拒否（`managed`、`configuration`）を書く。
3. managed ストア。開けないとき、選択中のバージョンを示すファイル（`current`）を読めないときは 500。選択中のバージョンが `expect` でない（無いときも）ときは 409 `the chosen managed version is not the one that was expected`（監査ログに拒否、`expect`）。ロールバックは、ここでロールバック先を決める。無ければ 409、設定の変更履歴を読めなければ 503（どちらも監査ログに書かない）。
4. プロキシの状態を、制御ソケットで問い合わせる。
   - 接続できない: 503 `the proxy cannot be reached`。設定の変更履歴に `unreachable` の行を書く（監査ログに拒否、`unreachable`）。
   - 接続を受けて何も応答せずに閉じる（同時の接続の上限）: 503 `the proxy is busy`（監査ログに拒否、`busy`）。
   - 稼働中の設定に `managed` が無い: 409 `the configuration in force has no managed object`（監査ログに拒否、`unmanaged`）。
5. 名前で反映とロールバックでは、バージョンが managed ストアにあること。無ければ、名前で反映は 404、ロールバックは 409 `the version to go back to is not in the store`。`POST /api/managed/apply` は、ここでバージョンを保存する（上の「保存して反映」の 4〜6）。
6. 反映の処理を始める。応答の時間（30 秒）の残りが 5 秒以下のときと、1 の後に管理プロセスが停止し始めたときは、503（監査ログに失敗、`time`、`stopping`）。スレッドを作れなければ 503（監査ログに失敗、`thread`）。

応答は 202 で、`version`（反映するバージョン）と `job` を持つ。

ロールバック先:

- 設定の変更履歴の中で、結果が `applied` で、`from` と `to` が違う、最も新しい行の `from` である。
- ただし、その行の `to` が、今の選択中のバージョンのときだけ。反映が `applied` に終わらなかった後や、コマンドでバージョンを選択した後は、履歴の終わりが選択中のバージョンと合わないので、ロールバックできない（409 `the history does not end at the chosen version`）。`applied` の行が無いときは 409 `there is no change to go back from`。
- ロールバックも履歴に `rollback` として入る。続けてもう一度ロールバックすると、元のバージョンに戻る。

### 反映の処理

変更（「保存して反映」「名前で反映」「ロールバック」）は、上の段に通るとすぐに 202 で応答し、反映は管理プロセスの中の反映の処理（`job`）として続く。反映は、1 つの応答を待てる時間より長くかかることがあるためである。終わりは `GET /api/managed/job`（viewer 以上。`{"job"}`、無ければ `null`）か、`GET /api/managed` の `job` で読む。

- 管理プロセスが持つ反映の処理は最後の 1 つだけで、メモリにだけある。管理プロセスを再起動すると失われる。動いている反映の処理は、管理プロセスと一緒に終わり、managed ストアのロックもプロセスと一緒に外れる。
- 反映の処理はキャンセルできない。依頼したユーザーのロールが変わっても止まらない。
- 反映の処理は、終わるまで変更の権利を持つ。その間、ほかの変更とバージョンの削除は 409 になる。
- 反映の順（managed ストアのロック、プロキシへのリロードの依頼、選択中のバージョンを進める順）と、途中で止まったときの扱いは、[運用リファレンス](operator-reference.md) の「反映」に書く。管理プロセスが制御ソケットで待つ時間は、上の「制御ソケット」にある。

| キー | 中身 |
|---|---|
| `kind` | `apply`（保存して反映）、`activate`（名前で反映）、`rollback` |
| `actor` | 依頼したユーザーの名前 |
| `from`、`to` | 変更前（`expect`）と変更後のバージョン |
| `started`、`ended` | 始めた時刻と終わった時刻（epoch からの秒）。動いている間、`ended` は `null` |
| `state` | `running`（反映中）か `ended` |
| `result` | 終わり方（下の表）。動いている間は `null` |
| `reason` | 決まった語。拒否したプロキシの部分（`configuration`、`version`、`store`、`upstream`、`tls`、`fixed`、`listener`、`thread`）、`busy` の理由（`store in use`、`proxy busy`、`reload under way`、`starting`、`too many orders`、`stopping`）、`error` の理由、`not recorded` の理由（`current changed`、`store`） |
| `detail` | 拒否したプロキシの文か、managed ストアの文 |
| `config_before`、`config_after` | 反映の前と後に効いていた設定ファイルの SHA-256。分かるときだけ |
| `history` | 設定の変更履歴が行を受け取ったか。行を書かない終わり方では `null` |

| `result` | 意味 | 監査ログ | 設定の変更履歴 |
|---|---|---|---|
| `applied` | プロキシが変更後のバージョンを稼働させ、managed ストアがそれを選択した | 変更の前に書いた `ok` の行 | 行を書く |
| `refused` | プロキシが拒否した。何も変更されていない | 失敗 | 行を書く |
| `busy` | managed ストアかプロキシが使用中だった。何も変更されていない | 変更の前の行より前なら拒否、後なら失敗 | 後なら行を書く |
| `current changed` | 選択中のバージョンが `expect` でなくなっていた | 拒否 | 書かない |
| `no version` | バージョンが managed ストアに無い | 拒否 | 書かない |
| `unmanaged` | 稼働中のプロキシの設定に `managed` が無い | 拒否 | 書かない |
| `store` | managed ストアのロックを取れない、選択中のバージョンを示すファイル（`current`）が無いか読めない、など | 拒否 | 書かない |
| `audit` | 変更の前の監査ログの行を書けなかった。何も変更されていない | − | 書かない |
| `error` | プロキシが依頼を受け付けなかった（`unknown op` は、制御ソケットの `reload` を知らない古いプロキシ） | 失敗 | 行を書く |
| `unreachable` | プロキシに接続できなかった | 拒否 | 行を書く |
| `failed` | プロキシは変更後のバージョンに切り替わらなかった | 失敗 | 行を書く |
| `unconfirmed` | 結果を確認できなかった | 失敗 | 行を書く |
| `not recorded` | プロキシは変更後のバージョンに切り替わったが、managed ストアが選択しなかった（`current changed`: 選択中のバージョンが手で変えられた、`store`: 選択中のバージョンを示すファイル（`current`）を書けない） | 失敗 | 行を書く |

- 監査ログの `ok` の行は、変更の前に書く（`from` と `to` を `before` と `after` に書く。設定ファイルの SHA-256 は、監査ログでなく設定の変更履歴に書く）。成功の印ではないので、終わり方は、後に続く行と設定の変更履歴で見る。
- 設定の変更履歴が行を受け取れなかったときは、監査ログに失敗（`history`）を書く。
- 反映の処理が途中で異常に終わったときは `unconfirmed` になり、管理プロセスがログに 1 行を書く。
- `unconfirmed` と `not recorded` の後は、選択中のバージョンと稼働中のバージョンが違うことがある。`GET /api/managed` の `current` と `serving` で確認し、違えば、どちらかのバージョンをもう一度反映する。

### バージョンの削除

`DELETE /api/managed/versions/<version>`（operator 以上、API トークン可、ボディなし）は、バージョンを managed ストアから削除する。元に戻せない。どのバージョンも名指さなくなったファイルと ACME の証明書も、一緒に片付ける（片付けで削除されるものは [運用リファレンス](operator-reference.md) の「バージョンの削除」）。

進み方（最初に拒否した段で応答する）:

1. 名前が 64 桁の小文字の 16 進数でなければ 404。
2. 変更の権利（反映の処理も持つ）。ほかの変更が進んでいれば 409、管理プロセスが停止中なら 503。監査ログには書かない。
3. 設定ファイルを再読み込みする。`managed` が無いとき、`managed.dir` が起動のときと違うとき、受け付けないときは 409（監査ログに拒否、`managed`、`configuration`）。
4. managed ストアを開けなければ 500。
5. managed ストアの一覧に無いバージョンは 404。
6. 選択中のバージョンは削除しない（409、監査ログに拒否、`chosen`）。
7. ロールバック先のバージョンは削除しない（409、監査ログに拒否、`rollback target`）。設定の変更履歴を読めなければ 503。
8. 監査ログに `managed-remove` の行（対象はバージョンの名前）を書く。書けなければ 503 で、削除しない。
9. managed ストアが削除する。拒否は、409 と managed ストアの文（監査ログに失敗、`store`）。

| バージョン | `error` |
|---|---|
| 選択中のバージョン | `the version is the one the managed store chooses` |
| ロールバック先のバージョン | `the version is the target of a rollback` |
| 使用中のバージョン（どれが使用中かは [運用リファレンス](operator-reference.md) の「バージョンの削除」） | `the managed version is in use` |

- 成功すると 200 `{"removed", "cleaned"}` を返す。`removed` は削除したバージョンの名前、`cleaned` は片付けを終えたかの真偽である。`cleaned` が `false` は、片付けを終えられなかったこと（ほかのバージョンを読めなかった、など）である。削除は取り消さず、次の削除のときにもう一度片付ける。
- プロキシには問い合わせない。使用中のバージョンは、managed ストアが拒否する。
- 削除は、ほかのバージョンを 1 つずつ読むので、バージョンが多いほど時間がかかる。応答が間に合わないと 503 になるが、削除はそのまま終わることがある。
- 設定の変更履歴には行を書かない。削除したバージョンを名指す行は残る。

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

## 設定の変更履歴

`GET /api/managed/history`（viewer 以上、API トークン可）は、managed 設定の変更（「保存して反映」「名前で反映」「ロールバック」）の履歴を、新しい順に 200 行まで `{"entries": [...]}` で返す。

| 項目 | 中身 |
|---|---|
| `ts` | 時刻（UTC の RFC 3339 で ms まで） |
| `actor` | 変更を依頼したユーザーの名前 |
| `kind` | `apply`、`activate`、`rollback` |
| `from` | 依頼のときに managed ストアが選択していたバージョン |
| `to` | 依頼したバージョン（ロールバックではロールバック先） |
| `result` | 結果の語（下の注） |
| `reason` | 決まった語。無ければ `null` |
| `config_before`、`config_after` | 反映の前と後に効いていた設定ファイルの SHA-256。無ければ `null` |

`result` は、`applied`、`refused`、`busy`、`error`、`failed`、`unconfirmed`、`not recorded`、`unreachable` の 8 つで、意味は「managed 設定の操作」の「反映の処理」の表と同じである。`reason` も、反映の処理の `reason` と同じ語である。

- 履歴は `admin.store.dir` の `managed.log` に、1 行 1 件の JSON で追記する。1 行を書き終えて同期する。ローテーションせず、削除もされない。読み戻すのは終わりの 1 MiB までで、それより古い行はロールバック先の判断にも使われない。決まった形に合わない行は除く。
- 管理画面と管理 API で依頼した変更だけが入る。コマンド（`managed activate`）による選択と、SIGHUP による反映は入らない。
- 行を書くのは、プロキシに接続できなかったとき（`unreachable`）と、変更の前の監査ログの行を書いた後の終わり方だけである（「反映の処理」の表）。入力のエラー、ほかの変更が進んでいる、`expect` が古い、ロールバック先が決まらない、プロキシが同時の接続の上限で問い合わせに応答しなかった、監査ログの行を書けなかった、のときは書かない。
- プロキシと managed ストアの文は、履歴には書かない。反映の処理の `detail` にだけある。
- 行を書けなかったときは、反映の処理の `history` が `false` になり、監査ログに失敗（`history`）を書く。
- 管理プロセスが起動したときに `managed` が無かったときは 409、履歴を読めないときは 503 になる。

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

管理画面は、管理プロセスが配る。ブラウザで `https://admin.example.com/`（`admin.origin`）を開く。

- ファイルは `proxy/admin-ui/` にあり、実行ファイルに埋め込む。管理プロセスと管理画面は、いつも同じバージョンである。ホストのファイルは読まない。
- 配るパスは、`GET /`（ページ）と `GET /ui/<ui-version>/<name>`（スタイルシート、icon、34 個の script の、合わせて 36 個）だけである。script の名前は、`proxy/admin-ui/js/` からのパスである（`js/app.js` は `/ui/<ui-version>/app.js`、`js/waf/waf.js` は `/ui/<ui-version>/waf/waf.js`）。セッションは要らない（ファイルに秘密は無い）。
- パスの `<ui-version>` は、36 個のファイルの名前と中身から作る、16 桁の小文字の 16 進数である（ファイルごとに名前と SHA-256 を並べた一覧の、SHA-256 の先頭 16 桁）。ページかファイルの最初のリクエストが来たときに1回だけ作り、ページの中の `/ui/` を `/ui/<ui-version>/` に置き換えて配る。ファイルの中身が変わらなければ、`<ui-version>` も変わらない。
- `<ui-version>` の無い `/ui/<name>`、違う `<ui-version>` のパス、36 個に無い名前は、どれも API の表に回って 404 になる。ページと、`<ui-version>` の下のファイルに `GET` と `HEAD` 以外の method を送ると、405（`Allow: GET, HEAD`）になる。
- ページとファイルの応答のヘッダー:

| ヘッダー | 値 |
|---|---|
| `Cache-Control` | ページは `no-store`。`<ui-version>` の下のファイルは `public, max-age=31536000, immutable` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'` |
| `Referrer-Policy` | `same-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Permissions-Policy` | `accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()` |

- ページは毎回読まれ、そのときの `<ui-version>` のパスでファイルを名指す。`<ui-version>` の下のファイルは中身が変わらないので、ブラウザは1年まで手元の写しを使う。画面のファイルが変わった実行ファイルで管理プロセスを再起動すると、`<ui-version>` が変わり、ブラウザはそのときだけ新しいパスのファイルを読む。
- 画面の script は、文字列から markup を作れない（Trusted Types）。画面が自分の script と style と icon を読み、自分の API を呼ぶ以外は、何もできない。
- API の応答の `Referrer-Policy` は `no-referrer`、画面のファイルの応答は `same-origin` である。

言語と保存:

- 言語は日本語と英語である。選んだ言語を覚えていればそれを、無ければブラウザの言語（`ja` で始まれば日本語、`en` で始まれば英語）を、どちらでもなければ英語を使う。上の帯で切り替えられる。
- テーマ（自動、ライト、ダーク）と、時刻の書き方（ローカルか UTC）も、上の帯で選べる。ブラウザの storage（`localStorage`）に置くのは、この言語とテーマと時刻の書き方の3つだけである。パスワード、認証コード、リカバリーコード、API トークン、CSRF トークン、二要素認証のセットアップキー、managed 設定の下書き（下の「下書き」）は、どれも画面のメモリにだけ置く。一度しか返さないもの（リカバリーコード、API トークン、設定中のセットアップキー）も、画面を離れると捨てる。ただし、二要素認証の設定を確定した応答が画面を離れた後に届いたときは、そのリカバリーコードを、次に描く画面で見せるまで残す。ログインが終わると、どれも捨てる。URL と履歴にも入れない。
- 言語、テーマ、時刻の書き方を切り替えても、画面は描き直さず、文字だけを置き換える。入力した文字、選んだファイル、絞り込みは、そのまま残る。
- 二要素認証の QR コードは、画面の中で描く（外には何も送らない）。

使える画面はロールで決まる。メニューは、画面を 7 つのまとまり（下の表の「メニュー」の列）ごとに並べ、ロールが使える画面だけを出す。

| メニュー | 画面 | ロール | すること |
|---|---|---|---|
| （名前なし） | 概要 | viewer 以上 | プロキシの数（「リクエスト」「ブロック」「ポリシーで拒否」「アップストリームのエラー」「設定のリロード」の5つ。「リクエスト」の下に起動からの時間を添える。中身は上の「一覧と中身」の `GET /api/status`）、プロキシの状態（検査核の段、モード、エンジン、世代の切り替え中か）、選択中の世代と稼働中の世代、ロールバック先、現在の設定ファイルの SHA-256 を表示する。切り替えの途中ではないのに2つの世代が違うときは、帯に警告を出す。途中のときは、概要の画面にその旨だけを出す。managed 設定を使っているときは、「managed 設定」の枠に、選択中のバージョンと稼働中のバージョン、2つの「一致」「不一致」（反映の処理の間は「反映中」）を出し、「設定のバージョンを開く」で設定のバージョンの画面へ移れる |
| WAF | ルールの世代 | viewer 以上 | 世代の一覧と詳細（ファイル、読み込む順、検査除外のルート）を見る。operator 以上は、選択、プロキシの切り替え（選択中なのに稼働していない世代の「プロキシに反映する」）、削除ができる。選択中の世代、稼働中の世代、ロールバック先は削除できない |
| WAF | ルールのインポート | operator 以上 | ブラウザでファイルを選び、検査のエンジン（Coraza か ModSecurity。初めは Coraza）、CRS の使用と使わないファイル、検査除外のルート、検知のみを指定してインポートする。検査除外のルートは、ホスト（省ける）とパスを1行に1つずつ書く。アクションはいつも `bypass` で、送るボディの `routes` は、`--routes` のファイルと同じ形の JSON である。ホストだけの行はエラーとして示し、何も書かない行は送らない。上限をブラウザでも数える。事前検証でブロックされたら、確認を経て「ブロックを受け入れてインポートする」ができる。新しい世代は選択されない |
| WAF | 切り替え履歴 | viewer 以上 | 切り替えの履歴（新しい順に 200 件まで。画面にもそう書く）とロールバック先。operator 以上は、「前の世代にロールバックする」ができる |
| ログ | アクセスログ | viewer 以上 | 条件を指定してログを検索する。リクエストから来た文字は、`%XX` の形のまま表示する。リクエスト ID を持つログは、行の内容（method と host と path など）を押すと詳細を開く。リクエスト ID は、内容の title と、詳細の「すべての欄」と「JSON」に出る。リクエスト ID を持たないログ（接続や、プロキシの文の行など）は、行の「詳細」で開く。開くと、先に要点（結果の `class`・`status`・`reason`、ルール、`score`、時刻、クライアント、method と host と path、世代）を見せ、その下に、たたんだ「すべての欄」と「JSON」を置く。「すべての欄」で「URL デコードした文字も表示する」を選ぶと、デコードした文字も見せる |
| ログ | 監査ログ | operator 以上 | 最新の 200 件（新しい順。画面にもそう書く）。リクエスト ID がプロキシと管理プロセスの付ける形のときは、その ID からアクセスログを開ける |
| プロキシ | サイト | operator 以上 | managed 設定の下書きの、サイトの一覧と編集（名前、ホスト、証明書。証明書は、証明書チェーンと秘密鍵のファイルか ACME）。一覧と編集の面に、managed ストアにある証明書の有効期限、状態、証明書に含まれるホスト名を出す（上の「証明書の情報」） |
| プロキシ | アップストリーム | operator 以上 | 下書きの、デフォルトのアップストリームと、アップストリームの一覧と編集（サーバー、TLS と CA のファイル） |
| プロキシ | ルート | operator 以上 | 下書きの、ルートの一覧と編集（ホスト、パス、アップストリーム。たたんだ部分に、アクセス制御、ストリーミング応答、書き換え）。1024 本まで読む |
| ポリシー | アクセス制御とレート制限 | operator 以上 | 下書きの、全体のアクセス制御とレート制限と、ホストごとの設定の一覧と編集（下の「ホストごとの設定の画面」） |
| 設定 | 設定のバージョン | viewer 以上 | 選択中のバージョンと稼働中のバージョン、プロキシの状態、反映の状況、バージョンの一覧（下の「managed 設定の画面」）。operator 以上は、バージョンの内容（JSON と証明書）を見て、名前で反映、削除、下書きの作成ができる。選択中のバージョン、稼働中のバージョン、ロールバック先は削除できない |
| 設定 | 設定の変更履歴 | viewer 以上 | 設定の変更履歴（新しい順に 200 件まで。画面にもそう書く）とロールバック先。設定ファイルが反映の前と後で違う行には「変更あり」を出す。operator 以上は、「前のバージョンにロールバックする」ができる |
| 設定 | 設定ファイル | operator 以上 | 設定ファイルの現在の値（上の「設定ファイルの値」）。ここでは変更できない。パスは表示せず、書かれていれば true、書かれていなければ「—」と表示する。稼働中のプロキシとの比較（「一致」か「不一致（リロード待ち）」）を出す |
| 管理 | アカウント | viewer 以上 | パスワードの変更、二要素認証の設定と無効化、API トークンの作成と削除 |
| 管理 | ユーザー | owner | ユーザーの一覧、作成、ロールの変更、無効・有効、パスワードと二要素認証の初期化、全員の API トークンの一覧と削除 |

- 概要の数がプロキシから得られないときは、数の代わりに「—」と短い語を出し、0 と混ぜない。理由は、プロキシの面に1回だけ出す。理由は、プロキシに接続できない（`reachable` が `false`）、プロキシが処理中（`proxy` が `null`）、そのプロキシが数を返さない（前のバージョンのプロキシで、値が `null`）のどれかである。設定ファイルの SHA-256 も同じである。
- 世代の選択、ロールバック、削除は、先に確認を出す。確認には、「現在」と「切り替え後」（ロールバックでは「ロールバック後」、削除では「削除後」）の世代を、フィンガープリント（先頭 12 桁）、モード、エンジン、検査除外のルートの数の表で並べ、変わる値を太字にする。選択の「現在」は選択中の世代、「切り替え後」は選択する世代で、プロキシが選択中の世代と違う世代を使っているときは、その世代も出す。ロールバックの「ロールバック後」はロールバック先で、削除の「削除後」はどれも「なし」である。分からない値は「—」になる。インポートは確認なしで送り、事前検証のブロックを受け入れてインポートし直すときだけ確認を出す。実行中は、ほかの変更を始められない。
- 結果が分からないとき（ボディに `result` が無い 502 と 504、接続が切れた）は、世代の選択とロールバックでは状態と履歴を、インポートでは世代の一覧の新しい方3つを、削除では世代の一覧を再読み込みして見せる。managed 設定の変更で、変更が始まったか分からないときは、「結果不明」として状態を再読み込みして見せる。
- 画面は、時間をおいて自分から再読み込みすることはしない。例外は managed 設定の反映の処理で、画面は、反映の処理が終わるまで、前の応答の 1 秒後に `GET /api/managed/job` を読んで状態を確認し続ける。読めない応答が3回続くか、反映の処理にかかりうる時間を過ぎると、確認をやめ、その旨を出す。確認の間はリクエストのたびにセッションが使われたことになるので、セッションは `admin.session_idle_ms` では終わらない（`admin.session_total_ms` では終わる）。プロキシを通して使っているときは、ログの残し方が `security` でなければ、確認の1回ごとに、プロキシのログに1行が入る。画面から変更したときは、それに関わる表示を再読み込みする。最新にするには「再読み込み」を使う（インポートの画面には無い）。
- 一覧の表は、並べ替えられる列の名前を押すと、その列で並べ替える（押すたびに昇順と降順が切り替わり、値の無い行は後ろに来る）。表の上の欄に語を打つと、セルに見えている文字がその語をすべて含む行に絞り込む（語は空白で区切り、大文字と小文字は区別しない。操作の button の列は見ない）。行は 50 行ずつのページに分け、「前へ」と「次へ」で進む。並べ替えと絞り込みは、画面が読んだ行の中だけで行う。世代の中の検査除外のルートの表など、絞り込みの欄が無い小さな表もある。
- アクセスログは、`GET /api/records` の1回の応答（500 行まで）を、50 行ずつのページで見せる。応答に続き（`next`）があれば、最後のページの「次へ」で続きの古いログを読む。最初のページの「前へ」で、前に読んだ新しい方に戻る。続きの位置は URL に入らないので、URL を開き直すと最初から読む。
- 画面の場所は、URL の `#` の後に入る。`#/<screen>`（`overview`、`generations`、`import`、`history`、`records`、`audit`、`sites`、`upstreams`、`routes`、`policy`、`managed`、`managed-history`、`config`、`account`、`users`）のほか、世代の詳細は `#/generations/<fingerprint>`、バージョンの内容は `#/managed/<version>`、ログの1件は `#/records/<id>`、ログの検索は `#/records?<key>=<value>`（条件の名前は `GET /api/records` と同じで、続きの位置を除く）である。移るたびにブラウザの履歴に入るので、戻ると進むで行き来できる。URL を開き直しても、同じ画面になる。
- URL の中の値は、使う前に形を検証する。形の違う値、画面が知らない条件、余分な部分は、使わずに URL から取り除き、「アドレスの正しくない部分を取り除きました。」と出す。知らない画面と、ロールが使えない画面は、概要を開く。ログの1件は、読んだ行に無ければ、そのリクエスト ID の条件で読み出し、見つからなければその旨を出す。
- 時刻は1つの書き方で見せる。初めはローカルの時刻（`2026-11-04 16:33:56（JST）` の形。括弧の中は、ブラウザが返す時間帯の短い名前で、`JST` や `GMT+8` などになる）で、上の帯の「時刻」で UTC（`（UTC）`）に切り替えられる。表では、時間帯の名前を列の名前に1回だけ書き（`時刻（JST）` など）、セルには書かない。夏時間などで列の名前と違う時間帯の時刻だけ、セルにも時間帯を書く。もう一方の書き方は、その時刻の title（ポインタを重ねると出る文字）に出る。ログの検索の `from` と `to` は、この切り替えに関わらず、UTC の RFC 3339（`Z` で終わる）で書く。
- ログインの後、パスワードの変更待ちと設定待ちのときは、その画面だけを出す。
- 画面は、ブラウザの `fetch` で管理 API を呼ぶ。API の応答の文（`error`）は、画面が言語ごとの文に置き換える。
- 応答に `error` の文が無い失敗（前に置いたプロキシがルールでブロックしたリクエストの 403、プロキシが管理プロセスに接続できなかった 502 など）では、画面は失敗の文の後に、応答の `X-Request-ID` のリクエスト ID を出す。その ID で「アクセスログ」の画面を検索すると、ブロックしたルールなどが分かる（上の「管理の Host の CRS の調整」）。ID は、プロキシと管理プロセスが付ける形のときだけ出す。

managed 設定の画面:

- 管理プロセスが managed 設定なしで起動しているときは、設定のバージョンの画面と編集の画面に、managed 設定でできることと、使い始めるまでの手順の要点を出す。手順は [運用リファレンス](operator-reference.md) の「managed の無い設定ファイルから移す」に従う。
- 設定のバージョンの画面は、選択中のバージョン、稼働中のバージョン、プロキシの状態（「接続可」「接続不可」「プロキシが処理中」「managed 設定は未使用」「リロード中」）を出す。2つのバージョンが違うときは、その通知と、operator 以上には「選択中のバージョンをもう一度反映する」と「稼働中のバージョンを選択し直す」の2つの操作を出す。前者はプロキシを選択中のバージョンに切り替え、後者は稼働中のバージョンを名前で反映して選択中のバージョンにする。
- 設定ファイルが、稼働中のプロキシが読み込んだ内容と違うとき（`GET /api/config` の `sha256` が `/api/status` の `proxy.config` と違う）は、その旨を出す。この画面から反映すると、設定ファイルの変更も一緒に反映される。設定ファイルにエラーがあると、反映は拒否される。
- 名前で反映（「このバージョンを反映する」）、ロールバック、2つのバージョンをそろえる操作、削除（「このバージョンを削除する」）は、先に確認を出す。確認には、「現在」と「反映後」（削除では「削除後」）のバージョンを、サイト数、アップストリーム数、ルート数、デフォルトのアップストリーム、全体のアクセス制御、全体のレート制限、ホストごとの設定数の表で並べ、反映では「各サーバーのダウン判定と、アップストリームの失敗回数はリセットされます。」も出す。
- 変更を送ると、反映の処理が終わるまで「反映中」と出し、終わると、結果（「反映済み」「拒否」「使用中」など）と、起きたこと、次にすることを出す。
- バージョンの内容（`#/managed/<version>`）は operator 以上だけが開ける。中身は秘密を含みうるので、開いている間だけ画面のメモリに置く。選択中でないバージョンでは、「このバージョンから下書きを作成する」で、そのバージョンから下書きを作れる。

下書き:

- サイト、アップストリーム、ルート、アクセス制御とレート制限の4つの画面は、managed 設定の1つの下書きを編集する。下書きは、選択中のバージョンから作る（バージョンの内容の画面から、ほかのバージョンからも作れる）。ここでの変更は、「保存して反映する」を押すまで有効にならない。
- 下書きは、このページのメモリにだけある。ブラウザの storage、URL、履歴には入れない。ログアウトしたとき、操作がないままセッションが切れたとき、タブを閉じたときに失われる。変更のある下書きを残してページを離れようとすると、ブラウザが確認を出す。
- 下書きに入力している間は、30 秒に1回まで `GET /api/session` を送り、セッションを延ばす（入力はセッションを使ったことになる）。
- 画面の上の帯に、元のバージョンと「変更あり」か「変更なし」を出す。「変更あり」は、下書きから作るバージョンが元のバージョンと違うときだけである。入力して元に戻した下書きは「変更なし」になる。入力の形にエラーのある下書きは「変更あり」になる。
- 帯の「検証する」は `POST /api/managed/check` を送り、拒否されたらエラーをその欄に出す（下の「答えの形」の `at`）。「保存して反映する」は、検証、確認、`POST /api/managed/apply` の順に進む。「変更なし」の下書きは保存できない（検証は「元のバージョンと同じで、変更はありません。」と出す）。
- 「保存して反映する」の確認には、保存する変更（アップストリーム、デフォルトのアップストリーム、アクセス制御、レート制限、ホストごとの設定、サイト、ルートの追加・削除・変更）を名前で並べ、値は出さない（書き換えに秘密を書けるため）。ACME の証明書が新しく要るサイトがあるときは（`{n}` はその数）、「{n} 件のサイトで新しい証明書が必要です。acme renew で発行されるまで（タイマーに任せると最大 1 日あまり）、そのサイトのホストには TLS で接続できません。」を出す。
- 下書きの元のバージョンがもう選択中でないとき（ほかのユーザーかコマンドが先に変更した）は、そのままでは保存できない。
- 証明書チェーン、秘密鍵、CA の PEM のファイルは、ブラウザで読み、UTF-8 のテキストで 1 MiB 以下かを検証し、送るテキストの SHA-256 で名指す。ファイルの中身は表示しない。SHA-256 をブラウザの暗号の機能で計算するので、安全な接続（https か localhost）でだけ選べる。読んだバイトは使い終わるとすぐに 0 で埋めるが、テキストはブラウザの中で 0 で埋められず、どこからも参照されなくなるまでメモリに残る。

ホストごとの設定の画面:

- アクセス制御とレート制限の画面は、上から、「全体の設定とホストごとの設定は、管理画面のルートには適用されません。」の注意、全体のアクセス制御とレート制限の枠、ホストごとの設定の一覧と「ホストごとの設定を追加する」、開いたホストごとの設定の編集の面を並べる。
- ホストごとの設定の設定キー、ホストの比較の決まり、重ね方は、[運用リファレンス](operator-reference.md) の「ホストごとの設定（`host_policies`）」に書く。
- 編集の面では、名前と、ホスト（1 行に 1 つ）を書き、アクセス制御とレート制限のそれぞれで、次の3つから選ぶ。切り替えても、入力は下書きに残る。
  - 「引き継ぐ」: 全体の設定を、このホストにも掛ける。レート制限は、全体と同じカウンターで数える。
  - 「このホストの設定」: 全体の設定の代わりに、この面の値を掛ける。全体のアクセス制御は引き継がれない。レート制限は、このホスト用のカウンターで数える。
  - 「使わない」: このホストには掛けない。アクセス制御では、全体の拒否もこのホストには適用されない。
- 全体のアクセス制御かレート制限を変える下書きでは、全体の枠と「保存して反映する」の確認に、「全体のアクセス制御を引き継がない {n} 件のホストごとの設定（{names}）には、この変更は効きません。」（`{n}` は数、`{names}` は名前。レート制限も同じ形）を出す。「このホストの設定」と「使わない」のホストには、全体の変更（緊急の拒否を含む）が効かないためである。
- 一覧には、「ホストごとの設定は、Host ヘッダーがそのホストであるリクエストにだけ適用されます。別のホストのリクエストが、デフォルトのアップストリーム、ホストのないルート、*. で始まるホストのルートを通って同じアップストリームに届くときは、全体の設定だけが適用されます。ホストごとにルートを書き、デフォルトのアップストリームを「なし」にすることをお勧めします。」と出す。
- `geo` の無い設定ファイルで国の一覧を書くと、検証の `at` が、そのホストごとの設定のアクセス制御に出る。管理画面のルートと同じホストを書くと、検証の `at` が、その行に出る。

## API の path の一覧

「トークン」の列は、API トークンで使えるかである。「状態」の列は、使えるセッションの状態である（通常は、状態の制限が無いこと。状態は上の「ログインと第二要素」）。

| method | path | 最小のロール | トークン | 状態 | すること |
|---|---|---|---|---|---|
| POST | `/api/login` | （不要） | × | | ログイン。`{"name", "password"}` |
| POST | `/api/login/mfa` | viewer | × | 確認待ち | 二要素認証の確認。`{"code"}` か `{"recovery"}` |
| POST | `/api/logout` | viewer | × | どの状態でも | ログアウト |
| GET | `/api/session` | viewer | × | 確認待ち以外 | セッションの情報 |
| PUT | `/api/account/password` | viewer | × | 通常、変更待ち | パスワードの変更。`{"current", "new"}` |
| POST | `/api/account/mfa/setup` | viewer | × | 通常、設定待ち | 二要素認証の設定の開始。`{"password"}` |
| POST | `/api/account/mfa/confirm` | viewer | × | 通常、設定待ち | 設定の確定。`{"code"}` |
| DELETE | `/api/account/mfa` | viewer | × | 通常、設定待ち | 二要素認証を無効にする。`{"password", "code"}` |
| GET | `/api/account/tokens` | viewer | × | 通常 | 自分の API トークンの一覧 |
| POST | `/api/account/tokens` | viewer | × | 通常 | API トークンの作成 |
| DELETE | `/api/account/tokens/<id>` | viewer | × | 通常 | 自分の API トークンの削除。ほかの人の API トークンは 404 |
| GET | `/api/status` | viewer | ○ | 通常 | プロキシと世代の状態 |
| GET | `/api/generations` | viewer | ○ | 通常 | 世代の一覧 |
| GET | `/api/generations/<fingerprint>` | viewer | ○ | 通常 | 世代の詳細 |
| POST | `/api/generations` | operator | ○ | 通常 | インポート |
| DELETE | `/api/generations/<fingerprint>` | operator | ○ | 通常 | 世代の削除 |
| POST | `/api/activate` | operator | ○ | 通常 | 世代の選択とプロキシの切り替え |
| POST | `/api/rollback` | operator | ○ | 通常 | 前の世代へのロールバック |
| GET | `/api/history` | viewer | ○ | 通常 | 切り替えの履歴 |
| GET | `/api/managed` | viewer | ○ | 通常 | managed 設定の状態 |
| GET | `/api/managed/versions` | viewer | ○ | 通常 | managed 設定のバージョンの一覧 |
| GET | `/api/managed/versions/<version>` | operator | ○ | 通常 | バージョンの内容 |
| DELETE | `/api/managed/versions/<version>` | operator | ○ | 通常 | バージョンの削除 |
| GET | `/api/managed/certificates/<version>` | operator | ○ | 通常 | バージョンのサイトの証明書の情報 |
| POST | `/api/managed/check` | operator | ○ | 通常 | バージョンの検証。`{"version", "files", "expect"}`（`expect` は省ける） |
| POST | `/api/managed/apply` | operator | ○ | 通常 | バージョンを保存して反映する。`{"expect", "version", "files"}` |
| POST | `/api/managed/activate` | operator | ○ | 通常 | 名前で反映。`{"expect", "version"}` |
| POST | `/api/managed/rollback` | operator | ○ | 通常 | 前のバージョンへのロールバック。`{"expect"}` |
| GET | `/api/managed/job` | viewer | ○ | 通常 | 最後の反映の処理 |
| GET | `/api/managed/history` | viewer | ○ | 通常 | 設定の変更履歴 |
| GET | `/api/config` | operator | ○ | 通常 | 設定ファイルの値 |
| GET | `/api/records` | viewer | ○ | 通常 | ログの読み出し |
| GET | `/api/audit` | operator | ○ | 通常 | 監査ログの最新 200 行 |
| GET | `/api/users` | owner | × | 通常 | ユーザーの一覧 |
| POST | `/api/users` | owner | × | 通常 | ユーザーの作成。`{"name", "role", "password"}` |
| PUT | `/api/users/<name>` | owner | × | 通常 | ロールか有効・無効の変更。`{"role"}` か `{"disabled"}` のどちらか1つ |
| POST | `/api/users/<name>/password` | owner | × | 通常 | ほかのユーザーのパスワードを決める。`{"password"}` |
| DELETE | `/api/users/<name>/mfa` | owner | × | 通常 | ほかのユーザーの二要素認証を無効にする |
| GET | `/api/tokens` | owner | × | 通常 | 全員の API トークンの一覧 |
| DELETE | `/api/tokens/<id>` | owner | × | 通常 | 全員の API トークンの削除 |

- 「通常」の API は、パスワードの変更待ちと設定待ちのセッションでは使えない。
- 主な応答のボディ（時刻は、ユーザーと API トークンではミリ秒の epoch、世代の `made`、managed 設定のバージョンの `made`、反映の処理の `started` と `ended`、証明書の `not_after` では秒の epoch、履歴と監査ログの `ts` では RFC 3339）:
  - `POST /api/login`、`POST /api/login/mfa`: `{"name", "role", "csrf", "mfa", "must_change"}` と cookie
  - `GET /api/session`: `{"name", "role", "csrf", "mfa", "recovery_left", "must_change", "state", "idle_expires_in_ms", "total_expires_in_ms"}`。`mfa` は二要素認証を設定しているか
  - `PUT /api/account/password`、`DELETE /api/account/mfa`: `{"csrf"}` と新しい cookie。ほかのセッションは終わる。パスワードの変更では API トークンがすべて削除される
  - `POST /api/account/mfa/setup`: `{"secret", "uri"}`。`POST /api/account/mfa/confirm`: `{"csrf", "recovery"}` と新しい cookie
  - `GET /api/users`: `{"users": [..]}`（`name`、`role`、`disabled`、`mfa`、`must_change`、`created`、`changed`）。`POST /api/users` と `PUT /api/users/<name>` は、そのユーザーを返す
  - `GET /api/account/tokens`、`GET /api/tokens`: `{"tokens": [..]}`（新しい順。秘密は含まない）
  - `POST /api/managed/check`: 200 `{"version"}`。`POST /api/managed/apply`: 202 `{"version", "placed", "job"}`。`POST /api/managed/activate`、`POST /api/managed/rollback`: 202 `{"version", "job"}`。`DELETE /api/managed/versions/<version>`: 200 `{"removed", "cleaned"}`（上の「managed 設定の操作」）

## 答えの形

### 答え

- 応答はどれも JSON で、次のヘッダーを持つ（管理画面のファイルは別である。上の「管理画面」）: `Content-Type: application/json`、`Cache-Control: no-store`、`X-Content-Type-Options: nosniff`、`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`、`Referrer-Policy: no-referrer`、`X-Request-ID`（リクエスト ID）。
- リクエスト ID は、`admin.trusted_proxies` に入る相手からのリクエストが持つ `X-Request-ID` が、プロキシの付ける形（16 桁の小文字の 16 進数、`-`、1〜16 桁の数字）のときはそれである。そうでなければ、管理プロセスが同じ形の ID を作る。プロキシを通したリクエストは、プロキシのログの `id` と監査ログの `id` が同じになる。
- 失敗の応答は `{"error": "<sentence>"}` である。文は、エラーの種類ごとに決まった英語の1文で、リクエストの値は含まない（入力のファイルの名前だけは、インポートの 400 の `subject` に別の項目で付く）。インポートの 422 は `trial` も、世代の選択とロールバックの失敗は上の表の項目も持つ。管理画面は、この文を言語ごとの文に置き換える。
- `POST /api/managed/check` と `POST /api/managed/apply` の 400 は、`{"error", "at"}` である。`at` は、ボディの中で、拒否した値の場所である。場所が無いときは `null` になる。
  - 場所は、リクエストのボディの設定キーのパスで書く。`files` はファイルが多すぎるとき、`files[k]` は大きすぎる・2 回ある・バージョンが名指さないファイルである。バージョンの中の場所は、`sites[1].hosts[0]`、`upstreams.app.servers[2].address`、`sites[0].certificate.key`、`host_policies[1].rate_limit.keys` の形になる。
  - 配列の番号は 0 から数える。
  - JSON の形が違うボディと、64 桁の小文字の 16 進数でない `expect` は、場所が無い（`null`）。上の「管理 API の確かめの順」で拒否した 400 には、`at` のキーが無い。
  - 文は、場所を含まない決まった文である。設定ファイルの拒否（409）も、文だけで場所を持たない。
- 反映の処理の `detail`（プロキシが拒否した文）は、場所を `at` で持たず、文の中に書く。そのとき、リスナーとアップストリームのサーバーは 1 から数え（`listener 1 cannot be bound`、`(upstream app, server 1)` など）、サイトは名前で書く（`site app`）。検証の `at` とは数え方が違う。

### 状態コード

| 状態コード | とき | 主な `error` |
|---|---|---|
| 400 | ボディが JSON の object でない、その API が知らないキーがある、cookie と API トークンの両方がある、入力のエラー | `bad request`、API ごとの文。`/api/managed/check` と `/api/managed/apply` では `at` も付く |
| 401 | セッションも API トークンも無い、終わった、ユーザーが変わった、無効の API トークン。ログインのエラー | `unauthorized`、`invalid credentials` |
| 403 | `Origin`・CSRF・ロール・状態・API トークンが使えない API で拒否した。パスワードや認証コードのエラー。ほかの拒否 | `forbidden`、`second factor required`、`password change required`、`second factor setup required`、`the password is wrong`、`the current password is wrong`、`the code is wrong`、`mfa is required` |
| 404 | 表に無いパス、無い世代・managed 設定のバージョン・ユーザー・API トークン、`records` が無い設定 | `not found`、`no such generation`、`records are not configured` |
| 405 | パスにその method が無い。`Allow` を付ける（`GET` があれば `HEAD` も挙げる） | `method not allowed` |
| 408 | ボディが 30 秒の中に届かない | `request timeout` |
| 409 | 別の変更と重なった、状態に合わない、数の上限、世代のエンジンが使えない、managed 設定が無い、設定ファイルを受け付けない | `conflict`、`the name is taken`、`the store has too many users`、`the user has too many tokens`、`the last enabled owner stays`、`the user was changed since it was read`、世代の操作の文、`the configuration has no managed object`、`a change of the managed configuration is under way`、managed 設定の操作の文 |
| 413 | ボディが上限を超える | `payload too large` |
| 415 | ボディを読む API に、`application/json` でない `Content-Type` | `unsupported media type` |
| 422 | インポートの事前検証の失敗 | `the trial failed` |
| 429 | クライアントの回数を超えた | `too many tries` |
| 500 | 管理プロセスの中の不整合、ルールストアか managed ストアを読めない | `internal error`、ルールストアと managed ストアの文 |
| 502 | プロキシが切り替えなかった | `the proxy did not switch` |
| 503 | 保存先や監査ログの行を読み書きできない、時間が尽きた、プロキシに接続できない、managed 設定の検証が重なった | `unavailable`、`the proxy cannot be reached`、`the proxy is busy`、`the proxy did not say how the switch ended`、`a check of a managed version is under way` |

managed 設定の変更（「保存して反映」「名前で反映」「ロールバック」）は、受け付けると 202 で応答する。終わり方は、反映の処理（上の「managed 設定の操作」）で読む。

### 管理 API の確かめの順

最初に通らなかった検証で応答する。

1. パス（表に無ければ 404）と method（無ければ 405）
2. 最小のロールを持つ API は、資格（セッションの cookie か `Authorization: Bearer`）。両方あれば 400、どちらも無い、または合わなければ 401、API トークンの回数を使い切ったクライアントは 429
3. 変更では `Origin`（403）と、セッションなら `X-CSRF-Token`（403）
4. API トークンが使えない API に API トークン（403）
5. セッションの状態（403。決まった文）
6. ロール（403）

3 から 6 で拒否したリクエストは、ユーザーが分かっているので、監査ログに書く。その後、その API がボディを読むなら、`Content-Type`（415）と JSON の形（400）を検証する。
