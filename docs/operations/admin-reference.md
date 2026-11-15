# 管理リファレンス

この文書では、現在の実装の管理プロセス、設定キー `admin`、管理 API、管理画面を、調べて使える形でまとめています。プロキシの設定キーとコマンドは [運用リファレンス](operator-reference.md) を、配置と systemd のユニットの例は [ビルドと配置](../build/binary-deployment.md) を参照してください。

この文書に出てくるパスと名前（`/etc/tukuyomi-core/config.json`、OS ユーザー `tukuyomi`、`admin.example.com`、`192.0.2.0/24` など）は例です。

## 構成

管理プロセスは、`tukuyomi-proxy` と同じ実行ファイルの `admin` コマンドで動く、プロキシとは別のプロセスです。ブラウザーで開く管理画面と、プログラムが使う管理 API に応答します。

| 構成要素 | 内容 |
|---|---|
| 管理プロセス | `tukuyomi-proxy admin <config>`。TLS を使わないループバックのリスナーで、管理画面と管理 API に応答します |
| 管理画面 | 実行ファイルに組み込んだ画面（日本語と英語）。管理プロセスが提供します |
| 管理データの保存先 | 設定の `admin.store.dir`。ユーザー、API トークン、監査ログ、切り替えの履歴、設定の変更履歴を置くディレクトリ |
| 制御ソケット | 設定の `admin.control`。プロキシが作る Unix ドメインソケット。管理プロセスが、プロキシの状態を問い合わせ、世代の切り替えと、managed 設定のバージョンでの設定のリロードを依頼するために使います（プロキシ側は [運用リファレンス](operator-reference.md) の「制御ソケット」） |
| ログファイル | 設定の `records.dir`。プロキシがログの写しを置きます。管理プロセスが読み出します（[運用リファレンス](operator-reference.md) の「ログファイル（`records`）」） |
| managed ストア | 設定の `managed.dir`（`managed` のある設定だけ）。managed 設定のバージョンと、バージョンが使う証明書などのファイルを置くディレクトリ。管理プロセスがバージョンを保存し、削除します。プロキシは読むだけです（[運用リファレンス](operator-reference.md) の「managed ストアとバージョン」） |

- 管理プロセスとプロキシは、同じ設定ファイルを読みます。管理プロセスは、`admin` などの値を起動時に 1 回だけ読み、再読み込みしません。ただし、設定ファイルの値を読み出す `GET /api/config` と、managed 設定の検証と変更では、そのたびに設定ファイルを再読み込みします（下の「managed 設定の操作」）。プロキシは SIGHUP でリロードしますが、`admin` は動作中に変更できない設定キーです（[運用リファレンス](operator-reference.md) の「SIGHUP（設定のリロード）」）。
  - プロキシが `admin` から使う設定キーは `listen` と `control` で、managed のある設定では `route` も使います。`route` はプロキシだけが使い、管理プロセスは使いません。ほかの設定キーは、同じファイルを両方が受け付けるか両方が受け付けないようにするため、プロキシも範囲を検証するだけです。
  - `admin` の設定キーを変更したら、管理プロセスを再起動します。プロキシは、`admin` が違う設定のリロードを拒否するので、プロキシも再起動します。`admin.route` を変更したときのプロキシの扱いは、[運用リファレンス](operator-reference.md) の「`admin`」と「SIGHUP（設定のリロード）」を参照してください。
- 管理プロセスは、プロキシが停止していても動作します。停止している間も、世代とログの読み出し、インポート、ユーザーの管理、managed 設定のバージョンの読み出し・検証・削除は使えます。プロキシに依頼する世代の切り替えとロールバック、managed 設定の反映は、プロキシに接続できなければ拒否します。managed 設定の「保存して反映」の操作では、そのときバージョンも保存しません（下の「世代の操作」と「managed 設定の操作」）。
- 設定に `admin` が無ければ、管理プロセスは起動せず（exit 2）、プロキシは制御ソケットを作りません。

## 管理プロセス

### `admin`

```text
tukuyomi-proxy admin <config>
```

- 設定ファイルは絶対パスで渡します（[運用リファレンス](operator-reference.md) の「コマンド」と同じ決まりです）。
- 起動は次の順に進みます。
  1. 起動前の検証を行います（root でないこと、SIGCHLD、ファイルディスクリプター。プロキシと同じで、内容は [ビルドと配置](../build/binary-deployment.md) の「起動前の検証」を参照してください）。
  2. 設定ファイルを読み込みます。
  3. 管理データの保存先を開き、`process.lock` のロックを取得します。
  4. 監査ログを開きます。
  5. リスナーをバインドします。
- リスナーをバインドすると、`admin: listening` の行を出力し、環境に `NOTIFY_SOCKET` があれば `READY=1` を送ります。
- 1 つの管理データの保存先で動作する管理プロセスは、1 つだけです。`process.lock` を保持している間、ほかの管理プロセスは同じ保存先で起動できません（exit 1）。2 つのプロセスが、同じ時間枠の認証コードや同じリカバリーコードを、それぞれ 1 回ずつ受け入れてしまうのを防ぐためです。
- プロキシと同じ OS ユーザーで実行します。ルールストア、管理データの保存先、ログファイルを置くディレクトリ、managed ストア（`managed.dir`）は、どれも所有者がその OS ユーザーで、グループとその他のユーザーの権限が無いディレクトリでなければ使いません。制御ソケットを置くディレクトリは、プロキシがソケットを作るときに同じ検証をします。インポートの事前検証は検査プロセスを起動するので、設定の `kernel`（検査プロセスの実行ファイルと作業ディレクトリ）もプロキシと同じ値を使います。
- 終了コードは次のとおりです。

| 終了コード | 意味 |
|---|---|
| 0 | シグナルで停止しました |
| 1 | それ以外の終了。root での起動、起動前の検証の失敗、使えない管理データの保存先（別の管理プロセスが使用しているときを含む）、開けない監査ログ、バインドできない `admin.listen` |
| 2 | 引数のエラー、受け付けられなかった設定ファイル、`admin` の無い設定ファイル |

### `admin bootstrap`

```text
tukuyomi-proxy admin bootstrap <config> <name>
```

最初のユーザー（ロールは `owner`）を作成します。管理データの保存先にユーザーが 1 人もいないときだけ作成できます。

- パスワードは標準入力の最初の 1 行から読み込みます。引数には渡しません。例:

  ```bash
  read -r -s -p 'password: ' PW; echo
  printf '%s\n' "$PW" | sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy admin bootstrap /etc/tukuyomi-core/config.json alice
  unset PW
  ```

- 名前は 1〜32 バイトの小文字の英字・数字・`.`・`_`・`-` で、パスワードは 12〜128 バイトの UTF-8 です。
- 成功すると、標準出力に `created owner <name>` が出力され、exit 0 で終了します。ほかの行は標準エラーに出力され、`admin bootstrap:` で始まります。
- 監査ログの行（`action` が `create`、`auth` が `bootstrap`、操作者とクライアントのアドレスは無し）を、ユーザーを作成する前に書きます。書けなければユーザーは作成しません。この行は標準エラーに JSON のまま出力されます。
- 管理プロセスが動作していなくても実行できます。

### `admin reset`

```text
tukuyomi-proxy admin reset <config> <name>
```

ロックアウトされたユーザー（たとえば、パスワードと二要素認証を両方失った唯一の owner）のために、パスワードを決め直します。

- パスワードの読み込み方、名前とパスワードの決まり、標準エラーの行、監査ログの行の書き方は、`admin bootstrap` と同じです。監査ログの行は `action` が `reset`、`auth` が `reset` で、対象がユーザーの名前になります。
- 成功すると、標準出力に `reset password of <name>` が出力され、exit 0 で終了します。
- ユーザーに対して、次のことを行います。
  - パスワードを入力された値にし、次のログインで変更させます。
  - 二要素認証とリカバリーコードを無効にします。
  - このユーザーのセッションを終了し、API トークンをすべて無効にします。トークンのファイルを削除できなかったときは、その旨の行を標準エラーに出力しますが、トークンは無効のままで、exit 0 で終了します。
  - ロックアウトを解除し、失敗回数を 0 から数え直します。
- 無効にしたユーザーは、有効には戻しません。無効のユーザーを使えるようにするには、owner が `PUT /api/users/<name>` で有効にします。
- 管理プロセスが動作している間も実行できます。変更は、保存先のロックの中で、読み込んだユーザーが変わっていないときだけ書き込みます。別の書き込みと重なったときは、`the admin store is in use by another process` か `the user was changed since it was read` で拒否されます（exit 1）。その場合は、もう一度実行してください。

`bootstrap` と `reset` の終了コードと標準エラーの主な行は次のとおりです。

| 終了コード | 場合 | 標準エラーの行（`admin bootstrap:` か `admin reset:` の後） |
|---|---|---|
| 0 | 成功 | （標準出力に上の行） |
| 1 | root での実行、起動前の検証の失敗 | `host check refused: ...` |
| 1 | パスワードを読み込めない | `the password is not 12 to 128 bytes`、`the password line is too long`、`the password is not UTF-8` |
| 1 | 使えない管理データの保存先、書き込めない監査ログ | `admin store refused: ...`、`audit log refused: ...`、`the audit log cannot be written` |
| 1 | ユーザーがすでにいる（`bootstrap`）、ユーザーがいない（`reset`） | `the store has a user already`、`the user is not in the store` |
| 2 | 設定が受け付けられなかった、`admin` が無い | `configuration refused: ...` |
| 2 | 名前のエラー | `the name is not 1 to 32 bytes of a-z, 0-9, '.', '_' and '-'` |
| 2 | 引数のエラー | （`admin:` で始まる行に、使い方の行が続きます） |

### リスナー

管理プロセスは、`admin.listen` のループバックアドレスで、HTTP/1.1 に応答します。TLS は使いません（外部から使うときは、プロキシの TLS のリスナーを通します。下の「外部からの利用」）。

| 項目 | 値 |
|---|---|
| 同時接続数 | 32。超えた接続は、受け付けてすぐに閉じます |
| 1 つの接続 | リクエストを 1 つ受け付けて応答し、閉じます（`Connection: close`）。次のリクエストは待ちません |
| ヘッダー部 | 8 KiB まで、ヘッダーフィールドは 64 個まで。10 秒以内に読み終えます |
| ボディ | 64 KiB まで。30 秒以内に読み終えます |
| インポート、`POST /api/managed/check`、`POST /api/managed/apply` のボディ | 12 MiB まで。その API を使えるユーザー（operator 以上で、セッションかトークンが有効で、状態による制限を受けていない）にだけ読み込みます。それ以外では読み込まずに、検証の 400・401・403・429・503 で拒否します（クッキーとトークンの両方がある場合は 400、トークンの回数を使い切ったクライアントは 429、保存先を読めないときは 503） |
| 応答を作る時間 | 30 秒。インポート、世代の選択、ロールバックは、下の「時間のかかる応答」の時間 |
| 接続の存続時間 | ヘッダー部とボディと応答の時間の合計まで |

- `Content-Length` が上限を超えるリクエストは、認証情報を検証する前に、ボディを読み込まずに 413 で応答します。ヘッダー部のエラーや上限超過は、HTTP ライブラリが自身の応答を返すか、何も返しません。
- ボディを読み込む API は、`Content-Type` が `application/json` でなければ 415 になります。JSON の形式が違うボディや、その API が認識しないキーを含むボディは 400 になります。
- `HEAD` は `GET` として扱います。表に無いパスは 404、表にあるパスの別のメソッドは 405（`Allow` を付けます）になります。

時間のかかる応答: インポート（事前検証を含む）、世代の選択、ロールバックは、時間がかかります。応答を作る時間は、次の長い方に 7 秒を加えた時間です（`proxy` の時間の設定キーを使います）。時間切れになったリクエストは 503 `unavailable` になります。

- インポート: `ready_wait_ms + 3 × inspect_wait_ms + stop_inspect_ms`
- 選択とロールバック: `ready_wait_ms + stop_inspect_ms + 14 秒`

運用リファレンスの例の値（`ready_wait_ms` 30000、`inspect_wait_ms` 55000、`stop_inspect_ms` 10000）では、上限は約 212 秒です。問題なく終わるインポートは、これよりずっと短い時間で済みます。

### 停止と systemd

- SIGTERM、SIGINT、SIGHUP で停止します。`admin: stop: <signal>` の行を出力し、`NOTIFY_SOCKET` があれば `STOPPING=1` を送ります。
  1. 動作中のインポートの事前検証を、失敗として終了させます（検査プロセスと作業ディレクトリを片付けます）。
  2. リスナーを閉じます。
  3. 処理中のリクエストを最長 10 秒待ち、残った接続は打ち切ります。
  4. exit 0 で終了します。
- `NOTIFY_SOCKET` の決まりはプロキシと同じです（[運用リファレンス](operator-reference.md) の「systemd への通知」）。扱うシグナルはこの 3 つだけで、SIGUSR1 と SIGUSR2 は扱いません（送るとデフォルトの動作でプロセスが終了します）。
- セッション、ユーザーごとの失敗回数とロックアウトの状態、設定中の二要素認証のセットアップキー、managed 設定の反映の処理はメモリだけにあるので、再起動すると全員がログインし直すことになり、反映の処理も残りません。API トークン、ユーザー、監査ログ、切り替えの履歴、設定の変更履歴は保存先に残ります。

systemd のユニットは、プロキシのユニット（[ビルドと配置](../build/binary-deployment.md) の「systemd」）に合わせて作成します。管理プロセスの違いは次のとおりです。

- `ExecStart` は `tukuyomi-proxy admin <config>` にし、`User` と `Group` はプロキシと同じにします。
- `Type=notify` にします。リスナーをバインドした後に `READY=1` を送ります。
- `KillMode=mixed` にします。デフォルトの `control-group` では、インポートの事前検証の検査プロセスにも SIGTERM が届き、管理プロセスが検査プロセスを順に停止できません（理由はプロキシと同じです）。
- `TimeoutStopSec` は、停止時に待つ 10 秒より長くします。インポートの事前検証が実行中の場合に備えて、その検査プロセスを停止する時間（`proxy.stop_inspect_ms` と `kernel.kill_grace_ms`）も足しておきます。
- `admin.listen` のポートが 1024 以上なら、`AmbientCapabilities` は不要です。`ReadWritePaths` には、ルールストア、管理データの保存先、`kernel.tmp_root`、制御ソケットを置くディレクトリ、managed ストア（`managed.dir` があるとき）を含めます。
- `LogRateLimitIntervalSec=0` にします。監査ログの行は標準エラー（ジャーナル）にも出力されるので、journald のレート制限で失われないようにします。
- プロキシのユニットと順序を付ける必要はありません。

ログは、プロキシと同じく標準エラーに 1 行 1 件の JSON で出力されます（[運用リファレンス](operator-reference.md) の「ログ」）。`admin:` で始まる文の `line` と、監査ログの行の `audit` を出力します。`audit` はプロキシのログファイル（`records.dir`）には入りません。

## 設定キー `admin`

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

`admin` と `records` は、設定ファイルの最上位のオブジェクト（`proxy`、`forward`、`kernel` などと並びます）です。どちらも省略できます。`admin` を書くときは、`crs_dir` と `route` 以外のすべての設定キーを書きます。`route` は、`managed` のある設定では必ず書き、`managed` の無い設定では書けません。未知の設定キー、重複、型の違いを受け付けない決まりは、[運用リファレンス](operator-reference.md) の「設定ファイル」と同じです。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `listen` | ループバックの IP（`127.0.0.0/8` か `::1`）とポート（0 は不可） | 管理プロセスのリスナーのアドレス。`::ffff:127.0.0.1` の形はループバックと見なしません |
| `control` | 絶対パス、107 バイトまで | 制御ソケットのファイル |
| `store` | `{"kind": "file", "dir"}` | 管理データの保存先。`kind` は現在 `file` だけです。`dir` は絶対パスで 3840 バイトまで |
| `origin` | `https://` とホスト（任意で `:port`） | 管理画面を開く URL のオリジン。ルートの `host` と同じ形（小文字の名前）で、ワイルドカード、パス、クエリ、末尾の `/` は書けません。`POST` などの変更リクエストの `Origin` と比較します |
| `trusted_proxies` | 0〜256 個のネットワーク | 管理プロセスのクライアントのアドレスを、`X-Forwarded-For` から決めるときに信頼する相手。ホスト部が 0 の `address/prefix` の形で書きます。読み方はプロキシと同じです（[運用リファレンス](operator-reference.md) の「クライアントのアドレス」） |
| `mfa` | `"optional"`、`"required"` | 二要素認証を求めるか。`required` は、二要素認証を設定していないユーザーに、設定だけをさせます（下の「ログインと二要素認証」） |
| `session_idle_ms` | 1 分〜24 時間 | セッションが使われないまま続く時間 |
| `session_total_ms` | `session_idle_ms` 〜 7 日 | セッションが続く時間の上限 |
| `crs_dir` | 絶対パス、3840 バイトまで。省略できます | インポートで使える CRS のディレクトリ。`scripts/fetch-crs.sh` で取得したもの（[ビルドと配置](../build/binary-deployment.md) の「CRS の取得」）。省略すると、インポートで CRS を使えません |
| `route` | `managed` のある設定だけ。そのときは必須 | 管理画面のルート（ホスト、証明書、`access`）。プロキシだけが使います。形式と決まりは [運用リファレンス](operator-reference.md) の「`admin`」を、使い方は下の「managed 設定を使う場合の管理画面のルート」を参照してください |

- `listen` は、リスナー（`proxy.listeners`）と `status.listen` のどれとも重ならないようにします。重なりの決まりはリスナーどうしと同じで、同じアドレスとポート、または片方が `0.0.0.0` や `::` でポートが同じものです。
- アップストリームのサーバーのアドレスには、`admin.listen` を書けます（リスナーと `status.listen` は書けません）。プロキシのルートを通して外部から使うためです（下の「外部からの利用」）。
- ディレクトリは互いに離します。ルールストア（`rules.store.dir`）、`records.dir`（あるとき）、`admin.store.dir`、`admin.control` を置くディレクトリ、`managed.dir`（あるとき）、`acme.challenge_dir`（あるとき）は、どれも同じディレクトリにすることも、互いの中に置くこともできません。`admin.control` そのものも、ルールストア、`records.dir`、`admin.store.dir` の中に置くことはできません。
- `admin.route.host` を変更すると、ブラウザーで開く URL も変わるので、`admin.origin` も新しいホストに合わせ（下の「外部からの利用」）、管理プロセスを再起動します。管理プロセスは、`admin.origin` を起動時にだけ読みます。プロキシ側の扱いは、[運用リファレンス](operator-reference.md) の「`admin`」を参照してください。
- `admin.store.dir` と、`admin.control` を置くディレクトリは、先に作っておきます。所有者がプロキシの OS ユーザーで、グループとその他のユーザーの権限が無い（0700）、シンボリックリンクでないディレクトリにします。管理プロセスは、その中に `users/`、`tokens/`、`audit/` を作ります。
- `config check` は、`admin` と `records` の設定キーと値の関係を検証します。管理データの保存先、制御ソケット、ログファイルを開けるかどうかは検証しません。

管理データの保存先の内容（ファイルは 0600、ディレクトリは 0700）:

| パス | 内容 |
|---|---|
| `users/<name>.json` | ユーザー。パスワードのハッシュ、二要素認証のセットアップキー、リカバリーコードのハッシュを含みます。最大 1000 人 |
| `tokens/<id>.json` | API トークン。トークンの秘密の SHA-256 だけを持ちます。所有者ごとに 50 個まで |
| `audit/` | 監査ログ（`audit.log` と、ローテーションした古いファイル） |
| `activations.log` | 切り替えの履歴 |
| `managed.log` | 設定の変更履歴（下の「設定の変更履歴」） |
| `lock`、`process.lock` | 書き込みのロックと、管理プロセスのロック |

### 制御ソケット

プロキシは、設定に `admin` があると、起動時に `admin.control` の制御ソケットを作ります。作り方、使えるユーザー、依頼と応答の形式は、[運用リファレンス](operator-reference.md) の「制御ソケット」を参照してください。管理プロセス側の扱いは次のとおりです。

- 状態の問い合わせ: 接続は 2 秒、応答は 2 秒待ちます。プロキシが接続を受け付けて何も応答せずに閉じる（同時接続数の上限に達している）ときは、250 ms 後に 1 回だけ問い合わせ直し、それでも同じなら「プロキシが処理中」とします（`GET /api/status` では、`reachable` が `true` で `proxy` が `null` になります）。
- 状態の問い合わせと世代の切り替えの依頼では、ソケットが無い、接続を受け付けるプロセスが無い、応答が決まった形式でない、時間内に応答が無い、のどれも「プロキシに接続できない」になります。
- 世代の切り替えの依頼は、`ready_wait_ms + 7 秒` まで待ちます。プロキシ自身が応答を待つ時間は `ready_wait_ms + 5 秒` で、管理プロセスの待ち時間は 2 秒長くなっています。
- プロキシが切り替えの依頼に `busy` と応答したとき、または依頼を読まずに閉じたときは、管理プロセスが 250 ms ごとに状態を問い合わせます。
  - プロキシが、依頼した世代を使い始めれば `switched` とします。
  - 切り替えの途中でない状態が、依頼した世代でないまま 2 回続けば `failed` とします。
  - `stop_inspect_ms + 7 秒` が過ぎた場合も `failed` とします。
  - 途中で接続できなくなれば `unconfirmed` とします。
- managed 設定のバージョンでのリロードの依頼（`reload`）は、アップストリームのサーバーの名前解決にかかる可能性のある時間（プロキシが状態で返す `forward.resolve_timeout_ms`。返さない古いプロキシでは、管理プロセスが読み込んだ設定ファイルの値）に 7 秒を加えた時間まで待ちます。プロキシ自身が待つ時間より 2 秒長くなっています。
- プロキシが証明書（`tls`）で拒否したときは、1 秒後に 1 回だけ依頼し直します。証明書の更新（`acme renew`）がファイルを書き換えている瞬間に読み込んだ証明書は、その瞬間だけ拒否されるためです。
- `reload` の依頼では、ソケットが無い、接続を受け付けるプロセスが無い、応答が決まった形式でない、時間内に応答が無い、何も応答せずに閉じられた、プロキシが `busy`（`reload under way`）と応答した、のどれも、結果が分からないものとして扱います。依頼が届いて、リロードが続いていることがあるためです。管理プロセスは、待った時間と同じ時間だけ、250 ms ごとにプロキシの状態を問い合わせ、リロード中でなくなるのを待ちます。
  - プロキシが依頼したバージョンを使っていて、設定を切り替えたリロードの数（`config_reloads` の `replaced`）が依頼の前より増えていれば、反映済みとします。
  - そうでなければ `failed` とします。
  - 途中で接続できなくなったとき、時間の終わりにまだリロード中か、まだ問い合わせに応答できないときは、`unconfirmed` とします。

結果の扱いは、下の「世代の操作」と「managed 設定の操作」を参照してください。反映の順序と、反映が途中で停止したときの扱いは、[運用リファレンス](operator-reference.md) の「反映」を参照してください。

### ログファイル

`GET /api/records` は、プロキシが書き込むログファイル（`records.dir`）を読み込みます。ファイルの名前、サイズ、ローテーションは、[運用リファレンス](operator-reference.md) の「ログファイル（`records`）」を参照してください。

- 設定に `records` が無いと、この API は 404 になります。
- 管理プロセスは、プロキシと同じ OS ユーザーとしてファイルを読み込みます。ディレクトリの所有者が違う、グループかその他のユーザーの権限がある、ディレクトリでない（シンボリックリンクは使えません）のどれかの場合は、読み込みません（503）。
- ログファイルにはクライアントのアドレスとパスが入ります。管理 API では viewer 以上が読めるので、viewer のロールを渡すユーザーを検討したうえで決めてください。

## 外部からの利用

管理プロセスは TLS を使わないので、プロキシの TLS のリスナーを通して使います。クッキーは `Secure` 付きで出力されるので、管理画面は https でしか使えません。通し方は、設定ファイルに `managed` があるかどうかで違います。

- `managed` の無い設定: 管理用の Host のルートを `forward.routes` に書きます（下の例）。
- `managed` のある設定: 管理画面のルートを `admin.route` に書きます（[運用リファレンス](operator-reference.md) の「全体の構成」と「`admin`」、下の「managed 設定を使う場合の管理画面のルート」）。

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

（`forward` のほかの設定キーは省略しています。`admin.listen` が `127.0.0.1:9100` の例です。）

- 証明書: `admin.example.com` を `hosts` に持つ証明書を、TLS のリスナーに置きます。持たない名前のハンドシェイクは失敗します。
- アップストリーム: サーバーのアドレスに `admin.listen` を書きます。
- `access`: `allow_cidrs` で、管理画面を使うユーザーのアドレスだけを許可します。クライアントのアドレスの決め方と、`access` を使うときの注意は、[運用リファレンス](operator-reference.md) の「クライアントのアドレス」と「`access` を使うときの注意」を参照してください。どれかのルートが `access` を持つと、どのルートの `host` にもポートを書けません。
- 全体の設定（全体のアクセス制御とレート制限）とホストごとの設定は、ルートを選択する前に、この Host のリクエストにも適用されます（[運用リファレンス](operator-reference.md) の「アクセス制御とレート制限」）。管理画面を使うユーザーの数と速さに合わせて決めます。
- 平文のリスナーに、この Host を通さないでください。ルートはリスナーを問わずに選択されるので、`redirect` でない平文のリスナーがあると、パスワードが暗号化されずに流れる可能性があります。平文のリスナーは `redirect` にします。

次の 2 つは、どちらの設定でも書きます。

- `admin.trusted_proxies`: プロキシが管理プロセスに接続する元のアドレス（同じホストなら `127.0.0.1/32`）を書きます。書かないと、すべてのクライアントがプロキシのアドレスになり、ログインの試行回数の制限（クライアントごと）が全員で共有され、監査ログの `client` がどれもプロキシのアドレスになります。
- `admin.origin`: ブラウザーで開く URL のオリジンと一字一句同じにします（ポートが 443 のときは書きません）。違うと、ログインを含む変更が 403 になります。

### managed 設定を使う場合の管理画面のルート

`managed` のある設定では、管理画面のルートを設定ファイルの `admin.route` に書き、プロキシがこのルートを自分で作成します。設定キーの形式、証明書と `access`、全体の設定とホストごとの設定が適用されないこと、managed 設定のバージョンに書けないホストについては、[運用リファレンス](operator-reference.md) の「`admin`」を、リクエストを受信してからの処理については、同じ文書の「リクエストの検証の順序」を参照してください。ボディの上限は、下の「ボディのサイズ」を参照してください。

管理画面のルートのリクエストも、ほかのルートと同じく、稼働中の世代で検査されます。管理画面で managed 設定を編集するには、`POST /api/managed/check`（検証）と `POST /api/managed/apply`（「保存して反映」の操作）を検査除外のルートにします。この 2 つのリクエストのボディは、証明書チェーンと秘密鍵の PEM や多くのルートを含む、最大 12 MiB の JSON です。検査の対象にすると、ルールがブロックすることがあります。ルールのインポートのパス（下の「インポートのルートを検査除外にする」）と一緒に、1 つの `--routes` のファイルに書けます。

```json
[
  {"host": "admin.example.com", "path": "/api/generations", "action": "bypass"},
  {"host": "admin.example.com", "path": "/api/managed/check", "action": "bypass"},
  {"host": "admin.example.com", "path": "/api/managed/apply", "action": "bypass"}
]
```

- `path` は `/` で終わらないので、そのパスだけに一致します。ほかの `/api/managed` のパスは、検査されます。
- 検査除外のルートは世代の一部です。どの世代にも同じルートを入れ続けてください。入れ忘れた世代を選択すると、その世代からは `check` と `apply` のボディが検査されます。
- 検査除外のルートが無い世代で、ルールが `check` か `apply` のリクエストを 403 でブロックすると、管理画面は「プロキシか WAF がリクエストを拒否しました。PEM のファイルや多くのルートを含むリクエストボディは、WAF にブロックされることがあります。/api/managed/check と /api/managed/apply を検査の対象から除外する設定を確認してください。」と表示します。

### インポートのルートを検査除外にする

`POST /api/generations`（インポート）のボディは、ルールのファイルを含む大きな JSON です。これを検査の対象にすると、ルールの検査がインポートをブロックすることがあります。このパスは、世代の検査除外のルート（[運用リファレンス](operator-reference.md) の「検査除外のルート」）にします。

```json
[
  {"host": "admin.example.com", "path": "/api/generations", "action": "bypass"}
]
```

- `path` は `/` で終わらないので、このパスだけに一致します。`/api/generations/<fingerprint>`（世代の読み出しと削除）は、検査されます。
- 検査除外のルートは世代の一部です。どの世代にも同じルートを入れ続けてください。入れ忘れた世代を選択すると、その世代からはインポートが検査されます。
- このルートが効くのは、入れた世代が使われてからです。最初にこのルートを入れる世代は、コマンドでインポートします（`rules import ... --routes <file>`）。管理画面のインポートでも、ホストとパスを表の行に書いて入れられます（送るボディは同じ形の JSON です）。

### 管理画面の Host での CRS の調整

管理画面の Host を CRS で検査すると、CRS のデフォルトの設定は、管理画面の次のリクエストをブロックします。どちらも、管理画面の Host にだけ効く調整で通します。調整の後も、ほかの Host の検査は変わりません。

- PUT と DELETE: CRS がデフォルトで許可するメソッドは `GET`・`HEAD`・`POST`・`OPTIONS` だけで、ほかのメソッドはルール 911100 でブロックされます。管理 API は、パスワードの変更、ロールと有効・無効の変更、二要素認証の無効化、API トークンと世代の削除に PUT と DELETE を使います。調整が無いと、新しいユーザーは最初のパスワードの変更ができず、ログインを終えられません。
- パスワードの欄: CRS は JSON のボディの値も検査します。記号の並びによっては、正しいパスワードが SQL インジェクションと判定され、ログインやパスワードの変更がブロックされます（ルール 942100 など）。

メソッドの調整は、CRS のディレクトリの `crs-setup.conf` の終わりに追加してから、世代をインポートします。運用者のルールのファイルは CRS のルールの後に読み込まれる（[運用リファレンス](operator-reference.md) の「`rules`」）ので、そこに書いても、メソッドのルールより後になって効きません。管理画面のインポートで CRS を使うときは、`admin.crs_dir` の `crs-setup.conf` に追加します。

```text
SecRule REQUEST_HEADERS:Host "@rx ^admin\.example\.com(?::[0-9]{1,5})?$" \
    "id:1000100,phase:1,pass,nolog,t:none,t:lowercase,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT DELETE'"
```

パスワードの欄の調整は、運用者のルールのファイルに書き、インポートで `--rules`（管理画面では「ルールファイル」）に渡します。フェーズ 1 のルールなので、CRS の後に読み込まれても、ボディを検査する CRS のルールより先に効きます。

```text
SecRule REQUEST_HEADERS:Host "@rx ^admin\.example\.com(?::[0-9]{1,5})?$" \
    "id:1000101,phase:1,pass,nolog,t:none,t:lowercase,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.password,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.current,\
    ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:json.new"
```

- `admin\.example\.com` は、`admin.origin` のホストに置き換えます。`.` は `\.` と書きます。
- 検査の対象から外すのはパスワードの 3 つの欄（`password`、`current`、`new`）だけです。名前の欄、トークンの名前、クエリなどは、調整の後も検査されます。攻撃に似た名前はブロックされるので、別の名前にしてください。
- ルール ID は、ほかのルールと重ならない値にします（検査プロセスが使う ID は、[運用リファレンス](operator-reference.md) の「検査プロセスが追加する設定とルール」を参照してください）。
- 調整を入れた世代は、管理画面の Host の PUT と DELETE、記号を含むパスワードでのログインを試してから選択します。ブロックされたリクエストは、画面に表示されるリクエスト ID でログを検索すると、`rules` でルール ID が分かります。

### ボディのサイズ

- ルールのインポート（`POST /api/generations`）と、managed 設定の `POST /api/managed/check`・`POST /api/managed/apply` のリクエストボディは、最大 12 MiB になります。`proxy.max_body` を 12 MiB（12582912）以上にしてください。ルートの `max_body` は `proxy.max_body` を下げることしかできないので、ほかのルートを制限したい場合は、そちらのルートに小さい `max_body` を書きます。管理画面のルート（`admin.route`）には `max_body` が無いので、`proxy.max_body` が上限になります。
- 検査除外のルートの長いボディは、バッファリングせずに流すので、12 MiB のボディが `max_buffered_bytes` を使い切ることはありません（[運用リファレンス](operator-reference.md) の「リクエストボディの上限と検査する長さ」）。
- 管理画面は、検証のリクエストボディが 12 MiB を超えるか、ファイルが 192 件を超えるときは、送信せずにその旨を表示します。設定ファイルの `proxy.max_body`（`GET /api/config` で読み出します）より大きいだけのときは、送信したうえで、検証の結果と一緒に「送信するリクエストボディが、設定ファイルの proxy.max_body より大きくなります。プロキシを経由して接続しているときは拒否されます。」と表示します。プロキシがボディの上限で拒否した 413 には、「リクエストボディがプロキシの上限（proxy.max_body）を超えました。」と表示します。

### 時間のかかる応答とタイムアウト

- インポート、世代の選択、ロールバックは、数十秒以上かかることがあります（時間の上限は「リスナー」の「時間のかかる応答」）。プロキシの時間の設定キーはルートごとに変更できません。応答のヘッダー部を待つ時間は、`upstream_header_ms`、`response_idle_ms`、`request_total_ms` のうち先に尽きたもので切れます（[運用リファレンス](operator-reference.md) の「`proxy`: 時間」と「値どうしの関係」）。ボディを流すリクエスト（検査除外のルートのインポートなど）では、応答のヘッダー部が届くまで `response_idle_ms` は効きません。
- 切れると、プロキシはクライアントに 502（`request_total_ms` では 503）を返します。管理プロセスは処理を続け、インポート、選択、ロールバックは最後まで進みます。プロキシの切断では止まりません。
- 管理画面は、ボディに `result` を持たない 502 と 504 を「結果不明」として扱い、画面ごとに、状態と履歴、または世代の一覧を再読み込みして表示します。`result` を持つ応答（`failed` の 502、`unreachable` と `unconfirmed` の 503 を含む）は、その値で読み取ります。`result` を持たない 503 は変更が拒否されたものと読み取るので、`request_total_ms` は、ボディを受信する時間と検査の時間に `upstream_header_ms` を加えた時間より十分に長くしておいてください。API を直接使う場合も、同じ応答のときは `GET /api/status` と `GET /api/history`（インポートなら `GET /api/generations`）で確認します。
- 時間の設定キーは、インポートと切り替えに必要な時間を測ってから決めてください。`upstream_header_ms` を長くすると、ほかの Host のアップストリームが遅いときも長く待つことになります。

## ユーザーとロール

ユーザーは、名前、ロール、パスワードを持ちます。名前は 1〜32 バイトの小文字の英字・数字・`.`・`_`・`-`、パスワードは 12〜128 バイトの UTF-8 です（日本語の文字は 1 文字が 3 バイトです）。パスワードは、PBKDF2-HMAC-SHA256（600000 回、ソルト 16 バイト）のハッシュで保存します。

| ロール | できること |
|---|---|
| `viewer` | 状態、世代の一覧と内容、切り替えの履歴、ログを読めます。managed 設定の状態、バージョンの一覧、反映の処理、設定の変更履歴を読めます。自分のパスワード、二要素認証、API トークンを扱えます |
| `operator` | viewer のすべて。加えて、監査ログを読めます。ルールのインポート、世代の選択、ロールバック、削除ができます。managed 設定のバージョンの内容と証明書の情報、設定ファイルの値を読め、検証、保存して反映、名前で反映、ロールバック、削除ができます |
| `owner` | operator のすべて。加えて、ユーザーを作成し、ロールと有効・無効を変更し、ほかのユーザーのパスワードと二要素認証を初期化し、全員の API トークンを閲覧して削除できます |

- 最初の owner は `admin bootstrap` で作成します。以降のユーザーは、owner が `POST /api/users` で作成します。作成できるのは 1000 人までです。1000 人に達すると、作成は 409 `the store has too many users` で拒否されます。ユーザーは削除できないので、上限には無効にしたユーザーも数えます。
- ユーザーを削除する API はありません。使わなくなったユーザーは無効にします。無効にしたユーザーは、ログインできず、セッションと API トークンが使えなくなります。有効にし直しても、削除された API トークンは戻りません。
- owner が作成したユーザーと、owner が `POST /api/users/<name>/password` でパスワードを決めたユーザーは、次のログインで、自分のパスワードに変更するまで、ほかの API を使えません。
- owner の自分自身に対する操作と、owner がいなくなる操作は拒否します。
  - 自分のロールを下げる、自分を無効にする: 403
  - 自分のパスワードと二要素認証の初期化: 403（アカウントの API で変更します）
  - 有効な owner が 1 人もいなくなる変更: 409
- ユーザーの管理は、管理プロセスの中で 1 つずつ順に進みます。2 人の owner が同時に互いを下げて、owner がいなくなることはありません。
- ロールと状態の変更（ロールを変更する、無効にする、有効にする、パスワードを決める、二要素認証を無効にする）は、そのユーザーのセッションを終了します。ロールを下げること、無効にすること、パスワードを決めることは、API トークンも無効にします。
- ロールも有効・無効も変わらない `PUT /api/users/<name>` は、何も変更せずに 200 でそのユーザーを返します。セッションは終了せず、監査ログにも書きません。

## ログインと二要素認証

ログインは `POST /api/login`（`{"name", "password"}`）で始まります。応答の `mfa` が次の段階を示します。

| `mfa` | 意味 | 次の操作 |
|---|---|---|
| `off` | セッションが使えます | API を使います。`must_change` が `true` なら、パスワードを変更します |
| `verify` | 二要素認証の認証コードが必要です | `POST /api/login/mfa` |
| `setup` | `admin.mfa` が `required` で、二要素認証が未設定です | 二要素認証を設定します |

セッションは、状態によって使える API が決まります。状態に合わない API は、403 と次の決まった文で拒否します。

| 状態 | 場合 | 使える API | 拒否するときの `error` |
|---|---|---|---|
| 認証コード待ち | パスワードが合い、二要素認証を設定しているユーザー。5 分で終了します | `POST /api/login/mfa`、`POST /api/logout` | `second factor required` |
| パスワード変更待ち | owner が作成したユーザー、または owner か `admin reset` でパスワードを決められたユーザー | `PUT /api/account/password`、`GET /api/session`、`POST /api/logout` | `password change required` |
| 二要素認証の設定待ち | `admin.mfa` が `required` で、二要素認証が未設定のユーザー | `POST /api/account/mfa/setup`、`POST /api/account/mfa/confirm`、`GET /api/session`、`POST /api/logout` | `second factor setup required` |
| 通常 | 上のどれでもない場合 | ロールが許可するすべての API | |

- パスワード変更待ちと二要素認証の設定待ちが重なるときは、両方の API を使えます。
- `GET /api/session` は、状態（`state`: `active`、`must_change`、`mfa_setup`）、残りの時間、残りのリカバリーコードの数を返します。認証コード待ちのセッションは 403 になります。

二要素認証（MFA）:

- 時刻に基づくワンタイムパスワード（RFC 6238）で、HMAC-SHA1、6 桁、30 秒ごとの時間枠で作成します。現在の枠の前後 1 つの枠の認証コードも受け入れます。使った枠は保持していて、その枠と、それより前の枠の認証コードは拒否します。
- 設定:
  1. `POST /api/account/mfa/setup`（`{"password"}`）は、セットアップキー（20 バイトの乱数）を base32 の文字列（`secret`）と `otpauth://` のアドレス（`uri`）で返します。セットアップキーはセッションのメモリに 10 分だけ置きます。
  2. `POST /api/account/mfa/confirm`（`{"code"}`）は、認証アプリの認証コードを検証し、二要素認証を有効にして、リカバリーコードを返します。このユーザーのほかのセッションは終了し、新しいセッションと CSRF トークンが返されます。
- 設定の開始と確定を拒否する場合: すでに二要素認証を設定しているユーザーは、どちらも 409 `mfa is set already` で拒否されます。確定は、設定を始めていない、または 10 分を過ぎたときも、409 `mfa setup was not started or has run out` で拒否されます。認証コードが合わないときは 403 `the code is wrong` になります。
- リカバリーコードは 10 個で、1 個は 16 文字（大文字の `A`〜`Z` と `2`〜`7`）、1 回だけ使えます。設定のとき 1 回だけ返し、保存先には SHA-256 だけを置きます。使い切る前に作り直すには、二要素認証を無効にして設定し直します。`admin.mfa` が `required` のときは、自分では無効にできません。owner に `DELETE /api/users/<name>/mfa` で無効にしてもらいます（owner 自身の分は、ほかの owner に無効にしてもらうか、`admin reset` を使います）。
- ログインでの認証コードの確認では、`POST /api/login/mfa` に `{"code"}`（6 桁）か `{"recovery"}`（リカバリーコード。大文字で送ります）の一方を送ります。合うと、認証コード待ちのセッションが終了し、新しいセッション（新しい ID と CSRF トークン）が返されます。
- 無効にする: `DELETE /api/account/mfa`（`{"password", "code"}`。`code` は認証コードかリカバリーコード）。`admin.mfa` が `required` のときは 403 `mfa is required` で拒否されます。owner は、ほかのユーザーの二要素認証を `DELETE /api/users/<name>/mfa` で無効にできます。
- `required` のとき、二要素認証を設定していないユーザーの API トークンは使えません。
- 二要素認証のセットアップキーは、ユーザーのファイルに、そのまま置きます（認証コードを計算するのにセットアップキーそのものが必要なためです）。保存先のディレクトリを 0700 にして保護します。

## ロックアウトと試行回数の制限

| 対象 | 決まり |
|---|---|
| ユーザーごと | 続けて 5 回失敗すると、15 分間ロックアウトします。ロックアウト中の試行も失敗に数え、15 分を数え直します。成功すると失敗回数をリセットします |
| クライアントごと | 1 分間に 30 回まで試行できます。超えた試行は、ハッシュを計算する前に 429 `too many tries` で拒否し、ユーザーの失敗には数えません |

- ユーザーごとの失敗に数えるのは、ログインでパスワードが合わなかった場合、ログインの認証コード（`POST /api/login/mfa`）が合わなかった場合、二要素認証の無効化の認証コードが合わなかった場合、パスワードを検証する API（パスワードの変更、二要素認証の設定と無効化、トークンの作成）でパスワードが合わなかった場合です。無効のユーザーやロックアウト中のユーザーのログインも、そのユーザーの失敗に数えます。二要素認証を設定しているユーザーは、パスワードが合っても失敗回数をリセットしません。認証コードが合ったときにリセットします。パスワードを知っている人が、ログインのたびに失敗回数をリセットして認証コードを試し続けられないようにするためです。二要素認証の設定の確定（`POST /api/account/mfa/confirm`）で認証コードが合わなかった場合は、ユーザーの失敗にもクライアントの回数にも数えず、監査ログにも書きません。応答は 403 `the code is wrong` です。
- クライアントごとの回数に数えるのは、ログイン、ログインの認証コード、パスワードを検証する API（上と同じ）、合わない API トークンです。正しい API トークンのリクエストと、二要素認証の設定の確定は数えません。ログインは、成功した試行も数えます。回数を使い切ったクライアントの API トークンのリクエストは、トークンが正しくても、トークンを検証する前に 429 `too many tries` で拒否します。
- 最大 4096 のクライアントを追跡します。1 分以内に試行したクライアントで満杯のときは、ほかのクライアントを受け付けません。
- ログインは、存在しない名前、無効なユーザー、ロックアウト中のユーザー、パスワードの不一致のどれでも、同じ応答（401 `invalid credentials`）にします。存在しない名前やロックアウト中でもハッシュを 1 回計算するので、かかる時間でも見分けられません。ログインの認証コードの不一致も、同じ 401 `invalid credentials` で応答します。ほかの API でのエラーは 403 で、パスワードは `the password is wrong`（パスワードの変更は `the current password is wrong`）、認証コードは `the code is wrong` です。
- 理由は監査ログにだけ書きます（`unknown user`、`disabled`、`locked`、`wrong password`、`wrong code`）。存在しない名前は書きません。名前の欄に入力されたパスワードがログに出ないようにするためです。
- ユーザーごとの失敗回数とロックアウトの状態、クライアントごとの試行回数は、管理プロセスのメモリにだけあります。再起動すると消えます。
- ユーザーが変更されると（`admin reset`、owner の操作、パスワードの変更、二要素認証の設定と無効化）、ロックアウトは解除され、次の失敗から数え直します。

## セッション

- ログインが通ると、セッションを作成し、クッキー `tukuyomi_admin` を返します。クッキーの値は、32 バイトの乱数を base64url にした 43 文字です。

  ```text
  Set-Cookie: tukuyomi_admin=<43-characters>; Secure; HttpOnly; SameSite=Strict; Path=/
  ```

  有効期限は付けません（ブラウザーを閉じると消えます）。ログアウトでは `Max-Age=0` のクッキーを返して削除します。
- 管理プロセスは、セッションを ID の SHA-256 で保持し、ID そのものは持ちません。監査ログの `session` には、その SHA-256 の先頭 8 桁だけを書きます。
- セッションごとに、CSRF トークン（別の 32 バイトの乱数、43 文字）を持ちます。ログインの応答と `GET /api/session` で返します。
- セッションが終了する場合:
  - `admin.session_idle_ms` の間、使われなかった場合（リクエストごとに数え直します）
  - 作成してから `admin.session_total_ms` が過ぎた場合
  - ログアウトした場合
  - そのユーザーのパスワード、ロール、有効・無効、二要素認証が変更された場合（`admin reset` と、別の管理プロセスの操作を含みます）。パスワードと二要素認証を自分で変更したときは、そのリクエストに新しいセッションを返し、ほかのセッションを終了します
  - ユーザーが無効になった場合
  - 管理プロセスを再起動した場合
- 1 人のユーザーが持てるセッションは、認証コード待ちと通常のそれぞれで 16 個までです。17 個目を作成すると、いちばん古いものを終了し、監査ログに `logout`（`reason` は `too many sessions`）を書きます。認証コード待ちを繰り返しても、通常のセッションは終了しません。全体では 1024 個まで持ち、満杯になると新しいセッションを作成できません（ログインは 503）。
- 1 つのリクエストは、セッションのクッキーか API トークンのどちらかを持ちます。両方あると 400 になります。`Authorization` ヘッダーが Bearer でなくても、セッションのクッキーと並ぶと 400 になるので、管理画面の前に Basic 認証などの HTTP 認証をかけると、ログイン後のリクエストは 400 になります。クッキーが 2 回含まれるリクエストは、セッションを持たないものとして 401 にします。

## CSRF と Origin

`GET` と `HEAD` 以外のリクエスト（変更）には、次の 2 つの検証があります。

- `Origin`: ヘッダーがあれば、`admin.origin` と一字一句同じで、1 つだけであること。違うと 403 `forbidden` になります。`Origin` ヘッダーが無いリクエスト（プログラムからのリクエスト）は通ります。ログインのリクエストにも適用します。
- `X-CSRF-Token`: セッションのリクエストでは、そのセッションの CSRF トークンと同じ値を、1 つだけ付けること（一定の時間で比較します）。違うか無いと 403 `forbidden` になります。API トークンのリクエストには不要です（クッキーを使わないためです）。

検証の順序は、「応答の形式」の「管理 API の検証の順序」を参照してください。

- 管理画面は、CSRF トークンをメモリにだけ置き、変更のリクエストごとに付けます。ページを開き直すと `GET /api/session` で受け取り直します。認証コード待ちのセッションは `GET /api/session` が 403 になり CSRF トークンを受け取れないので、ページを開き直すとログインからやり直しになります。
- `Origin` の不一致と CSRF の不一致で拒否したリクエストは、ユーザーが分かっているときに監査ログに書きます（`reason` は `origin`、`csrf`）。

## API トークン

プログラムが管理 API を使うためのトークンです。

- 形式は `tkc_<16-hex-digits>_<43-characters>` です。前の部分がトークンの ID で、後ろが秘密（32 バイトの乱数の base64url）です。作成したときに 1 回だけ全体を返します。管理データの保存先には秘密の SHA-256 だけを置きます。
- `Authorization: Bearer <token>` で送ります。セッションのクッキーとは一緒に送れません（400）。
- 作成: `POST /api/account/tokens`（`{"name", "role", "days", "password"}`）。セッションのユーザーが自分のために作成します。現在のパスワードが必要です。
  - `name`: 1〜64 バイトの印字可能な ASCII
  - `role`: 自分のロール以下。それより上のロールは 403 `the role is above the role of the user` で拒否します。
  - `days`: 1〜365。作成した時刻からこの日数で有効期限が切れます。
  - 1 人が持てるのは 50 個までです（超えると 409 `the user has too many tokens`）。50 個の数には、期限が切れたトークンも含まれます。期限が切れたトークンは自動では削除されないので、`DELETE /api/account/tokens/<id>` で削除します。
  - 応答は、トークンの情報（`id`、`owner`、`name`、`role`、`created`、`expires`、`expired`、`last_used`。時刻はミリ秒のエポック）に、`token`（全体の文字列）を加えたものです。
- 使える API: 状態、世代、インポート、選択、ロールバック、削除、履歴、ログ、監査ログ、managed 設定と設定ファイルの値（下の「API のパスの一覧」で「トークン」が ○ のもの）。アカウントの API と、ユーザーの管理の API には使えません（403）。owner のトークンで、ほかのユーザーのパスワードや二要素認証を初期化して、そのユーザーとしてログインできてしまうのを防ぐためです。
- リクエストのロールはトークンのロールです（所有者のロール以下）。CSRF トークンは不要です。変更のリクエストの `Origin` は、あれば `admin.origin` と同じであること。
- 使うたびに、次を検証します。
  - 形式が正しく、保存先にその ID があり、秘密の SHA-256 が合うこと
  - 所有者がいて、無効でなく、ロールがトークンのロール以上であること
  - トークンが、所有者の「この時刻より前に作ったトークンは無効」の時刻より後に作成されていること
  - 有効期限が過ぎていないこと
  - `admin.mfa` が `required` なら、所有者が二要素認証を設定していること
- 無効になる場合（ファイルを削除できなくても、上の検証で通らなくなります）:
  - 有効期限が来た場合、または削除した場合（`DELETE /api/account/tokens/<id>`、owner は `DELETE /api/tokens/<id>`）
  - 所有者が無効になった場合
  - 所有者のロールが下がった場合（所有者のすべてのトークンが無効になります）
  - 所有者のパスワードが変更された場合（自分で変更したとき、owner が決めたとき、`admin reset`）
- 合わないトークンは、クライアントごとの試行回数（上の「ロックアウトと試行回数の制限」）に数えます。監査ログには書きません。誰でも送れるリクエストで、監査ログを埋め尽くされないようにするためです。
- 最後に使った時刻（`last_used`）は、10 分に 1 回までしか書き込みません。書き込めなくてもリクエストは通ります。
- 使い方の例（`$TOKEN` にトークンを入れます）:

  ```bash
  curl -sS -H "Authorization: Bearer $TOKEN" https://admin.example.com/api/status
  curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"generation":"<target-fingerprint>","expect":"<current-fingerprint>"}' \
    https://admin.example.com/api/activate
  ```

## 監査ログ

管理プロセスは、ログイン、変更、拒否したリクエストを、監査ログの行として残します。

| 項目 | 内容 |
|---|---|
| `ts`、`type` | ログと同じです。`type` は `audit` です |
| `id` | リクエスト ID（`X-Request-ID`）。コマンド（`admin bootstrap`、`admin reset`）の行にはありません |
| `actor` | 検証したユーザーの名前。検証できなかったときはありません。リクエストヘッダーからは取得しません |
| `session` | セッション ID の SHA-256 の先頭 8 桁。ID そのものは書きません |
| `auth` | セッション以外の場合の認証方法。`token:<id>`、`bootstrap`、`reset` |
| `client` | クライアントのアドレス。コマンドの行にはありません |
| `action` | 操作（下の表） |
| `target` | 操作の対象（ユーザーの名前、API トークンの ID、世代のフィンガープリント、managed 設定のバージョンの名前）。存在しない名前のログインにはありません |
| `result` | `ok`、`denied`（拒否）、`failed`（実行を試みたが失敗） |
| `reason` | 決まった語（`wrong password`、`locked`、`expect`、`store` など） |
| `before`、`after` | 変更の前と後。ロール、有効・無効、世代のフィンガープリント、managed 設定のバージョンの名前 |

パスワード、API トークン、認証コード、リカバリーコード、二要素認証のセットアップキー、クッキーは書きません。

| `action` | 場合 |
|---|---|
| `login` | ログインの成功（`ok`）と失敗（`denied`。`reason` は `unknown user`、`wrong password`、`locked`、`disabled`）。セッションを作成できないとき（`failed`、`no session`）。二要素認証を設定したユーザーのパスワードが合ったときの `reason` は `second factor pending` です |
| `mfa` | 認証コードの成功と失敗（`wrong code`、`locked`）。リカバリーコードの成功は `reason` が `recovery code` です |
| `lock` | ユーザーのロックアウト（`reason` は `too many failures`） |
| `logout` | ログアウト。セッションが多すぎて終了させたときは `reason` が `too many sessions` です |
| `password`、`mfa_setup`、`mfa_confirm`、`mfa_disable` | 自分のパスワード、二要素認証の設定の開始・確定・無効化。パスワードや認証コードのエラーは `denied`（`wrong password`、`wrong code`、`locked`）になります。ただし、`mfa_confirm` の認証コードのエラーは行を書きません |
| `token_create`、`token_revoke` | API トークンの作成（`after` がロール）と削除 |
| `user_create`、`role`、`disable`、`enable`、`user_password`、`user_mfa` | owner が行うユーザーの管理 |
| `import`、`activate`、`rollback`、`remove` | 世代の操作（下の「世代の操作」） |
| `managed-import` | `POST /api/managed/apply`（「保存して反映」の操作）で、バージョンを保存する前（下の「managed 設定の操作」の「保存して反映」） |
| `managed-apply`、`managed-activate`、`managed-rollback` | managed 設定の「保存して反映」「名前で反映」「ロールバック」の操作（下の「managed 設定の操作」） |
| `managed-remove` | managed 設定のバージョンの削除 |
| `create`、`reset` | コマンド `admin bootstrap`、`admin reset` |
| API ごとの `action` | 拒否した API の名前で、`denied` の行を書きます（下の注）。名前は、上の世代の操作と managed 設定の `action` のほかに、`status`、`generations`、`generation`（世代 1 つの読み出し）、`history`、`records`、`audit`、`session`、`users`、`user_update`（`PUT /api/users/<name>`）、`tokens`、`managed`（`GET /api/managed`）、`managed-versions`、`managed-version`（バージョン 1 つの読み出し）、`managed-job`、`managed-history`、`managed-check`、`managed-certificates`、`config`（`GET /api/config`）です |

- API ごとの検証で拒否したリクエストは、ユーザーが分かっていれば `denied` の行を書きます。`reason` は `origin`、`csrf`、`token`（API トークンが使えない API）、`role`、`state`、`second factor pending`、`password change`、`second factor setup` です。
- ユーザーが分からない段階で拒否したリクエストは書きません。セッションも API トークンも無い、合わない API トークン、クライアントの回数を超えたログイン、`Origin` が違うログイン、パスが無いなどです。誰でも送れるリクエストで、古い行を押し出されないようにするためです。
- 世代の操作の行は、`target` に対象の世代のフィンガープリントを書きます。`activate` と `rollback` の `ok` の行は、`before` に選択中だった世代、`after` に依頼した世代も書きます。`ok` の行は変更の前に書くので、成功を示す行ではありません。終わり方は、後に続く `failed` の行と、切り替えの履歴で確認します。`failed` の `reason` は、`expect`、`store`、`refused`、`failed`、`unconfirmed`、`history`（履歴の行を書き込めなかった）で、インポートは `store` と `trial` です。変更の前に拒否したときは `denied` で、`reason` は `expect`、`engine`、`busy`、`unreachable` です。削除は、選択中の世代が `chosen`、ロールバック先が `rollback target` です。
- managed 設定の行は、`target` に対象のバージョンの名前を書きます。`managed-apply`、`managed-activate`、`managed-rollback` の `ok` の行は、反映の処理がプロキシに依頼する前に書き、`before` に変更前、`after` に変更後のバージョンを書きます。成功を示す行ではないので、終わり方は、後に続く行と設定の変更履歴で確認します。
  - 変更の前に拒否したときは `denied` で、`reason` は `managed`、`configuration`、`expect`、`unreachable`、`busy`、`unmanaged` と、反映の処理の結果を表す語（`current changed`、`no version`、`store`）です。
  - 変更の前の行を書いた後に失敗したときは `failed` で、`reason` は反映の処理の結果を表す語（`refused`、`busy`、`error`、`failed`、`unconfirmed`、`not recorded`）と `history`（設定の変更履歴の行を書き込めなかった）です。反映の処理を始められなかったときも `failed` で、`reason` は `time`、`stopping`、`thread` です。
  - `managed-import` の失敗の `reason` は `store`、`version`、`configuration` です。削除は、拒否が `managed`、`configuration`、`chosen`（選択中のバージョン）、`rollback target`（ロールバック先）、失敗が `store` です。
  - 検証と、読み出しだけの API は、変更ではないので、入口で拒否したとき以外は行を書きません。

書き込みの方法:

- 変更は、監査ログの行を先に書いてから行います。行を書けない（ディスクが満杯の場合など）ときは、変更せずに 503 `unavailable` で拒否します。行はディスクに同期してから、標準エラーにも出力します。
- 例外はログアウトです。権限を取り消す操作なので、行を書けなくてもセッションを終了します。
- 変更が失敗したときは、後から `failed` の行を書きます（書けなくても応答は変えません）。
- 保存先は `admin.store.dir` の `audit/audit.log` で、1 行 1 件の JSON です。1 つのファイルが 16 MiB を超えると次のファイルに移り、8 ファイル（`audit.log`、`audit.1.log` から `audit.7.log`）を残します。同じ行を標準エラー（ジャーナル）にも出力します。
- `GET /api/audit`（operator 以上、API トークン可）は、最新の 200 行を新しい順に `{"entries": [...]}` で返します。ファイルの終わりから読み、足りなければ古いファイルを読みます。1 つのファイルは終わりの 1 MiB までを読み、ファイルがそれより大きいときは、古いファイルを読まずにそこで終了します。読めない行は飛ばします。

## 世代の操作

世代の一覧と内容は viewer が読めます。インポート、選択、ロールバック、削除は operator 以上が行えます。

### 一覧と内容

- `GET /api/status`: 次を返します。
  - `current`: ルールストアで選択中の世代のフィンガープリント（無ければ `null`）
  - `reachable`: プロキシに接続できるか。同時接続数の上限のために応答できないプロキシは、接続できるものとして扱います
  - `proxy`: プロキシの状態（`generation`、`mode`、`engine`、`phase`、`switching`、`reloading`、`ready`）と数（`uptime_ms`、`requests`、`blocked`、`policy_refused`、`upstream_failures`、`config`、`managed`、`resolve_timeout_ms`、`config_reloads`）。プロキシの応答のままで、読めなければ `null`。`reloading` と数は前のバージョンのプロキシが送らないので、送られなかったものはそれぞれ `null` になります（応答は拒否しません）。`reloading` は、設定のリロードの途中かどうかです。数の内容は次のとおりで、詳しくは [運用リファレンス](operator-reference.md) の「制御ソケット」を参照してください
    - `uptime_ms`: プロキシが起動してからのミリ秒
    - `requests`: リクエストの数（ログの 7 つの `class` のすべて）
    - `blocked`: ルールがブロックしたリクエストの数
    - `policy_refused`: 全体の `access` と `rate_limit`、ホストごとの設定が拒否したリクエストの数
    - `upstream_failures`: 稼働中の設定の、アップストリームのサーバーの失敗回数。設定のリロードで設定が切り替わると、0 から数え直します
    - `config`: 稼働中の設定ファイルの SHA-256（64 桁の小文字の 16 進数）
    - `managed`: 稼働中の managed 設定のバージョンの名前（64 桁の小文字の 16 進数）。`managed` の無い設定では `null`
    - `resolve_timeout_ms`: 稼働中の設定の `forward.resolve_timeout_ms`
    - `config_reloads`: SIGHUP と制御ソケットの `reload` による設定のリロードの数。`{"replaced", "refused"}`（切り替えた数と拒否した数）
  - `rollback_to`: 今ロールバックを依頼したら選択される世代（無ければ `null`）
  - `crs`: `{"available", "files"}`。`admin.crs_dir` があるかどうかと、インポートで除外できる CRS の `.conf` の名前
- `GET /api/generations`: `{"reachable", "generations"}`。新しい順に、各世代の `fingerprint`、`made`（作成した時刻。エポックからの秒数）、`mode`（`block`、`detect`、マニフェストが読めなければ `unknown`）、`engine`（`coraza`、`modsecurity`、マニフェストが読めなければ `unknown`）、`routes`（検査除外のルートの数）、`current`（ルールストアで選択中か）、`serving`（プロキシで稼働中か）を返します。
- `GET /api/generations/<fingerprint>`: 上に加えて、`load`（読み込む順）、`files`（`path`、`size`、`sha256`）を返します。`routes` は、ここでは数ではなくルートの配列（`host`、`path`、`action`）です。ルートが `host` を持たないときは、`host` は付きません。ルールストアに無い世代は 404 になります。

「選択中」の世代と「稼働中」の世代は別です。ルールストアで選択中でも、プロキシが切り替えに失敗していれば、稼働していません。管理画面は、切り替えの途中ではないのに 2 つが違うときに、警告を表示します。

### インポート

`POST /api/generations`（operator 以上、API トークン可）は、`rules import` と同じ順序で、世代を作成します。ファイルを集め、ルールストアに仮に置き、検査プロセスで事前検証し、事前検証に通れば世代にします。世代は選択しません。

ボディは JSON のオブジェクトで、キーはすべて省略できます。

| キー | 内容 |
|---|---|
| `rules` | ルールのファイル。`{"name", "data"}` の配列で、書いた順に読み込みます。`name` はディレクトリを除いた名前（`--rules` と同じ決まり）、`data` は標準の base64（パディング付き） |
| `data` | データのファイル。形式は `rules` と同じです（`--data` に対応します） |
| `crs` | `true` で `admin.crs_dir` の CRS を使います。リクエストではパスを指定できません。`admin.crs_dir` が無いと 400 になります |
| `crs_off` | 読み込まない CRS の `.conf` の名前の配列（`--crs-off` に対応します） |
| `routes` | 検査除外のルートの配列（`--routes` のファイルと同じ形式） |
| `engine` | 検査エンジンの名前（`--engine` に対応します）。`coraza` か `modsecurity`（小文字）。省略すると `coraza` です |
| `detect_only` | `true` で検知のみの世代にします |
| `accept_block` | `true` で、事前検証のリクエストがブロックされても失敗にしません |

- 上限と名前の決まりは `rules import` と同じです（[運用リファレンス](operator-reference.md) の「`rules`」）。ファイルは 128 個、1 つ 2 MiB、全体 8 MiB までです。2 MiB を超えるファイルは、デコードする前に拒否します。
- `engine` がエンジンの名前でないときと、そのエンジンが使えないときは、ファイルを集める前に 400 で拒否します。何も仮に置かず、事前検証も実行しません。文は次のどちらかです。
  - `engine is not the name of an engine (coraza or modsecurity)`
  - `kernel.engines has no inspector for the engine of the generation`（設定に、そのエンジンの検査プロセスが無い）
- 事前検証は `rules import` と同じで、管理プロセスが検査プロセスを 1 つ起動し、決まった 3 つのリクエスト（`GET /`、フォームの `POST /`、JSON の `POST /`）を検査します。検査プロセスは、`engine` のエンジンのもの（`coraza` は `kernel.inspector`、`modsecurity` は `kernel.engines`）です。`kernel` の値と、`proxy` の `ready_wait_ms`・`inspect_wait_ms`・`stop_inspect_ms`・`drive_slice_ms` を使います。
- インポート、選択、ロールバック、削除は、管理プロセスの中で 1 つずつ順に進みます。ほかの変更が進んでいるときは、待たずに 409 `a change of the rules is under way` になります。コマンドや別のプロセスがルールストアのロックを保持しているときは、409 `the rules store is in use by another command` になります。

応答:

| ステータスコード | 場合 | ボディ |
|---|---|---|
| 200 | 世代を作成できたとき | `{"fingerprint", "result", "trial"}`。`result` は `created`、`existing`（同じ世代が既にあった）、`repaired`（壊れていた同じフィンガープリントの世代を作り直した） |
| 400 | 入力が拒否されたとき（使えないエンジンも含みます） | `{"error"}`。入力のファイルの名前があれば `subject` に付きます（0x20〜0x7e の外のバイトは `\xNN`、128 バイトまで） |
| 409 | ルールストアで拒否されたとき、ほかの変更が進んでいるとき | `{"error"}` |
| 422 | 事前検証が失敗したとき。世代は作成しません | `{"error": "the trial failed", "trial": {..}}` |
| 500 | 事前検証を実行できないとき | `{"error"}` |
| 503 | 監査ログの行を書けないとき | `{"error": "unavailable"}` |

`trial` は、通ったとき `{"passed": true, "accepted": [..]}`、失敗したとき `{"passed": false, "failure": <message>}` で、検査プロセスの出力があれば、`passed` の値に関わらず `detail`（512 バイトまで）が付きます。事前検証のリクエストがすべて通っても、検査プロセスか作業ディレクトリが片付かなかったときは、`passed` が `false`、`failure` が `the inspector did not stop cleanly; a process or a directory may be left behind` になり、422 で世代は作成しません。このときは、ホストにプロセスやディレクトリが残っていないか確認してください。`accepted` は、事前検証で受け入れたブロック（`{"kind": "block", "probe", "rule", "phase", "status"}`）と検知（`{"kind": "detected", "probe", "rule", "status"}`）です。`probe` は事前検証のリクエストの名前（`GET /`、`POST / with a urlencoded body`、`POST / with a JSON body`）です。

### 選択とロールバック

`POST /api/activate`（`{"generation", "expect"}`）と `POST /api/rollback`（`{"expect"}`）は、ルールストアの選択中の世代を変更し、プロキシを切り替えさせます。operator 以上で、API トークン可です。

- フィンガープリントは 64 桁の小文字の 16 進数です。違うと 400 `a generation is not 64 lowercase hexadecimal digits` になります。
- `expect` は、画面で見た「選択中の世代」です。画面を見た後に別のユーザーやコマンドが選択し直していれば、古い画面で選択し直して上書きするのを防ぐため、409 で拒否します。
- ルールストアに選択中の世代が無いと、`expect` が合わないので選択できません。最初の世代はコマンド（`rules activate`）で選択します。画面も、選択中の世代が無いときは選択の操作を表示せず、`rules activate` を案内します。
- `generation` に現在選択中の世代を指定すると、ルールストアの選択中の世代は変わらず、プロキシだけを切り替えさせます（管理画面の「プロキシに反映する」）。

進み方:

1. 世代がルールストアにあること（`activate`。無ければ 404 `no such generation`）。ロールバックは、ロールバック先を決めます（下）。
2. ルールストアで選択中の世代が `expect` と同じであること。違えば 409（変更なし。履歴には書きません。監査ログに `denied`、`reason` は `expect`）。
3. 切り替え先の世代のエンジンが使えること。使えなければ、`{"error": <message>}` の 409（変更なし。履歴には書きません。監査ログに `denied`、`reason` は `engine`）。文は、上の「インポート」の 400 の `kernel.engines has no inspector for the engine of the generation` と同じです。マニフェストが読めない世代は、ここでは拒否せず、ルールストアで世代を選択する段階で拒否されます。
4. プロキシの状態を問い合わせます。
   - 接続できない: 503 `the proxy cannot be reached`。ルールストアは変更せず、履歴に `unreachable` を書きます（監査ログにも `denied`、`reason` は `unreachable`）。
   - 接続を受け付けて何も応答せずに閉じる（同時接続数の上限）: 503 `the proxy is busy`。ルールストアは変更せず、履歴には書きません（監査ログに `denied`、`reason` は `busy`）。
5. 監査ログの行を書きます（書けなければ 503 `unavailable` で、変更しません）。
6. ルールストアで世代を選択します。選択はロックの中で行い、`expect` をもう一度検証します。別のプロセスがこの間に選択していれば、上書きせずに 409 とします。
7. プロキシに切り替えを依頼し、終わりを待ちます（上の「制御ソケット」）。
8. 履歴に 1 行書き、応答します。

応答（ボディは `{"result", "from", "generation", "chosen"}`。失敗では `error` も付きます）:

| `result` | ステータスコード | 意味 | `chosen` |
|---|---|---|---|
| `switched` | 200 | プロキシは現在その世代を使っています | `true` |
| `unchanged` | 200 | プロキシはすでにその世代を使っていました | `true` |
| `refused` | 409 | プロキシが拒否しました（`the proxy refused the switch`）。プロキシが `expect` の不一致を検出したときも含みます | `true` |
| `failed` | 502 | プロキシは切り替えませんでした（`the proxy did not switch`）。時間内に切り替わらなかったときも含みます | `true` |
| `unreachable` | 503 | プロキシに接続できません。ルールストアは変更していません | `false` |
| `unconfirmed` | 503 | ルールストアは変更しましたが、プロキシが結果を応答しませんでした（`the proxy did not say how the switch ended`） | `true` |

- `chosen` は、ルールストアで現在その世代が選択中かどうかを示します。
- 切り替えが `refused`、`failed`、`unconfirmed` に終わっても、ルールストアは元に戻しません。`refused` と `failed` では、プロキシは前の世代を使い続けます。`unconfirmed` では、プロキシがどちらの世代を使っているか分からないので、`GET /api/status` の `proxy.generation` で確認します。プロキシを再起動すると、ルールストアで選択中の世代で始まります。その世代を使わない場合は、前の世代を選択し直します。
- 履歴に行を書けなかったときは、応答に `"history": "not written"` が付きます。
- `result` と `chosen` を持つのは、上の表の 6 つの場合だけです。ほかの失敗のボディは `{"error": <message>}` だけです。`expect` が合わない 409（`the chosen generation is not the one that was expected`）、`the proxy is busy` の 503、ロールバック先が決まらない 409、世代のエンジンが使えない 409、ルールストア自体で選択が拒否された 409 がそれに当たります。この中で履歴に行（`refused`）を書くのは、ルールストア自体で選択が拒否されたときだけです。

ロールバック先:

- 履歴の中で、結果が `switched` で、`from` と `to` が違う、最も新しい行の `from` です。
- ただし、その行の `to` が、ルールストアで現在選択中の世代のときだけです。切り替えが失敗した後や、コマンドで世代を選択した後は、履歴の終わりが選択中の世代と合わないので、ロールバックできません（409 `the history does not end at the chosen generation`）。`switched` の行が無いときは 409 `there is no switch to go back from` になります。
- ロールバック先の世代がルールストアに無ければ 409 `the generation to go back to is not in the store` になります。
- ロールバックも履歴に `rollback` として入ります。続けてもう一度ロールバックすると、元の世代に戻ります。

### 削除

`DELETE /api/generations/<fingerprint>`（operator 以上、API トークン可）は、世代をルールストアから削除します。元に戻せません。次の世代は削除せず、409 で拒否します。

| 世代 | `error` |
|---|---|
| ルールストアで選択中の世代 | `the generation is the one the rules store chooses` |
| ロールバック先の世代 | `the generation is the target of a rollback` |
| プロキシで稼働中の世代 | `the generation is used by a running proxy` |

ルールストアに無い世代は 404 です。ほかの変更が進んでいるときは、409 `a change of the rules is under way`（この管理プロセスの中）か `the rules store is in use by another command`（コマンドや別のプロセスがルールストアのロックを保持している）で拒否します。削除の検証の後にコマンドが世代を選択したときは、409 `the generation is the current one` になります。成功すると `{"removed": <fingerprint>}` を返します。

## managed 設定の操作

managed 設定は、サイトと証明書、アップストリーム、ルート、デフォルトのアップストリーム、全体のアクセス制御とレート制限、ホストごとの設定を、設定ファイルとは別の managed ストアにバージョンとして置き、管理画面と管理 API から変更する設定です。managed 設定を使うかどうか、managed ストアとバージョンの形式、コマンド、反映の順序については、[運用リファレンス](operator-reference.md) の「managed 設定」を参照してください。ここでは、管理 API の操作を説明します。

- 状態、バージョンの一覧、反映の処理、設定の変更履歴は viewer が読めます。バージョンの内容、証明書の情報、設定ファイルの値、検証、保存して反映、名前で反映、ロールバック、削除は operator 以上が行えます。どれも API トークンで使えます。
- バージョンの内容と設定ファイルの値を operator 以上に限るのは、ルートの書き換え（`rewrite`）に、アップストリームの認証の値などの秘密を書けるためです。
- この API が使えるのは、管理プロセスが起動したときに、設定ファイルに `managed` があった場合だけです。無かった場合は、`GET /api/managed` は `{"managed": false}` を返し、`GET /api/config` はあるときと同じように使え、ほかは 409 `the configuration has no managed object` で拒否します。
- managed ストアは、管理プロセスの起動時に `managed.dir` が指していたディレクトリで、リクエストのたびに開きます。開けないときは、500 と managed ストアの文で応答します。検証と変更では設定ファイルを再読み込みし、`managed.dir` が起動時と違えば 409 `the managed object of the configuration names another directory than at the start` で拒否します。`managed` の有無や `managed.dir` を変更したら、管理プロセスを再起動します。

### 状態と一覧

- `GET /api/managed`: 次を返します。
  - `managed`: `true`
  - `current`: managed ストアの選択中のバージョン（無ければ `null`）
  - `serving`: プロキシが制御ソケットで応答した、稼働中のバージョン（状態を読めないとき、プロキシが `managed` の無い設定で動いているときは `null`）
  - `reachable`: プロキシに接続できるか。同時接続数の上限のために問い合わせに応答できないプロキシは、接続できるものとして扱います
  - `reloading`: プロキシが設定をリロード中か（分からなければ `null`）
  - `rollback_to`: 今ロールバックを依頼したら反映するバージョン（無ければ `null`。下の「名前を指定した反映とロールバック」）
  - `job`: 最後の反映の処理（無ければ `null`。下の「反映の処理」）

  設定の変更履歴を読めないときは 503 になります。
- `GET /api/managed/versions`: `{"reachable", "versions"}`。新しい順に、各バージョンの `name`（バージョンの名前。SHA-256 の 64 桁の小文字の 16 進数）、`made`（バージョンのファイルの更新時刻。エポックからの秒数）、`current`（選択中か）、`serving`（稼働中か）を返します。
- `GET /api/managed/versions/<version>`（operator 以上）: 上の 4 つに加えて、`version`（managed ストアにあるとおりのバージョンの JSON）を返します。バージョンは、ファイルを SHA-256 だけで指定し、どの応答もファイルの内容を持ちません。managed ストアに無いバージョンは 404、内容が名前と合わないバージョンは 500 になります。

「選択中」のバージョンと「稼働中」のバージョンは別です。反映が途中で停止したときや、コマンドでバージョンを選択したときは、2 つが違うことがあります。どちらかのバージョンをもう一度反映すると、2 つはそろいます。管理画面は、2 つが違うときに通知と、そろえる 2 つの操作を表示します（下の「管理画面」）。

### 証明書の情報

`GET /api/managed/certificates/<version>`（operator 以上）は、バージョンのサイトごとに、managed ストアにある証明書の状態を、バージョンでの順序で返します。応答は `{"name", "sites"}` で、サイトごとに次のキーを持ちます。

| キー | 内容 |
|---|---|
| `name` | サイトの名前 |
| `kind` | `files`（証明書チェーンと秘密鍵のファイル）、`acme`。どちらの形式でもなければ `null` |
| `chain`、`key` | `files` のサイトの、証明書チェーンと秘密鍵のファイルの名前（SHA-256）。内容は返しません |
| `hosts` | `acme` のサイトのホスト。読める形式のときだけ |
| `state` | 下の表 |
| `not_after`、`expired` | 証明書チェーンの最初の証明書が持つ有効期限（エポックからの秒数）と、サーバーの時計で期限切れかどうか。有効期限を読み取れたときだけ |
| `names`、`more` | 証明書に含まれるホスト名（DNS 名、100 個まで）と、ほかの名前の数。名前も読み取れたときだけ。`[]` は、証明書に DNS 名が無いことを示します |

`state` は、次のうち最初に一致するものです。

| `state` | 意味 |
|---|---|
| `unreadable` | 証明書チェーンか秘密鍵のファイルを読めません（シンボリックリンク、1 MiB 以下の通常のファイルでない、`files` のサイトで内容が名前と合わない、など）。どちらの形式でもない証明書も、これになります |
| `missing` | `files` のサイトで、証明書チェーンか秘密鍵のファイルが managed ストアに無いとき |
| `waiting` | `acme` のサイトで、まだ発行されていないとき（`acme renew` が書く証明書チェーンか秘密鍵が無い） |
| `unparsed` | 証明書チェーンの最初の証明書から、名前か有効期限を読み取れないとき |
| `present` | `files` のサイトで、証明書チェーンを読め、秘密鍵のファイルがあるとき |
| `issued` | `acme` のサイトで、証明書チェーンを読め、秘密鍵のファイルがあるとき |

- 応答は、ディスクにある証明書の状態であり、プロキシがメモリに持つ証明書の状態ではありません。`acme renew` の後は、プロキシが証明書を再読み込みする（SIGUSR2）まで、2 つは違います。バージョンは、稼働中のものでなくてもかまいません。
- `present` と `issued` は、ファイルがあり、証明書チェーンを読めることだけを示します。秘密鍵の内容、証明書チェーンと秘密鍵が対応しているか、証明書がサイトのホストを含むかは検証しません。どのサイトも `present` のバージョンを、プロキシが拒否することはあります。
- プロキシは証明書の有効期限を確認せず、期限切れの証明書もそのまま使います。`check` と `apply` の検証でも、有効期限を確認しません。
- この API は、変更の実行権もロックも取得せず、プロキシに問い合わせず、監査ログに書きません。

### 設定ファイルの値

`GET /api/config`（operator 以上）は、設定ファイルの現在の値を返します。設定ファイルに `managed` があっても無くても使えます。

- 設定ファイルをリクエストのたびに再読み込みし、設定ファイルの検証をすべて通ったときだけ応答します。読めないときと受け付けられないときは、409 と決まった文で応答します。
- 応答は `{"sha256", "managed", ...}` です。`sha256` はファイルの SHA-256（プロキシが読み込むと `/api/status` の `proxy.config` に出る値）、`managed` は設定ファイルに `managed` があるか、残りは設定ファイルの設定キーを、設定ファイルと同じ名前と形式で並べたものです。
- 決まった一覧にある設定キーだけを出力します。パスの値（証明書、秘密鍵、CA のファイル、ディレクトリ、検査プロセス、ソケット、データベースのファイル）は、書かれていれば `true`、無ければ `null` で返し、パスの文字列は返しません。
- operator 以上に限るのは、ルートの書き換えに秘密を書けること、サーバーとリスナーのアドレスが含まれることのためです。

### 検証

`POST /api/managed/check`（operator 以上）は、バージョンを `POST /api/managed/apply` と同じように検証し、何も保存しません。画面が、保存する前に、エラーをその欄に表示するための API です。

- ボディは `{"version", "files", "expect"}` で、`POST /api/managed/apply` と同じ形式です（下の「保存して反映」）。`expect` は省略でき、あっても形式を検証しません。
- 進み方（最初に拒否した段階で応答します）:
  1. 検証の実行枠。ほかのリクエストが保持していれば 503 `a check of a managed version is under way`。管理プロセスが起動したときに `managed` が無かった場合は、すぐに 409。
  2. ボディ、ファイル、バージョンの形式。拒否は 400（文と場所）。
  3. 設定ファイルを再読み込みします。`managed` が無いとき、`managed.dir` が起動時と違うとき、受け付けられないときは 409。
  4. managed ストアを開きます。開けなければ 500。
  5. バージョンとファイルを、設定ファイルと、リクエストのファイルと managed ストアのファイルで検証します。拒否は 400（文と場所）。
- 応答は 200 `{"version"}` で、保存した場合のバージョンの名前です。
- 変更の実行権を取得せず、プロキシに問い合わせず、managed ストアに何も置かず、監査ログにも書きません。選択中のバージョンが無い managed ストア（コマンドで最初のバージョンを作成する前）でも検証できます。
- 検証の実行枠: `check` と `apply` のバージョンの検証は、管理プロセスの中で同時に 1 つだけ実行します。12 MiB のボディと managed ストアのファイルをもう一度読み込むので、メモリを多く使うためです。

### 保存して反映

`POST /api/managed/apply`（operator 以上）は、バージョンを managed ストアに保存し、稼働中のプロキシに反映します。ボディは JSON のオブジェクトで、3 つのキーがどれも必要です。

| キー | 内容 |
|---|---|
| `expect` | 画面で見た選択中のバージョン（64 桁の小文字の 16 進数） |
| `version` | 保存するバージョン。managed ストアのバージョンの形式（ファイルを SHA-256 で指定し、パスを持たない）で、書き方は問いません。保存するときは 1 つの決まった書き方にし、その SHA-256 がバージョンの名前になります |
| `files` | バージョンと一緒に保存するファイル（証明書チェーン、秘密鍵、CA のファイルの PEM の文字列）の配列 |

- `files` は 192 個まで、1 つ 1 MiB までです。同じファイルを 2 回送ることはできず、どのファイルもバージョンが指定するものであること。バージョンが指定していて、リクエストに含まれないファイルは、managed ストアに既にあること。
- ファイルの内容は、応答、監査ログ、設定の変更履歴に書きません。

進み方（最初に拒否した段階で応答します）:

1. 検証の実行枠。ほかのリクエストが保持していれば 503。監査ログには書きません。
2. ボディ。JSON の形式が違うとき、ファイルが多すぎるか大きすぎるとき、バージョンの形式が違うとき（設定キーの重複、未知の設定キー、不足している設定キー、型の違い）、`expect` が 64 桁の小文字の 16 進数でないときは 400。監査ログには書きません。
3. 変更の実行権、設定ファイルの再読み込み、managed ストアと `expect`、プロキシの状態（下の「名前を指定した反映とロールバック」の 1〜4 と同じ）。プロキシがバージョンを受け付けられないときは、何も保存しません。
4. バージョンを、設定ファイルとファイルで検証します（`managed import` と同じ検証。国のデータベースは読み込まず、プロキシが反映のときに読み込みます）。拒否は 400（文と場所）。監査ログには書きません。
5. 監査ログに `managed-import` の行（対象はバージョンの名前）を書きます。書けなければ 503 で、何も保存しません。
6. ファイルとバージョンを、managed ストアのロックの中で置きます。コマンドがロックを保持していれば 409 `the managed store is in use by another command`、ほかの managed ストアの拒否も 409。managed ストアのファイルと合わせて読み込んだバージョンが拒否されれば 400（場所なし）、設定ファイルが拒否されれば 409。どれも監査ログに失敗（`store`、`version`、`configuration`）を書きます。
7. 反映の処理を始めます（下の「名前を指定した反映とロールバック」の 6）。保存したが反映の処理を始められなかったバージョンは、managed ストアに残ります。害はありません。

応答は 202 で、`version`（バージョンの名前）、`placed`（保存の結果。`created`、同じバージョンが既にあった `existing`、壊れた写しを置き換えた `recreated`）、`job`（始めた反映の処理）を持ちます。

### 名前を指定した反映とロールバック

`POST /api/managed/activate`（`{"expect", "version"}`）は managed ストアのバージョンを名前で、`POST /api/managed/rollback`（`{"expect"}`）はロールバック先のバージョンを、稼働中のプロキシに反映します。operator 以上で、API トークンでも使えます。

- `expect` と `version` は 64 桁の小文字の 16 進数です。違うと 400 `a version is not 64 lowercase hexadecimal digits` になります。
- `expect` は、画面で見た選択中のバージョンです。画面を見た後にほかのユーザーかコマンドが選択し直していれば、古い画面から上書きしないよう、409 で拒否します。
- 選択中のバージョンが無い managed ストアでは、`expect` が合わないので反映できません。最初のバージョンは、コマンド（`managed import` と `managed activate`）で作成して選択します（[運用リファレンス](operator-reference.md) の「managed 設定での初回起動」）。

進み方（上の「保存して反映」の 3 も同じです。最初に拒否した段階で応答します）:

1. 変更の実行権。管理プロセスの中で、変更は反映の処理の終わりまで含めて 1 つずつ順に進みます。ほかの変更（バージョンの削除を含みます）が進んでいれば 409 `a change of the managed configuration is under way`、管理プロセスが停止中なら 503。監査ログには書きません。
2. 設定ファイルを再読み込みします。`managed` が無いとき（管理プロセスの起動時に無かったときも）、`managed.dir` が起動時と違うとき、受け付けられないときは 409。監査ログに拒否（`managed`、`configuration`）を書きます。
3. managed ストア。開けないとき、選択中のバージョンを示すファイル（`current`）を読めないときは 500。選択中のバージョンが `expect` でない（無いときも）ときは 409 `the chosen managed version is not the one that was expected`（監査ログに拒否、`expect`）。ロールバックは、ここでロールバック先を決めます。無ければ 409、設定の変更履歴を読めなければ 503（どちらも監査ログには書きません）。
4. プロキシの状態を、制御ソケットで問い合わせます。
   - 接続できない: 503 `the proxy cannot be reached`。設定の変更履歴に `unreachable` の行を書きます（監査ログに拒否、`unreachable`）。
   - 接続を受け付けて何も応答せずに閉じる（同時接続数の上限）: 503 `the proxy is busy`（監査ログに拒否、`busy`）。
   - 稼働中の設定に `managed` が無い: 409 `the configuration in force has no managed object`（監査ログに拒否、`unmanaged`）。
5. 名前で反映とロールバックでは、バージョンが managed ストアにあること。無ければ、名前で反映は 404、ロールバックは 409 `the version to go back to is not in the store`。`POST /api/managed/apply` は、ここでバージョンを保存します（上の「保存して反映」の 4〜6）。
6. 反映の処理を始めます。応答の時間（30 秒）の残りが 5 秒以下のときと、1 の後に管理プロセスが停止し始めたときは、503（監査ログに失敗、`time`、`stopping`）。スレッドを作成できなければ 503（監査ログに失敗、`thread`）。

応答は 202 で、`version`（反映するバージョン）と `job` を持ちます。

ロールバック先:

- 設定の変更履歴の中で、結果が `applied` で、`from` と `to` が違う、最も新しい行の `from` です。
- ただし、その行の `to` が、現在選択中のバージョンのときだけです。反映が `applied` に終わらなかった後や、コマンドでバージョンを選択した後は、履歴の終わりが選択中のバージョンと合わないので、ロールバックできません（409 `the history does not end at the chosen version`）。`applied` の行が無いときは 409 `there is no change to go back from` になります。
- ロールバックも履歴に `rollback` として入ります。続けてもう一度ロールバックすると、元のバージョンに戻ります。

### 反映の処理

変更（「保存して反映」「名前で反映」「ロールバック」）は、上の段階を通るとすぐに 202 で応答し、反映は管理プロセス内の反映の処理（`job`）として続きます。反映は、1 つの応答を待てる時間より長くかかることがあるためです。終わりは `GET /api/managed/job`（viewer 以上。`{"job"}`、無ければ `null`）か、`GET /api/managed` の `job` で読み取ります。

- 管理プロセスが保持する反映の処理は最後の 1 つだけで、メモリにだけあります。管理プロセスを再起動すると失われます。動作中の反映の処理は、管理プロセスと一緒に終了し、managed ストアのロックもプロセスと一緒に解放されます。
- 反映の処理はキャンセルできません。依頼したユーザーのロールが変わっても止まりません。
- 反映の処理は、終わるまで変更の実行権を保持します。その間、ほかの変更とバージョンの削除は 409 になります。
- 反映の順序（managed ストアのロック、プロキシへのリロードの依頼、選択中のバージョンを進める順序）と、途中で停止したときの扱いは、[運用リファレンス](operator-reference.md) の「反映」を参照してください。管理プロセスが制御ソケットで待つ時間は、上の「制御ソケット」を参照してください。

| キー | 内容 |
|---|---|
| `kind` | `apply`（保存して反映）、`activate`（名前で反映）、`rollback` |
| `actor` | 依頼したユーザーの名前 |
| `from`、`to` | 変更前（`expect`）と変更後のバージョン |
| `started`、`ended` | 始めた時刻と終わった時刻（エポックからの秒数）。動作中は、`ended` は `null` です |
| `state` | `running`（反映中）か `ended` |
| `result` | 終わり方（下の表）。動作中は `null` です |
| `reason` | 決まった語。拒否したプロキシの部分（`configuration`、`version`、`store`、`upstream`、`tls`、`fixed`、`listener`、`thread`）、`busy` の理由（`store in use`、`proxy busy`、`reload under way`、`starting`、`too many orders`、`stopping`）、`error` の理由、`not recorded` の理由（`current changed`、`store`） |
| `detail` | 拒否したプロキシの文か、managed ストアの文 |
| `config_before`、`config_after` | 反映の前と後に使われていた設定ファイルの SHA-256。分かるときだけ |
| `history` | 設定の変更履歴に行が書き込まれたか。行を書かない終わり方では `null` |

| `result` | 意味 | 監査ログ | 設定の変更履歴 |
|---|---|---|---|
| `applied` | プロキシが変更後のバージョンで稼働し、managed ストアで変更後のバージョンが選択されました | 変更の前に書いた `ok` の行 | 行を書きます |
| `refused` | プロキシが拒否しました。何も変更されていません | 失敗 | 行を書きます |
| `busy` | managed ストアかプロキシが使用中でした。何も変更されていません | 変更の前の行より前なら拒否、後なら失敗 | 後なら行を書きます |
| `current changed` | 選択中のバージョンが `expect` ではなくなっていました | 拒否 | 書きません |
| `no version` | バージョンが managed ストアにありません | 拒否 | 書きません |
| `unmanaged` | 稼働中のプロキシの設定に `managed` がありません | 拒否 | 書きません |
| `store` | managed ストアのロックを取得できない、選択中のバージョンを示すファイル（`current`）が無いか読めない、など | 拒否 | 書きません |
| `audit` | 変更前の監査ログの行を書けませんでした。何も変更されていません | − | 書きません |
| `error` | プロキシが依頼を受け付けませんでした（`unknown op` は、制御ソケットの `reload` に対応していない古いプロキシ） | 失敗 | 行を書きます |
| `unreachable` | プロキシに接続できませんでした | 拒否 | 行を書きます |
| `failed` | プロキシは変更後のバージョンに切り替わりませんでした | 失敗 | 行を書きます |
| `unconfirmed` | 結果を確認できませんでした | 失敗 | 行を書きます |
| `not recorded` | プロキシは変更後のバージョンに切り替わりましたが、managed ストアで選択されませんでした（`current changed`: 選択中のバージョンが手作業で変更された、`store`: 選択中のバージョンを示すファイル（`current`）を書けない） | 失敗 | 行を書きます |

- 監査ログの `ok` の行は、変更の前に書きます（`from` と `to` を `before` と `after` に書きます。設定ファイルの SHA-256 は、監査ログではなく設定の変更履歴に書きます）。成功を示す行ではないので、終わり方は、後に続く行と設定の変更履歴で確認します。
- 設定の変更履歴に行を書き込めなかったときは、監査ログに失敗（`history`）を書きます。
- 反映の処理が途中で異常終了したときは `unconfirmed` になり、管理プロセスがログに 1 行を書きます。
- `unconfirmed` と `not recorded` の後は、選択中のバージョンと稼働中のバージョンが違うことがあります。`GET /api/managed` の `current` と `serving` で確認し、違っていれば、どちらかのバージョンをもう一度反映します。

### バージョンの削除

`DELETE /api/managed/versions/<version>`（operator 以上、API トークン可、ボディなし）は、バージョンを managed ストアから削除します。元に戻せません。どのバージョンも指定しなくなったファイルと ACME の証明書も、一緒に片付けます（片付けで削除されるものは [運用リファレンス](operator-reference.md) の「バージョンの削除」）。

進み方（最初に拒否した段階で応答します）:

1. 名前が 64 桁の小文字の 16 進数でなければ 404。
2. 変更の実行権（反映の処理も保持します）。ほかの変更が進んでいれば 409、管理プロセスが停止中なら 503。監査ログには書きません。
3. 設定ファイルを再読み込みします。`managed` が無いとき、`managed.dir` が起動時と違うとき、受け付けられないときは 409（監査ログに拒否、`managed`、`configuration`）。
4. managed ストアを開けなければ 500。
5. managed ストアの一覧に無いバージョンは 404。
6. 選択中のバージョンは削除しません（409、監査ログに拒否、`chosen`）。
7. ロールバック先のバージョンは削除しません（409、監査ログに拒否、`rollback target`）。設定の変更履歴を読めなければ 503。
8. 監査ログに `managed-remove` の行（対象はバージョンの名前）を書きます。書けなければ 503 で、削除しません。
9. managed ストアから削除します。拒否は、409 と managed ストアの文（監査ログに失敗、`store`）。

| バージョン | `error` |
|---|---|
| 選択中のバージョン | `the version is the one the managed store chooses` |
| ロールバック先のバージョン | `the version is the target of a rollback` |
| 使用中のバージョン（どれが使用中かは [運用リファレンス](operator-reference.md) の「バージョンの削除」） | `the managed version is in use` |

- 成功すると 200 `{"removed", "cleaned"}` を返します。`removed` は削除したバージョンの名前、`cleaned` は片付けを終えたかどうかの真偽値です。`cleaned` が `false` の場合は、片付けを終えられなかったこと（ほかのバージョンを読めなかった、など）を示します。削除は取り消さず、次の削除のときにもう一度片付けます。
- プロキシには問い合わせません。使用中のバージョンは、managed ストアで拒否されます。
- 削除は、ほかのバージョンを 1 つずつ読み込むので、バージョンが多いほど時間がかかります。応答が間に合わないと 503 になりますが、削除はそのまま完了することがあります。
- 設定の変更履歴には行を書きません。削除したバージョンを指定している行は残ります。

## 切り替えの履歴

`GET /api/history`（viewer 以上、API トークン可）は、世代の選択とロールバックの履歴を、新しい順に 200 行まで `{"entries": [...]}` で返します。

| 項目 | 内容 |
|---|---|
| `ts` | 時刻（UTC の RFC 3339 で ms まで） |
| `actor` | 切り替えを依頼したユーザーの名前 |
| `from` | 依頼の前にルールストアで選択中だった世代 |
| `to` | 依頼した世代（ロールバックではロールバック先） |
| `kind` | `activate`、`rollback` |
| `result` | 結果の語（下の注） |

`result` は、「選択とロールバック」の応答の `result`（`switched`、`unchanged`、`refused`、`failed`、`unreachable`、`unconfirmed`）と同じ 6 つで、意味も同じです。

- 履歴は `admin.store.dir` の `activations.log` に追記します。1 行を書き終えて同期してから応答します。ローテーションせず、削除もされません。読み戻すのは終わりの 1 MiB（約 4000 行）までで、それより古い行はロールバック先の判断にも使われません。
- 管理画面と管理 API で依頼した切り替えだけが入ります。コマンド（`rules activate`）と SIGUSR1 による選択と切り替えは入りません。
- 履歴に書くのは、プロキシに接続できなかったときと、監査ログの行を書いた後の結果（ルールストアで選択が拒否されたときと、プロキシの応答）だけです。入力のエラー、世代が無い、ロールバック先が決まらない、ほかの変更が進んでいる、`expect` が古い、プロキシが同時接続数の上限のために状態の問い合わせに応答しなかった、監査ログの行を書けなかった、のときは書きません。

## 設定の変更履歴

`GET /api/managed/history`（viewer 以上、API トークン可）は、managed 設定の変更（「保存して反映」「名前で反映」「ロールバック」）の履歴を、新しい順に 200 行まで `{"entries": [...]}` で返します。

| 項目 | 内容 |
|---|---|
| `ts` | 時刻（UTC の RFC 3339 で ms まで） |
| `actor` | 変更を依頼したユーザーの名前 |
| `kind` | `apply`、`activate`、`rollback` |
| `from` | 依頼のときに managed ストアで選択中だったバージョン |
| `to` | 依頼したバージョン（ロールバックではロールバック先） |
| `result` | 結果の語（下の注） |
| `reason` | 決まった語。無ければ `null` |
| `config_before`、`config_after` | 反映の前と後に使われていた設定ファイルの SHA-256。無ければ `null` |

`result` は、`applied`、`refused`、`busy`、`error`、`failed`、`unconfirmed`、`not recorded`、`unreachable` の 8 つで、意味は「managed 設定の操作」の「反映の処理」の表と同じです。`reason` も、反映の処理の `reason` と同じ語です。

- 履歴は `admin.store.dir` の `managed.log` に、1 行 1 件の JSON で追記します。1 行を書き終えて同期します。ローテーションせず、削除もされません。読み戻すのは終わりの 1 MiB までで、それより古い行はロールバック先の判断にも使われません。決まった形式に合わない行は除きます。
- 管理画面と管理 API で依頼した変更だけが入ります。コマンド（`managed activate`）による選択と、SIGHUP による反映は入りません。
- 行を書くのは、プロキシに接続できなかったとき（`unreachable`）と、変更前の監査ログの行を書いた後の終わり方だけです（「反映の処理」の表）。入力のエラー、ほかの変更が進んでいる、`expect` が古い、ロールバック先が決まらない、プロキシが同時接続数の上限のために問い合わせに応答しなかった、監査ログの行を書けなかった、のときは書きません。
- プロキシと managed ストアの文は、履歴には書きません。反映の処理の `detail` にだけあります。
- 行を書けなかったときは、反映の処理の `history` が `false` になり、監査ログに失敗（`history`）を書きます。
- 管理プロセスが起動したときに `managed` が無かった場合は 409、履歴を読めない場合は 503 になります。

## ログの読み出し

`GET /api/records`（viewer 以上、API トークン可）は、`records.dir` のファイルを新しい行から読み、条件に合う行を返します。行は書かれたままの JSON のオブジェクトで、リクエストから来た文字（`path` など）は `%XX` の形のままです（[運用リファレンス](operator-reference.md) の「ログ」）。キーの順序は変わることがあります。

条件（クエリ）は次のとおりです。どれも 1 回までで、値は `%XX` で書けます（デコードの後に 128 バイトまで）。

| 条件 | 形式 |
|---|---|
| `from`、`to` | 開始と終了の時刻。UTC の RFC 3339 で、`Z` で終わります。秒の小数は 9 桁まで（ミリ秒に切り捨てます）か、なし |
| `type` | `request`、`connection`、`tunnel`、`line`、`audit`、`dropped` |
| `class` | リクエストのログの結果（1〜32 文字の小文字・数字・`_`・`-`） |
| `status` | ステータスコード（1〜3 桁の数字） |
| `rule` | ルール ID。判定したルールか、ほかに一致したルールの中にあるもの |
| `id` | リクエスト ID |
| `client` | IP アドレス |
| `generation` | 世代のフィンガープリント。先頭 16 桁か 64 桁（ログには先頭 16 桁だけがあります） |
| `file`、`offset`、`inode` | 続きの位置。3 つがそろって初めて使えます |

- `audit` のログは、管理プロセスの標準エラーと監査ログの保存先に出力されるもので、プロキシのログファイルには入りません。`type=audit` で検索しても、このファイルからは見つかりません。監査ログは `GET /api/audit` で読みます。
- 1 回に返すのは 500 行まで、読み込むのは 256 MiB までです。どちらかに達して、まだログが残っているときは、応答の `next` に続きの位置が入ります。読み込む量の上限で、条件に合う行を見つける前に読み込みが止まると、`records` が空でも `next` が入ります。`next` が `null` になるまで続けて読みます。
- 応答は `{"records": [..], "next": null か {"file", "offset", "inode"}}` です。`inode` は文字列で返します。続きを読むには、同じ条件に `next` の 3 つの値を加えます。
- 続きの位置は、ファイルの番号と、その中の位置、ファイルの inode で決まります。ログファイルのローテーションで番号が変わっても、inode でファイルを探します。ファイルがローテーションで削除された、または位置が行の終わりでなくなったときは、409 `the continuation names no place in the record files any more` になります。その場合は、最初から読み直します。
- 新しい行から順に読み、`from` より古い行に出会うと、そこで読み込みを終了します。書き込みの途中で改行が無い最後の行、`ts` を持たない行、長すぎる行は、返しません。
- 失敗:
  - 設定に `records` が無い: 404 `records are not configured`
  - 条件のエラー（未知の条件、同じ条件が 2 回、値の形式のエラー、続きの位置の 3 つがそろわない）: 400。文は決まった英語の 1 文
  - ログファイルのディレクトリが、所有者・権限の検証に通らない: 503。文は検証の文
  - ファイルを読めない: 503 `unavailable`

## 管理画面

管理画面は、管理プロセスが提供します。ブラウザーで `https://admin.example.com/`（`admin.origin`）を開きます。

- ファイルは `proxy/admin-ui/` にあり、実行ファイルに組み込みます。管理プロセスと管理画面は、いつも同じバージョンです。ホストのファイルは読み込みません。
- 提供するパスは、`GET /`（ページ）と `GET /ui/<ui-version>/<name>`（スタイルシート、アイコン、34 個のスクリプトの、合わせて 36 個）だけです。スクリプトの名前は、`proxy/admin-ui/js/` からのパスです（`js/app.js` は `/ui/<ui-version>/app.js`、`js/waf/waf.js` は `/ui/<ui-version>/waf/waf.js`）。セッションは不要です（ファイルに秘密は含まれません）。
- パスの `<ui-version>` は、36 個のファイルの名前と内容から作成する、16 桁の小文字の 16 進数です（ファイルごとに名前と SHA-256 を並べた一覧の、SHA-256 の先頭 16 桁）。ページかファイルの最初のリクエストが来たときに 1 回だけ作成し、ページの中の `/ui/` を `/ui/<ui-version>/` に置き換えて提供します。ファイルの内容が変わらなければ、`<ui-version>` も変わりません。
- `<ui-version>` の無い `/ui/<name>`、違う `<ui-version>` のパス、36 個に無い名前は、どれも API の表に回って 404 になります。ページと、`<ui-version>` の下のファイルに `GET` と `HEAD` 以外のメソッドを送ると、405（`Allow: GET, HEAD`）になります。
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

- ページは毎回読み込まれ、そのときの `<ui-version>` のパスでファイルを指定します。`<ui-version>` の下のファイルは内容が変わらないので、ブラウザーは 1 年までキャッシュを使います。画面のファイルが変わった実行ファイルで管理プロセスを再起動すると、`<ui-version>` が変わり、ブラウザーはそのときだけ新しいパスのファイルを読み込みます。
- 画面のスクリプトは、文字列からマークアップを作成できません（Trusted Types）。画面は、自分のスクリプトとスタイルとアイコンを読み込み、自分の API を呼び出す以外のことはできません。
- API の応答の `Referrer-Policy` は `no-referrer`、画面のファイルの応答は `same-origin` です。

言語と保存:

- 言語は日本語と英語です。選択した言語が保存されていればそれを、無ければブラウザーの言語（`ja` で始まれば日本語、`en` で始まれば英語）を、どちらでもなければ英語を使います。画面上部の帯で切り替えられます。
- テーマ（自動、ライト、ダーク）と、時刻の表示方法（ローカルか UTC）も、画面上部の帯で選べます。ブラウザーのストレージ（`localStorage`）に保存するのは、この言語とテーマと時刻の表示方法の 3 つだけです。パスワード、認証コード、リカバリーコード、API トークン、CSRF トークン、二要素認証のセットアップキー、managed 設定の下書き（下の「下書き」）は、どれも画面のメモリにだけ置きます。一度しか返さないもの（リカバリーコード、API トークン、設定中のセットアップキー）も、画面を離れると破棄します。ただし、二要素認証の設定を確定した応答が画面を離れた後に届いたときは、そのリカバリーコードを、次の画面に表示するまで保持します。ログアウトしたときやセッションが終了したときは、どれも破棄します。URL と履歴にも入れません。
- 言語、テーマ、時刻の表示方法を切り替えても、画面は再描画せず、文字だけを置き換えます。入力した文字、選択したファイル、絞り込みは、そのまま残ります。
- 二要素認証の QR コードは、画面の中で描画します（外部には何も送信しません）。

使える画面はロールで決まります。メニューは、画面を 7 つのまとまり（下の表の「メニュー」の列）ごとに並べ、ロールが使える画面だけを表示します。

| メニュー | 画面 | ロール | 内容 |
|---|---|---|---|
| （名前なし） | 概要 | viewer 以上 | プロキシの数（「リクエスト」「ブロック」「ポリシーで拒否」「アップストリームのエラー」「設定のリロード」の 5 つ。「リクエスト」の下に起動からの時間を添えます。内容は上の「一覧と内容」の `GET /api/status`）、プロキシの状態（検査カーネルの段階、モード、エンジン、世代の切り替え中か）、選択中の世代と稼働中の世代、ロールバック先、現在の設定ファイルの SHA-256 を表示します。切り替えの途中ではないのに 2 つの世代が違うときは、画面上部の帯に警告を表示します。途中のときは、概要の画面にその旨だけを表示します。managed 設定を使っているときは、「managed 設定」の枠に、選択中のバージョンと稼働中のバージョン、2 つの「一致」「不一致」（反映の処理の間は「反映中」）を表示し、「設定のバージョンを開く」で設定のバージョンの画面へ移れます |
| WAF | ルールの世代 | viewer 以上 | 世代の一覧と詳細（ファイル、読み込む順、検査除外のルート）を表示します。operator 以上は、選択、プロキシの切り替え（選択中なのに稼働していない世代の「プロキシに反映する」）、削除ができます。選択中の世代、稼働中の世代、ロールバック先は削除できません |
| WAF | ルールのインポート | operator 以上 | ブラウザーでファイルを選択し、検査エンジン（Coraza か ModSecurity。初期値は Coraza）、CRS の使用と使わないファイル、検査除外のルート、検知のみを指定してインポートします。検査除外のルートは、ホスト（省略できます）とパスを 1 行に 1 つずつ書きます。アクションはいつも `bypass` で、送信するボディの `routes` は、`--routes` のファイルと同じ形式の JSON です。ホストだけの行はエラーとして表示し、何も書かない行は送信しません。上限をブラウザーでも数えます。事前検証でブロックされたら、確認を経て「ブロックを受け入れてインポートする」ができます。新しい世代は選択されません |
| WAF | 切り替え履歴 | viewer 以上 | 切り替えの履歴（新しい順に 200 件まで。画面にもそのように書かれています）とロールバック先を表示します。operator 以上は、「前の世代にロールバックする」ができます |
| ログ | アクセスログ | viewer 以上 | 条件を指定してログを検索します。リクエストから来た文字は、`%XX` の形のまま表示します。リクエスト ID を持つログは、行の内容（メソッドとホストとパスなど）を押すと詳細を開きます。リクエスト ID は、内容の `title` 属性と、詳細の「すべての欄」と「JSON」に出ます。リクエスト ID を持たないログ（接続や、プロキシの文の行など）は、行の「詳細」で開きます。開くと、先に要点（結果の `class`・`status`・`reason`、ルール、`score`、時刻、クライアント、メソッドとホストとパス、世代）を表示し、その下に、折りたたんだ「すべての欄」と「JSON」を置きます。「すべての欄」で「URL デコードした文字も表示する」を選択すると、デコードした文字も表示します |
| ログ | 監査ログ | operator 以上 | 最新の 200 件（新しい順。画面にもそのように書かれています）を表示します。リクエスト ID がプロキシと管理プロセスの付与する形式のときは、その ID からアクセスログを開けます |
| プロキシ | サイト | operator 以上 | managed 設定の下書きの、サイトの一覧と編集（名前、ホスト、証明書。証明書は、証明書チェーンと秘密鍵のファイルか ACME）。一覧と編集の面に、managed ストアにある証明書の有効期限、状態、証明書に含まれるホスト名を表示します（上の「証明書の情報」） |
| プロキシ | アップストリーム | operator 以上 | 下書きの、デフォルトのアップストリームと、アップストリームの一覧と編集（サーバー、TLS と CA のファイル） |
| プロキシ | ルート | operator 以上 | 下書きの、ルートの一覧と編集（ホスト、パス、アップストリーム。折りたたんだ部分に、アクセス制御、ストリーミング応答、書き換え）。1024 本まで読み込みます |
| ポリシー | アクセス制御とレート制限 | operator 以上 | 下書きの、全体のアクセス制御とレート制限と、ホストごとの設定の一覧と編集（下の「ホストごとの設定の画面」） |
| 設定 | 設定のバージョン | viewer 以上 | 選択中のバージョンと稼働中のバージョン、プロキシの状態、反映の状況、バージョンの一覧を表示します（下の「managed 設定の画面」）。operator 以上は、バージョンの内容（JSON と証明書）を表示し、名前で反映、削除、下書きの作成ができます。選択中のバージョン、稼働中のバージョン、ロールバック先は削除できません |
| 設定 | 設定の変更履歴 | viewer 以上 | 設定の変更履歴（新しい順に 200 件まで。画面にもそのように書かれています）とロールバック先を表示します。設定ファイルが反映の前と後で違う行には「変更あり」を表示します。operator 以上は、「前のバージョンにロールバックする」ができます |
| 設定 | 設定ファイル | operator 以上 | 設定ファイルの現在の値（上の「設定ファイルの値」）を表示します。ここでは変更できません。パスは表示せず、書かれていれば true、書かれていなければ「—」と表示します。稼働中のプロキシとの比較（「一致」か「不一致（リロード待ち）」）を表示します |
| 管理 | アカウント | viewer 以上 | パスワードの変更、二要素認証の設定と無効化、API トークンの作成と削除 |
| 管理 | ユーザー | owner | ユーザーの一覧、作成、ロールの変更、無効・有効、パスワードと二要素認証の初期化、全員の API トークンの一覧と削除 |

- 概要の数がプロキシから得られないときは、数の代わりに「—」と短い語を表示し、0 とは区別します。理由は、プロキシの面に 1 回だけ表示します。理由は、プロキシに接続できない（`reachable` が `false`）、プロキシが処理中（`proxy` が `null`）、そのプロキシが数を返さない（前のバージョンのプロキシで、値が `null`）のどれかです。設定ファイルの SHA-256 も同じです。
- 世代の選択、ロールバック、削除は、先に確認を表示します。確認には、「現在」と「切り替え後」（ロールバックでは「ロールバック後」、削除では「削除後」）の世代を、フィンガープリント（先頭 12 桁）、モード、エンジン、検査除外のルート数の表で並べ、変わる値を太字にします。選択の「現在」は選択中の世代、「切り替え後」は選択する世代で、プロキシが選択中の世代と違う世代を使っているときは、その世代も表示します。ロールバックの「ロールバック後」はロールバック先で、削除の「削除後」はどれも「なし」です。分からない値は「—」になります。インポートは確認なしで送信し、事前検証のブロックを受け入れてインポートし直すときだけ確認を表示します。実行中は、ほかの変更を始められません。
- 結果が分からないとき（ボディに `result` が無い 502 と 504、接続が切れた）は、世代の選択とロールバックでは状態と履歴を、インポートでは世代の一覧の新しい方から 3 つを、削除では世代の一覧を再読み込みして表示します。managed 設定の変更で、変更が始まったか分からないときは、「結果不明」として状態を再読み込みして表示します。
- 画面は、時間をおいて自分から再読み込みすることはありません。例外は managed 設定の反映の処理で、画面は、反映の処理が終わるまで、前の応答の 1 秒後に `GET /api/managed/job` を読んで状態を確認し続けます。読めない応答が 3 回続くか、反映の処理にかかる可能性のある時間を過ぎると、確認をやめ、その旨を表示します。確認の間はリクエストのたびにセッションが使われたことになるので、セッションは `admin.session_idle_ms` では終了しません（`admin.session_total_ms` では終了します）。プロキシを通して使っているときは、ログの残し方が `security` でなければ、確認の 1 回ごとに、プロキシのログに 1 行が入ります。画面から変更したときは、それに関わる表示を再読み込みします。最新にするには「再読み込み」を使います（インポートの画面にはありません）。
- 一覧の表は、並べ替えられる列の名前を押すと、その列で並べ替えます（押すたびに昇順と降順が切り替わり、値の無い行は後ろに来ます）。表の上の欄に語を入力すると、セルに見えている文字がその語をすべて含む行に絞り込みます（語は空白で区切り、大文字と小文字は区別しません。操作のボタンの列は対象にしません）。行は 50 行ずつのページに分け、「前へ」と「次へ」で進みます。並べ替えと絞り込みは、画面が読み込んだ行の中だけで行います。世代に含まれる検査除外のルートの表など、絞り込みの欄が無い小さな表もあります。
- アクセスログは、`GET /api/records` の 1 回の応答（500 行まで）を、50 行ずつのページで表示します。応答に続き（`next`）があれば、最後のページの「次へ」で続きの古いログを読み込みます。最初のページの「前へ」で、前に読み込んだ新しい方に戻ります。続きの位置は URL に入らないので、URL を開き直すと最初から読み込みます。
- 画面の場所は、URL の `#` の後に入ります。`#/<screen>`（`overview`、`generations`、`import`、`history`、`records`、`audit`、`sites`、`upstreams`、`routes`、`policy`、`managed`、`managed-history`、`config`、`account`、`users`）のほか、世代の詳細は `#/generations/<fingerprint>`、バージョンの内容は `#/managed/<version>`、ログの 1 件は `#/records/<id>`、ログの検索は `#/records?<key>=<value>`（条件の名前は `GET /api/records` と同じで、続きの位置を除きます）です。移動するたびにブラウザーの履歴に入るので、ブラウザーの戻る操作と進む操作で行き来できます。URL を開き直しても、同じ画面になります。
- URL の中の値は、使う前に形式を検証します。形式の違う値、画面が認識しない条件、余分な部分は、使わずに URL から取り除き、「アドレスの正しくない部分を取り除きました。」と表示します。未知の画面と、ロールが使えない画面は、概要を開きます。ログの 1 件は、読み込んだ行に無ければ、そのリクエスト ID の条件で読み出し、見つからなければその旨を表示します。
- 時刻は 1 つの表示方法で表示します。初期状態ではローカルの時刻（`2026-11-04 16:33:56（JST）` の形。括弧の中は、ブラウザーが返すタイムゾーンの短い名前で、`JST` や `GMT+8` などになります）で、画面上部の帯の「時刻」で UTC（`（UTC）`）に切り替えられます。表では、タイムゾーンの名前を列の名前に 1 回だけ書き（`時刻（JST）` など）、セルには書きません。夏時間などで列の名前と違うタイムゾーンの時刻だけ、セルにもタイムゾーンを書きます。もう一方の表示方法は、その時刻の `title` 属性（ポインターを重ねると表示される文字）に表示されます。ログの検索の `from` と `to` は、この切り替えに関わらず、UTC の RFC 3339（`Z` で終わる）で書きます。
- ログインの後、パスワード変更待ちと二要素認証の設定待ちのときは、その画面だけを表示します。
- 画面は、ブラウザーの `fetch` で管理 API を呼び出します。API の応答の文（`error`）は、画面が言語ごとの文に置き換えます。
- 応答に `error` の文が無い失敗（手前に置いたプロキシがルールでブロックしたリクエストの 403、プロキシが管理プロセスに接続できなかった 502 など）では、画面は失敗の文の後に、応答の `X-Request-ID` のリクエスト ID を表示します。その ID で「アクセスログ」の画面を検索すると、ブロックしたルールなどが分かります（上の「管理画面の Host での CRS の調整」）。ID は、プロキシと管理プロセスが付与する形式のときだけ表示します。

managed 設定の画面:

- 管理プロセスが managed 設定なしで起動しているときは、設定のバージョンの画面と編集の画面に、managed 設定でできることと、使い始めるまでの手順の要点を表示します。手順は [運用リファレンス](operator-reference.md) の「managed 設定への移行」に従います。
- 設定のバージョンの画面は、選択中のバージョン、稼働中のバージョン、プロキシの状態（「接続可」「接続不可」「プロキシが処理中」「managed 設定は未使用」「リロード中」）を表示します。2 つのバージョンが違うときは、その通知と、operator 以上には「選択中のバージョンをもう一度反映する」と「稼働中のバージョンを選択し直す」の 2 つの操作を表示します。前者はプロキシを選択中のバージョンに切り替え、後者は稼働中のバージョンを名前で反映して選択中のバージョンにします。
- 設定ファイルが、稼働中のプロキシが読み込んだ内容と違うとき（`GET /api/config` の `sha256` が `/api/status` の `proxy.config` と違う）は、その旨を表示します。この画面から反映すると、設定ファイルの変更も一緒に反映されます。設定ファイルにエラーがあると、反映は拒否されます。
- 名前で反映（「このバージョンを反映する」）、ロールバック、2 つのバージョンをそろえる操作、削除（「このバージョンを削除する」）は、先に確認を表示します。確認には、「現在」と「反映後」（削除では「削除後」）のバージョンを、サイト数、アップストリーム数、ルート数、デフォルトのアップストリーム、全体のアクセス制御、全体のレート制限、ホストごとの設定数の表で並べ、反映では「各サーバーのダウン判定と、アップストリームの失敗回数はリセットされます。」も表示します。
- 変更を送信すると、反映の処理が終わるまで「反映中」と表示し、終わると、結果（「反映済み」「拒否」「使用中」など）と、起きたこと、次にすることを表示します。
- バージョンの内容（`#/managed/<version>`）は operator 以上だけが開けます。内容は秘密を含む可能性があるので、開いている間だけ画面のメモリに置きます。選択中でないバージョンでは、「このバージョンから下書きを作成する」で、そのバージョンから下書きを作成できます。

下書き:

- サイト、アップストリーム、ルート、アクセス制御とレート制限の 4 つの画面は、managed 設定の 1 つの下書きを編集します。下書きは、選択中のバージョンから作成します（バージョンの内容の画面から、ほかのバージョンからも作成できます）。ここでの変更は、「保存して反映する」を押すまで有効になりません。
- 下書きは、このページのメモリにだけあります。ブラウザーのストレージ、URL、履歴には入れません。ログアウトしたとき、操作がないままセッションが切れたとき、タブを閉じたときに失われます。変更のある下書きを残してページを離れようとすると、ブラウザーが確認を表示します。
- 下書きに入力している間は、30 秒に 1 回まで `GET /api/session` を送信し、セッションを延長します（入力はセッションを使ったことになります）。
- 画面上部の帯に、元のバージョンと「変更あり」か「変更なし」を表示します。「変更あり」は、下書きから作成するバージョンが元のバージョンと違うときだけです。入力して元に戻した下書きは「変更なし」になります。入力の形式にエラーのある下書きは「変更あり」になります。
- 帯の「検証する」は `POST /api/managed/check` を送信し、拒否されたらエラーをその欄に表示します（下の「応答の形式」の `at`）。「保存して反映する」は、検証、確認、`POST /api/managed/apply` の順に進みます。「変更なし」の下書きは保存できません（検証は「元のバージョンと同じで、変更はありません。」と表示します）。
- 「保存して反映する」の確認には、保存する変更（アップストリーム、デフォルトのアップストリーム、アクセス制御、レート制限、ホストごとの設定、サイト、ルートの追加・削除・変更）を名前で並べ、値は表示しません（書き換えに秘密を書けるためです）。ACME の証明書が新しく必要なサイトがあるときは（`{n}` はその数）、「{n} 件のサイトで新しい証明書が必要です。acme renew で発行されるまで（タイマーに任せると最大 1 日あまり）、そのサイトのホストには TLS で接続できません。」を表示します。
- 下書きの元のバージョンがもう選択中でないとき（ほかのユーザーかコマンドが先に変更した）は、そのままでは保存できません。
- 証明書チェーン、秘密鍵、CA の PEM のファイルは、ブラウザーで読み込み、UTF-8 のテキストで 1 MiB 以下かを検証し、送信するテキストの SHA-256 で指定します。ファイルの内容は表示しません。SHA-256 をブラウザーの暗号機能で計算するので、安全な接続（https か localhost）でだけ選択できます。読み込んだバイト列は使い終わるとすぐに 0 で埋めますが、テキストはブラウザーの中で 0 で埋められず、どこからも参照されなくなるまでメモリに残ります。

ホストごとの設定の画面:

- アクセス制御とレート制限の画面は、上から、「全体の設定とホストごとの設定は、管理画面のルートには適用されません。」の注意、全体のアクセス制御とレート制限の枠、ホストごとの設定の一覧と「ホストごとの設定を追加する」、開いたホストごとの設定を編集する面を並べます。
- ホストごとの設定の設定キー、ホストの比較の決まり、重ね方については、[運用リファレンス](operator-reference.md) の「ホストごとの設定（`host_policies`）」を参照してください。
- 編集の面では、名前と、ホスト（1 行に 1 つ）を書き、アクセス制御とレート制限のそれぞれで、次の 3 つから選びます。切り替えても、入力は下書きに残ります。
  - 「引き継ぐ」: 全体の設定を、このホストにも適用します。レート制限は、全体と同じカウンターで数えます。
  - 「このホストの設定」: 全体の設定の代わりに、この面の値を適用します。全体のアクセス制御は引き継がれません。レート制限は、このホスト用のカウンターで数えます。
  - 「使わない」: このホストには適用しません。アクセス制御では、全体の拒否もこのホストには適用されません。
- 全体のアクセス制御かレート制限を変更する下書きでは、全体の枠と「保存して反映する」の確認に、「全体のアクセス制御を引き継がない {n} 件のホストごとの設定（{names}）には、この変更は効きません。」（`{n}` は数、`{names}` は名前。レート制限も同じ形）を表示します。「このホストの設定」と「使わない」のホストには、全体の変更（緊急の拒否を含む）が効かないためです。
- 一覧には、「ホストごとの設定は、Host ヘッダーがそのホストであるリクエストにだけ適用されます。別のホストのリクエストが、デフォルトのアップストリーム、ホストのないルート、*. で始まるホストのルートを通って同じアップストリームに届くときは、全体の設定だけが適用されます。ホストごとにルートを書き、デフォルトのアップストリームを「なし」にすることをお勧めします。」と表示します。
- `geo` の無い設定ファイルで国の指定を書くと、検証の `at` が、そのホストごとの設定のアクセス制御を示します。管理画面のルートと同じホストを書くと、検証の `at` が、その行を示します。

## API のパスの一覧

「トークン」の列は、API トークンで使えるかどうかです。「状態」の列は、使えるセッションの状態です（通常は、状態による制限が無いこと。状態は上の「ログインと二要素認証」を参照してください）。

| メソッド | パス | 最小のロール | トークン | 状態 | 内容 |
|---|---|---|---|---|---|
| POST | `/api/login` | （不要） | × | | ログイン。`{"name", "password"}` |
| POST | `/api/login/mfa` | viewer | × | 認証コード待ち | 二要素認証の確認。`{"code"}` か `{"recovery"}` |
| POST | `/api/logout` | viewer | × | どの状態でも | ログアウト |
| GET | `/api/session` | viewer | × | 認証コード待ち以外 | セッションの情報 |
| PUT | `/api/account/password` | viewer | × | 通常、パスワード変更待ち | パスワードの変更。`{"current", "new"}` |
| POST | `/api/account/mfa/setup` | viewer | × | 通常、二要素認証の設定待ち | 二要素認証の設定の開始。`{"password"}` |
| POST | `/api/account/mfa/confirm` | viewer | × | 通常、二要素認証の設定待ち | 設定の確定。`{"code"}` |
| DELETE | `/api/account/mfa` | viewer | × | 通常、二要素認証の設定待ち | 二要素認証を無効にします。`{"password", "code"}` |
| GET | `/api/account/tokens` | viewer | × | 通常 | 自分の API トークンの一覧 |
| POST | `/api/account/tokens` | viewer | × | 通常 | API トークンの作成 |
| DELETE | `/api/account/tokens/<id>` | viewer | × | 通常 | 自分の API トークンの削除。ほかのユーザーの API トークンは 404 |
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
| GET | `/api/managed/certificates/<version>` | operator | ○ | 通常 | バージョンに含まれるサイトの証明書の情報 |
| POST | `/api/managed/check` | operator | ○ | 通常 | バージョンの検証。`{"version", "files", "expect"}`（`expect` は省略できます） |
| POST | `/api/managed/apply` | operator | ○ | 通常 | バージョンを保存して反映します。`{"expect", "version", "files"}` |
| POST | `/api/managed/activate` | operator | ○ | 通常 | 名前で反映。`{"expect", "version"}` |
| POST | `/api/managed/rollback` | operator | ○ | 通常 | 前のバージョンへのロールバック。`{"expect"}` |
| GET | `/api/managed/job` | viewer | ○ | 通常 | 最後の反映の処理 |
| GET | `/api/managed/history` | viewer | ○ | 通常 | 設定の変更履歴 |
| GET | `/api/config` | operator | ○ | 通常 | 設定ファイルの値 |
| GET | `/api/records` | viewer | ○ | 通常 | ログの読み出し |
| GET | `/api/audit` | operator | ○ | 通常 | 監査ログの最新 200 行 |
| GET | `/api/users` | owner | × | 通常 | ユーザーの一覧 |
| POST | `/api/users` | owner | × | 通常 | ユーザーの作成。`{"name", "role", "password"}` |
| PUT | `/api/users/<name>` | owner | × | 通常 | ロールか有効・無効の変更。`{"role"}` か `{"disabled"}` のどちらか 1 つ |
| POST | `/api/users/<name>/password` | owner | × | 通常 | ほかのユーザーのパスワードを決めます。`{"password"}` |
| DELETE | `/api/users/<name>/mfa` | owner | × | 通常 | ほかのユーザーの二要素認証を無効にします |
| GET | `/api/tokens` | owner | × | 通常 | 全員の API トークンの一覧 |
| DELETE | `/api/tokens/<id>` | owner | × | 通常 | 全員の API トークンの削除 |

- 「通常」の API は、パスワード変更待ちと二要素認証の設定待ちのセッションでは使えません。
- 主な応答のボディ（時刻は、ユーザーと API トークンではミリ秒のエポック、世代の `made`、managed 設定のバージョンの `made`、反映の処理の `started` と `ended`、証明書の `not_after` では秒のエポック、履歴と監査ログの `ts` では RFC 3339）:
  - `POST /api/login`、`POST /api/login/mfa`: `{"name", "role", "csrf", "mfa", "must_change"}` とクッキー
  - `GET /api/session`: `{"name", "role", "csrf", "mfa", "recovery_left", "must_change", "state", "idle_expires_in_ms", "total_expires_in_ms"}`。`mfa` は二要素認証を設定しているかどうか
  - `PUT /api/account/password`、`DELETE /api/account/mfa`: `{"csrf"}` と新しいクッキー。ほかのセッションは終了します。パスワードの変更では API トークンがすべて削除されます
  - `POST /api/account/mfa/setup`: `{"secret", "uri"}`。`POST /api/account/mfa/confirm`: `{"csrf", "recovery"}` と新しいクッキー
  - `GET /api/users`: `{"users": [..]}`（`name`、`role`、`disabled`、`mfa`、`must_change`、`created`、`changed`）。`POST /api/users` と `PUT /api/users/<name>` は、そのユーザーを返します
  - `GET /api/account/tokens`、`GET /api/tokens`: `{"tokens": [..]}`（新しい順。秘密は含みません）
  - `POST /api/managed/check`: 200 `{"version"}`。`POST /api/managed/apply`: 202 `{"version", "placed", "job"}`。`POST /api/managed/activate`、`POST /api/managed/rollback`: 202 `{"version", "job"}`。`DELETE /api/managed/versions/<version>`: 200 `{"removed", "cleaned"}`（上の「managed 設定の操作」）

## 応答の形式

### 応答

- 応答はどれも JSON で、次のヘッダーを持ちます（管理画面のファイルは別です。上の「管理画面」）: `Content-Type: application/json`、`Cache-Control: no-store`、`X-Content-Type-Options: nosniff`、`Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`、`Referrer-Policy: no-referrer`、`X-Request-ID`（リクエスト ID）。
- リクエスト ID は、`admin.trusted_proxies` に入る相手からのリクエストが持つ `X-Request-ID` が、プロキシの付与する形式（16 桁の小文字の 16 進数、`-`、1〜16 桁の数字）のときは、その値です。そうでなければ、管理プロセスが同じ形式の ID を作成します。プロキシを通したリクエストは、プロキシのログの `id` と監査ログの `id` が同じになります。
- 失敗の応答は `{"error": "<sentence>"}` です。文は、エラーの種類ごとに決まった英語の 1 文で、リクエストの値は含みません（入力のファイルの名前だけは、インポートの 400 の `subject` に別の項目で付きます）。インポートの 422 は `trial` も、世代の選択とロールバックの失敗は上の表の項目も持ちます。管理画面は、この文を言語ごとの文に置き換えます。
- `POST /api/managed/check` と `POST /api/managed/apply` の 400 は、`{"error", "at"}` です。`at` は、ボディの中で、拒否した値の場所です。場所が無いときは `null` になります。
  - 場所は、リクエストボディ内の設定キーのパスで書きます。`files` はファイルが多すぎるとき、`files[k]` は大きすぎる・2 回ある・バージョンが指定していないファイルです。バージョンの中の場所は、`sites[1].hosts[0]`、`upstreams.app.servers[2].address`、`sites[0].certificate.key`、`host_policies[1].rate_limit.keys` の形になります。
  - 配列の番号は 0 から数えます。
  - JSON の形式が違うボディと、64 桁の小文字の 16 進数でない `expect` は、場所がありません（`null`）。下の「管理 API の検証の順序」で拒否した 400 には、`at` のキーがありません。
  - 文は、場所を含まない決まった文です。設定ファイルの拒否（409）も、文だけで場所を持ちません。
- 反映の処理の `detail`（プロキシが拒否した文）は、場所を `at` で持たず、文の中に書きます。そのとき、リスナーとアップストリームのサーバーは 1 から数え（`listener 1 cannot be bound`、`(upstream app, server 1)` など）、サイトは名前で書きます（`site app`）。検証の `at` とは数え方が違います。

### ステータスコード

| ステータスコード | 場合 | 主な `error` |
|---|---|---|
| 400 | ボディが JSON のオブジェクトでない、その API が認識しないキーがある、クッキーと API トークンの両方がある、入力のエラー | `bad request`、API ごとの文。`/api/managed/check` と `/api/managed/apply` では `at` も付きます |
| 401 | セッションも API トークンも無い、終了した、ユーザーが変更された、無効の API トークン。ログインのエラー | `unauthorized`、`invalid credentials` |
| 403 | `Origin`・CSRF・ロール・状態・API トークンが使えない API による拒否。パスワードや認証コードのエラー。ほかの拒否 | `forbidden`、`second factor required`、`password change required`、`second factor setup required`、`the password is wrong`、`the current password is wrong`、`the code is wrong`、`mfa is required` |
| 404 | 表に無いパス、存在しない世代・managed 設定のバージョン・ユーザー・API トークン、`records` が無い設定 | `not found`、`no such generation`、`records are not configured` |
| 405 | パスにそのメソッドが無いとき。`Allow` を付けます（`GET` があれば `HEAD` も含めます） | `method not allowed` |
| 408 | ボディが 30 秒以内に届かない | `request timeout` |
| 409 | 別の変更と重なった、状態に合わない、数の上限、世代のエンジンが使えない、managed 設定が無い、設定ファイルが受け付けられない | `conflict`、`the name is taken`、`the store has too many users`、`the user has too many tokens`、`the last enabled owner stays`、`the user was changed since it was read`、世代の操作の文、`the configuration has no managed object`、`a change of the managed configuration is under way`、managed 設定の操作の文 |
| 413 | ボディが上限を超える | `payload too large` |
| 415 | ボディを読み込む API に、`application/json` でない `Content-Type` | `unsupported media type` |
| 422 | インポートの事前検証の失敗 | `the trial failed` |
| 429 | クライアントの回数の超過 | `too many tries` |
| 500 | 管理プロセスの中の不整合、ルールストアか managed ストアを読めない | `internal error`、ルールストアと managed ストアの文 |
| 502 | プロキシが切り替えなかった | `the proxy did not switch` |
| 503 | 保存先や監査ログの行を読み書きできない、時間切れ、プロキシに接続できない、managed 設定の検証が重なった | `unavailable`、`the proxy cannot be reached`、`the proxy is busy`、`the proxy did not say how the switch ended`、`a check of a managed version is under way` |

managed 設定の変更（「保存して反映」「名前で反映」「ロールバック」）は、受け付けると 202 で応答します。終わり方は、反映の処理（上の「managed 設定の操作」）で読み取ります。

### 管理 API の検証の順序

最初に通らなかった検証で応答します。

1. パス（表に無ければ 404）とメソッド（無ければ 405）
2. 最小のロールを持つ API は、認証情報（セッションのクッキーか `Authorization: Bearer`）。両方あれば 400、どちらも無い、または合わなければ 401、API トークンの回数を使い切ったクライアントは 429
3. 変更では `Origin`（403）と、セッションなら `X-CSRF-Token`（403）
4. API トークンが使えない API に API トークン（403）
5. セッションの状態（403。決まった文）
6. ロール（403）

3 から 6 で拒否したリクエストは、ユーザーが分かっているので、監査ログに書きます。その後、その API がボディを読み込むなら、`Content-Type`（415）と JSON の形式（400）を検証します。
