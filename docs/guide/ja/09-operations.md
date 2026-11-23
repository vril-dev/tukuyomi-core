# 第9章　運用

本章では、動作中のプロキシを運用するときの操作を説明します。
扱うのは、監視（`/readyz`、`/metrics`、systemd への通知）、シグナルによる設定のリロード、停止、バージョンの更新と前のバージョンへの切り戻しです。
操作の結果はログの行とメトリクスで確認します。

## 9.1　監視

### 監視用のリスナー

監視用のリスナーは、ヘルスチェックとメトリクスのリクエストに応答するリスナーです。
設定に `status` を書くと、ループバックアドレスで待ち受けます。`status` を省略すると、監視用のリスナーはありません。
書き方の例は次のとおりです。

```json
"status": {"listen": "127.0.0.1:9101"}
```

`listen` には、ループバックの IP（`127.0.0.0/8` か `::1`）とポートを書きます。
応答に認証はありません。同じホストの監視プログラムから使ってください。
このアドレスは `proxy.listeners` や `admin.listen` のアドレスと重ねることも、アップストリームのサーバーに書くこともできません。
例のポートはほかのリスナーと重ならない値に替えてください。

| リクエスト | 応答 |
|---|---|
| `GET /healthz` | 200 `ok` で、プロキシが応答できることだけを示します |
| `GET /readyz` | 準備ができていれば 200 `ready`、できていなければ 503 と理由を示す語（`starting`、`inspector down`、`stopping`） |
| `GET /metrics` | 200 と、Prometheus のテキスト形式のメトリクス |

`/readyz` が 200 を返すのは、次のすべてを満たすときです。

- 起動しているすべてのエンジンの検査プロセスが稼働している
- リスナーをすべてバインドしている
- 停止が始まっていない

世代の切り替えの間は、古い世代が応答するため、準備ができた状態のままです。
ロードバランサーで準備状態を確認するときは、`/readyz` を使ってください。

- 監視のリクエストは検査も転送もせず、ログにも記録しません。
  全体の `access` と `rate_limit` や、ホストごとの設定も適用されません。
- 監視用のリスナーは検査プロセスより前にバインドし、停止の途中で閉じます。閉じるまで `/healthz` は 200 を返します。
- 同時に応答する接続の数などの細かい決まりは、付録A 運用リファレンスの「監視」を参照してください。

### メトリクス

`/metrics` の値はプロキシのメモリの中にあるため、再起動すると 0 から数え直します。
ラベルの値は決まった語か設定の名前だけで、リクエストから来る値はラベルにしません。
メトリクスは見る対象ごとに次のようにまとまっています。

- **リクエストの結果**: `tukuyomi_requests_total`（`class` ラベルは、リクエストのログの `class` と同じ 7 つ）、`tukuyomi_waf_rule_hits_total`（`decision` が `block` か `detect`）、`tukuyomi_uninspectable_total`（検査できなかったリクエスト）、`tukuyomi_policy_refusals_total`（アクセス制御とレート制限で拒否したリクエスト）
- **検査プロセスとルールの世代**: `tukuyomi_inspector_up`（起動しているエンジンの検査カーネルがすべて準備できていれば 1、そうでなければ 0）、`tukuyomi_inspector_restarts_total`、エンジンごとの `tukuyomi_inspector_engine_up` と `tukuyomi_inspector_engine_restarts_total`、リクエストを受けている世代を示す `tukuyomi_rules_generation_info`
- **操作の結果（`result` ラベル）**: `tukuyomi_rules_switches_total`（SIGUSR1 と制御ソケットによる世代の切り替え）、`tukuyomi_certificate_reloads_total`（SIGUSR2）、`tukuyomi_config_reloads_total`（SIGHUP と制御ソケットの `reload`）
- **ログ**: `tukuyomi_records_dropped_total`、`tukuyomi_record_write_errors_total`、`tukuyomi_record_file_errors_total`、`tukuyomi_records_refused_total`、`tukuyomi_records_healthy`、`tukuyomi_records_admitting`、`tukuyomi_records_unshipped_bytes`（第7章）
- **接続とアップストリーム**: `tukuyomi_connections_open`、`tukuyomi_tls_handshake_failures_total`、`tukuyomi_upstream_failures_total`（設定のリロードで 0 から数え直します）など

すべてのメトリクスの名前、型、ラベルは、付録A 運用リファレンスの「メトリクス（`/metrics`）」を参照してください。

### systemd への通知

環境変数 `NOTIFY_SOCKET` があれば、プロキシはそのソケットへ通知を送ります。
リスナーをすべてバインドした後に `READY=1` を 1 回送り、停止が始まったときに `STOPPING=1` を 1 回送ります。

- ユニットを `Type=notify` にすると、`systemctl start` は検査カーネルの準備とリスナーのバインドが終わるまで待ちます（ユニットの例は第3章の 3.5）。
- 通知を送れなかったときは、`notify:` の文を 1 行出すだけで、動作は変わりません。
  `NOTIFY_SOCKET` が絶対パスでも `@` で始まる名前でもないときは、`start:` の文を 1 行出し、通知を送らずに動きます。
- 検査プロセスの環境変数は空なので、検査プロセスが通知を送ることはありません。

## 9.2　シグナルと設定のリロード

### シグナル

シグナルはプロキシのメインプロセスにだけ送ってください。
送り方（`systemctl reload` と `systemctl kill --kill-whom=main`）は、第3章の 3.7 を参照してください。

| シグナル | すること |
|---|---|
| SIGTERM、SIGINT | 停止します（9.3） |
| SIGHUP | 設定ファイルをリロードし、停止せずに新しい設定に切り替えます |
| SIGUSR1 | エンジンを 1 つずつ、ルールストアでそのエンジンの選択中の世代へ切り替えます（第4章） |
| SIGUSR2 | TLS のリスナーすべてについて、証明書と鍵のファイルを再読み込みします（第8章） |

### 設定のリロードの流れ

SIGHUP を受けると、プロキシは起動のときと同じパスの設定ファイルを別のスレッドで読み込みます。
`managed` があれば、その時点の選択中のバージョン（`current`）も一緒に読み込みます。

そのうえで、起動のときと同じ検証で、ルールストアより前の起動の段階を実行します。
対象は、設定ファイルとバージョン、アップストリームのサーバーの名前解決と `ca_file`、リスナーの証明書と鍵、ACME のチャレンジ、`geo` の国のデータベースです。

- すべての検証に通り、動作中に変更できない設定キー（下で説明します）がどれも起動のときと同じなら、新しい設定に一度に切り替えます。
- どこかで拒否した場合は、何も変更せずに、理由を書いた行を出します。
- 結果はログの行と `/metrics` の `tukuyomi_config_reloads_total`（`replaced`、`refused`）で確認します。
  `systemctl reload` が成功を返しても、設定が切り替わったとは限りません（第3章の 3.7）。

| ログの行 | 意味 |
|---|---|
| `reload: configuration replaced <sha256>` | 切り替えました。`managed` のある設定では、`reload: configuration replaced <sha256> managed <version>` になります。どのファイルとバージョンが効いているかは、この値で確認します |
| `reload: configuration refused: <reason>` | 拒否しました。拒否の行には、ほかに `reload: upstream refused: <reason>`、`reload: tls refused: <reason>` などがあります。拒否の行に、ファイルの値は出しません |

管理プロセスが managed 設定のバージョンを反映するときは、制御ソケットへ `reload` を依頼します。
プロキシはこの依頼を受けたときも、同じ手順で設定をリロードします（第5章）。
リロードは一度に 1 つしか行わないため、途中で SIGHUP を受けても `reload: a configuration reload is in progress, ignored` の行を出すだけです。

### 変更できるもの、できないもの

設定のリロードで変更できるものは次のとおりです。

- `proxy` の設定キーと、リスナー（追加、削除、並べ替え、TLS と証明書、`http2`、`redirect`）。
  `proxy` の設定キーのうち、下に挙げる変更できない設定キーは除きます。
- `forward`（アップストリームとルート）。
  `managed` のある設定では、バージョンのサイト、アップストリーム、ルート、デフォルトのアップストリームがこれに当たります。
  アップストリームの `engine` は、変更後のエンジンが稼働していれば変更できます。
- アップストリームの `ca_file`、リスナーの証明書と鍵、ACME のチャレンジ
- 全体の `access`・`rate_limit`、`host_policies`、`geo`
- 管理画面のルートの証明書と `access`
- `records.keep`

動作中に変更できない設定キーは次のとおりです。

- `proxy.max_conns`、`max_buffered_bytes`、`drive_slice_ms`、`ready_wait_ms`、`stop_inspect_ms`、`stop_wait_ms`
- `records`（`keep` を除くすべてと、有無）、`status`、`admin`、`admin.route.host`
- `rules.store`、`managed`（有無と `dir`）、`kernel`（`default_engine` を含むすべて）

どれかが起動のときと違うと、設定の全体を拒否します（`reload: configuration refused: <key> cannot change while running`）。
これらを変更するときは、`systemctl restart` で再起動してください。

### 接続とリスナー

切り替えた後に受け付けた接続は、新しい設定を使います。
すでに開いている接続は受け付けたときの設定を使い続け、リクエストを拒否せずに閉じます。

- HTTP/1.1 では、応答した後で次のリクエストを待っている接続は、すぐに閉じます。
  応答の途中の接続は、その応答に `Connection: close` を付けて閉じます。
- HTTP/2 では、`GOAWAY` を送り、開いているストリームが終了してから閉じます。
- WebSocket のトンネルとルートの `stream` の応答は、前の設定のまま、それぞれのタイムアウトまで続きます。

リスナーを変更するときは、切り替える前に、新しい設定のアドレスのうち今は待ち受けていないものをすべてバインドします。
1 つでもバインドできなければ、全体を拒否します（`reload: configuration refused: listener <number> cannot be bound`）。

今も待ち受けているアドレスと重なるアドレスはバインドできないため、全体を拒否します。
たとえば、`0.0.0.0:8080` で待ち受けている間は、`127.0.0.1:8080` をバインドできません。
このようなときは、リスナーを削除するリロードと追加するリロードに分けるか、再起動します。

### 持ち越すもの、触れないもの

- レート制限のテーブルは、テーブルごとに、設定が同じなら持ち越します。
  持ち越せないテーブルは新しいテーブルにして 0 から数え、`reload: rate limit table started anew` の行を出します。
  持ち越す条件は、第6章と、付録A 運用リファレンスの「ホストごとの設定（`host_policies`）」を参照してください。
- アップストリームのダウン判定と失敗の数、アップストリームへの待機中の接続、リスナーの TLS のセッションは作り直します。
  ファイルの内容とバージョンが前と同じでも作り直し、待機中の接続を閉じます。
- ルールの世代には触れません。
  稼働中の世代はそのままで、ルールストアも読み込みません。世代を切り替えるのは SIGUSR1 です。
  リロードは検査プロセスを起動しないため、新しい設定のアップストリームが使うエンジンが稼働していなければ、リロードを拒否します（`reload: configuration refused: the engine of an upstream is not ready (upstream <name>)`）。
  そのエンジンは先に SIGUSR1 で起動しておいてください（第4章）。

### リロードしないもの

上で挙げた、動作中に変更できない設定キーは、起動のときに読み込み、プロキシを再起動するまで変わりません。

管理プロセスとログ送信プロセスは設定をリロードしません。
どちらにとっても、SIGHUP は停止のシグナルです。
ユニットに `ExecReload` は置かず、設定を変更したときはこれらのプロセスを再起動してください。

## 9.3　停止

プロキシは SIGTERM か SIGINT を受けると停止します。
最初の停止の理由（シグナル、起動かドライバーの失敗）が起きた時刻を t0 とすると、停止は次の順に進みます。

1. リスナーを閉じ、新しいリクエストを拒否します。
   制御ソケットも閉じて、そのファイルを削除します。
   次のリクエストを待っている接続は閉じます。
   `/readyz` は 503 `stopping` を返すようになり、`NOTIFY_SOCKET` があれば `STOPPING=1` を送ります。
2. 検査は `t0 + stop_inspect` までに終えます。
3. 接続は `t0 + stop_wait` まで待ち、残った接続は打ち切ります。
   WebSocket のトンネルは停止が始まっても終了せず、このときに打ち切られます。
   その後、監視用のリスナーを閉じます。
4. 起動しているエンジンの検査カーネルがすべて終了するのを `t0 + stop_wait + kill_grace` まで待ちます。
5. ログを最長 200 ms かけて書き出し、終了します。

ログには、起動しているエンジンごとに `driver: stop, engine <engine>, records <count>, held <count>, waiting <count>` の行が出ます。
最後に `stop: kernel ..., bye ..., exit_confirmed ..., dir_removed ..., held_left ..., waiting_left ..., results ..., retired_clean ...` の行が出ます。

終了コードが 0 になるのは、次の両方を満たすときだけです。

- 停止の理由が失敗ではない
- 停止したすべての検査カーネルで、検査プロセスの終了と作業ディレクトリの削除を確認できた

ユニットの `TimeoutStopSec` は、`stop_wait_ms`、`kill_grace_ms`、ログの書き出しの 200 ms の合計より長くしてください。
これより短いと、プロキシが終了する前に systemd が SIGKILL を送ってしまいます（第3章の 3.5）。

管理プロセスとログ送信プロセスの停止の仕方は、プロキシとは別です。

- 管理プロセスは停止のシグナル（SIGTERM、SIGINT、SIGHUP）を受けると、リスナーを閉じ、処理中のリクエストを最大 10 秒待ちます。
- ログ送信プロセスは実行中の 1 回分の処理を終えてから停止し、`STOPPING=1` を送ります。
  DB を呼び出している間は停止のシグナルの処理が待たされるため、長いと 1〜2 分かかります。
  SIGKILL で停止した場合でも、次の起動では、DB に残った位置から続けます（第7章）。

停止の細かい順序と各項目の意味は、付録A 運用リファレンスの「停止」を参照してください。

## 9.4　バージョンの更新

1.0 までは、直前のリリースからの更新だけをサポートします。
2 つ以上先のリリースへ上げるときは、間のリリースを 1 つずつ順に更新してください。
前のバージョンへ切り戻すときは、更新前に取ったバックアップを戻します。
新しいリリースの実行ファイルの入手と確認は、第3章の 3.3 を参照してください。

### 更新前のバックアップ

更新の前に、設定ファイル、ルールストア（`rules.store.dir`）、managed ストア（`managed.dir`）、管理データの保存先（`admin.store.dir`）のうち、使っているもののバックアップを取ります。

バックアップを取る間は、管理プロセス、プロキシ、ログ送信プロセスと、証明書の更新のタイマーを止めておきます。
所有者と権限は元のまま保ちます。
バックアップには、パスワードのハッシュ、API トークン、秘密鍵なども入ります。
root だけが読めるディレクトリに置いてください。
第3章のディレクトリとユニットの例では、次のようになります。

```bash
sudo systemctl stop tukuyomi-core-admin.service tukuyomi-core.service tukuyomi-core-records-ship.service tukuyomi-core-acme.timer
sudo install -d -m 0700 /var/backups/tukuyomi-core
sudo tar -C / -cpf /var/backups/tukuyomi-core/before-update.tar etc/tukuyomi-core/config.json var/lib/tukuyomi-core/store var/lib/tukuyomi-core/managed var/lib/tukuyomi-core/admin
```

ログのディレクトリ（`records.dir`）、証明書と鍵、作業ディレクトリ（`kernel.tmp_root`）は、バックアップに含めません。

### 0.1.0 からの更新

0.2.0 では、アップストリームごとに検査エンジンを選べます（第4章）。
更新するときは、上のバックアップを取ってから、実行ファイルを入れ替えます。
0.1.0 の設定ファイル、ルールストア、managed ストアは、実行ファイルを入れ替えるだけで、そのまま読めます。
新しい設定キー（`kernel.default_engine`、アップストリームの `engine`）を書かなければ、0.1.0 と同じように 1 つのエンジンだけで稼働します。

- **0.1.0 で Coraza の世代を選択していたとき**: `kernel.default_engine` を書く必要はありません。
  0.1.0 が書いた `current` は Coraza の選択中の世代として読まれます。
  `config check` は `accepted` を出し、起動すると `start: rules engine coraza` の行が 1 つだけ出ます。
  `current` は書き換わらず、`current.*` も増えません。
- **0.1.0 で ModSecurity の世代を選択していたとき**: `kernel.default_engine` に `modsecurity` を書きます。
  書かないと、`config check` も起動も、`rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` の行を出して拒否されます（exit 1）。ルールストアは変わりません。

管理プロセス、プロキシ、ログ送信プロセスは、同じビルドにそろえてください。
注意する点は次のとおりです。

- 更新後の管理プロセスは、以前のバージョンのプロキシに対しては、世代の選択とロールバックを行いません（409）。
- ログ送信プロセスは設定ファイルにある未知の設定キーを受け付けません。
  `kernel.default_engine` やアップストリームの `engine` を書く前に、ログ送信プロセスを同じビルドに入れ替えてください。
  0.1.0 のプロキシも、`kernel.default_engine` のある設定ファイルを `configuration has an unknown key` で拒否します（exit 2）。
- 実行ファイルをすべて同じリリースのものに入れ替えてから、管理プロセス、プロキシ、ログ送信プロセスの順に再起動します。
  管理プロセスを先に再起動すると、入れ替えの間、更新後の管理プロセスは以前のプロキシに対する世代の選択とロールバックを 409 で拒否します。
  拒否するだけなので、ルールストアと切り替えの履歴は変わりません。

### 前のバージョンへの切り戻し

前のバージョンに戻すときは、更新前に取ったバックアップを戻し、前のバージョンの実行ファイルで起動します。バージョンによって違う手順はありません。

1. 管理プロセス、プロキシ、ログ送信プロセスと、証明書の更新のタイマーを止めます。
2. 今の設定ファイルと、バックアップを取ったディレクトリは、削除せずに別の名前に変えて退避します。
3. バックアップを戻します。
4. 実行ファイルを前のバージョンに戻し、前のバージョンの `config check` が `accepted` を出すことを確認します。
5. 管理プロセス、プロキシ、ログ送信プロセスの順に起動し、証明書の更新のタイマーを起動します。

上の例で取ったバックアップの場合、2 と 3 は次のとおりです。

```bash
sudo mv /etc/tukuyomi-core/config.json /etc/tukuyomi-core/config.json.after-update
sudo mv /var/lib/tukuyomi-core/store /var/lib/tukuyomi-core/store.after-update
sudo mv /var/lib/tukuyomi-core/managed /var/lib/tukuyomi-core/managed.after-update
sudo mv /var/lib/tukuyomi-core/admin /var/lib/tukuyomi-core/admin.after-update
sudo tar -C / -xpf /var/backups/tukuyomi-core/before-update.tar
```

更新の後に変えた次のものは失われます。

- インポートや選択をした世代
- managed 設定のバージョンと反映
- 作ったユーザー、API トークン、セッション
- 管理データの保存先にある監査ログの行

ログのディレクトリは戻さないため、更新の後のログは残ります。
ほかの注意点は、付録A 運用リファレンスの「前のバージョンへの切り戻し」を参照してください。

## 9.5　運用上の注意

最後に、日々の運用で気を付ける点をまとめます。

- **設定の変更の結果**: `systemctl reload` が成功を返しても、ログの `reload: configuration replaced` か `reload: configuration refused` の行で結果を確認してください。
- **動作中に変更できない設定キー**: `systemctl restart` で再起動して変更します。
  管理プロセスとログ送信プロセスが読む設定キーを変えたときも、それらを再起動してください。
- **ルールの世代**: 設定のリロードでは切り替わりません。
  世代は SIGUSR1 か管理画面で切り替えます。
- **証明書と鍵だけの再読み込み**: SIGHUP ではなく SIGUSR2 を送ってください。
  SIGHUP は設定ファイルの全体を読み込むため、書きかけの設定を読み込んでしまうことがあります。
- **実行ファイルのビルド**: 管理プロセス、プロキシ、ログ送信プロセスは、同じビルドにそろえてください。
- **バックアップと切り戻し**: 更新の前にバックアップを取り、前のバージョンへはこのバックアップを戻して切り戻します。
