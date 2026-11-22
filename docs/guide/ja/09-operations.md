# 第9章　運用

本章では、稼働中のプロキシを運用するときの操作を説明します。監視（`/readyz`、`/metrics`、systemd への通知）、シグナルによる設定のリロード、停止、0.1.0 からの更新が分かります。操作の結果は、ログの行とメトリクスで確認します。

## 9.1　監視

### 監視用のリスナー

設定に `status` を書くと、ループバックアドレスのリスナーが、ヘルスチェックとメトリクスに応答します。省けば、監視用のリスナーはありません。次は書き方の例です。

```json
"status": {"listen": "127.0.0.1:9101"}
```

`listen` には、ループバックの IP（`127.0.0.0/8` か `::1`）とポートを書きます。応答に認証は無いので、同じホストの監視プログラムから使います。`proxy.listeners` と `admin.listen` のアドレスとは重ねられません。アップストリームのサーバーにも、このアドレスは書けません。例のポートは、ほかのリスナーと重ならない値に替えてください。

| リクエスト | 応答 |
|---|---|
| `GET /healthz` | 200 `ok`。プロキシが応答できることだけを示します |
| `GET /readyz` | 準備ができていれば 200 `ready`。でなければ 503 と理由の語（`starting`、`inspector down`、`stopping`） |
| `GET /metrics` | 200 と、Prometheus のテキスト形式のメトリクス |

`/readyz` が 200 を返すのは、起動しているすべてのエンジンの検査プロセスが稼働していて、リスナーをすべてバインドし、停止が始まっていないときです。世代の切り替えの間は、古い世代が応答するので、準備ができたままです。ロードバランサーの準備状態の確認には、`/readyz` を使います。

- 監視のリクエストは、検査も転送もせず、ログにも記録しません。全体の `access` と `rate_limit`、ホストごとの設定も適用されません。
- 監視用のリスナーは、検査プロセスより前にバインドし、停止の途中で閉じます。それまで `/healthz` は 200 を返します。
- 同時に応答する接続の数など、細かい決まりは、付録A 運用リファレンスの「監視」を参照してください。

### メトリクス

`/metrics` の値はプロキシのメモリの中にあり、再起動すると 0 から数えます。ラベルの値は、決まった語か、設定の名前だけです。リクエストから来る値は、ラベルにしません。メトリクスは、見るものごとに、次のようにまとまっています。

- リクエストの結果: `tukuyomi_requests_total`（`class` ラベルは、リクエストのログの `class` と同じ 7 つ）、`tukuyomi_waf_rule_hits_total`（`decision` が `block` か `detect`）、`tukuyomi_uninspectable_total`（検査できなかったリクエスト）、`tukuyomi_policy_refusals_total`（アクセス制御とレート制限で拒否したリクエスト）
- 検査プロセスとルールの世代: `tukuyomi_inspector_up`（起動しているエンジンの検査カーネルが、すべて準備できていれば 1、でなければ 0）、`tukuyomi_inspector_restarts_total`、エンジンごとの `tukuyomi_inspector_engine_up` と `tukuyomi_inspector_engine_restarts_total`、リクエストを受けている世代を示す `tukuyomi_rules_generation_info`
- 操作の結果（`result` ラベル）: `tukuyomi_rules_switches_total`（SIGUSR1 と制御ソケットによる世代の切り替え）、`tukuyomi_certificate_reloads_total`（SIGUSR2）、`tukuyomi_config_reloads_total`（SIGHUP と制御ソケットの `reload`）
- ログ: `tukuyomi_records_dropped_total`、`tukuyomi_record_write_errors_total`、`tukuyomi_record_file_errors_total`、`tukuyomi_records_refused_total`、`tukuyomi_records_healthy`、`tukuyomi_records_admitting`、`tukuyomi_records_unshipped_bytes`（第7章）
- 接続とアップストリーム: `tukuyomi_connections_open`、`tukuyomi_tls_handshake_failures_total`、`tukuyomi_upstream_failures_total`（設定のリロードで 0 から数え直します）など

全部の名前、型、ラベルは、付録A 運用リファレンスの「メトリクス（`/metrics`）」を参照してください。

### systemd への通知

環境に `NOTIFY_SOCKET` があれば、プロキシは、リスナーをすべてバインドした後に `READY=1` を、停止が始まったときに `STOPPING=1` を、そのソケットへ 1 回ずつ送ります。

- ユニットを `Type=notify` にすると、`systemctl start` は、検査カーネルの準備とリスナーのバインドまで待ちます（ユニットの例は第3章の 3.5）。
- 通知を送れなかったときは、`notify:` の文を 1 行出すだけで、動作は変わりません。`NOTIFY_SOCKET` が、絶対パスでも `@` で始まる名前でもないときは、`start:` の文を 1 行出し、通知を送らずに動きます。
- 検査プロセスの環境は空なので、検査プロセスは通知を送りません。

## 9.2　シグナルと設定のリロード

### シグナル

シグナルは、プロキシのメインプロセスだけに送ります。送り方（`systemctl reload` と `systemctl kill --kill-whom=main`）は、第3章の 3.7 を参照してください。

| シグナル | すること |
|---|---|
| SIGTERM、SIGINT | 停止します（9.3） |
| SIGHUP | 設定ファイルをリロードし、停止せずに新しい設定に切り替えます |
| SIGUSR1 | ルールストアでエンジンごとに選択中の世代へ、エンジンを 1 つずつ切り替えます（第4章） |
| SIGUSR2 | すべての TLS のリスナーの証明書と鍵のファイルを再読み込みします（第8章） |

### 設定のリロードの流れ

プロキシは、SIGHUP を受けると、起動のときと同じパスの設定ファイルを別のスレッドで読み込みます。`managed` があれば、そのときの選択中のバージョン（`current`）も一緒に読み込みます。ルールストアより前の起動の段階（設定ファイルとバージョン、アップストリームのサーバーの名前解決と `ca_file`、リスナーの証明書と鍵、ACME のチャレンジ、`geo` の国のデータベース）を、起動のときと同じ検証で実行します。

- すべてが通り、動作中に変更できない設定キー（下）がどれも起動のときと同じなら、新しい設定に一度に切り替えます。
- どこかで拒否したら、何も変更せず、理由の行を出します。
- 結果は、ログの行と `/metrics` の `tukuyomi_config_reloads_total`（`replaced`、`refused`）で確認します。`systemctl reload` が成功を返しても、設定が切り替わったとは限りません（第3章の 3.7）。

| ログの行 | 意味 |
|---|---|
| `reload: configuration replaced <sha256>` | 切り替えました。`managed` のある設定では `reload: configuration replaced <sha256> managed <version>`。どのファイルとバージョンが効いているかは、この値で確認します |
| `reload: configuration refused: <reason>` | 拒否しました。ほかに `reload: upstream refused: <reason>`、`reload: tls refused: <reason>` などがあります。拒否の行には、ファイルの値を出しません |

管理プロセスが managed 設定のバージョンを反映するときも、制御ソケットの `reload` の依頼で、同じ手順で設定をリロードします（第5章）。リロードは一度に 1 つだけです。リロードの途中に受けた SIGHUP は、`reload: a configuration reload is in progress, ignored` の行を出すだけです。

### 変更できるもの、できないもの

変更できるものは、次のとおりです。

- `proxy` の設定キー（下の変更できない設定キーを除きます）と、リスナー（追加、削除、並べ替え、TLS と証明書、`http2`、`redirect`）
- `forward`（アップストリームとルート。`managed` のある設定では、バージョンのサイト、アップストリーム、ルート、デフォルトのアップストリーム）。アップストリームの `engine` は、変更後のエンジンが稼働していれば、変更できます。
- アップストリームの `ca_file`、リスナーの証明書と鍵、ACME のチャレンジ
- 全体の `access`・`rate_limit`、`host_policies`、`geo`
- 管理画面のルートの証明書と `access`
- `records.keep`

動作中に変更できない設定キーは、次のとおりです。どれかが起動のときと違う設定は、全体を拒否します（`reload: configuration refused: <key> cannot change while running`）。変更するときは、`systemctl restart` で再起動します。

- `proxy.max_conns`、`max_buffered_bytes`、`drive_slice_ms`、`ready_wait_ms`、`stop_inspect_ms`、`stop_wait_ms`
- `records`（`keep` を除くすべてと、有無）、`status`、`admin`、`admin.route.host`
- `rules.store`、`managed`（有無と `dir`）、`kernel`（`default_engine` を含むすべて）

### 接続とリスナー

切り替えた後に受け付けた接続は、新しい設定を使います。開いている接続は、受け付けたときの設定を使い続け、リクエストを拒否せずに閉じます。HTTP/1.1 では、応答した後で次のリクエストを待っている接続をすぐ閉じ、応答の途中の接続は、その応答に `Connection: close` を付けて閉じます。HTTP/2 では、`GOAWAY` を送り、開いているストリームが終了してから閉じます。WebSocket のトンネルと、ルートの `stream` の応答は、前の設定のまま、それぞれのタイムアウトまで続きます。

リスナーを変更するときは、新しい設定のアドレスのうち、今は待ち受けていないものを、切り替える前にすべてバインドします。1 つでもバインドできなければ、全体を拒否します（`reload: configuration refused: listener <number> cannot be bound`）。今も待ち受けているアドレスと重なるアドレス（たとえば `0.0.0.0:8080` で待ち受けているときの `127.0.0.1:8080`）は、バインドできず、全体を拒否します。そのときは、削除するリロードと追加するリロードに分けるか、再起動します。

### 持ち越すもの、触れないもの

- レート制限のテーブルは、テーブルごとに、設定が同じなら持ち越します。持ち越せないテーブルは、新しいテーブルで 0 から数え、`reload: rate limit table started anew` の行を出します。条件は、第6章と、付録A 運用リファレンスの「ホストごとの設定（`host_policies`）」を参照してください。
- アップストリームのダウン判定と失敗の数、アップストリームへの待機中の接続、リスナーの TLS のセッションは作り直します。同じ内容のファイルと同じバージョンでも作り直し、待っている接続を閉じます。
- ルールの世代には触れません。稼働中の世代はそのままで、ルールストアも読み込みません。世代を切り替えるのは SIGUSR1 です。リロードは検査プロセスを起動しないので、新しい設定のアップストリームのエンジンが稼働していなければ、リロードを拒否します（`reload: configuration refused: the engine of an upstream is not ready (upstream <name>)`）。そのエンジンは、先に SIGUSR1 で起動します（第4章）。

### リロードしないもの

起動のときに読み込み、プロキシを再起動するまでそのままのものがあります。上の動作中に変更できない設定キーが、それです。

管理プロセスとログ送信プロセスは、設定をリロードしません。どちらも、SIGHUP が停止のシグナルです。ユニットに `ExecReload` を置かず、設定を変更したら、それらを再起動します。

## 9.3　停止

プロキシは、SIGTERM か SIGINT で停止します。最初の停止の理由（シグナル、起動かドライバーの失敗）の時刻を t0 とすると、停止は次の順に進みます。

1. リスナーを閉じ、新しいリクエストを拒否します。制御ソケットも閉じて、そのファイルを削除します。次のリクエストを待っている接続は閉じます。`/readyz` は 503 `stopping` になり、`NOTIFY_SOCKET` があれば `STOPPING=1` を送ります。
2. 検査は `t0 + stop_inspect` までに終えます。
3. 接続は `t0 + stop_wait` まで待ち、残りは打ち切ります。WebSocket のトンネルは、停止では終了せず、このときに打ち切られます。この後に監視用のリスナーを閉じます。
4. 起動しているエンジンの検査カーネルが、すべて終了するのを `t0 + stop_wait + kill_grace` まで待ちます。
5. ログを最長 200 ms 書き出して終了します。

最後に `stop: kernel ..., bye ..., exit_confirmed ..., dir_removed ..., held_left ..., waiting_left ..., results ..., retired_clean ...` の行が出ます。その前に、起動しているエンジンごとに `driver: stop, engine <engine>, records <count>, held <count>, waiting <count>` の行が出ます。終了コードが 0 になるのは、停止の理由が失敗でなく、停止した検査カーネルのすべてで、検査プロセスの終了と作業ディレクトリの削除が確認できたときだけです。

ユニットの `TimeoutStopSec` は、`stop_wait_ms` と `kill_grace_ms` と、ログの書き出しの 200 ms を足した時間より長くします。短いと、systemd が先に SIGKILL を送ります（第3章の 3.5）。

管理プロセスとログ送信プロセスの停止は、別です。

- 管理プロセスは、停止のシグナル（SIGTERM、SIGINT、SIGHUP）を受けると、リスナーを閉じ、処理中のリクエストを最大 10 秒待ちます。
- ログ送信プロセスは、動作中の 1 回分を終えてから停止し、`STOPPING=1` を送ります。DB を呼び出している間は、停止のシグナルの処理が待たされるので、長いと 1〜2 分かかります。SIGKILL で停止しても、次の起動は DB に残った位置から続けます（第7章）。

停止の細かい順序と各項目の意味は、付録A 運用リファレンスの「停止」を参照してください。

## 9.4　バージョンの更新

0.1.0 から更新する手順です。更新後のバージョンは、アップストリームごとに検査エンジンを選べます（第4章）。新しいリリースの実行ファイルの入手と確認は、第3章の 3.3 を参照してください。

### 0.1.0 からの更新

実行ファイルを入れ替えるだけで、0.1.0 の設定ファイル、ルールストア、managed ストアは、そのまま読めます。新しい設定キー（`kernel.default_engine`、アップストリームの `engine`）を書かなければ、0.1.0 と同じように、1 つのエンジンだけで稼働します。

- 0.1.0 で Coraza の世代を選択していたときは、`kernel.default_engine` を書く必要はありません。0.1.0 が書いた `current` は、Coraza の選択中の世代として読まれます。`config check` は `accepted` で、起動すると `start: rules engine coraza` の行が 1 つだけ出ます。`current` は書き換わらず、`current.*` も増えません。
- 0.1.0 で ModSecurity の世代を選択していたときは、`kernel.default_engine` に `modsecurity` を書きます。書かないと、`config check` と起動は、`rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` の行を出して受け付けません（exit 1）。ルールストアは変わりません。

管理プロセス、プロキシ、ログ送信プロセスは、同じビルドにそろえます。

- 以前のバージョンのプロキシには、更新後の管理プロセスは世代の選択とロールバックを行いません（409）。
- ログ送信プロセスは、設定ファイルの未知の設定キーを受け付けません。`kernel.default_engine` やアップストリームの `engine` を書く前に、ログ送信プロセスを同じビルドに入れ替えます。0.1.0 のプロキシも、`kernel.default_engine` のある設定ファイルを、`configuration has an unknown key` で受け付けません（exit 2）。
- 実行ファイルを同じリリースのものにすべて入れ替えてから、管理プロセス、プロキシ、ログ送信プロセスの順に再起動します。管理プロセスを先に再起動すると、入れ替えの間は、更新後の管理プロセスが以前のプロキシへの世代の選択とロールバックを 409 で拒否するだけで、ルールストアと切り替えの履歴は変わりません。

### 0.1.0 への切り戻し

0.1.0 に戻すときは、更新後の実行ファイルで何をしたか（世代の選択、新しい設定キー）によって、手順が変わります。手順と、それぞれの場合の `config check` と起動の結果は、付録A 運用リファレンスの「0.1.0 への切り戻し」を参照してください。

## 9.5　運用上の注意

- 設定を変更したら、`systemctl reload` が成功を返しても、ログの `reload: configuration replaced` か `reload: configuration refused` の行で結果を確認します。
- 動作中に変更できない設定キーは、`systemctl restart` で再起動します。管理プロセスとログ送信プロセスが読む設定キーを変えたときも、それらを再起動します。
- 設定のリロードは、ルールの世代を切り替えません。世代は SIGUSR1 か管理画面で切り替えます。証明書と鍵だけを再読み込みするときは、SIGHUP ではなく SIGUSR2 を送ります。SIGHUP は設定ファイルの全体を読み込むので、書きかけの設定を読み込んでしまうことがあります。
- 管理プロセス、プロキシ、ログ送信プロセスは、同じビルドにそろえます。
- 0.1.0 に戻す前に、更新後の実行ファイルで何を選択し、どの設定キーを書いたかを確認します。結果が変わります。
