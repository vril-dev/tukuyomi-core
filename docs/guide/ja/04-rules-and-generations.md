# 第4章　ルールセットと世代

本章では、tukuyomi core がリクエストを検査するときのルールの単位である「世代」を説明します。世代を作る（インポート）、選ぶ（選択）、動作中のプロキシに使わせる（SIGUSR1）という 3 つの操作の分け方、検知のみのモードから始めて遮断に移る流れ、検査除外のルート、ModSecurity の世代、アップストリームごとの検査エンジンの選択が分かります。コマンドの引数と終了コードの全体は、付録A 運用リファレンスの「`rules`」を参照してください。

## 4.1　世代の考え方

世代は、`rules import` が作るルールセットの一式です。フィンガープリント（マニフェストの SHA-256）で呼びます。作った後は変えません。

世代は、ルールを検査するエンジンも持ちます。このビルドが持つエンジンは `coraza`（Coraza）と `modsecurity`（ModSecurity v3）です。`rules import --engine` で指定し、省けば、設定の `kernel.default_engine` のエンジン（書かなければ `coraza`）になります。同じファイルでも、エンジンが違えばマニフェストが変わり、別の世代（別のフィンガープリント）になります。`modsecurity` の世代は、設定の `kernel.engines` に検査プロセスがあるときだけ、インポート、選択、起動ができます。

世代を使い始めるまでには、3 つの操作があります。それぞれ別のコマンドかシグナルで、動作中のプロキシが変わるのは最後の 1 つだけです。

| 操作 | すること | 動作中のプロキシへの効果 |
|---|---|---|
| インポート（`rules import`） | 入力からルールセットを作ってルールストアに置き、事前検証に通れば世代にします。世代は選択しません | ありません |
| 選択（`rules activate`） | 世代を、そのエンジンの選択中の世代にします | ありません。後で起動するプロキシと、SIGUSR1 を受けたプロキシが使います |
| 切り替え（SIGUSR1） | エンジンごとに、選択中の世代へ切り替えます | 切り替えた後の新しいリクエストを、新しい世代で検査します |

`rules` のコマンドは短いコマンドで、動作中のプロキシとは別のプロセスです。動作中のプロキシは、コマンドが行った変更を検知しません。管理プロセスの API は、世代を選択し、続けて動作中のプロキシに切り替えを依頼します（第5章）。

フィンガープリントが検出するのは、事故による破損と取り違え、動作中のプロキシが保持しているフィンガープリントと中身が違う起動です。同じ OS ユーザーのプロセス（検査プロセスも同じ OS ユーザー）がルールストアを書き換えることは防ぎません。ルールストアの中身は、付録A 運用リファレンスの「ルールセットと世代」を参照してください。

## 4.2　ルールセットをインポートする

```text
tukuyomi-proxy rules import <config> [--crs <dir>] [--crs-off <name>]... [--rules <file>]... [--data <file>]... [--routes <file>] [--engine <name>] [--accept-block] [--detect-only]
```

最初のインポートは、検知のみの世代にする形をおすすめします（理由は 4.5 で説明します）。CRS は、第2章の 2.6 で取得したものを使います。コマンドは、サービスの OS ユーザーで実行します。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0 --detect-only
```

主なオプションは次のとおりです。

- `--crs <dir>`: CRS のディレクトリ。`--crs-off <name>` で、読み込まない `crs/rules/` の `.conf` を指定できます。
- `--rules <file>`: 運用者のルールのファイル。何度でも書け、CRS の後に書いた順に読み込みます。`--data <file>` は、運用者のルールが読むデータのファイルです。
- `--routes <file>`: 検査除外のルートのファイル（4.6）。
- `--engine <name>`: 世代の検査エンジン。`coraza` か `modsecurity`（小文字）。
- `--detect-only`: 検知のみの世代にします（4.5）。
- `--accept-block`: 事前検証のリクエストがブロックされても、事前検証を失敗にしません。

ルールセットに入れるファイルの名前の決まりと、数・大きさの上限は、付録A 運用リファレンスの「`rules`」を参照してください。

### 事前検証

インポートは、検査プロセスを 1 つ起動し、決まった 3 つのリクエスト（`GET /`、フォームのボディ `a=b` の `POST /`、JSON のボディ `{"a":"b"}` の `POST /`）を検査します。これが事前検証です。事前検証に通ったときだけ世代になり、標準出力に `<fingerprint> created` が出ます。同じ内容の世代が既にあれば `<fingerprint> already exists` が出ます。

- 遮断の世代では、事前検証のリクエストが 1 つでもブロックされると失敗にします（`--accept-block` を付けたときを除きます）。`crs-setup.conf` の設定を厳しくした場合などは、ログを見て修正するか、`--accept-block` を付けてください。検知のみの世代では、ルールに一致しても失敗にしません。
- 事前検証で分かるのは、ルールセットが起動し、通常の形のリクエストを通すことだけです。ルールが正しいことは分かりません。
- インポートは検査プロセスを起動するので、起動前の検証（第3章）も実行します。検査プロセスの権限の制限（Landlock）も、事前検証で起動する検査プロセスにかかります。

### 運用者のルールの決まり

Coraza の世代では、`--rules` で渡す運用者のルールの後に、検査プロセスが設定とルールを追加します。運用者のルールで変更することはできません。ModSecurity の世代の決まりは、4.7 を参照してください。

- ルール ID 4000001〜4000003 は、すべての世代で検査プロセスが使います。4000010・4000011 は、検知のみの世代で使います。運用者のルールで同じ ID を使うと、その世代のルールセットを組み立てられません。
- `Include`、`SecIgnoreRuleCompilationErrors`、名前が `SecAuditLog`・`SecDebugLog`・`SecUpload` で始まるディレクティブ、`ctl:ruleEngine`・`ctl:requestBodyAccess`・`ctl:requestBodyLimit`、`@inspectFile`・`@rbl`・`setenv:`、変数の名前 `reserved_body_cut` を含むルールは、受け付けません。判定は文字の並びだけで、大文字と小文字を区別せず、`msg` の中の語にも一致します。
- `ctl:ruleRemoveById`、`SecRuleRemoveById` などで、ブロックするルールを意図的に外すことは、運用者の判断に任せ、拒否しません。
- CRS のデフォルトは、`application/<name>+json` のボディをブロックします。受け付ける場合は、インポートの前に `crs-setup.conf` で受け付ける型に追加します。

そのほかの決まりは、付録A 運用リファレンスの「検査プロセスが追加する設定とルール」と「運用者の責任範囲」を参照してください。

## 4.3　世代の一覧、選択、解除、削除

```text
tukuyomi-proxy rules activate <config> <fingerprint>
tukuyomi-proxy rules deactivate <config> <engine>
tukuyomi-proxy rules remove <config> <fingerprint>
tukuyomi-proxy rules list <config>
```

- `list` は、世代の一覧を出します。フィンガープリント、作成時刻、モード（`block`・`detect`）、エンジン（`coraza`・`modsecurity`）が並び、選択中の世代に `current` の印が付きます。2 つのエンジンの世代を選択していれば、印は 2 行に付きます。
- `activate` は、世代を選択します。選択は、世代のエンジンごとに 1 つです。標準出力は `<fingerprint> current` です。世代のエンジンが使えないときは、選択せずに受け付けません（exit 2）。
- `deactivate` は、エンジンの選択中の世代を解除します（4.9）。標準出力は `<fingerprint> deactivated` です。
- `remove` は、どのエンジンでも選択中でない世代で、どのプロキシも使っていないものを削除します。使用中の世代は削除できません。

## 4.4　SIGUSR1 で世代を切り替える

`rules activate` で選択した世代を、動作中のプロキシに使わせるには、SIGUSR1 を送ります。送り方は、第3章の 3.7 を参照してください（プロキシのメインプロセスにだけ送ります）。

- プロキシは、選択中の世代が稼働中の世代と違うエンジンを、1 つずつ切り替えます。デフォルトのエンジンが先で、ほかは名前の順です。
- 切り替えでは、選択中の世代で新しい検査カーネルと検査プロセスを起動します。新しい方の準備ができたら、そのエンジンの新しいリクエストを、そちらへ振り向けます。古い方は、持っているリクエストを検査してから停止します。
- 新しい方が起動に失敗するか、準備できなければ、切り替えは失敗です（`reload: generation <fingerprint> failed to start: <reason>` の行を出します）。古い方がそのまま検査を続けます。
- 選択中の世代があり、稼働していないエンジンは、同じ切り替えで起動します。選択中の世代が稼働中の世代と同じエンジンは、`reload: generation <fingerprint> is already running` の行を出して、次のエンジンへ進みます。
- 切り替えの途中で受けた SIGUSR1 は、`reload: a switch is in progress, ignored` の行を出すだけです。切り替えの間は、そのエンジンの検査プロセスが 1 つ増えます。
- SIGHUP（設定のリロード）は、ルールの世代に触れず、ルールストアも読み込みません。世代を切り替えるのは SIGUSR1 です。

詳しい動作は、付録A 運用リファレンスの「SIGUSR1（世代の切り替え）」を参照してください。

## 4.5　検知のみのモードから遮断へ

最初は検知のみのモードで動かし、誤検知を確認し、除外を追加してから、遮断の世代をインポートし直すことをおすすめします。流れは次のとおりです。

1. `--detect-only` を付けて、検知のみの世代をインポートします。4.2 の最初の例のとおりです。
2. `rules activate <config> <fingerprint>` で選択し、SIGUSR1 で切り替えます。
3. 検知のみの世代は、ルールに一致したリクエストも通します。リクエストのログは、`class` が `forwarded`、`reason` が `detected by a rule` になり、`rule` に、一致したルールの ID が入ります（ログは第7章）。
4. ログの `rule` を見て誤検知を確認し、除外（ルールの除外）を追加します。
5. `--detect-only` を付けずに、遮断の世代をインポートし直します。`rules activate` で選択し、SIGUSR1 で切り替えます。

検知のみの世代は、遮断の世代と同じルールのファイルで、ブロックするかどうかだけが違います。注意することは次のとおりです。

- 検知のみの世代でも、検査プロセスが追加するルール 4000001〜4000003 は、ブロックします。
- Coraza の検知のみの世代は、ルールの前と後に目印のルール（ID 4000010、4000011）を追加します。運用者のルールでこれを削除したりスキップしたりすると、そのリクエストは検査できないとして 503 になります。黙ってブロックや素通しにはなりません。ModSecurity の世代は、目印のルールを追加しません。
- 検知のみの世代を選択しているエンジンを使うアップストリームは、ルールに一致したリクエストもブロックしません。起動、リロード、`config check` のときに、そのアップストリームごとに `upstream <name>: engine <engine>, mode detect` の行（`start:`・`reload:`・`config check:` で始まります）を出します。どのアップストリームがブロックしない状態かは、この行で分かります。

## 4.6　検査除外のルート

検査除外のルート（bypass）は、決まった `host` と `path` のリクエストを、検査せずにアップストリームへ転送するための仕組みです。`rules import --routes <file>` のファイルは、次の形の JSON の配列です。

```json
[
  {"host": "app.example.com", "path": "/api/uploads", "action": "bypass"}
]
```

- `host` は省けます。ほかの設定キーは受け付けません。`action` は `bypass` だけです。
- ルートに一致するリクエストは検査せず、アップストリームへ転送します。検査のスロットを取らないので、検査が混んでいるときや、検査プロセスが止まっているときも通ります。プロキシが自分で行う検証（ヘッダー部、ボディのサイズの上限）は、その前に行います。
- `path` は `/` だけにはできません（すべてのリクエストの検査を外してしまうためです）。`host` にワイルドカードは書けません。
- ルートは世代のマニフェストに入り、フィンガープリントの一部になります。リクエストを検査するエンジンの、稼働中の世代のルートだけが、そのリクエストに適用されます。

`host` と `path` の一致の方法、数の上限、アップストリームの選び方は、付録A 運用リファレンスの「検査除外のルート」を参照してください。管理画面のパスを検査除外のルートにする手順は、第5章の 5.4 にあります。

## 4.7　ModSecurity の世代

`rules import --engine modsecurity` で作る世代は、libmodsecurity（ModSecurity v3.0.17）でリクエストを検査します。検査プロセスは別の実行ファイル（`tukuyomi-inspector-modsecurity`）で、設定の `kernel.engines.modsecurity.inspector` に書きます。ModSecurity の世代を使わないホストでは省けます。次のように、`kernel` に `engines` を足します（`kernel` のほかの設定キーは省略しています）。

```json
"kernel": {
  "inspector": "/opt/tukuyomi-core/bin/tukuyomi-inspector",
  "engines": {"modsecurity": {"inspector": "/opt/tukuyomi-core/bin/tukuyomi-inspector-modsecurity"}}
}
```

インポートの手順、事前検証、`--detect-only`、検査除外のルート、CRS のインポートは、Coraza の世代と同じです。違うのは、次のところです。

- ルール ID 4000001〜4000011 は、検査プロセスのために空けてあります。運用者のルールが使うと、モードを問わず、その世代のルールセットを組み立てられません。
- 運用者のルールは、検証できる決まった書き方だけを受け付けます。行の終わりに CR があるファイル、NUL を含むファイル、最後が改行で終わらないファイルのほか、決まった書き方でないもの、使えるディレクティブとアクションの決まりの外にあるもの、使えない演算子や変数を含むものは、検査プロセスが起動せず（exit 11）、インポートが失敗します。理由とルールのファイルの名前は、標準エラーの `rules import: the inspector said:` の行に出ます。ModSecurity が読める書き方でも、検証できる決まった書き方でなければ受け付けないので、害の無いルールを受け付けないことがあります。
- 同じルールとリクエストでも、結果が違うことがあります。たとえば、入れ子が 62〜64 段の JSON のボディは、ModSecurity ではブロックされず、Coraza ではブロックされます。また、境界が空の multipart のボディは、ModSecurity の世代では検査不能として扱われ、503 になります。

受け付ける書き方の全体と、Coraza の世代との違いは、付録A 運用リファレンスの「ModSecurity の世代」を参照してください。ソースからビルドする場合は、リポジトリのドキュメント「ビルドと配置」の「ModSecurity の検査プロセス」を参照してください。

## 4.8　検査エンジンの選択

### アップストリームの `engine`

アップストリームごとに、リクエストを検査するエンジンを選べます。エンジンは `coraza` と `modsecurity` です。アップストリームの `engine` で選びます。`modsecurity` を書くには、4.7 のとおり、設定の `kernel.engines` に検査プロセスが必要です。書かないと、`kernel.engines has no inspector for the engine of an upstream` で受け付けません。

```json
"upstreams": {
  "app": {
    "servers": [
      {"address": "127.0.0.1:8080", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}
    ],
    "engine": "modsecurity"
  }
}
```

- `engine` を省いたアップストリームは、デフォルトのエンジン（`kernel.default_engine`。書かなければ `coraza`）で検査します。`rules import` の `--engine` を省いたときのエンジンも、デフォルトのエンジンです。
- リクエストは、行き先のアップストリームが使うエンジンで検査します。そのエンジンの検査カーネルだけを使い、別のエンジンへは回しません。その検査カーネルが使えないときは、503 で応答します。
- 同じアドレスのサーバーを持つアップストリームで、エンジンが違う設定は、受け付けません（`two upstreams with a server at the same address have different engines`）。クライアントが `Host` を選ぶだけで、同じサーバーへ届くアップストリームのうち、最も弱いエンジンやモードのものを通れてしまうためです。別の名前で同じサーバーへ届くアップストリームは、運用者が同じエンジンにそろえてください。
- 設定キーの形と受け付けない値は、付録A 運用リファレンスの「`forward`」と「`kernel`」を参照してください。

### 起動するエンジン

プロキシは、選択中の世代があり、検査プロセスが設定にあるエンジンのすべてを起動します。デフォルトのエンジンが先で、ほかは名前の順です。どのアップストリームも使わないエンジンも、起動します。

- デフォルトのエンジンと、アップストリームのエンジンには、選択中の世代が必要です。無ければ、起動も `config check` も、`rules store refused: no generation is chosen` で受け付けません。
- デフォルトのエンジンに選択中の世代が無く、ほかのエンジンには選択中の世代があるときは、`rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` で受け付けません（exit 1）。ModSecurity だけで始めるときは、設定の `kernel.default_engine` を `modsecurity` にして、ModSecurity の世代を選択します。
- 起動したエンジンは、プロキシが停止するまで止まりません。`rules deactivate` を実行しても、同じです。どのアップストリームも使わず、デフォルトのエンジンでもないエンジンでも、検査カーネルが失敗すると、プロキシ全体が停止します（`stop: the kernel failed: <reason>`、exit 1）。
- メモリの目安は、付録A 運用リファレンスの「検査エンジンの選択」を参照してください。

### デフォルトのエンジンを変更する手順

デフォルトのエンジンを変更すると、`engine` を省いたアップストリームの検査エンジンも変わります。変えたくないアップストリームには、先に、今のエンジンを `engine` に書きます。`kernel` は動作中に変更できないので、`kernel.default_engine` は、プロキシの再起動で変更します。次の例は、`managed` のある設定で、デフォルトのエンジンを `coraza` から `modsecurity` に変更する手順です。コマンドは、サービスと同じ OS ユーザーで実行します。

```text
tukuyomi-proxy rules import <config> --engine modsecurity --crs <crs-dir> --rules <rules-file> --routes <routes-file>   # 新しいデフォルトのエンジンの世代。まだ選択しない
tukuyomi-proxy managed import <config> <document>         # 全部のアップストリームに、今のエンジンを engine に書いたバージョン
tukuyomi-proxy managed activate <config> <version>        # 上で作ったバージョンを選択する
kill -HUP <proxy-pid>
   reload: configuration replaced <sha256> managed <version>
tukuyomi-proxy rules activate <config> <fingerprint>      # 新しいデフォルトのエンジンの世代。SIGUSR1 は送らない
tukuyomi-proxy rules list <config>                        # current の印が 2 行（Coraza の世代と ModSecurity の世代）
（設定ファイルの kernel に "default_engine": "modsecurity" を書く）
tukuyomi-proxy config check <config>                      # accepted
（プロキシと管理プロセスを再起動する）
   start: rules engine modsecurity
   start: rules engine coraza
```

- 新しいデフォルトのエンジンの世代は、先頭の `rules import` で作ります。管理画面の Host での CRS の調整と、インポートのルートの検査除外のルートを、その世代にも入れます（付録B 管理リファレンスの「管理画面の Host での CRS の調整」と「インポートのルートを検査除外にする」）。
- その世代は、`kernel.default_engine` を書く前に選択します。SIGUSR1 を送らない間は、そのエンジンは起動せず、プロキシは稼働を続けます。
- 世代を選択する前に、`kernel.default_engine` を書いて `config check` を実行すると、`rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine`（exit 1）で受け付けません。起動も、同じ文で受け付けません。
- 動作中のプロキシへの SIGHUP は、`config check` が `accepted` でも、`reload: configuration refused: kernel cannot change while running` で拒否します。変更するには、再起動します。管理プロセスも設定ファイルの `kernel.default_engine` を読むので、プロキシと一緒に再起動します。
- 再起動の後、`start: rules engine` の行は、デフォルトのエンジンが先に出ます。管理画面のルートのリクエストは新しいデフォルトのエンジンで、`engine` を書いたアップストリームのリクエストは、書いたエンジンで検査します（リクエストのログの `engine`）。

## 4.9　エンジンごとの選択中の世代

ルールストアは、エンジンごとに、選択中の世代を 1 つ持ちます。ファイルは `current.coraza` と `current.modsecurity` です。`rules activate` は、その世代のエンジンの `current.<engine>` を書きます。途中で止まっても、中途半端な内容は読まれません。

- 以前のバージョンが書いた `current` は、同じエンジンの選択中の世代として読みます。このバージョンで選択した後は、以前のバージョンは、そのエンジンの選択中の世代を読めません（第9章の 9.4 と、付録A 運用リファレンスの「バージョンの更新」）。
- 同じエンジンについて、`current` と `current.<engine>` の両方があり、別の世代を指しているときは、`the current generation records of the engine disagree` で受け付けません。`rules list`、`config check`、起動、SIGUSR1 のどれも同じです。`rules activate` で、そのエンジンの世代を選択し直すと、元に戻ります。

`rules deactivate <config> <engine>` は、そのエンジンの選択を解除します。

- 次の再起動から、そのエンジンは起動しません。動作中のプロキシは、起動したエンジンの検査カーネルを止めません。そのエンジンは、プロキシを再起動するまで稼働します。再起動までの SIGUSR1 は、`reload: rules store refused: no generation is chosen` の行を出します。
- デフォルトのエンジンか、どれかのアップストリームのエンジンがそのエンジンなら、`rules deactivate: the configuration uses the engine` の行を出して受け付けません（exit 1）。エンジンに選択中の世代が無いときも、`rules deactivate: no generation is chosen` の行を出して受け付けません（exit 1）。

### 稼働していないエンジンを使うアップストリームを書く順

選択中の世代があり、稼働していないエンジン（たとえば、起動のときに ModSecurity の世代を選択していなかったとき）を、アップストリームに書くときは、順序が大切です。設定のリロードは検査プロセスを起動せず、稼働していないエンジンのアップストリームを拒否するためです。次の例は、Coraza だけを起動しているプロキシに、`managed` のある設定で、ModSecurity のアップストリーム `mod` を足す場合です。

1. `rules activate` で、ModSecurity の世代を選択します。SIGUSR1 はまだ送りません。
2. `managed activate` で、アップストリーム `mod` を書いたバージョンを選択します。バージョンのアップストリームが使うエンジンに、選択中の世代が無いと、`managed activate` は選択せずに拒否するので、1 を先に行います。
3. SIGUSR1 を送って、ModSecurity を起動します。
4. SIGHUP（`systemctl reload`）を送って、設定をリロードします。ログに `reload: configuration replaced <sha256> managed <version>` の行が出ます。

3 の前に SIGHUP を送ると、ModSecurity が稼働していないので、`reload: configuration refused: the engine of an upstream is not ready (upstream mod)` で拒否します。前の設定のまま稼働し続け、`tukuyomi_config_reloads_total` の `refused` が 1 増えます。

## 4.10　運用上の注意

- 世代を使い始めるには、インポート、選択、切り替え（SIGUSR1）の 3 つが要ります。コマンドだけでは、動作中のプロキシは変わりません。
- 最初は `--detect-only` で動かし、誤検知を確認してから、遮断の世代をインポートし直します。検知のみの世代でも、ルール 4000001〜4000003 はブロックします。
- 事前検証に通っても、ルールが正しいことは分かりません。
- 検査除外のルートの `path` は、`/` だけにはできません（すべてのリクエストの検査を外してしまうためです）。管理画面のリクエストを検査するエンジンのどの世代にも、管理画面のための同じルートを入れ続けます。
- `rules deactivate` は、動作中のプロキシのエンジンを止めません。止めるには、再起動します。
- 稼働していないエンジンを使うアップストリームを足すときは、SIGUSR1 でエンジンを起動してから SIGHUP を送ります。
- どのアップストリームも使わないエンジンでも、検査カーネルが失敗すると、プロキシ全体が停止します。
- `kernel.default_engine` の変更は、再起動が必要です。SIGHUP は拒否します。
