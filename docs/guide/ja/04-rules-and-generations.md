# 第4章　ルールセットと世代

tukuyomi core は、リクエストを検査するルールを「世代」という単位で扱います。
本章では、世代を作る（インポート）、選ぶ（選択）、動作中のプロキシに使わせる（SIGUSR1）という 3 つの操作がどう分かれているのかを説明します。

続けて、検知のみのモードから始めてブロックに移る流れ、検査除外のルート、ModSecurity の世代、アップストリームごとの検査エンジンの選択を扱います。
コマンドの引数と終了コードの一覧は、付録A 運用リファレンスの「`rules`」にあります。

## 4.1　世代の考え方

世代は `rules import` が作るルールセットの一式で、フィンガープリント（マニフェストの SHA-256）で指します。
一度作った世代は後から変わることはありません。

世代ごとに、そのルールで検査するエンジンも決まっています。
このビルドに含まれるエンジンは、`coraza`（Coraza）と `modsecurity`（ModSecurity v3）です。
エンジンは `rules import --engine` で指定します。
省略すると、設定の `kernel.default_engine` に書いたエンジンになり、書いていなければ `coraza` になります。

ルールのファイルが同じでも、エンジンが違えばマニフェストが変わるので、別の世代（別のフィンガープリント）になります。
`modsecurity` の世代をインポート、選択、起動できるのは、設定の `kernel.engines` に検査プロセスがあるときだけです。

世代を使い始めるまでには、3 つの操作があります。
それぞれ別のコマンドかシグナルで行い、動作中のプロキシが変わるのは最後の 1 つだけです。

| 操作 | すること | 動作中のプロキシへの効果 |
|---|---|---|
| インポート（`rules import`） | 入力からルールセットを作り、ルールストアに置きます。事前検証に通ったものが世代になります。この時点では世代を選択しません | ありません |
| 選択（`rules activate`） | 世代を、そのエンジンの選択中の世代にします | ありません。選択した世代は、この後に起動するプロキシと、SIGUSR1 を受けたプロキシが使います |
| 切り替え（SIGUSR1） | エンジンごとに、選択中の世代へ切り替えます | 切り替えの後に届いた新しいリクエストを、新しい世代で検査します |

`rules` のコマンドは動作中のプロキシとは別のプロセスとして動き、短時間で終わります。
動作中のプロキシはコマンドによる変更に気付きません。
一方、管理プロセスの API は世代を選択したうえで、動作中のプロキシに切り替えを依頼します（第5章）。

フィンガープリントでは、事故による破損と取り違えのほか、動作中のプロキシが持つフィンガープリントと中身が合わない起動も検出できます。
同じ OS ユーザーのプロセス（検査プロセスも同じ OS ユーザーです）がルールストアを書き換えることは防ぎません。
ルールストアの中身については、付録A 運用リファレンスの「ルールセットと世代」を参照してください。

## 4.2　ルールセットをインポートする

```text
tukuyomi-proxy rules import <config> [--crs <dir>] [--crs-off <name>]... [--rules <file>]... [--data <file>]... [--routes <file>] [--engine <name>] [--accept-block] [--detect-only]
```

最初のインポートでは、検知のみの世代を作ることをおすすめします（理由は 4.5 で説明します）。
CRS は、第2章の 2.6 でダウンロードしたものを使います。
コマンドはサービスの OS ユーザーで実行してください。

```bash
sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy rules import /etc/tukuyomi-core/config.json --crs /var/lib/tukuyomi-core/crs-4.23.0 --detect-only
```

主なオプションは次のとおりです。

- `--crs <dir>`: CRS のディレクトリを指定します。
  `crs/rules/` の `.conf` のうち、読み込まないものは `--crs-off <name>` で指定できます。
- `--rules <file>`: 運用者のルールのファイルで、何度でも指定でき、CRS の後に指定した順で読み込みます。
  運用者のルールが読むデータのファイルは、`--data <file>` で指定します。
- `--routes <file>`: 検査除外のルートのファイルです（4.6）。
- `--engine <name>`: 世代の検査エンジンで、`coraza` か `modsecurity` を小文字で指定します。
- `--detect-only`: 検知のみの世代にします（4.5）。
- `--accept-block`: 事前検証のリクエストがブロックされても、事前検証を失敗にしません。

ルールセットに入れるファイルの名前の決まりや、ファイルの数と大きさの上限は、付録A 運用リファレンスの「`rules`」にあります。

### 事前検証

インポートでは事前検証として、検査プロセスを 1 つ起動し、決まった 3 つのリクエスト（`GET /`、フォームのボディ `a=b` を持つ `POST /`、JSON のボディ `{"a":"b"}` を持つ `POST /`）を検査します。

事前検証に通ったときだけ世代が作られ、標準出力に `<fingerprint> created` が出ます。
同じ内容の世代が既にある場合は、`<fingerprint> already exists` が出ます。

- ブロックする世代では、事前検証のリクエストが 1 つでもブロックされると、事前検証は失敗します（`--accept-block` を付けたときを除きます）。
  `crs-setup.conf` の設定を厳しくした場合などは、ログを見て設定を直すか、`--accept-block` を付けてください。
  検知のみの世代では、ルールに一致しても失敗にはなりません。
- 事前検証で分かるのは、ルールセットで起動でき、通常の形のリクエストを通すことだけです。
  ルールが正しいかどうかまでは分かりません。
- インポートは検査プロセスを起動するため、起動前の検証（第3章）も行います。
  事前検証で起動する検査プロセスにも、検査プロセスの権限の制限（Landlock）がかかります。

### 運用者のルールの決まり

Coraza の世代では、`--rules` で渡した運用者のルールの後に、検査プロセスが設定とルールを追加します。
この設定とルールは、運用者のルールでは変更できません。
ModSecurity の世代の決まりは、4.7 を参照してください。

- ルール ID 4000001〜4000003 はすべての世代で、4000010・4000011 は検知のみの世代で、検査プロセスが使います。
  運用者のルールで同じ ID を使うと、その世代のルールセットを組み立てられません。
- `Include`、`SecIgnoreRuleCompilationErrors`、名前が `SecAuditLog`・`SecDebugLog`・`SecUpload` で始まるディレクティブ、`ctl:ruleEngine`・`ctl:requestBodyAccess`・`ctl:requestBodyLimit`、`@inspectFile`・`@rbl`・`setenv:`、変数の名前 `reserved_body_cut` を含むルールは受け付けません。
  この判定は文字の並びだけで行うため、`msg` の中の語にも一致します。
  大文字と小文字は区別しません。
- `ctl:ruleRemoveById` や `SecRuleRemoveById` などでブロックするルールを意図的に外すことは、運用者の判断に任せており、拒否しません。
- CRS はデフォルトでは `application/<name>+json` のボディをブロックします。
  このボディを受け付けるには、インポートの前に、`crs-setup.conf` で受け付ける型に追加します。

そのほかの決まりは、付録A 運用リファレンスの「検査プロセスが追加する設定とルール」と「運用者の責任範囲」を参照してください。

## 4.3　世代の一覧、選択、解除、削除

```text
tukuyomi-proxy rules activate <config> <fingerprint>
tukuyomi-proxy rules deactivate <config> <engine>
tukuyomi-proxy rules remove <config> <fingerprint>
tukuyomi-proxy rules list <config>
```

- `list` は世代の一覧を出します。
  各行には、フィンガープリント、作成時刻、モード（`block`・`detect`）、エンジン（`coraza`・`modsecurity`）が並びます。
  選択中の世代には `current` の印が付き、2 つのエンジンで世代を選択していれば、印は 2 行に付きます。
- `activate` は世代を選択します。
  選択できる世代はエンジンごとに 1 つです。
  標準出力には `<fingerprint> current` が出ます。
  世代のエンジンが使えないときは、選択せずに拒否します（exit 2）。
- `deactivate` は、そのエンジンで選択中の世代を解除し、標準出力に `<fingerprint> deactivated` を出します（4.9）。
- `remove` は、どのエンジンでも選択中でなく、どのプロキシも使っていない世代を削除します。
  使用中の世代は削除できません。

## 4.4　SIGUSR1 で世代を切り替える

`rules activate` で選択した世代を動作中のプロキシに使わせるには、SIGUSR1 を送ります。
シグナルは第3章の 3.7 のとおり、プロキシのメインプロセスにだけ送ります。

- プロキシは、選択中の世代と稼働中の世代が違うエンジンを、1 つずつ切り替えます。
  順番はデフォルトのエンジンが先で、ほかのエンジンは名前の順です。
- 切り替えでは、まず選択中の世代で、新しい検査カーネルと検査プロセスを起動します。
  新しい方の準備ができたら、そのエンジンに来る新しいリクエストを、新しい方へ振り向けます。
  古い方は受け持っているリクエストを検査し終えてから停止します。
- 新しい方が起動に失敗したり、準備ができなかったりした場合は、切り替えは失敗です。
  ログに `reload: generation <fingerprint> failed to start: <reason>` の行が出て、古い方がそのまま検査を続けます。
- 選択中の世代があり、まだ稼働していないエンジンは、同じ切り替えの中で起動します。
  選択中の世代と稼働中の世代が同じエンジンについては、`reload: generation <fingerprint> is already running` の行を出して、次のエンジンへ進みます。
- 切り替えの途中に SIGUSR1 を受けても、`reload: a switch is in progress, ignored` の行を出すだけです。
  切り替えの間は、そのエンジンの検査プロセスが 1 つ多くなります。
- SIGHUP（設定のリロード）は、ルールの世代には触れず、ルールストアも読み込みません。
  世代を切り替えるのは SIGUSR1 です。

詳しい動作は、付録A 運用リファレンスの「SIGUSR1（世代の切り替え）」を参照してください。

## 4.5　検知のみのモードから、ブロックするモードへ

最初は検知のみのモードで動かし、誤検知を確認して除外を追加してから、ブロックする世代をインポートし直すことをおすすめします。
流れは次のとおりです。

1. 4.2 の最初の例のとおり、`--detect-only` を付けて検知のみの世代をインポートします。
2. `rules activate <config> <fingerprint>` で選択し、SIGUSR1 で切り替えます。
3. 検知のみの世代は、ルールに一致したリクエストも通します。
   そのときのリクエストのログは、`class` が `forwarded`、`reason` が `detected by a rule` になり、`rule` には一致したルールの ID が入ります（ログは第7章）。
4. ログの `rule` を見て誤検知を確認し、ルールの除外を追加します。
5. `--detect-only` を付けずに、ブロックする世代をインポートし直します。
   `rules activate` で選択し、SIGUSR1 で切り替えます。

検知のみの世代とブロックする世代は、ルールのファイルが同じで、ブロックするかどうかだけが違います。
注意する点は次のとおりです。

- 検知のみの世代でも、検査プロセスが追加するルール 4000001〜4000003 はブロックします。
- Coraza の検知のみの世代では、ルールの前と後に目印のルール（ID 4000010、4000011）を追加します。
  運用者のルールでこれを削除したりスキップしたりすると、そのリクエストは検査できなかったものとして扱われ、503 になります。
  何も知らせずにブロックしたり、素通しにしたりすることはありません。
  ModSecurity の世代では、目印のルールを追加しません。
- 検知のみの世代を選択しているエンジンを使うアップストリームでは、ルールに一致したリクエストもブロックしません。
  起動、リロード、`config check` のときには、そうしたアップストリームごとに `upstream <name>: engine <engine>, mode detect` の行が出ます（行の頭は `start:`・`reload:`・`config check:` です）。
  どのアップストリームがブロックしない状態なのかは、この行で確認できます。

## 4.6　検査除外のルート

検査除外のルート（bypass）は、指定した `host` と `path` のリクエストを、検査せずにアップストリームへ転送する仕組みです。
ルートは `rules import --routes <file>` に渡すファイルに、次の形の JSON の配列で書きます。

```json
[
  {"host": "app.example.com", "path": "/api/uploads", "action": "bypass"}
]
```

- `host` は省略できます。
  ほかの設定キーは受け付けません。
  `action` に書けるのは `bypass` だけです。
- ルートに一致するリクエストは、検査せずにアップストリームへ転送します。
  検査のスロットを使わないので、検査が混んでいるときや、検査プロセスが止まっているときも通ります。
  プロキシ自身が行う検証（ヘッダー部、ボディのサイズの上限）は、転送の前に行います。
- すべてのリクエストの検査を外してしまうため、`path` を `/` だけにすることはできません。
  `host` にワイルドカードは書けません。
- ルートは世代のマニフェストに含まれ、フィンガープリントの一部になります。
  リクエストに適用されるのは、そのリクエストを検査するエンジンで稼働中の世代のルートだけです。

`host` と `path` の一致の仕方、ルートの数の上限、アップストリームの選ばれ方は、付録A 運用リファレンスの「検査除外のルート」を参照してください。
管理画面のパスを検査除外のルートにする手順は、第5章の 5.4 にあります。

## 4.7　ModSecurity の世代

`rules import --engine modsecurity` で作った世代は、libmodsecurity（ModSecurity v3.0.17）でリクエストを検査します。
この世代の検査プロセスは別の実行ファイル（`tukuyomi-inspector-modsecurity`）で、設定の `kernel.engines.modsecurity.inspector` に指定します。
ModSecurity の世代を使わないホストでは、この設定キーは省略できます。

書くときは、次のように `kernel` に `engines` を追加します（`kernel` のほかの設定キーは省略しています）。

```json
"kernel": {
  "inspector": "/opt/tukuyomi-core/bin/tukuyomi-inspector",
  "engines": {"modsecurity": {"inspector": "/opt/tukuyomi-core/bin/tukuyomi-inspector-modsecurity"}}
}
```

インポートの手順、事前検証、`--detect-only`、検査除外のルート、CRS のインポートは、Coraza の世代と同じです。
違うのは次の点です。

- ルール ID 4000001〜4000011 は、検査プロセスのために空けてあります。
  運用者のルールでこの ID を使うと、モードにかかわらず、その世代のルールセットを組み立てられません。
- 運用者のルールは、検証できる決まった書き方のものだけを受け付けます。
  行の終わりに CR があるファイル、NUL を含むファイル、最後が改行で終わらないファイルは受け付けません。
  決まった書き方でないもの、使えるディレクティブとアクションの決まりの外にあるもの、使えない演算子や変数を含むものも同じです。
  どの場合も、検査プロセスが起動せず（exit 11）、インポートは失敗します。
  理由とルールのファイルの名前は、標準エラーの `rules import: the inspector said:` の行に出ます。
  ModSecurity が読める書き方でも、検証できる決まった書き方でなければ受け付けないため、害の無いルールが拒否されることがあります。
- 同じルールとリクエストでも、結果が違うことがあります。
  たとえば入れ子が 62〜64 段の JSON のボディは、Coraza ではブロックされますが、ModSecurity ではブロックされません。
  また、境界が空の multipart のボディは、ModSecurity の世代では検査できないものとして扱われ、503 になります。

受け付ける書き方の詳細と、Coraza の世代との違いは、付録A 運用リファレンスの「ModSecurity の世代」を参照してください。
ソースからビルドする場合は、リポジトリのドキュメント「ビルドと配置」の「ModSecurity の検査プロセス」を参照してください。

## 4.8　検査エンジンの選択

### アップストリームの `engine`

リクエストを検査するエンジンは、アップストリームの `engine` に `coraza` か `modsecurity` を書いて、アップストリームごとに選べます。
`modsecurity` を書くには、4.7 のとおり、設定の `kernel.engines` に検査プロセスが必要です。
検査プロセスを書いていないと、設定は `kernel.engines has no inspector for the engine of an upstream` で拒否されます。

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

- `engine` を省略したアップストリームは、デフォルトのエンジン（`kernel.default_engine`。書かなければ `coraza`）で検査します。
  `rules import` で `--engine` を省略したときのエンジンも、デフォルトのエンジンです。
- リクエストは行き先のアップストリームが使うエンジンの検査カーネルだけで検査し、別のエンジンへ回すことはありません。
  その検査カーネルが使えないときは、503 を返します。
- 同じアドレスのサーバーを持つアップストリームどうしで、エンジンが違う設定は受け付けません（`two upstreams with a server at the same address have different engines`）。
  エンジンの違いを許すと、同じサーバーへ届くアップストリームのうち最も弱いエンジンやモードのものを、クライアントが `Host` を選ぶだけで通れてしまうためです。
  別の名前で同じサーバーへ届くアップストリームは、運用者が同じエンジンにそろえてください。
- 設定キーの形と、受け付けない値については、付録A 運用リファレンスの「`forward`」と「`kernel`」を参照してください。

### 起動するエンジン

プロキシは、選択中の世代があり、設定に検査プロセスがあるエンジンをすべて起動します。
起動の順番はデフォルトのエンジンが先で、ほかのエンジンは名前の順です。
どのアップストリームも使わないエンジンでも起動します。

- デフォルトのエンジンと、アップストリームが使うエンジンには、選択中の世代が必要です。
  選択中の世代が無いと、起動も `config check` も `rules store refused: no generation is chosen` で拒否されます。
- デフォルトのエンジンに選択中の世代が無く、ほかのエンジンにはある場合は、`rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` で拒否されます（exit 1）。
  ModSecurity だけで使い始めるときは、設定の `kernel.default_engine` を `modsecurity` にしたうえで、ModSecurity の世代を選択してください。
- 一度起動したエンジンは、`rules deactivate` を実行しても、プロキシが停止するまで止まりません。
  どのアップストリームも使わず、デフォルトのエンジンでもないエンジンでも、検査カーネルが失敗するとプロキシ全体が停止します（`stop: the kernel failed: <reason>`、exit 1）。
- メモリの目安は、付録A 運用リファレンスの「検査エンジンの選択」を参照してください。

### デフォルトのエンジンを変更する手順

デフォルトのエンジンを変更すると、`engine` を省略したアップストリームの検査エンジンも変わるので、変えたくないアップストリームには、先に今のエンジンを `engine` に書いておきます。
`kernel` は動作中に変更できないため、`kernel.default_engine` はプロキシを再起動して変更します。

次の例は、`managed` のある設定で、デフォルトのエンジンを `coraza` から `modsecurity` に変更する手順です。
コマンドはサービスと同じ OS ユーザーで実行してください。

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

- 新しいデフォルトのエンジンの世代は、最初の `rules import` で作ります。
  その世代にも、管理画面の Host での CRS の調整と、インポートのルートを検査除外にするルートを入れます（付録B 管理リファレンスの「管理画面の Host での CRS の調整」と「インポートのルートを検査除外にする」）。
- この世代は、`kernel.default_engine` を書く前に選択しておきます。
  SIGUSR1 を送らなければ、そのエンジンは起動せず、プロキシはそのまま稼働を続けます。
- 世代を選択する前に `kernel.default_engine` を書くと、`config check` も起動も `rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine`（exit 1）で拒否されます。
- `config check` が `accepted` でも、動作中のプロキシに SIGHUP を送ると、`reload: configuration refused: kernel cannot change while running` で拒否されます。
  変更するには再起動します。
  管理プロセスも設定ファイルの `kernel.default_engine` を読むため、プロキシと一緒に再起動します。
- 再起動すると、`start: rules engine` の行は、デフォルトのエンジンのものから先に出ます。
  管理画面のルートへのリクエストは新しいデフォルトのエンジンで、`engine` を書いたアップストリームへのリクエストは書いたエンジンで検査します。
  どのエンジンで検査したかは、リクエストのログの `engine` に出ます。

## 4.9　エンジンごとの選択中の世代

ルールストアは選択中の世代をエンジンごとに 1 つ持ちます（ファイルは `current.coraza` と `current.modsecurity`）。
`rules activate` は、選択した世代のエンジンの `current.<engine>` を書きます。
書き込みが途中で止まっても、中途半端な内容が読まれることはありません。

- 以前のバージョンが書いた `current` は、同じエンジンの選択中の世代として読みます。
  一方、このバージョンで選択した後は、以前のバージョンは、そのエンジンの選択中の世代を読めなくなります（第9章の 9.4 と、付録A 運用リファレンスの「バージョンの更新」）。
- 同じエンジンについて `current` と `current.<engine>` の両方があり、別々の世代を指している場合は、`the current generation records of the engine disagree` で拒否されます。
  `rules list`、`config check`、起動、SIGUSR1 のどれも同じです。
  そのエンジンの世代を `rules activate` で選択し直すと、元に戻ります。

`rules deactivate <config> <engine>` は、そのエンジンの選択を解除します。

- 解除したエンジンは、次の再起動から起動しなくなります。
  動作中のプロキシは、すでに起動しているエンジンの検査カーネルを止めないので、そのエンジンはプロキシを再起動するまで稼働を続けます。
  再起動までに SIGUSR1 を送ると、`reload: rules store refused: no generation is chosen` の行が出ます。
- デフォルトのエンジンか、どれかのアップストリームのエンジンがそのエンジンの場合は、`rules deactivate: the configuration uses the engine` の行を出して拒否します（exit 1）。
  そのエンジンに選択中の世代が無いときも、`rules deactivate: no generation is chosen` の行を出して拒否します（exit 1）。

### 稼働していないエンジンを使うアップストリームを書く順

エンジンに選択中の世代があっても、そのエンジンが稼働していないことがあります。
たとえば、起動のときに ModSecurity の世代を選択していなかった場合です。
設定のリロードは検査プロセスを起動せず、稼働していないエンジンを使うアップストリームを拒否するため、このようなエンジンをアップストリームに書くときは手順の順序が大切です。

次の例は、`managed` のある設定で、Coraza だけを起動しているプロキシに ModSecurity のアップストリーム `mod` を追加する場合です。

1. `rules activate` で ModSecurity の世代を選択し、SIGUSR1 はまだ送りません。
2. `managed activate` で、アップストリーム `mod` を書いたバージョンを選択します。
   バージョンのアップストリームが使うエンジンに選択中の世代が無いと、`managed activate` は選択せずに拒否するので、1 を先に行います。
3. SIGUSR1 を送って、ModSecurity を起動します。
4. SIGHUP（`systemctl reload`）を送って、設定をリロードします。
   ログに `reload: configuration replaced <sha256> managed <version>` の行が出ます。

3 より前に SIGHUP を送ると、ModSecurity が稼働していないため、`reload: configuration refused: the engine of an upstream is not ready (upstream mod)` で拒否されます。
プロキシは前の設定のまま稼働を続け、`tukuyomi_config_reloads_total` の `refused` が 1 増えます。

## 4.10　運用上の注意

- **世代を使い始めるには、3 つの操作が要ります**: インポート、選択、切り替え（SIGUSR1）です。
  コマンドだけでは、動作中のプロキシは変わりません。
- **最初は `--detect-only` で動かします**: 誤検知を確認してから、ブロックする世代をインポートし直します。
  検知のみの世代でも、ルール 4000001〜4000003 はブロックします。
- **事前検証に通っても、ルールが正しいとは限りません**: 事前検証で分かるのは、ルールセットで起動でき、通常の形のリクエストを通すことだけです（4.2）。
- **検査除外のルートの `path` は、`/` だけにはできません**: すべてのリクエストの検査を外してしまうためです。
  管理画面のリクエストを検査するエンジンでは、どの世代にも、管理画面のための同じルートを入れ続けてください。
- **`rules deactivate` は、動作中のプロキシのエンジンを止めません**: 止めるには再起動します。
- **稼働していないエンジンを使うアップストリームを追加する順**: SIGUSR1 でエンジンを起動してから、SIGHUP を送ります。
- **使っていないエンジンの失敗**: どのアップストリームも使わないエンジンでも、検査カーネルが失敗すると、プロキシ全体が停止します。
- **`kernel.default_engine` の変更には、再起動が必要です**: SIGHUP は拒否されます。
