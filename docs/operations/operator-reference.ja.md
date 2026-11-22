[English](operator-reference.md) | [日本語](operator-reference.ja.md)

# 運用リファレンス

この文書は、現在の実装について、運用に必要な事項をまとめたリファレンスです。扱うのは、コマンド、シグナル、設定ファイルの設定キー、ルールセットの扱い、managed 設定、リクエストの処理、アクセス制御とレート制限、ログ、監視です。書くのは、プロキシから見えるものだけです。

配置と systemd の例は、[ビルドと配置](../build/binary-deployment.ja.md) を参照してください。管理プロセス（`admin` コマンド）の設定と API は、[管理リファレンス](admin-reference.ja.md) にあります。

この文書に出てくるパスと名前（`/etc/tukuyomi-core/config.json`、OS ユーザー `tukuyomi`、`example.com` など）は、どれも例です。

## コマンド

コマンドはどれも `tukuyomi-proxy` という 1 つの実行ファイルで実行します。設定ファイルは絶対パスで渡してください。`.`・`..`・空の要素・末尾の `/` を含むパスは受け付けません。

root ではどのコマンドも実行できません。プロセスの 4 つのユーザー ID（real、effective、saved、file system）のどれかが 0 なら、`host check refused` の行を出して拒否します（exit 1）。コマンドはサービスの OS ユーザーで実行してください（例: `sudo -u tukuyomi ...`）。

### 起動

```text
tukuyomi-proxy <config>
```

- 起動は次の順に進みます。
  1. 起動前の検証（root でないこと、SIGCHLD、ファイルディスクリプター）
  2. 設定ファイル（`managed` があれば、managed ストアの選択中のバージョンと、それが指すファイルも含みます。`geo` があれば、国のデータベースも読み込んで検証します）
  3. アップストリームのサーバーの名前解決と、アップストリームの CA のファイル
  4. TLS のリスナーの証明書と鍵
  5. ルールストアと、エンジンごとの選択中の世代
  6. ログファイルを開く（設定に `records` があるとき）
  7. 監視用のリスナーのバインド（設定に `status` があるとき）
  8. 制御ソケットのバインド（設定に `admin` があるとき）
  9. 検査カーネルの起動と、検査プロセスの準備（起動するエンジンごと）
  10. リスナーのバインド
- 起動するのは、選択中の世代があり、設定に検査プロセスがあるエンジンのすべてです。起動の順は、デフォルトのエンジンが先で、ほかのエンジンは名前の順です。
  - デフォルトのエンジンとアップストリームのエンジンには、選択中の世代が必要です。無ければ `start: rules store refused: no generation is chosen` の行を出して停止します（exit 1）。
  - デフォルトのエンジンに選択中の世代が無く、ほかのエンジンにはあるときは、`start: rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` の行を出して停止します（exit 1）。`kernel.default_engine` を書くか、デフォルトのエンジンの世代を選択してください。
  - どのアップストリームも使わないエンジンも、選択中の世代があれば起動します（下の「検査エンジンの選択」）。
- ログファイルは、検査プロセスより前に開きます。開けなければ `start: record file refused: ...` の行を出し、検査プロセスを起動せずに停止します（exit 1）。
- 監視用のリスナーと制御ソケットも、検査プロセスより前にバインドします。バインドできなければ、検査プロセスを起動せずに停止します（exit 1）。制御ソケットのときは、`start: control socket refused: ...` の行が出ます。
- リスナーは、起動するエンジンの検査カーネルがすべて準備できてから、すべてバインドします。1 つでもバインドできなければ、どのリスナーも使わずに停止します。
- シグナルの処理が有効になるのは、6 の後です。それより前に届いたシグナルは、どれもプロキシをそのまま終了させます。6 より前の段階には名前解決があり、これには最長で `resolve_timeout_ms` かかります。
- 準備ができると `start: the kernel is ready` の行が、リスナーが待ち受けを始めると `start: listening` の行が、ログに出ます（`line` のログです。下の「ログ」）。
- 環境変数 `NOTIFY_SOCKET` があれば、すべてのリスナーをバインドした後に `READY=1` を送ります（下の「systemd への通知」）。
- 終了コードは次のとおりです。

| 終了コード | 意味 |
|---|---|
| 0 | シグナルで停止し、検査カーネルの停止（検査プロセスの終了と作業ディレクトリの削除）まで確認できたとき |
| 1 | それ以外の終了です。root での起動、起動前の検証の失敗、名前解決できないアップストリームの名前、使えない CA のファイル、受け付けない証明書や鍵、受け付けないルールストアや世代、選択中の世代が無いデフォルトのエンジンやアップストリームのエンジン、受け付けない managed ストアやバージョン、開けないログファイル、バインドできない監視用のリスナーや制御ソケットを含みます。これらの場合は何も起動していません |
| 2 | 引数のエラー、または設定ファイルを受け付けなかったとき |

### `config check`

```text
tukuyomi-proxy config check <config>
```

設定ファイルなどを、プロキシを起動せずに検証するコマンドです。

- 起動と同じ検証を、選択中の世代と検査カーネルの設定まで実行します。対象は上の 2〜5 と、検査カーネルの設定の値です。起動前の検証（上の 1）のうち、検証するのは root でないことだけです。
  - 通れば、標準出力に `accepted` の 1 行が出て、exit 0 になります。
  - ほかの行は標準エラーに出て、`config check:` で始まります。引数のエラーのときだけは `config:` で始まり、使い方の行が続きます。
  - 終了コードは起動と同じです。
  - 検査カーネルの設定は、選択中の世代があるエンジンごとに検証します。検査カーネルの設定を作れない世代があると、`config check: rules generation refused: <reason>` の行を出して exit 1 になります。このビルドが持つ検査エンジンは、`coraza` と `modsecurity` です。`modsecurity` を使えるのは、設定の `kernel.engines` に検査プロセスがあるときだけです（下の「`kernel`」の `engines`）。
  - デフォルトのエンジンやアップストリームのエンジンに選択中の世代が無いときは、起動のときと同じ文で受け付けません（`config check: rules store refused: no generation is chosen`、`config check: rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine`。どちらも exit 1）。
  - デフォルトのエンジンかアップストリームのエンジンが `modsecurity` で、設定に `kernel.engines` が無いときは、設定ファイルかバージョンを受け付けません。どのアップストリームも使わないエンジンで設定に検査プロセスが無いものは、選択中の世代があっても検証も起動もしません。
  - 検知のみの世代を選択しているエンジンへ向かうアップストリームがあれば、そのアップストリームごとに `config check: upstream <name>: engine <engine>, mode detect` の行を出します。
- `managed` があれば、managed ストアの選択中のバージョン（`current`）を、起動のときと同じように読み込んで検証し、`config check: managed version <version>` の行を出します。選択中のバージョンが無ければ、`config check: managed store refused: no managed version is chosen` の行を出して exit 1 になります（下の「managed 設定」）。読んでいる間は、そのバージョンの削除を拒否します。
- `geo` があれば、国のデータベースも、起動のときと同じように読み込んで検証します（「アクセス制御とレート制限」の `geo`）。
- 次のものは検証しません。
  - SIGCHLD とファイルディスクリプター（上の 1 のうち、root でないこと以外）
  - 作業ディレクトリ（`kernel.tmp_root`）。検査プロセスを起動するときに検証します
  - 検査プロセスの実行ファイルが起動できること、Landlock が使えること
  - 世代のエンジン（Coraza か ModSecurity）でルールを組み立てられること。起動のときに検証します。ルールは `rules import` が事前検証してから世代にします
  - ログファイルを開けること（上の 6）
  - リスナーと監視用のリスナーのポート、制御ソケットをバインドできること
  - systemd の設定
  - 動作中のプロキシが、設定のリロードで拒否する理由（動作中に変更できない設定キーの違い、アップストリームのエンジンが稼働していないこと、新しいリスナーのバインド。下の「SIGHUP（設定のリロード）」）
- このコマンドが書き込むのは、目印だけです。起動のときと同じく、起動するエンジンごとに、選択中の世代を使うことを示す目印をルールストアの `using/` に作ります（まだ無いとき）。目印のロックは、コマンドが終了すると解除されます。
- このコマンドは、サービスと同じ OS ユーザーで実行してください。別の OS ユーザーで実行すると、ルールストアと managed ストアの所有者の検証や、鍵のファイルの読み込みで受け付けません。

### `rules`

```text
tukuyomi-proxy rules import <config> [--crs <dir>] [--crs-off <name>]... [--rules <file>]... [--data <file>]... [--routes <file>] [--engine <name>] [--accept-block] [--detect-only]
tukuyomi-proxy rules activate <config> <fingerprint>
tukuyomi-proxy rules deactivate <config> <engine>
tukuyomi-proxy rules remove <config> <fingerprint>
tukuyomi-proxy rules list <config>
```

どれも短時間で終わるコマンドで、動作中のプロキシとは別のプロセスです。動作中のプロキシは、これらのコマンドによる変更を検知しません。新しい世代を使わせるには、プロキシに SIGUSR1 を送ります（下の「シグナル」）。管理プロセスの API は、世代を選択した後、続けて動作中のプロキシに切り替えを依頼します（[管理リファレンス](admin-reference.ja.md)。依頼の仕組みは「制御ソケット」）。

| コマンド | すること | 標準出力 |
|---|---|---|
| `import` | 入力からルールセットを作ってルールストアに置き、事前検証に通ったら世代にします。世代の選択はしません | `<fingerprint> created`、`<fingerprint> already exists`、`<fingerprint> recreated, the stored copy was broken` |
| `activate` | 世代を選択します。選択できるのは、世代のエンジンごとに 1 つです（下の「エンジンごとの選択中の世代」）。選択した世代は、後で起動するプロキシと、SIGUSR1 を受けたプロキシが使います。世代のエンジンが使えないときは、選択せずに拒否します（exit 2） | `<fingerprint> current` |
| `deactivate` | エンジンの選択中の世代を解除します。次に起動するプロキシは、そのエンジンを起動しません。動作中のプロキシは、起動したエンジンを止めません。デフォルトのエンジンと、アップストリームが使っているエンジンは、解除せずに拒否します（exit 1。下の「エンジンごとの選択中の世代」） | `<fingerprint> deactivated`（解除した世代） |
| `remove` | どのエンジンでも選択中でなく、どのプロキシも使っていない世代を削除します | `<fingerprint> removed` |
| `list` | 世代の一覧を出します | 世代ごとに、フィンガープリント、作成時刻（エポックからの秒数）、モード、エンジンを出します。モードは `block`・`detect` で、マニフェストが読めなければ `unknown` です。エンジンは `coraza`・`modsecurity` で、マニフェストが読めなければ `unknown` です。検査除外のルート（bypass）があれば、`routes` とその数も出ます。エンジンごとの選択中の世代には `current` が付きます（2 つのエンジンの世代が選択中なら、2 行に付きます）。選択中の世代を決められないとき（ファイルを読めない、内容が正しくない、`current` と `current.<engine>` が食い違う）は、世代の行をすべて出した後、標準エラーに `rules list: <reason>` の行を出して exit 1 になります |

`import` の入力は次のとおりです。オプションのパスは、カレントディレクトリからの相対パスでも指定できます。

| オプション | 内容 |
|---|---|
| `--crs <dir>` | `scripts/fetch-crs.sh` でダウンロードした CRS のディレクトリ。中に置けるのは、`crs-setup.conf`（と、任意で `crs-setup.conf.example`）と、`rules/` の `.conf`・`.data`・`.example` だけです。ほかのもの（隠しファイル、`plugins` などのディレクトリ、ほかの拡張子、シンボリックリンク）があれば受け付けません |
| `--crs-off <name>` | `crs/rules/` の `.conf` のうち、読み込まないもの。何度でも指定できます。`--crs` が必要です |
| `--rules <file>` | 運用者のルールのファイル。何度でも指定でき、CRS の後に、指定した順に読み込みます |
| `--data <file>` | 運用者のルールが読むデータのファイル。ルールセットには入りますが、ルールとしては読み込みません |
| `--routes <file>` | 検査除外のルート（bypass）のファイル（下の「検査除外のルート」） |
| `--engine <name>` | 世代の検査エンジンの名前で、`coraza` か `modsecurity`（小文字）です。省略すると、設定の `kernel.default_engine` のエンジンになります（`kernel.default_engine` を書いていなければ `coraza`）。これ以外の名前は、何も置かずに受け付けません（exit 2）。設定の `kernel.engines` に検査プロセスが無いときの `modsecurity` も同じです |
| `--accept-block` | 事前検証のリクエストがブロックされても、事前検証を失敗にしません（一致したルールは出力されます） |
| `--detect-only` | 検知のみの世代にします（下の「検知のみのモード」） |

- 読み込む順は、`crs/crs-setup.conf`、`crs/rules/` の `.conf`（名前のバイト順）、運用者のルールのファイル（指定した順）です。
- `--rules` と `--data` のファイルは、ディレクトリの部分を除いた名前で、ルールセットの `rules/<name>` に入ります。
  - 名前は 1〜128 文字の英数字・`.`・`_`・`-` で、`.` で始まる名前は使えません。
  - 同じ名前は、`--rules` と `--data` をまたいでも受け付けません。
  - 入力のファイルがシンボリックリンクのときと、`--crs` のディレクトリがシンボリックリンクのときも受け付けません。
- 1 つのファイルは 2 MiB まで、ルールセット全体は 128 ファイル・8 MiB までです。ディレクトリは 1024 項目まで調べます。マニフェストは 64 KiB までで、この中にファイルの一覧と検査除外のルートが入ります。
- ルールが読めるファイル（`@pmFromFile` など）は、ルールセットの中のファイルだけです。ルールには、ルールセットの中のパス（`rules/<name>` など）で書きます。
- 事前検証では、検査プロセスを 1 つ起動し、決まった 3 つのリクエスト（`GET /`、フォームのボディ `a=b` の `POST /`、JSON のボディ `{"a":"b"}` の `POST /`）を検査します。
  - 検査プロセスが `ready_wait` 以内に準備でき、どのリクエストも `inspect_wait` 以内に許可され、検査プロセスが正常に終了すれば、事前検証に通ります。
  - ブロックする世代では、事前検証のリクエストが 1 つでもブロックされると失敗にします（`--accept-block` を付けたときを除きます）。検知のみの世代では、ルールに一致しても失敗にしません。
  - 事前検証で分かるのは、ルールセットが起動し、通常の形のリクエストを通すことだけです。ルールが正しいかどうかは分かりません。
- 事前検証の間に SIGINT（Ctrl-C）か SIGTERM を受けると、事前検証を止め、検査プロセスと作業ディレクトリを片付けて、世代を作らずに終了します。事前検証が終わった後は、この 2 つのシグナルではコマンドは止まりません。
- `import` は検査プロセスを起動するので、起動前の検証（[ビルドと配置](../build/binary-deployment.ja.md) の「起動前の検証」）も実行します。

終了コードは次のとおりです。

- 0: 成功
- 1: それ以外の終了。受け付けないルールストアや入力、失敗した事前検証、使用中のルールストア、`list` でマニフェストが読めない世代（一覧は最後まで出します）や選択中の世代を決められないルールストア、設定が使っているエンジンや選択中の世代が無いエンジンの `deactivate`、root での実行を含みます
- 2: 引数のエラー、受け付けない設定ファイル（`deactivate` では、`managed` の選択中のバージョンも含みます）、または使えないエンジン（`import` と `activate`）

選択中の世代が無いルールストアの `list` は、exit 0 です。

### `managed`

```text
tukuyomi-proxy managed import <config> <document>
tukuyomi-proxy managed activate <config> <version>
tukuyomi-proxy managed remove <config> <version>
tukuyomi-proxy managed list <config>
```

managed 設定のバージョン（下の「managed 設定」）を扱うコマンドです。どれも短時間で終わり、動作中のプロキシとは別のプロセスで動きます。これらのコマンドはプロキシに依頼をしないので、動作中のプロキシは、選択中のバージョンを次の SIGHUP（`systemctl reload`）か起動のときに読み込みます。管理プロセスによる反映では、制御ソケットでプロキシに設定をリロードさせてから、バージョンを選択します（下の「managed 設定」の「反映」）。

設定ファイルには `managed` が必要です。`<version>` は、バージョンの SHA-256（64 桁の小文字の 16 進数）です。

| コマンド | すること | 標準出力 |
|---|---|---|
| `import` | 文書からバージョンを作り、managed ストアに置きます。文書が指すファイルを読み、プロキシと同じように検証して、`files/` に置きます。バージョンの選択はしません | `<version> created`、`<version> existing`、`<version> recreated, the stored copy was broken` |
| `activate` | 起動のうち、ルールストアより前の段階を実行します（設定ファイルとバージョン、アップストリームの名前解決と CA のファイル、証明書）。次に、バージョンのアップストリームが使うエンジンに選択中の世代があることを、ルールストアで確認します。通ったときだけ、バージョンを選択します（`current` を変更します）。選択中の世代が無いエンジンを使うアップストリームがあれば、`managed activate: rules store refused: no generation is chosen for the engine of an upstream (upstream <name>)` の行を出し、選択せずに拒否します（exit 1）。`import` は、この確認をしません | `<version> current` |
| `remove` | 選択中でも使用中でもないバージョンを削除します。どのバージョンも指さなくなったファイルと、ACME のサイトの証明書も片付けます。ロールバックの先かどうかは調べません | `<version> removed` |
| `list` | バージョンの一覧を出します | バージョン、ファイルの更新時刻（エポックからの秒数）。選択中のバージョンには `current` が付きます |

- `import` の文書のパスは、カレントディレクトリからの相対パスでも指定できます。文書の形は下の「managed ストアとバージョン」を参照してください。
- `import` と `activate` は、国のデータベースも読み込んで検証します。`remove` と `list` が読み込むのは、設定ファイルだけです。
- `import`・`activate`・`remove` は、managed ストアのロックを取得します。管理プロセスの反映の間など、ほかがロックを持っていれば、待たずに拒否します（`the managed store is in use by another command`）。
- `activate` は、ACME のサイトの証明書がまだ無いとき、`managed activate: tls certificate not issued yet (site <name>)` の行を出します。拒否はしません。
- `activate` で選択したバージョンは、動作中のプロキシには次の SIGHUP まで効きません。すぐに `systemctl reload` を実行し、`reload: configuration replaced <sha256> managed <version>` の行が出ることを確認してください（下の「managed 設定」の「反映」）。
- `remove` が片付けをすべては終えられなかったときは、標準エラーに `managed remove: the files that no version names were not cleaned up` の行を出し、exit 0 で終了します。バージョンは削除済みです。残ったものは次の削除でまた片付けます。
- 結果の行のほかは標準エラーに出て、コマンドの名前で始まります（`managed import: document refused: <reason>` など）。文書に書かれたパスは、0x20〜0x7e の範囲の外のバイトを `\xNN` にして出力します。

終了コードは次のとおりです。

- 0: 成功
- 1: それ以外の終了。受け付けない managed ストア・文書・ファイル、使用中の managed ストア、`activate` で名前解決できない名前や使えないファイル、`activate` が受け付けないバージョン、`remove` が拒否したバージョン、`list` で `current` が読めないか `current` が指すバージョンが無い managed ストア、root での実行を含みます
- 2: 引数のエラーか、受け付けない設定ファイル（`managed` の無い設定ファイルを含みます）

### `acme renew`

```text
tukuyomi-proxy acme renew <config>
```

- `acme` を持つ証明書を、設定の順に調べます。`managed` のある設定では、管理画面のルート、バージョンのサイトの順です（下の「ACME のサイト」）。次のどれかに当てはまる証明書は、更新が必要とみなし、新しい鍵で注文し直します。
  - 証明書か鍵のファイルが読めない
  - 鍵が証明書に合わない
  - 証明書がすべてのホストを含まない
  - 有効期間の終わりまでが `renew_before_days` 日より短い（ちょうどその日数のときは、短いとみなしません）
- 更新が必要ない証明書は、`valid` になります。
- 更新が必要な証明書が 1 つでもあれば、アカウントの鍵を読み込むか作成し、続けて CA にアカウントを作成するか、既存のアカウントを見つけます。アカウントは、CA の利用規約に同意し、`contact_email` を連絡先にして作成します。
- コマンド全体にかけられる時間は、CA の応答と待ち時間を含めて `timeout_ms` までです。時間が尽きたときは、まだ更新できていない証明書が、その後のものも含めて `failed` になります。更新が必要ない証明書は、`valid` のままです。
- 結果は `acme` を持つ証明書ごとに、標準出力に 1 行ずつ出ます。
  - `managed` の無い設定では、`<listener>.<certificate> renewed|valid|failed` の形です。リスナーと証明書の番号は、どちらも 1 から数えます。リスナーの番号は `proxy.listeners` の並びの位置で、TLS でないリスナーも数えます。
  - `managed` のある設定では、`admin route renewed|valid|failed`、`site <name> renewed|valid|failed` の形です。
  - `failed` の証明書は、ファイルを前のまま残します。
- `managed` と `acme` のある設定でも、`acme` を持つ証明書が 1 つも無いことがあります（管理画面のルートにも、バージョンのサイトにも無いとき）。そのときは結果の行を出さず、標準エラーに 1 行出して exit 0 で終了します。
- `managed` のある設定では、`current` のバージョンを読み込みます。コマンドが終了するまで、そのバージョンの削除は拒否されます。managed ストアのロックは取得しません。
- CA から受け取ったもののうち、標準エラーに出すのは、エラーの文書（problem document）の `type` だけです。
- SIGINT と SIGTERM を受けると、チャレンジのファイルを削除して、すぐに終了します。
- 動作中のプロキシは、新しい証明書を検知しません。コマンドの後に SIGUSR2 を送ります（`systemctl kill --kill-whom=main -s USR2 tukuyomi-core.service`）。
- 終了コードは次のとおりです。
  - 0: すべてが `renewed` か `valid`（`managed` のある設定で、`acme` を持つ証明書が無いときも 0 です）
  - 1: 1 つでも `failed` がある、停止された、実行できない、root で実行した
  - 2: 引数のエラー、受け付けない設定ファイル（`managed` のある設定では、プロキシが起動しない managed ストア・`current`・バージョンも含みます）、`acme` の無い設定ファイル

手順は下の「ACME」を参照してください。

### `admin`（管理プロセスのコマンド）

```text
tukuyomi-proxy admin <config>
tukuyomi-proxy admin bootstrap <config> <name>
tukuyomi-proxy admin reset <config> <name>
```

- 管理プロセスを動かすコマンド（`admin <config>`）と、管理プロセスの短時間で終わるコマンド（`bootstrap`・`reset`）です。設定ファイルに `admin` が必要です。設定キー、API、コマンドの内容は、[管理リファレンス](admin-reference.ja.md) を参照してください。
- 管理プロセスは、動作中のプロキシとは別のプロセスです。管理プロセスがプロキシに依頼できるのは、状態の問い合わせ、世代の切り替え、managed 設定のバージョンを指定した設定のリロードの 3 つだけです（下の「制御ソケット」）。
- 起動前の検証も、root で実行できないことも、プロキシと同じです（`host check refused`）。
- `admin <config>` で動作中の管理プロセスは、ログを JSON で標準エラーに出します（systemd ではジャーナルに入ります）。`bootstrap` と `reset` は、人が読むための文を行で出します。
- 終了コードは、0 が成功、1 がそれ以外の終了です。2 は引数のエラー、受け付けない設定ファイル、`admin` の無い設定ファイルです。

## シグナル

動作中のプロキシには、シグナルで停止や設定のリロードなどを指示します。シグナルはプロキシのメインプロセスだけに送ってください。検査プロセスは、SIGUSR1・SIGUSR2 は無視しますが、SIGTERM・SIGINT・SIGHUP が届くと終了します。

systemd では、`systemctl reload` か `systemctl kill --kill-whom=main` を使います。`systemctl reload` を使えるのは、ユニットの `ExecReload` が、`config check` の後にメインプロセスへ SIGHUP を送る形になっているときです。

| シグナル | すること |
|---|---|
| SIGTERM、SIGINT | 停止します（下の「停止」） |
| SIGHUP | 設定ファイルをリロードし、停止せずに新しい設定に切り替えます |
| SIGUSR1 | エンジンを 1 つずつ、ルールストアでそのエンジンの選択中の世代に切り替えます。選択中の世代があって稼働していないエンジンは、起動します |
| SIGUSR2 | すべての TLS のリスナーについて、証明書と鍵のファイルを再読み込みします（`managed` のある設定では、`admin.route` の証明書と、managed ストアのサイトの証明書） |

以前のバージョンは、SIGHUP を受けると停止します。そのような以前のバージョンから入れ替えるときは、新しい実行ファイルを入れてから、ユニットを変更してください（[ビルドと配置](../build/binary-deployment.ja.md) の「systemd」）。

### SIGHUP（設定のリロード）

- 起動のときと同じパスの設定ファイルを、別のスレッドで読み込みます。`managed` があれば、その時点の選択中のバージョン（`current`）も一緒に読み込みます。
- 起動の段階のうち、ルールストアより前の段階（設定ファイルとバージョン、アップストリームのサーバーの名前解決と `ca_file`、リスナーの証明書と鍵、ACME のチャレンジ、`geo` の国のデータベース）を、起動と同じ検証で実行します。このときのログの行は `reload:` で始まります。
- 制御ソケットの `reload` の依頼も、同じ手順で設定をリロードします（`current` の代わりに、依頼で指定されたバージョンを読み込みます。下の「制御ソケット」）。リロードは一度に 1 つだけです。
- 検証がすべて通り、動作中に変更できない設定キー（下）がどれも起動のときと同じなら、新しい設定に一度に切り替えます。最後に、`reload: configuration replaced <sha256>` の行を出します（`managed` のある設定では `reload: configuration replaced <sha256> managed <version>`）。どのファイルとバージョンが効いているかは、この値で確認できます。
- どこかで拒否したときは、何も変更せずに理由の行を出します（`reload: configuration refused: <reason>`、`reload: upstream refused: <reason>`、`reload: tls refused: <reason>`、`managed` のある設定では `reload: managed store refused: <reason>`・`reload: managed version refused: <reason>` など）。拒否の行に、ファイルの値は出しません。
- 新しい設定のアップストリームのエンジンが、稼働していないときや準備ができていないときも、何も変更せずに拒否します（`reload: configuration refused: the engine of an upstream is not ready (upstream <name>)`。`<name>` はそのアップストリームの名前です）。リロードは検査プロセスを起動しないので、そのエンジンは先に SIGUSR1 で起動しておきます（下の「SIGUSR1（世代の切り替え）」と「エンジンごとの選択中の世代」）。制御ソケットの `reload` の依頼では、この拒否は `reason` が `fixed` になります。
- 切り替えても拒否しても、`tukuyomi_config_reloads_total` に数えます（`replaced`、`refused`）。制御ソケットの `reload` で始めたリロードも、同じように数えます。
- 動作中に変更できるのは、次のものです。
  - `proxy` の設定キー（下の、変更できない設定キーを除きます）、リスナー（追加、削除、並べ替え、TLS と証明書、`http2`、`redirect`）
  - `forward`（アップストリームとルート）。アップストリームのサーバーの名前は、リロードのたびに名前解決をやり直します。アップストリームの `engine` は、変更後のエンジンが稼働していれば変更できます。`managed` のある設定では、バージョンのサイト、アップストリーム、ルート、デフォルトのアップストリームがこれに当たります
  - アップストリームの `ca_file`、リスナーの証明書と鍵、ACME のチャレンジ
  - 全体の `access`・`rate_limit`、`host_policies`、`geo`（国のデータベースを読み込みます）
  - 管理画面のルートの証明書と `access`
  - `records.keep`
- 動作中に変更できない設定キーは、`proxy.max_conns`、`max_buffered_bytes`、`drive_slice_ms`、`ready_wait_ms`、`stop_inspect_ms`、`stop_wait_ms`、`records`（`keep` を除くすべてと、有無）、`status`、`admin`、`admin.route.host`、`rules.store`、`managed`（有無と `dir`）、`kernel`（`default_engine` を含むすべて）です。どれかが起動のときと違えば、設定の全体を拒否します（`reload: configuration refused: <key> cannot change while running`）。これらを変更するときは、再起動してください。
  - `records`・`status`・`admin`・`rules.store`・`managed`・`kernel` を変更できないのは、管理プロセスとログ送信プロセスも、起動のときに同じファイルからこれらを読み込むためです。プロキシだけが変更すると、値が一致しなくなります。`admin.route.host` は、管理プロセスが起動のときに読み込む `admin.origin` と合わせて使うので、変更できません。
- 接続の扱いは次のとおりです。
  - 切り替えた後に受け付けた接続は、新しい設定を使います。開いている接続は、受け付けたときの設定を使い続け、次のように閉じます。リクエストは拒否しません。
  - HTTP/1.1: 応答した後で次のリクエストを待っている接続は、すぐに閉じます。応答の途中の接続は、その応答に `Connection: close` を付けて閉じます。受け付けたばかりの接続と、次のリクエストのヘッダー部を受信している途中の接続は、そのリクエストに応答してから閉じます。
  - HTTP/2: `GOAWAY` を送り、開いているストリームが終了してから閉じます。
  - WebSocket のトンネルとルートの `stream` の応答は、前の設定のまま、それぞれのタイムアウトまで続きます。
- リスナーの扱いは次のとおりです。
  - 新しい設定のアドレスのうち、今は待ち受けていないものを、切り替える前にすべてバインドします。1 つでもバインドできなければ、全体を拒否します（`reload: configuration refused: listener <number> cannot be bound`。番号は新しい設定の中の位置で、1 から数えます）。
  - 新しい設定にも残るアドレスは、同じソケットのまま、新しい並びの位置へ移ります。そのアドレスへの接続は拒否しません。
  - 無くなったアドレスは、切り替えた後に閉じます。そこでまだ始まっていない接続（システムのバックログにあるもの、接続のスロットを待っているもの）は切断されます。開いている接続は、上のとおり続きます。
  - 今待ち受けているアドレスと重なるアドレスはバインドできないので、全体を拒否します。たとえば、`0.0.0.0:8080` で待ち受けているときの `127.0.0.1:8080`（逆も同じ）や、`127.0.0.1:8080` で待ち受けているときの `[::ffff:127.0.0.1]:8080` です。このように変更するときは、削除するリロードと追加するリロードに分けるか、再起動してください。
  - ログの `listener` は、その接続を受け付けたときの設定での番号です。並びを変更した後は、同じ番号が別のリスナーを指すことがあります。
- 持ち越すものと、作り直すものは次のとおりです。
  - レート制限のテーブルは、テーブルごとに持ち越します（下の「レート制限（`rate_limit`）」と「ホストごとの設定（`host_policies`）」）。全体のテーブルが続くのは、新旧の両方に全体の `rate_limit` があり、`keys`・`rate`・`burst` がどれも同じときです（`exempt_cidrs` は新しい値を使います）。どれかが違うときや片方に無いときは、新しいテーブルで 0 から数え、`reload: rate limit table started anew` の行を出します。
  - アップストリームのダウン判定と失敗の数、アップストリームへの待機中の接続、リスナーの TLS のセッションは作り直します。`tukuyomi_upstream_failures_total` は、0 から数え直します。
  - ルールの世代には触れません。稼働中の世代はそのままで、ルールストアも読み込みません（世代を切り替えるのは SIGUSR1 です）。エンジンも起動せず、新しい設定のアップストリームが使うエンジンの準備ができていることだけを確認します（上の拒否）。
- ファイルの内容とバージョンが前と同じでも、上のとおり作り直し、待っている接続を閉じます。
- リロードの途中に受けた SIGHUP は、`reload: a configuration reload is in progress, ignored` の行を出すだけです。シグナルの処理が有効になってからリスナーをバインドするまでの間と、停止の間に受けた SIGHUP も、行を 1 つ出すだけです。リロードの途中に制御ソケットで受け付けた `reload` の依頼には、`busy`（`reload under way`）で応答します。
- リロードの途中に SIGUSR2 を受けたときは、リロードが終わった後に、その時点の設定の証明書を読み込みます（切り替えたときも、拒否したときも同じです）。`reload: SIGUSR2` の行は、そのときに出ます。
- リロードの途中に停止が始まったら、リロードは破棄します。
- SIGHUP の処理が有効になる前（起動の 6 より前）に届いた SIGHUP は、ほかのシグナルと同じく、プロキシを終了させます。

### SIGUSR1（世代の切り替え）

- プロキシは、エンジンごとにルールストアを読み込み、選択中の世代が稼働中の世代と違うエンジンを切り替えます。切り替えは、デフォルトのエンジンが先で、ほかは名前の順に 1 つずつ行います。1 つの切り替えが終わってから、次のエンジンを始めます。
  - 切り替えでは、選択中の世代で、新しい検査カーネルと検査プロセスを起動します。新しい方の準備ができたら、そのエンジンの新しいリクエストを、そちらへ振り向けます。
  - 古い方は、持っているリクエストを `stop_inspect` まで検査してから停止します。
  - 新しい方が起動に失敗するか、`ready_wait` 以内に準備できなければ、切り替えは失敗です（`reload: generation <fingerprint> failed to start: <reason>` の行を出します）。古い方が、そのまま検査を続けます。
  - 新しい検査プロセスは、そのエンジンの実行ファイルで起動します（Coraza は `kernel.inspector`、ModSecurity は `kernel.engines`）。
  - 選択中の世代のエンジンが使えないときは、切り替えません。`reload: rules store refused: <reason>` の行を出し、古い方がそのまま検査を続けます。`rules activate` と管理プロセスは、そのような世代を選択しません。
- 選択中の世代があって稼働していないエンジンは、同じ切り替えで起動します。起動に失敗したときは、そのエンジンは稼働していないままです。
  - 選択中の世代が稼働中の世代と同じエンジンは、`reload: generation <fingerprint> is already running` の行を出して、次のエンジンへ進みます。
  - 稼働していないエンジンに選択中の世代が無いときは、何もしません（行も出しません）。
  - 稼働しているエンジンに選択中の世代が無いとき（`rules deactivate` の後など）は、`reload: rules store refused: no generation is chosen` の行を出し、`tukuyomi_rules_switches_total` の `refused` に数えます。そのエンジンは稼働し続けます。
- 準備の後に検査カーネルが失敗すると、プロキシ全体が停止します。SIGUSR1 で起動したエンジンも、どのアップストリームも使わないエンジンも同じです（下の「`kernel`」と「検査エンジンの選択」）。
- 検査除外のルートのテーブルは、エンジンごとにあります。新しい世代がリクエストを受け付け始めるときに、そのエンジンのテーブルも一緒に入れ替わります。
- 切り替えの間は、そのエンジンの検査プロセスが 1 つ増えます。切り替えはプロキシ全体で同時に 1 つだけなので、増えるのは 1 つまでです。メモリの目安は、下の「検査エンジンの選択」を参照してください。
- シグナルの処理が有効になってからリスナーをバインドするまでの間、切り替えの途中、停止の間に受けた SIGUSR1 は、ログに行を 1 つ出すだけで何もしません（切り替えの途中は `reload: a switch is in progress, ignored`）。先の SIGUSR1 でまだ切り替えていないエンジンがあるときは、途中の切り替えが終わってから続けます。
- プロキシは世代を使っている間、エンジンごとに稼働中の世代の目印（ルールストアの `using/<fingerprint>`）に共有ロックを持つので、`rules remove` は使用中の世代を削除できません。
- 管理プロセスは、制御ソケットでも、エンジンを指定して同じ切り替えを依頼できます（下の「制御ソケット」）。切り替えの手順と `tukuyomi_rules_switches_total` の数え方は、SIGUSR1 と同じです。

### SIGUSR2（証明書の再読み込み）

- 再読み込みしたすべての証明書と鍵が検証に通ったときだけ、まとめて入れ替えます（検証の内容は、下の `proxy.listeners` の `cert_file`・`key_file`）。新しいものを使うのは、入れ替えた後に始まるハンドシェイクからです。開いている接続は、それまでのものを使い続けます。
- `managed` のある設定では、`admin.route` の `cert_file`・`key_file` と、managed ストアのサイトの証明書を再読み込みします（ACME のサイトは、`acme/` にあるその時点のファイル）。この設定のリスナーには、`certificates` がありません。
- 1 つでも検証に通らなければ、どれも入れ替えません。どれが通らなかったかは、ログの行に出ます。
- `acme` を持つ証明書は、ファイルが無くても、入れ替えを拒否する理由になりません。そのような証明書は、ログに行を出してハンドシェイクの対象から外し、ファイルができた後の SIGUSR2 で使い始めます。動作中にファイルを削除してから SIGUSR2 を送ったときも、その証明書はハンドシェイクの対象から外れ、そのホストへの接続は失敗します。
- アップストリームの CA のファイルは、SIGUSR2 では再読み込みしません（SIGHUP でリロードします）。
- 証明書と鍵だけを再読み込みさせたいとき（ACME の更新の後など）は、SIGHUP ではなく SIGUSR2 を送ります。SIGHUP は設定ファイルの全体を読み込むので、書きかけの設定を読み込んでしまうことがあります。
- シグナルの処理が有効になってからリスナーをバインドするまでの間と、停止の間に受けた SIGUSR2 は、ログに行を 1 つ出すだけです。SIGUSR1 とは関係しません。

### リロードしないもの

次のものは起動のときに読み込み、プロキシを再起動するまでそのままです。

- 上の「SIGHUP（設定のリロード）」にある、動作中に変更できない設定キー（`records` の保存先とサイズ、`status`、`admin` の制御ソケットのパス、`admin.route.host`、`rules.store`、`managed`、`kernel` など）
- 管理プロセスとログ送信プロセスは、設定をリロードしません。どちらも SIGHUP を受けると停止します。設定を変更したら、この 2 つも再起動してください（[管理リファレンス](admin-reference.ja.md)、下の「ログ送信プロセス」）。

## 停止

停止は次の順に進みます。ここでは、最初の停止の理由（シグナル、起動かドライバーの失敗）が起きた時刻を t0 とします。

1. リスナーを閉じ、新しいリクエストを拒否します。制御ソケットも閉じて、そのファイルを削除します（応答を待っていたクライアントは、応答を受け取りません）。次のリクエストを待っている接続は閉じます。`/readyz` は 503 `stopping` になります。`NOTIFY_SOCKET` があれば、`STOPPING=1` を送ります。
2. 検査は `t0 + stop_inspect` までに終えます。
3. 接続の終了は `t0 + stop_wait` まで待ち、残った接続は打ち切ります。WebSocket のトンネルは、停止が始まっても終了しないので、このときに打ち切られます。この後に監視用のリスナーを閉じます。
4. 起動しているエンジンの検査カーネルが、すべて終了するのを `t0 + stop_wait + kill_grace` まで待ちます。
5. ログを最長 200 ms 書き出して、終了します。

最後に `stop: kernel ..., bye ..., exit_confirmed ..., dir_removed ..., held_left ..., waiting_left ..., results ..., retired_clean ...` の行が出ます。検査カーネルの終了が確認できなかったときは、代わりに `stop: the driver stopped: ...` か `stop: the driver gave no end` が出ます。

- その前に、起動しているエンジンごとに、`driver: stop, engine <engine>, records <count>, held <count>, waiting <count>` の行が出ます。
- `stop: kernel` の行は 1 つだけです。`bye`・`exit_confirmed`・`dir_removed` などは、起動しているエンジンのうち、名前の順で最初のエンジンの値です。ほかのエンジンと、切り替えで前に停止した検査カーネルの結果は、`retired_clean` にまとめて出ます。
- `bye true` は、検査プロセスが終了の通知を送ってから終了したことを示します。
- 終了コードが 0 になるのは、停止の理由が失敗でなく、停止したすべての検査カーネルで検査プロセスの終了と作業ディレクトリの削除が確認できたときだけです。この検査カーネルには、ほかのエンジンのものと、切り替えで前に停止したものも含みます。

## 設定ファイル

### 全体の構成

```text
{"proxy": {..}, "forward": {..}, "kernel": {..}, "rules": {"store": {..}}, "acme": {..}, "status": {..}, "records": {..}, "access": {..}, "rate_limit": {..}, "host_policies": [..], "geo": {..}, "admin": {..}, "managed": {..}}
```

- `acme`、`status`、`records`、`access`、`rate_limit`、`host_policies`、`geo`、`admin`、`managed` は省略できます（下のそれぞれの節）。

- 設定ファイルは UTF-8 の JSON で、1 つのオブジェクトです。大きさは 256 KiB までです。
- 値にデフォルト値はありません。省略できると書いた設定キーのほかは、すべて書いてください。
- 未知の設定キー、同じ設定キーの重複、型が違う値、オブジェクトの代わりの配列は受け付けません。省略できる設定キーに `null` を書くことも受け付けません。省略するか、値を書いてください。
- 受け付けないときのメッセージは、エラーの種類ごとに決まった英語の 1 文です。ファイルの値は含みません。
  - 形のエラー（JSON でない、設定キーが無い・未知・重複、型の違い）は、どの設定キーかを示しません。
  - 値の範囲や、値どうしの関係のエラーは、違反した決まりの設定キーの名前を示します（例: `max_conns is out of range`）。
  - 値は決まった順に検証し、最初に違反した決まりを返します。
- 設定の中のパスは、どれも絶対パスで書きます。`.`・`..`・空の要素・末尾の `/` は含めません。
- 時間は、名前が `_ms` で終わる設定キーに、ミリ秒の整数で書きます。
- バイト数の設定キーでは、1 KiB は 1024、1 MiB は 1048576 です。
- `acme` を書くかどうかは、`managed` の有無で変わります。
  - `managed` の無い設定ファイルでは、`acme` を持つ証明書があるときだけ書きます。そのときは必ず書きます。
  - `managed` のある設定ファイルでは、`acme` を持つ管理画面のルートの証明書があれば必ず書き、無くても書けます。ACME のサイトはバージョンの中にあるためです（下の「ACME のサイト」）。
- `geo` は、国の指定（全体の `access`、`host_policies` の `access`、ルートの `access` の `deny_countries`・`allow_countries`）が 1 つでもあるときは、必ず書きます。`managed` のある設定では、バージョンの国の指定にも必要です。
- `managed` のある設定ファイルでは、`forward` は `resolve_timeout_ms` だけになります。TLS のリスナーの `certificates`、全体の `access`・`rate_limit`、`host_policies` も書けません（書けば受け付けません）。これらはバージョンに書きます。`admin` があれば、`admin.route` が必要です（下の「managed 設定」）。

### 例

次の例は、TLS のリスナー（HTTP/2 と ACME の証明書）、https へのリダイレクトのリスナー、1 つのアップストリーム、ログファイル、レート制限を持つ設定です。省略できる設定キーのうち、この例に入れたのは `acme`、`records`、`rate_limit` だけです。ほかの設定キーは、下のそれぞれの節を参照してください。値は動かすときの目安で、受け付ける範囲は下の表にあります。

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
  },
  "records": {
    "dir": "/var/lib/tukuyomi-core/records",
    "file_bytes": 16777216,
    "files": 8
  },
  "rate_limit": {
    "rate": 50,
    "burst": 100,
    "keys": 65536,
    "exempt_cidrs": ["192.0.2.0/24"]
  }
}
```

### `proxy`: 接続とサイズ

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `listeners` | 1〜8 個 | リスナー（下の `proxy.listeners`） |
| `max_conns` | 1〜65536 | 同時に持つクライアントの接続の数。すべてのリスナーを合わせて数えます |
| `max_head_bytes` | 1024〜32768 | リクエストのヘッダー部の上限（バイト数）。超えると 431 です。リクエストラインの終わりが現れないまま上限に達したときは、414 です |
| `max_body` | 1 KiB〜4 GiB | リクエストのボディの上限（伸長した後の長さ）。超えると 413 です。検査するルートの gzip のボディは、`inspect_body` までです（下の「リクエストボディの上限と検査する長さ」）。検査除外のルートの gzip のボディは伸長しないので、送られたままの長さで数えます |
| `inspect_body` | 1 KiB〜1 MiB、かつ `max_body` 以下 | ボディの先頭から検査するバイト数。これより長いボディは、残りを検査せずに流します |
| `max_body_wire` | `max_body` 〜 `2 × max_body + 4 MiB` | chunked のボディの、回線上のバイト数の上限（チャンクのサイズ行と区切りを含みます）。超えると 413 です |
| `max_buffered_bytes` | `2 × inspect_body + 24 KiB + 32 KiB` 〜 4 GiB | リクエストがバッファリングするバイトの予算の合計（下の「リクエストボディの上限と検査する長さ」）。尽きると 503 です |
| `upstream_max_headers` | 1〜1024 | アップストリームが返す応答で、ヘッダー部に含まれるフィールド数の上限 |
| `upstream_max_head_bytes` | 8192〜1 MiB | アップストリームが返す応答の、ヘッダー部の上限（バイト数）。アップストリームとの接続で使う読み取りバッファーのサイズにもなります |
| `upstream_head_wire` | `2 × upstream_max_head_bytes` 〜 4 MiB | アップストリームから、最後の応答のヘッダー部までに読み込むバイト数の上限（1xx を含みます） |
| `trusted_proxies` | 0〜256 個のネットワーク | `X-Forwarded-For` を信頼する相手（下の「クライアントのアドレス」）。空なら、接続の相手がいつもクライアントです。ホスト部が 0 の `address/prefix` で書きます（`10.1.2.3/24` や、プレフィックスの無いアドレスは受け付けません） |
| `upstream_keepalive` | 0〜1024 | アップストリームごとの、再利用を待つ接続の数。アップストリームのサーバーすべてを合わせて数えます。0 なら、応答の後に閉じます |
| `upstream_keepalive_requests` | 1〜1000000 | アップストリームへの 1 本の接続で送るリクエストの数の上限 |
| `keepalive_requests` | 1〜1000000 | クライアントの 1 本の接続で受け付けるリクエストの数の上限。最後のリクエストの応答で、接続を閉じます。HTTP/2 では目安です（下の `http2`） |
| `lingering_bytes` | 1〜4 MiB | 接続を閉じる前に、読み込んで捨てるバイト数の上限 |

### `proxy`: 時間

範囲はどれも 1 ms〜3600 s です。ただし、`keepalive_timeout_ms` は 0 も指定でき、`conn_total_ms` は 24 時間まで指定できます。

| 設定キー | 意味 |
|---|---|
| `drive_slice_ms` | 検査のドライバーが、仕事のあるエンジンの検査カーネルを 1 回に動かす時間。仕事の無いエンジンの検査カーネルは、最短のステップ（1 ms）で動かします。新しいリクエストは動かす回と回の間に受け付けるので、ほかのリクエストがあるときに新しいリクエストが待つ最長の時間は、この時間に仕事のあるエンジンの数を掛けた時間が目安です。推奨値は 1 です |
| `ready_wait_ms` | 検査カーネルの準備を待つ時間（起動、世代の切り替え、`rules import` の事前検証） |
| `head_read_ms` | リクエストのヘッダー部を読み終える時間。接続の最初のヘッダー部は `accept` から数えます（TLS のハンドシェイクを含みます）。2 つ目以降のヘッダー部は、その最初のバイトから数えます。HTTP/2 のヘッダーブロックは、`HEADERS` フレームの最初のバイトから数えます |
| `body_read_ms` | ボディの先頭（`inspect_body` まで、またはボディ全体）を読み終える時間で、ヘッダー部の終わりから数えます。それより長いボディの残りでは、読み込みと読み込みの間がこの時間を超えると切断します |
| `inspect_wait_ms` | リクエストが検査の結果を待つ時間 |
| `upstream_connect_ms` | アップストリームへの接続を作る時間（TLS のハンドシェイクを含みます） |
| `upstream_header_ms` | リクエストをアップストリームへ送り始めてから、応答のヘッダー部を受信するまでの時間。送信の時間を含みます。ボディを流すリクエストでは、最後の断片をアップストリームの接続へ渡したときから数えます |
| `request_total_ms` | リクエストの始めから応答のヘッダー部までにかかる時間の上限。ボディを受信する時間と検査の時間も含みます。応答のボディを流す時間は含みません。接続の最初のリクエストは `accept` から数えます（TLS のハンドシェイクを含みます）。2 つ目以降のリクエストは、最初のバイトと前の応答のうち、遅い方から数えます |
| `response_idle_ms` | アップストリームへの接続で通信が無くてよい時間と、クライアントが受信しない時間の上限。応答のボディの間だけでなく、アップストリームの応答のヘッダー部を待つ間にも効きます（ボディを流すリクエストでは、応答のヘッダー部が来るまでは効きません）。そのため、ボディをバッファリングするリクエストでは、`upstream_header_ms` をこれより長くしても効きません |
| `conn_total_ms` | クライアントの 1 本の接続が続く時間の上限（`accept` から数えます）。これを超えて続けられるのは、`stream` を持つルートの応答だけです |
| `stop_inspect_ms` | 停止のときに、検査を終えるまでの時間（上の「停止」） |
| `stop_wait_ms` | 停止のときに、接続の終了を待つ時間 |
| `keepalive_timeout_ms` | 応答の後に、次のリクエストを待つ時間。0 なら、応答のたびに閉じます |
| `keepalive_time_ms` | 接続を再利用できる時間（`accept` から数えます）。この時間を過ぎてから応答するリクエストでは、その応答で接続を閉じます |
| `lingering_time_ms` | 接続を閉じる前に、クライアントがまだ送るものを読み込んで捨てる時間の上限 |
| `lingering_timeout_ms` | 接続を閉じる前に、次の読み込みを待つ時間の上限。HTTP/2 では、`GOAWAY` の後にクライアントを待つ時間と、ストリームの無い接続を残す時間にもなります |
| `upstream_keepalive_timeout_ms` | アップストリームへの接続が、再利用を待つ時間 |

### `proxy.listeners`

1 つのリスナーは `{"address", "tls"?, "redirect"?}` です。

- `address`: IP リテラルとポート（IPv6 は `[..]:port`）。ポート 0 は受け付けません。
- `tls` も `redirect` も無いとき: 通常のリスナーです。HTTP で受け付け、アップストリームへ転送します。
- `tls` があるとき: TLS を終端してから、通常のリスナーと同じことをします。
- `redirect` があるとき: すべてのリクエストに、https へのリダイレクト（308）か 404 で応答します。何も転送しません。全体の `access` や `rate_limit`、ホストごとの設定に拒否されたクライアントには、403 か 429 で応答します（下の「アクセス制御とレート制限」）。
- `tls` と `redirect` は、一緒に書けません。
- リスナーどうしには、次の決まりがあります。
  - 通常のリスナーか `tls` のリスナーが、少なくとも 1 つ必要です。
  - `redirect` のリスナーがあるなら、`tls` のリスナーも必要です。
  - 2 つのリスナーに、同じアドレスは書けません。片方が `0.0.0.0` や `::` で、もう片方と同じポートのものも書けません。

`tls` は `{"min_version", "certificates", "http2"?}` です。`managed` のある設定ファイルでは `{"min_version", "http2"?}` になり、`certificates` を書くと受け付けません（`a tls listener has certificates while the configuration has managed`）。この場合、証明書は managed 設定のバージョンのサイトと `admin.route` に書きます（下の「managed 設定」）。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `min_version` | `"1.2"`、`"1.3"` | 受け付ける TLS の最も古いバージョン。TLS 1.3 は、いつも受け付けます |
| `certificates` | 1〜16 個 | `{"cert_file", "key_file", "hosts", "acme"?}` |
| `cert_file`、`key_file` | 絶対パス、3840 バイトまで | 証明書のチェーンと秘密鍵のファイル。読み込むのは、起動のとき、SIGHUP と制御ソケットの `reload` によるリロードのとき、SIGUSR2 による再読み込みのときです |
| `hosts` | 1〜64 個 | 証明書に含まれる名前（小文字の英字・数字・`-`・`.`）か、`*.` と名前。IP リテラルは書けません。1 つのリスナーの中で、同じホストは 1 回だけ書けます |
| `acme` | `{"renew_before_days"}`（1〜60） | `acme renew` で発行・更新する証明書であることを示す設定。ホストに `*.` は書けません。ファイルは起動のときに無くてもかまいません |
| `http2` | オブジェクト | HTTP/2 を受け付けます（下の `http2`）。無ければ、HTTP/1.1 だけを受け付けます |

- `cert_file` と `key_file` は、読み込むたびに次を検証します（起動のとき、SIGHUP と制御ソケットの `reload` によるリロード、SIGUSR2 による再読み込み）。
  - どちらも、1 MiB までの通常のファイルです。
  - 証明書のファイルは PEM の証明書を 1〜10 枚持ち、先頭がホストの証明書です。鍵のファイルは、鍵をちょうど 1 つ持ちます。
  - 鍵が先頭の証明書と対になり、先頭の証明書が `hosts` のすべてを含みます。
  - 有効期間は検証しません。
- ハンドシェイクでは、クライアントが送ったサーバー名をもとに、`hosts` から証明書を選びます。名前で書いたホストが、ワイルドカードより先に一致します。サーバー名の無いハンドシェイクと、合うホストの無いハンドシェイクは失敗します。
- `*.` と名前は、名前の前のちょうど 1 つのラベルに一致します（`*.a.example` は `www.a.example` に一致し、`a.example` と `x.y.a.example` には一致しません）。英字の大小は区別しません。
- TLS の接続のリクエストでは、`Host` がハンドシェイクで使った証明書のホストに入っていなければ、421 で応答します。この検証は、全体の `access` と `rate_limit`、ホストごとの設定の後、ルートを選ぶ前に行います。

`http2` の 5 つの設定キーは、すべて書きます。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `max_streams` | 1〜256 | クライアントが同時に開けるストリームの数 |
| `stream_window` | 65535〜1 MiB | ストリームの受信ウィンドウ |
| `connection_window` | 65535〜4 MiB | 接続の受信ウィンドウ |
| `max_header_list` | 1 KiB〜`4 × max_head_bytes` | リクエストのヘッダーフィールドを展開した後のサイズ |
| `send_buffer` | 1 KiB〜1 MiB | ストリームごとに、送信を待つ応答のバイト数 |

- 1 本の接続が保持できる量にも、上限があります。
  - `connection_window + max_streams × (send_buffer + 32 KiB)` は、16 MiB までです。
  - さらに、ストリームごとに `max_header_list` と `upstream_max_head_bytes` を加えても、16 MiB までです。
- この量は `max_buffered_bytes` には入りません。接続ごとにこれだけ持てるので、全体では `max_conns` 倍になります。たとえば上の例の値では 1 本あたり約 12.3 MiB で、256 本なら約 3 GiB になる可能性があります。これらの値は、`max_conns` と合わせて決めてください。
- HTTP/2 では、`keepalive_requests` と `keepalive_time_ms` は目安です。
  - クライアントが、接続を閉じる通知（`GOAWAY`）の前に同じ書き込みで送ったストリームは、受け付け済みになります。
  - `GOAWAY` の後も、`lingering_timeout_ms` の間は新しいストリームを受け付けます。
- HTTP/2 を扱うのは、TLS のリスナーで、クライアントがハンドシェイクで `h2` を選んだときだけです。平文の HTTP/2（h2c）は扱いません。

`redirect` は `{"https_port"}`（1〜65535）です。

- リダイレクト先は `https://<host>:<https_port><target>` です。`<target>` は受信したままです。`https_port` が 443 なら、ポートは書きません。`Host` に書かれたポートは使いません。
- リダイレクトするのは、`Host` が、どれかの TLS のリスナーにある証明書のホストに入っていて、ルート（またはデフォルトのアップストリーム）がリクエストに一致するときだけです。
- `Host` が IP リテラルのとき、読めないとき、上の条件に当てはまらないときは、404 になります。
- ボディは読み込みません。
- 全体の `access` と `rate_limit`、ホストごとの設定に拒否されたクライアントには、リダイレクトも 404 も返さずに 403 か 429 で応答します（下の「アクセス制御とレート制限」）。この判定は、ACME のチャレンジの後、リダイレクトの前に行います。管理画面のルート（`admin.route`）のホストは、これらの判定をせずにリダイレクトします。
- ACME のチャレンジのリクエストには、リダイレクトより先に応答します（下の「ACME」）。

### `forward`

```text
{"resolve_timeout_ms", "upstreams": {"<name>": {..}}, "routes": [..], "default_upstream"}
```

`managed` のある設定ファイルでは、`forward` は `{"resolve_timeout_ms"}` だけです。`upstreams`・`routes`・`default_upstream` を書くと受け付けません（`forward has upstreams, routes or default_upstream while the configuration has managed`）。アップストリーム、ルート、デフォルトのアップストリームは、managed 設定のバージョンに同じ形で書きます（下の「managed 設定」）。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `resolve_timeout_ms` | 1 ms〜3600 s | アップストリームのサーバーの名前解決を終える時間。起動のときと、SIGHUP と制御ソケットの `reload` によるリロードのときに使います。制御ソケットの `reload` の依頼と、管理プロセスの反映が、応答を待つ時間にも効きます（下の「制御ソケット」と「managed 設定」の「反映」） |
| `upstreams` | 1〜64 個 | アップストリームの名前（1〜64 文字の英字・数字・`-`・`_`）から `{"servers", "tls"?, "engine"?}` への対応 |
| `routes` | 0〜1024 個 | リクエストの `Host` とパスから、アップストリームを選ぶルート |
| `default_upstream` | アップストリームの名前か空の文字列 | どのルートにも一致しないリクエストのアップストリーム。空なら、そうしたリクエストは 404 になります |

サーバーは `{"address", "weight", "max_fails", "fail_timeout_ms", "backup"}` で、すべての設定キーを書きます。1 つのアップストリームに、1〜64 個書けます。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `address` | IP リテラルとポート、または名前とポート（`name:port`） | 名前は、小文字の英字・数字・`-`・`_`・`.` で、253 バイトまでです。各ラベルは 1〜63 バイトで、最後のラベルは英字で始まります。ポートは 1〜65535 で、先頭に 0 を付けません。IP リテラルには、未指定アドレス（`0.0.0.0`、`::`）、マルチキャストアドレス、リスナーのアドレス（リスナーが未指定アドレスなら、そのポートのループバック）は書けません。プロキシのルートから管理プロセスへ到達できるようにするため、管理プロセスのリスナー（`admin.listen`）は書けます。`managed` のある設定のバージョンには書けません（管理画面へは `admin.route` で入ります） |
| `weight` | 1〜100 | 重み |
| `max_fails` | 0〜100 | `fail_timeout_ms` の間にこの回数失敗したら、サーバーを `fail_timeout_ms` の間除外します。0 なら数えません |
| `fail_timeout_ms` | 1 ms〜3600 s | 上の失敗を数える時間と、除外する時間 |
| `backup` | true、false | ほかのどのサーバーも使えないときだけ使います |

- 名前を名前解決するのは、起動のときと、SIGHUP と制御ソケットの `reload` によるリロードのときです。その間は名前解決をやり直しません（SIGUSR1 でもやり直しません）。
  - 名前のアドレスが変わったら（コンテナの名前など）、SIGHUP でリロードします。
  - 名前解決で得たアドレスは、どれもアップストリームのサーバーになります。これらのサーバーは、書いたサーバーと同じ設定の値を持ちます。名前解決した後のアップストリームのサーバーは、64 個までです。
  - 名前が解決できないとき、アドレスが無いとき、未指定・マルチキャスト・リスナーのアドレスを指すとき、時間内に名前解決を終えられないときは、起動しません。SIGHUP のリロードでは、その設定を拒否します。
- サーバーは、使えるサーバーの中から、重みに合わせて順に選びます（smooth weighted round robin）。
- アップストリームのサーバーが 1 つだけなら、除外しません。アップストリームのどのサーバーも使えないときは、何も試さずに 502 で応答します。
- 次のときは、サーバーの失敗として数えます。
  - 接続を拒否された・切断された、到達できない、`upstream_connect_ms` 以内に接続できない（TLS のハンドシェイクの失敗も含みます）
  - リクエストを送信できない、`upstream_header_ms` 以内に応答のヘッダー部が来ない、ヘッダー部の途中で切断された
- 読み取れない応答、大きすぎる応答、アップストリームが返したステータスコードは、サーバーの失敗にしません。
- 再利用を待っていた接続でリクエストを送信できなかったときは、待っている間にサーバーが接続を閉じただけかもしれないので、サーバーの失敗に数えません。2 回送っても問題の無いメソッドは、同じサーバーへの新しい接続で、1 回だけ送り直します。ほかのメソッドは送り直さず、502 で応答します。
- 失敗の後に次のサーバーへ回すのは、次の 2 つのときだけです。
  - 接続が作れなかった（何も送っていません）
  - 2 回送っても問題の無いメソッド（GET、HEAD、OPTIONS、PUT、DELETE、TRACE）
- ボディを流すリクエストは、接続が作れなかったときのほかは、送り直しません。
- 次のときは、サーバーの失敗にせず、ほかのサーバーへも回しません。
  - リクエストの時間（`request_total_ms`）が尽きて切断された段階。遅いクライアントのせいで、サーバーが除外されないようにするためです
  - プロキシ自身が接続を作れないとき（ファイルディスクリプターやポートが尽きたなど）。503 で応答します

アップストリームの `tls` は `{"ca_file", "server_name"?}` です。

- アップストリームのすべてのサーバーへ、TLS で接続します。サーバーの証明書は必ず検証します。検証を外す設定はありません。
- `ca_file` は、信頼するルート証明書を持つ PEM のファイルです。パスは絶対パスで、3840 バイトまでです。ファイルは 1 MiB までで、証明書を 1〜100 枚持ちます。読み込むのは起動のときと SIGHUP のリロードのときで、SIGUSR2 では読み込みません。
- `server_name` は小文字の名前で、TLS で使える形でなければなりません。`server_name` があれば、サーバーをその名前で検証します。無ければ、サーバーに書いた名前で検証します。IP リテラルで書いたサーバーは、そのアドレスで検証します。
- アップストリームへの接続は TLS 1.2 と 1.3 で、ALPN は `http/1.1` だけです（アップストリームへは HTTP/2 を使いません）。クライアント証明書は送りません。

アップストリームの `engine` は、そのアップストリームへのリクエストを検査するエンジンの名前です。

- `coraza` か `modsecurity`（小文字）です。省略すると、`kernel.default_engine` のエンジンで検査します（`kernel.default_engine` を書いていなければ `coraza`）。`null` は書けません。
- これ以外の名前は、`an upstream engine is not coraza or modsecurity` で受け付けません。設定の `kernel.engines` に検査プロセスが無いときの `modsecurity` も、`kernel.engines has no inspector for the engine of an upstream` で受け付けません。
- 同じアドレスのサーバーを持つアップストリームは、どれも同じエンジンにします（下の「値どうしの関係」と「検査エンジンの選択」）。
- 変更後のエンジンが稼働していれば、設定のリロードで変更できます（上の「SIGHUP（設定のリロード）」）。

ルートは `{"host"?, "path"?, "upstream", "access"?, "rewrite"?, "stream"?, "max_body"?, "records"?}` です。

| 設定キー | 意味 |
|---|---|
| `host` | 小文字の名前と、任意で `:port`（`*.` とポートを含めて 253 バイトまで）。ポートを書けばそのポートだけに一致し、書かなければどのポートにも一致します。`*.` で始めると、名前の前の 1 つ以上のラベルに一致します |
| `path` | `/` で始まる 1〜255 バイトのパス。`/` で終わるパスは、それで始まるパスのすべてに一致します。そうでなければ、そのパスだけに一致します。使えるバイトは英数字と `-._~!$&'()*+,=:@/%` で、`%` の後は 16 進数 2 桁です。読み方が複数ある形（下の「`access` を使うときの注意」）は書けません |
| `upstream` | アップストリームの名前 |
| `access` | `{"deny_cidrs"?, "allow_cidrs"?, "deny_countries"?, "allow_countries"?}`。ネットワークは一覧ごとに 256 個まで、国も一覧ごとに 256 個までです（下の「アクセス制御とレート制限」の `access`） |
| `rewrite` | アップストリームへ送るリクエストと、返す応答の書き換え（下） |
| `stream` | `{"idle_ms", "total_ms", "websocket"}`。3 つとも書きます（下の「ストリーミング応答と WebSocket」） |
| `max_body` | そのルートのボディの上限。`proxy.max_body` 以下で、下げることしかできません。0 なら、ボディを受け付けません |
| `records` | そのルートのリクエストに対するログの残し方で、`best_effort`、`required`、`security` のどれかです。省略すると、`records.keep` に従います（下の「ログ」の「ログの残し方」） |

- ルートは、リクエストの `Host` とリクエストターゲットの最初の `?` までを、受信したバイトのまま比較します。
  - デコードや整形はしません。パスの英字の大小は区別します。
  - ホストの英字の大小は区別せず、名前の末尾の `.` は 1 つ削除します。
- 同じ `host` と `path` のルートは、2 つ書けません。
- 読み方が複数あるパスのリクエストターゲット（下の「`access` を使うときの注意」に挙げた形）は、`path` を持つルートには一致しません。ホストだけのルートか、デフォルトのアップストリームへ回ります。
- 一致するルートが複数あるときは、最も具体的なものを使います。
  - 先にホストで決めます。名前がワイルドカードより先、長いワイルドカードが短いものより先、ポートのあるルートが無いものより先、ホストのあるルートが無いものより先です。
  - 次にパスで決めます。そのパスだけのルートがプレフィックスより先、長いプレフィックスが短いものより先、パスのあるルートが無いものより先です。
- デフォルトのアップストリームには、`access`・`rewrite`・`stream`・`max_body`・`records` はありません。デフォルトのアップストリームへ回るリクエストのログは、`records.keep` に従います。
- ルートを選ぶ前には、管理画面のルート、全体の `access`・`rate_limit` とホストごとの設定、TLS の接続の `Host` の検証があります（下の「アクセス制御とレート制限」の「リクエストの検証の順序」）。
- ルートを選んだ後は、ボディを読み込む前と検査の前に、次のように応答します。
  - どのルートにも一致せず、デフォルトのアップストリームも無い: 404
  - `access` に拒否されたクライアント: 403
  - `Content-Length` が、ルートの `max_body` を超える: 413
- `access` は、クライアントのアドレス（下の「クライアントのアドレス」）と国で、次のように拒否します。
  - アドレスが `deny_cidrs` に入るか、国が `deny_countries` に入れば、拒否します。
  - `allow_cidrs` が空でなければ、そこに入らないクライアントを拒否します。
  - `allow_countries` が空でなければ、国がそこに入らないクライアントも拒否します。
  - `allow_cidrs` と `allow_countries` を両方書けば、両方に入るクライアントだけが通ります。
  - 国は全体の `geo` のデータベースで判定します。国の指定を書くには、`geo` が必要です（下の「アクセス制御とレート制限」の `geo`）。

`access` を使うときの注意:

- ルートは受信したバイトで選びますが、アップストリームのアプリケーションは別の綴りを同じパスと読むことがあります（`/priv%61te/x` を `/private/x` と読むなど）。そのため、どれかのルートが `access` を持つ間は、取り違えられうるルートのすべてで、リクエストが `access` に通る必要があります。国の指定だけを持つ `access` も、`access` として数えます。次の決まりでも同じです。
- どれかのルートが `access` を持つ間は、`Host` が一致するルート（ホストを持たないルートを含みます）のどれかの `access` から外れるクライアントの、次のリクエストを 403 にします。
  - パス（`?` より前）が複数の読み方を持つリクエストターゲット。`\`、`;`、`//`、`.` か `..` のセグメント、`%2e`・`%2f`・`%5c`・`%00`・`%25`（大小どちらも）を含むもの、エスケープを置き換えると別のエスケープになるもの（`%2%65` など）
  - 読めない `Host`（すべてのルートが対象になります）
- `access` を持つルートのパスは、正規の形で書きます。エスケープは大文字で書き、そのまま書けるバイトはエスケープにしません。
- どれかのルートが `access` を持つなら、どのルートの `host` にもポートは書けません。
- 取り違えられうるルートを調べるときは、リクエストのパスの末尾に `/` を付けた形は調べますが、末尾の `/` を除いた形は調べないので、完全一致のルート `/admin` の制限は `/admin/` には効きません。アップストリームがこの 2 つを同じように扱うなら、両方を書いてください。
- パスの英字の大小は区別します。大小を区別しないアップストリームでは、制限は書いた綴りにだけ効きます。

`rewrite` は `{"host"?, "path"?, "query"?, "request_headers"?, "response_headers"?}` です。

- `host`: アップストリームへ送る `Host`。ルートの `host` と同じ形で、ワイルドカードは書けません。
- `path`: ルートのパスの置き換えです。`path` を持つルートにだけ書けます。ルートのパスが `/` で終わるなら、その後ろのリクエストターゲット（クエリを含みます）を、そのまま新しいパスの後ろに付けます。新しいパスも `/` で終わります。ルートのパスが `/` で終わらなければ、パスを置き換え、クエリは残します。
- `query`: `{"remove"?, "remove_prefixes"?, "set"?, "add"?}`。名前の比較では、ASCII の英字の大小を区別しません。名前の後ろに `[` が続く項目（`debug[]` など）も、同じ名前として扱います。
- `request_headers`・`response_headers`: `{"remove"?, "set"?, "add"?}`。`remove` は名前の一覧、`set` と `add` は `{"name", "value"}` の一覧です。`set` は同じ名前のヘッダーをすべて削除して 1 つ入れ、`add` は後ろに追加します。
- クエリ、リクエストヘッダー、レスポンスヘッダーは、それぞれ 32 項目まで書けます。
- リクエストヘッダーでは、次のものは書けません。
  - `_` を含む名前
  - 接続ごとのヘッダー（`Connection`、`Keep-Alive`、`Transfer-Encoding`、`Upgrade` など）
  - クライアントのアドレスを伝えるヘッダー（`X-Forwarded-For`、`X-Forwarded-Proto`、`X-Real-IP`、`Forwarded` など）
  - `Host`、`X-Forwarded-Host`、`X-Request-ID`
  - ボディの長さと型を伝えるヘッダー（`Content-Length`、`Content-Type`、`Content-Encoding`）
- レスポンスヘッダーでは、接続ごとのヘッダー、`Set-Cookie`、`X-Request-ID`、ボディの長さと型と範囲を伝えるヘッダー（`Content-Length`、`Content-Type`、`Content-Encoding`、`Content-Range`）は書けません。プロキシが自分で作る応答は書き換えません。
- 書き換えの順は、リクエストヘッダー、`Host`、リクエストターゲット（パス、次にクエリ）です。`X-Forwarded-Host` は、その前にクライアントが送った `Host` から作ります。
- 書き換えは、ルートを選んで検査した後に 1 回だけ行います。そのため、WAF のルールと除外、検査除外のルート、`access` は、公開側（書き換えの前）のパスと `Host` で書きます。2 つの公開側のプレフィックスが同じ内部のパスに書き換えられるときも、片方の公開側のパスに向けたルールは、もう片方には効きません。
- フォームのボディの引数は、`query` の書き換えの対象ではありません。
- 書き換えられないリクエスト（新しいリクエストターゲットが長すぎるなど）は、アップストリームへ送りません。サーバーの失敗にもしません。

#### ストリーミング応答と WebSocket（`stream`）

- `total_ms`（1 ms〜24 時間）: 応答のヘッダー部の後、接続を少なくともこの時間は続けます。WebSocket のトンネルは、101 から `total_ms` が過ぎると必ず終了します。
- `idle_ms`（1 ms〜`total_ms`）: アップストリームからの通信が無くてよい時間
- `websocket`: WebSocket のハンドシェイクを通すかどうか
- `stream` を持つルートの応答は、その接続の最後の応答になります。接続が終了するのは、もとの終了の時刻（`accept` から `conn_total_ms`）と、応答のヘッダー部から `total_ms` が過ぎた時刻のうち、遅い方です。`total_ms` が接続の残りの時間より短くても、応答はそこでは切断されません。
- WebSocket のハンドシェイクの GET は、ほかのリクエストと同じく検査します（検査除外のルートなら検査しません）。101 の後の WebSocket のフレームは検査せず、中継するだけです。
- ハンドシェイクの前に、トンネルの分の予算（16 KiB）を確保します。確保できなければ、何も送らずに 503 で応答します。
- トンネルは次のときに終了します。
  - 両方の向きが終了した
  - アップストリームが `idle_ms` の間何も送らない、またはどちらかへの書き込みが `response_idle_ms` の間進まない（両方の向きが開いている間は、クライアントからの送信が無くてもかまいません）
  - 片方の向きが終了してから `idle_ms` 以内に、もう片方が終了しない（その間にどれだけ動いていても終了します）
  - 101 から `total_ms` が過ぎた
  - 読み書きが失敗した、アップストリームの接続を引き継げない、101 をクライアントへ送れない
  - 停止で接続が打ち切られた
- WebSocket を通さないルートへの `Upgrade` のリクエスト（`Upgrade: h2c` も含みます）は、トンネルにしません。`Upgrade` を除き、通常のリクエストとして転送して、応答の後に閉じます。アップストリームが求められていない 101 を返したら、502 で応答します。
- `CONNECT` は 400 で拒否します。

### クライアントのアドレス

- `trusted_proxies` に入る相手からのリクエストでは、その `X-Forwarded-For` の行を 1 つの一覧として、右から左へ読みます。
  - 信頼するプロキシのアドレスは飛ばし、最初に現れた、信頼するプロキシでないアドレスをクライアントとします。
  - すべてが信頼するプロキシなら、いちばん左のアドレスをクライアントとします。
  - IP リテラルでない項目があれば、そこで読むのをやめ、相手をクライアントとします。
- 信頼しない相手からのリクエストでは、相手がクライアントです。その `X-Forwarded-For` などの申告は捨てます。
- 信頼する相手でも、`X-Forwarded-For` の行が無いリクエストでは、その相手がクライアントです。
- こうして決めたクライアントのアドレスを、検査、全体の `access`、`rate_limit`、国の判定、ルートの `access`、ログに使います。

アップストリームへ送るリクエストには、次のヘッダーを付けます。

| ヘッダー | 内容 |
|---|---|
| `X-Forwarded-For` | 信頼する相手からのリクエストでは、受信した行に相手のアドレスを追加したもの。それ以外では、相手のアドレスだけ |
| `X-Forwarded-Proto` | 信頼する相手が、ちょうど `http` か `https` を送ったときは、その値。それ以外では、リスナーのスキーム（TLS のリスナーは `https`、ほかは `http`） |
| `X-Forwarded-Host` | クライアントが送った `Host`（相手を問いません） |
| `X-Request-ID` | リクエスト ID（下の「ログ」の `id`）。クライアントが送ったものは、相手を問わず捨てて置き換えます |

### `kernel`

検査カーネルと検査プロセスの設定です。時間は、どれも 1 ms〜3600 s の範囲で書きます。

検査カーネルは、起動したエンジンごとに 1 つあります。`slots`・`wait_queue`・`records`・`restarts`・`restart_window_ms` は、エンジンごとの検査カーネルが、それぞれ同じ値を持ちます。たとえば `slots` は、1 つのエンジンが同時に検査するリクエストの数です。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `inspector` | 絶対パス | Coraza の検査プロセスの実行ファイル。省略できない設定キーで、ModSecurity の世代だけを使うホストでも書きます |
| `engines` | 省略できます。`{"modsecurity": {"inspector": <absolute-path>}}` の形で、どちらの階層の設定キーも必要です。パスは 4095 バイトまで | ModSecurity の検査プロセスの実行ファイル。この設定キーがあり、`modsecurity` の世代が選択中のときに起動します（アップストリームが使うかどうかは問いません）。省略したときは、次のようになります。`modsecurity` の世代は、インポートと選択で受け付けません（`kernel.engines has no inspector for the engine of the generation`）。起動のときは、デフォルトのエンジンでもアップストリームのエンジンでもない `modsecurity` は、選択中の世代があっても起動せず、行も出しません。デフォルトのエンジンかアップストリームのエンジンを `modsecurity` にする設定は、受け付けません（`kernel.engines has no inspector for kernel.default_engine`、`kernel.engines has no inspector for the engine of an upstream`） |
| `default_engine` | 省略できます。`coraza` か `modsecurity`（小文字）。省略すると `coraza` | アップストリームの `engine` を省略したとき、`rules import` の `--engine` を省略したとき、`managed` のある設定で管理画面のルートを検査するときに使うエンジンです（下の「検査エンジンの選択」）。`modsecurity` にするには、`engines` が必要です。これ以外の名前は `kernel.default_engine is not coraza or modsecurity` で受け付けません。`null` は書けません。動作中は変更できません（上の「SIGHUP（設定のリロード）」） |
| `tmp_root` | 絶対パス、3840 バイトまで | 起動ごとの作業ディレクトリを作る、親のディレクトリ。シンボリックリンクでないディレクトリで、所有者がプロキシの OS ユーザーであり、グループとその他のユーザーの権限が無く、setgid が無いことが必要です |
| `gomaxprocs` | 1〜65535 | 検査プロセスの `GOMAXPROCS`。ModSecurity の検査プロセスは 1 つのスレッドで動くので、この値を使いません（受け取った値を、最初のメッセージで返すだけです） |
| `gomemlimit` | 1〜9223372036854775807（バイト） | 検査プロセスの `GOMEMLIMIT`。ModSecurity の検査プロセスは、この値を使いません。受け取った値を最初のメッセージで返すだけで、メモリの上限にはなりません |
| `slots` | 1〜4 | 同時に検査するリクエストの数 |
| `wait_queue` | 1 以上、`max_conns` 以下 | 検査のスロットを待つリクエストの数 |
| `records` | `slots + wait_queue` 以上 | 同時に持つリクエストのレコードの数。最上位の `records`（ログファイル）とは別の設定キーです |
| `discard_limit` | `u32` の最大値より小さい | 検査プロセスの 1 回の起動で、捨ててよい応答の数。超えると接続のエラーとします |
| `tick_ms` | 1 s まで、かつ、ほかのどの時間以下 | 1 ステップで待つ時間の最長 |
| `hello_wait_ms` | | 検査プロセスの起動から、最初のメッセージ（HELLO）までの時間 |
| `frame_io_ms` | | 1 つのフレームの書き込みと、最初のバイトを受信した後の読み込みにかかる時間 |
| `verdict_wait_ms` | | 検査プロセスが判定を返すまでの時間 |
| `wait_deadline_ms` | | リクエストが検査プロセスに渡るまでの時間 |
| `closed_wait_ms` | | リクエストを閉じてから、閉じたことの通知までの時間 |
| `stop_after_ms` | | 検査プロセスを停止するまでの時間。判定を待つのをやめたとき（`verdict_wait_ms` が過ぎたとき）か、検査の終了を検査プロセスに伝えたときから数えます。検査のスロットが返らないままこの時間が過ぎると、検査プロセスを停止します |
| `drain_wait_ms` | | 終了の指示から、検査プロセスの終了の通知（BYE）までの時間 |
| `exit_wait_ms` | | 終了の通知の後に、検査プロセスが自分で終了するのを待つ時間 |
| `kill_grace_ms` | | SIGKILL の後、終了が確認できるまでの時間 |
| `restarts` | 0〜1000 | `restart_window_ms` の間に、再起動してよい回数。0 なら再起動しません |
| `restart_window_ms` | | 再起動の回数を数えるウィンドウ |

- 検査プロセスの再起動には、ウィンドウの中の回数に上限があります。上限に達したら、ウィンドウの中の再起動の回数が上限を下回るまで、再起動しません。その間に待つリクエストは 503 になります。
- ルールのエラーなど、再起動しても必ず失敗する理由では、再起動しません。どのエンジンの検査カーネルでも、停止するとプロキシも停止します。リクエストを渡していないエンジンの検査カーネルでも同じです（`stop: the kernel failed`）。

### `rules.store`

- `{"kind": "file", "dir"}` と書きます。`kind` に書けるのは、今は `file` だけです。
- `dir` は絶対パスで、3840 バイトまでです。シンボリックリンクでないディレクトリで、所有者がプロキシの OS ユーザーであり、グループとその他のユーザーの権限が無いことが必要です。

### `acme`

`managed` の無い設定ファイルでは、`acme` を持つ証明書があるときだけ書きます。`managed` のある設定ファイルでは、上の「全体の構成」のとおりです。書くときは、すべての設定キーを書きます。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `directory_url` | `https://` の URL、2048 バイトまで | CA の ACME ディレクトリ |
| `contact_email` | 254 バイトまで | CA に届ける連絡先。形式だけを検証します |
| `account_key_file` | 絶対パス | ACME のアカウントの鍵。無ければ、コマンドが作成します（0600） |
| `challenge_dir` | 絶対パス | チャレンジのファイルを置くディレクトリ |
| `ca_file` | 絶対パス | CA のサーバー証明書を検証するためのルート証明書（アップストリームの `ca_file` と同じ形で、1〜100 枚） |
| `timeout_ms` | 1 ms〜600 s | コマンド全体のタイムアウト |

- `account_key_file`、`ca_file`、`acme` を持つ証明書（管理画面のルートの証明書を含みます）の `cert_file`・`key_file` は、すべて別のファイルにします。`acme` を持たない証明書の `cert_file`・`key_file` も、これらのどれとも別のファイルにします。
- `challenge_dir` の直下に、これらのファイルや、ほかの証明書の `cert_file`・`key_file` を置かないでください（下の「配置の注意」）。
- `challenge_dir` は、ルールストア、`records.dir`、管理データの保存先（`admin.store.dir`）、制御ソケットのあるディレクトリ、managed ストアのどれとも同じにはできません。互いの中に置くこともできません。`managed` の無い設定でも同じです。重なりは書いたままのパスで比べるので、シンボリックリンクは使わないでください（下の「値どうしの関係」）。
- `managed` のある設定では、`account_key_file` と `ca_file` を managed ストアの中に置けません。
- CA は平文の HTTP でチャレンジを取得しに来るため、通常のリスナーかリダイレクトのリスナーが少なくとも 1 つ必要です。

### `status`

監視用のリスナー（下の「監視」）を置くときだけ書きます。省略すると、監視用のリスナーはありません。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `listen` | ループバックの IP（`127.0.0.0/8` か `::1`）とポート（0 は不可） | 監視用のリスナーのアドレス |

- 応答に認証が無いので、同じホストの監視プログラムから使います。`::ffff:127.0.0.1` の形はループバックと見なしません。
- リスナー（`proxy.listeners`）とは重ねられません。決まりはリスナーどうしと同じで、`0.0.0.0`・`::` と同じポートも重なるとみなします。
- アップストリームのサーバーは、このアドレスにできません（書いたアドレスも、名前解決したアドレスも）。リスナーのアドレスと同じく受け付けません。
- 監視用のリスナーは、リスナーの数（1〜8）に数えません。通常のリスナーか TLS のリスナーが少なくとも 1 つ必要、という決まりでも数えません。

### `admin`

管理プロセス（`tukuyomi-proxy admin`）の設定で、省略できます。省略すると管理プロセスは無く、プロキシは制御ソケットを作りません。

```text
{"listen", "control", "store", "origin", "trusted_proxies", "mfa", "session_idle_ms", "session_total_ms", "crs_dir"?, "route"?}
```

- プロキシと管理プロセスは、同じ設定ファイルを読み込みます。プロキシが使う設定キーは `listen`、`control`、`route` で、ほかの設定キーは値を検証するだけです。同じファイルを、プロキシと管理プロセスがそろって受け付けるか、そろって受け付けないようにするためです。ほかの設定キーの意味と範囲は、[管理リファレンス](admin-reference.ja.md) を参照してください。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `listen` | ループバックの IP（`127.0.0.0/8` か `::1`）とポート（0 は不可） | 管理プロセスのリスナーのアドレス。`::ffff:127.0.0.1` の形はループバックと見なしません。リスナー（`proxy.listeners`）とも監視用のリスナーとも重ねられません（リスナーどうしと同じ決まり）。`managed` の無い設定では、アップストリームのサーバーをこのアドレスにできます。`managed` のある設定のバージョンでは、できません |
| `control` | 絶対パス、107 バイトまで | 管理プロセスがプロキシに依頼を送る、制御ソケットのパス（下） |
| `route` | `{"host", "certificate", "access"}` | 管理画面のルート（下）。`managed` のある設定ファイルでは、必ず書きます。`managed` の無い設定ファイルには書けません |

- `rules.store.dir`、`records.dir`、`admin.store.dir`、`admin.control` のあるディレクトリ、`managed.dir` が重なる設定は受け付けません（下の「値どうしの関係」）。一方が他方の内容を変更しないようにするためです。たとえば、ログファイルのローテーションが、同じディレクトリにあるソケットを置き換えてしまうことを防ぎます。

`route` は、`managed` のある設定で、プロキシが管理プロセスへ転送するルートです。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `host` | 名前 1 つ（`*.` は書けません） | 管理画面のホスト名。`Host` がこの名前のリクエストは、バージョンのルートを選ばずに `admin.listen` へ転送します |
| `certificate` | `{"cert_file", "key_file", "acme"?}` | 管理画面のルートの証明書。リスナーの証明書（`hosts` が `host` だけのもの）と同じように、検証して読み込みます。`acme` を付けると `acme renew` が発行し、ファイルは起動のときに無くてもかまいません（その場合は設定ファイルに `acme` が必要です） |
| `access` | ルートの `access` と同じ形。`allow_cidrs` は必ず書き、空にできません | 管理画面のルートに適用されるアクセス制御 |

- 全体の設定（全体の `access`・`rate_limit`）も、ホストごとの設定も、管理画面のルートには適用されません。管理画面のルートに適用されるネットワークの制限は、`access` だけです（下の「リクエストの検証の順序」）。WAF の検査は、デフォルトのエンジンで受けます（下の「検査エンジンの選択」）。
- TLS のリスナーは、管理画面のルートの証明書も、バージョンのサイトの証明書と一緒に SNI で選びます。管理画面のホストへのリクエストを、ほかの証明書の接続で受信したときは 421 で応答し、転送しません。リダイレクトでない平文のリスナーで受信したときも、404 で応答して転送しません。リダイレクトのリスナーは、https へリダイレクトします。
- `host` と同じ名前は、バージョンのサイトの `hosts`、ルートの `host`、ホストごとの設定の `hosts` に書けません。`*.` のワイルドカードに含まれるのはかまいません。その場合は管理画面のルートが先に一致します。
- 証明書と `access` は、設定のリロードで変更できます。`host` は動作中に変更できないので、変更するときはプロキシと管理プロセスを再起動してください。
- `managed` の無い設定では、`admin.listen` を指すアップストリームとルートで、管理画面へ転送します（[管理リファレンス](admin-reference.ja.md) の「外部からの利用」）。そのルートには、全体の設定とホストごとの設定が適用されます。検査するエンジンは、そのアップストリームのエンジンです（`engine` を省略すれば、デフォルトのエンジン）。

#### 制御ソケット

管理プロセスがプロキシとやり取りするための Unix ドメインソケットです。管理プロセスは、このソケットでプロキシに状態を問い合わせ、世代の切り替えと、managed 設定のバージョンを指定した設定のリロードを依頼します。

- ソケットの作り方は、次のとおりです。
  - ソケットのあるディレクトリは、シンボリックリンクでないディレクトリで、所有者がプロキシの OS ユーザーであり、グループとその他のユーザーの権限が無いことが必要です（ルールストアと同じ検証）。ソケットは 0600 で作成します。
  - ソケットは検査カーネルを起動する前にバインドします。パスに既に何かがあるとき、削除して作り直すのは、それがプロキシの OS ユーザーのソケットで、待ち受けているプロセスが無い（接続が拒否される）ときだけです。待ち受けているプロセスがあるもの、ソケットでないもの、別の OS ユーザーのものは、`start: control socket refused: ...` の行を出して拒否します（exit 1）。
  - 停止のときは、リスナーを閉じる段階で一緒に閉じ、ファイルを削除します。削除するのは、そのファイルが、作ったときのものと同じときだけです。
- このソケットは、プロキシと同じ OS ユーザーで動くプロセスなら、どれも使えます。ソケットの先に認証は無く、利用を制限するのは、ディレクトリの権限とソケットの 0600 だけです。管理プロセスは、プロキシと同じ OS ユーザーで動かします。
- 1 つの接続では、2 秒以内に JSON の 1 行（4 KiB まで）を送り、1 行の応答を受け取って閉じます。プロキシが応答するのは、同時に 4 接続までです。それを超えた接続は、受け付けてすぐに閉じます。行が来ない接続と、切断された接続には、応答しません。

依頼と応答は次のとおりです。

| 依頼 | 応答 |
|---|---|
| `{"op":"status"}` | `{"generation", "mode", "engine", "phase", "switching", "reloading", "ready", "uptime_ms", "requests", "blocked", "policy_refused", "upstream_failures", "config", "managed", "resolve_timeout_ms", "config_reloads", "engines"}`。前から順に、次の値です。デフォルトのエンジンで稼働中の世代のフィンガープリント（64 桁の 16 進数）、その世代のモード（`block`、`detect`）、エンジン（`coraza` か `modsecurity`）、検査カーネルの段階（`starting`、`ready`、`stopping`、`stopped`、`failed`）、切り替えの途中かどうか、設定のリロード（SIGHUP か `reload` の依頼）の途中かどうか、`/readyz` が `ready` と応答する状態かどうか。続く 9 つはプロキシの数と値です（下）。最後の `engines` は、起動しているエンジンごとの状態です。エンジンの名前の順に、`[{"engine", "generation", "mode", "phase"}, ..]` の形で並びます |
| `{"op":"switch","engine"?:"<engine>","expect":"<fingerprint>"}` | `engine`（`coraza` か `modsecurity`。省略するとデフォルトのエンジン）について、ルールストアで選択中の世代が `expect` と同じときだけ、そのエンジンを SIGUSR1 と同じように切り替えます（稼働していないエンジンは起動します）。切り替えが終わってから、`{"result", "reason"?, "generation"}` で応答します。`generation` は、応答するときにそのエンジンで稼働中の世代です（稼働していなければ `null`） |
| `{"op":"reload","managed":"<version>"}` | 設定ファイルと指定されたバージョンで、SIGHUP と同じように設定をリロードします。managed ストアの `current` は読み込みません。同じバージョンでもリロードします。リロードが終わってから応答します（下） |
| ほかの行 | `{"result":"error","reason":..}`。`reason` は `line too long`、`malformed request`、`unknown op`、`bad expect`、`bad engine`、`bad managed` のどれかです |

`status` の数と値は、応答を作るときに読み取ります。`uptime_ms`、`config`、`managed`、`resolve_timeout_ms` のほかは、`/metrics` が出力する値と同じです（下の「メトリクス（`/metrics`）」）。

| 項目 | 内容 |
|---|---|
| `uptime_ms` | プロキシが起動してからのミリ秒 |
| `requests` | リクエストの数。ログの 7 つの `class` のすべてを数えます（`tukuyomi_requests_total` の合計） |
| `blocked` | ルールがブロックしたリクエストの数（`tukuyomi_waf_rule_hits_total` の `block`） |
| `policy_refused` | アクセス制御とレート制限で拒否したリクエストの数。数えるのは、全体の設定とホストごとの設定による、アクセス制御の 403 とレート制限の 429 です。ルートの `access` と `admin.route.access` の 403 は数えません（`tukuyomi_policy_refusals_total` の合計） |
| `upstream_failures` | 稼働中の設定にある、すべてのアップストリームのサーバーで起きた失敗の数（`tukuyomi_upstream_failures_total` の合計）。設定のリロードで設定が切り替わると、`/metrics` と同じく 0 から数え直します |
| `config` | 稼働中の設定ファイル（起動のときか、最後に切り替えたリロードで読み込んだファイル）の SHA-256（64 桁の小文字の 16 進数）。リロードで切り替えた後は、その `reload: configuration replaced` の行に出た値と同じです |
| `managed` | 稼働中の managed 設定のバージョン（64 桁の小文字の 16 進数）。`managed` の無い設定では `null` |
| `resolve_timeout_ms` | 稼働中の設定の `forward.resolve_timeout_ms` |
| `config_reloads` | `{"replaced", "refused"}`。SIGHUP と `reload` の依頼による設定のリロードの数を、切り替えたか拒否したかで分けたもの（`tukuyomi_config_reloads_total`） |

- これらの値が無い応答は、前のビルドのプロキシが返したものです。管理プロセスは、無い値を `null` として扱います（[管理リファレンス](admin-reference.ja.md) の「一覧と内容」）。`engines` の無い応答も、エンジンごとの状態を返さない前のビルドのプロキシが返したものです（[管理リファレンス](admin-reference.ja.md) の「選択とロールバック」）。

`switch` の `result` は次のとおりです。

| `result` | `reason` | とき |
|---|---|---|
| `switched` | 無し | 切り替えが終わり、選択中の世代で稼働しています（稼働していなかったエンジンは、起動しています） |
| `unchanged` | `already serving` | 選択中の世代を、既に使っています |
| `refused` | `current changed` | ルールストアで選択中の世代が、`expect` と違います（そのエンジンに選択中の世代が無いときも含みます）。何もしません |
| `refused` | `store refused` | ルールストアか設定を受け付けませんでした |
| `failed` | `driver did not take the order`、`not switched` | 切り替えを始められなかったか、新しい世代が起動しませんでした |
| `busy` | `starting`、`switch under way`、`too many orders`、`stopping` | 検査カーネルの準備ができる前、別の切り替えの途中、依頼が多すぎる、停止の間 |

- 切り替えの結果は、SIGUSR1 と同じように `tukuyomi_rules_switches_total` に数えます。数えないのは、`unchanged`、`busy`、`current changed` の応答だけです。`store refused` は `refused` に、`driver did not take the order` と `not switched` は `failed` に数えます。
- 切り替えの依頼は、`ready_wait_ms` に 5 秒を加えた時間まで、応答を待ちます。それを過ぎると `busy`（`switch under way`）で応答し、切り替えそのものは続きます。
- 状態の問い合わせに 2 秒以内に応答できないとき（依頼が多すぎるとき、停止の間を含みます）は、`{"result":"error","reason":"no answer"}` を返します。
- 切り替えの依頼に応答するたびに、ログに `control: switch expect <fingerprint>: <result> (<reason>), serving <fingerprint>` の行を 1 つ出します。`busy` の応答のときも出します。`busy` で応答した切り替えが後で終了すると、終了したときにもう 1 行出ます。この行には、エンジンの名前は出ません。`serving` は依頼のエンジンで稼働中の世代で、稼働していなければ `none` です。

`reload` の応答はどれも、応答するときに稼働中のバージョンを `managed` に持ちます（`managed` の無い設定では `null`）。

| `result` | 形 | とき |
|---|---|---|
| `replaced` | `{"result":"replaced","config":"<sha256>","managed":"<version>"}` | 切り替えました。2 つの値は、`reload: configuration replaced <sha256> managed <version>` の行と同じです |
| `refused` | `{"result":"refused","reason":..,"detail":..,"managed":..}` | 何も変更していません。`reason` は拒否した箇所で、次のどれかです。`configuration`（設定ファイルか国のデータベース）、`version`（バージョンの検証）、`store`（managed ストア、バージョンやファイルの名前と内容）、`upstream`（名前解決、アップストリームの CA）、`tls`（リスナーの証明書、サイト、管理画面のルート）、`fixed`（動作中に変更できない設定キー、稼働していないエンジンのアップストリーム）、`listener`（新しいリスナーをバインドできなかった）、`thread`（リロードのスレッドを始められなかった、スレッドが応答せずに終了した）。`detail` は、ログの行の `refused: ` の後ろと同じ文です |
| `refused` | `reason` が `unmanaged`、`detail` が `the configuration in force has no managed object` | 動作中の設定に `managed` がありません。リロードを始めずに拒否します |
| `busy` | `{"result":"busy","reason":..,"managed":..}` | `starting`（リスナーをバインドする前）、`reload under way`（SIGHUP かほかの `reload` によるリロードの途中。または、この依頼のリロードが待つ時間以内に終了しなかったとき。そのときも、リロードは続きます）、`too many orders`、`stopping` |

- `reload` の依頼は、稼働中の設定の `forward.resolve_timeout_ms` に 5 秒を加えた時間まで、応答を待ちます。
- 依頼のバージョンとして受け付けるのは、64 桁の小文字の 16 進数だけです（ほかは `bad managed`）。managed ストアの外は指せません。この依頼でできることは、同じ OS ユーザーが `current` を書いて SIGHUP を送るのと同じです。
- `reload` の依頼で始めたリロードは、SIGHUP と同じように `tukuyomi_config_reloads_total` に数えます。リロードを始めなかった依頼（`busy`、`unmanaged`、`error`）は数えません。
- 依頼でリロードを始めるときは、ログに `reload: control reload <version>` の行を出し、応答ごとに `control: reload <version>: <result> (<reason>)` の行を 1 つ出します（`replaced` には `(<reason>)` がありません）。待つ時間が尽きて `busy` で応答した依頼では、リロードが終了したときに、もう 1 行出ます。
- 管理プロセスがこの依頼で反映する手順は、下の「managed 設定」の「反映」を参照してください。

### 値どうしの関係

起動と `config check` は、値の範囲のほかに、次の関係を検証します。

| 関係 | 理由 |
|---|---|
| `inspect_body ≤ max_body` | 検査するのは、ボディの先頭です |
| `max_body ≤ max_body_wire ≤ 2 × max_body + 4 MiB` | chunked のボディは、チャンクのサイズ行と区切りの分も回線に載ります |
| `max_buffered_bytes ≥ 2 × inspect_body + 24 KiB + 32 KiB` | 1 つのリクエストがバッファリングする最大の量です。内訳は、検査する先頭、検査カーネル用のコピー、ヘッダーフィールド、流している途中の断片です |
| `routes[].max_body ≤ max_body` | ルートでは、下げることしかできません |
| `http2.max_header_list ≤ 4 × max_head_bytes` | 展開した後のヘッダーフィールドのサイズ |
| `connection_window + max_streams × (send_buffer + 32 KiB) ≤ 16 MiB` | 1 本の HTTP/2 の接続が保持できる量 |
| 上に `max_streams × (max_header_list + upstream_max_head_bytes)` を加えても 16 MiB 以下 | 同上（ストリームごとのヘッダーフィールドと、アップストリームから読み込む断片） |
| `upstream_head_wire ≥ 2 × upstream_max_head_bytes` | アップストリームのヘッダー部の読み込み |
| `drive_slice ≤ tick` | ドライバーの 1 回は、検査カーネルの 1 ステップより短くします |
| `ready_wait ≥ hello_wait` | 準備の待ち時間は、検査プロセスの最初のメッセージを待つ時間を含みます |
| `head_read ≤ request_total`、`body_read ≤ request_total` | リクエストの時間内の段階です |
| `inspect_wait ≥ wait_deadline + 2 × verdict_wait + 18 × (drive_slice + frame_io)` | 1 つの検査に必要な最短の時間 |
| `inspect_wait ≤ request_total` | リクエストの時間内の段階です |
| `upstream_connect + upstream_header < request_total` | アップストリームとのやり取りの 2 つの段階は、リクエストの時間の中で終了します。`upstream_header` は、`response_idle` より長くしても、ボディをバッファリングするリクエストでは効きません（上の `response_idle_ms`） |
| `request_total ≤ conn_total`、`response_idle ≤ conn_total`、`keepalive_timeout ≤ conn_total` | 接続の時間内の段階です |
| `upstream_keepalive_timeout ≤ response_idle` | 再利用を待つ接続にも、読み込みのアイドルの上限が適用されます |
| `keepalive_time + request_total ≤ conn_total` | `keepalive_time` の前に始まったリクエストは、接続の時間の中で応答のヘッダー部を受信します |
| `lingering_timeout ≤ lingering_time` | 閉じる前の読み込み |
| `stop_inspect < stop_wait`、`stop_inspect + kill_grace < stop_wait` | 停止の段階の順 |
| `wait_queue ≤ max_conns` | 1 つの接続が持つ検査は 1 つです |
| `kernel.records ≥ slots + wait_queue` | 検査カーネルのレコード |
| `tick ≤ 1 s`、`tick` はほかの検査カーネルのどの時間以下 | 検査カーネルの 1 ステップ |
| アップストリームの `engine` と `kernel.default_engine` は、検査プロセスが設定にあるエンジンだけ（`modsecurity` には `kernel.engines` が必要です） | 検査プロセスの無いエンジンでは、検査できません |
| 同じアドレスのサーバーを持つアップストリームは、どれも同じエンジン | クライアントが `Host` を選ぶだけで、同じサーバーへ届くアップストリームのうち、最も弱いエンジンやモードのものを通れてしまうためです（下の「検査エンジンの選択」） |
| 国の指定（全体の `access`、`host_policies` の `access`、ルートの `access` の `deny_countries`・`allow_countries`）があれば `geo` もあります | 国を判定するデータベースが必要です |
| `rules.store.dir`、`records.dir`、`admin.store.dir`、`admin.control` のあるディレクトリは、互いに同じでなく、どれも他の中にありません。`admin.control` 自身は、前の 3 つの中にありません | 一方のローテーションや書き換えが、他方の内容を置き換えないようにするためです |
| `managed.dir` は、上の 4 つのディレクトリと同じでなく、どれの中にもなく、どれを含むこともありません | 同上 |
| `acme.challenge_dir` は、上の 5 つ（`managed.dir` を含みます）と同じでなく、どれの中にもなく、どれを含むこともありません。`managed` の無い設定でも同じです | `acme renew` は、チャレンジのファイルを置き換えて削除します。チャレンジの応答で、ほかのディレクトリの中のファイルを返さないようにするためです |
| `managed` のある設定では、`acme.account_key_file`・`acme.ca_file`、`admin.route` の `cert_file`・`key_file` は `managed.dir` の中にありません | `acme renew` が、managed ストアの中の名前を上書きしないようにするためです |
| `admin.listen` は、`proxy.listeners` と `status.listen` に重なりません | 同じポートを、2 つのリスナーでバインドできません |
| ルートの `records` が `required` なら、`records` があります | 残す先のファイルが必要です |
| `records.ship` があり、`records.keep` かルートの `records` に `required` があれば、`records.files ≥ 3` | ログ送信プロセスの遅れでリクエストを拒否するしきい値（ファイル `files − 2` 個分）が、0 にならないようにするためです |

- 時間の関係は、設定キーの名前から `_ms` を除いて書いています。

## リクエストボディの上限と検査する長さ

- 推奨値は、`max_body` が 100 MiB、`inspect_body` が 16 KiB です。`inspect_body` は、検査の負荷を測定してから決め直す予定です。
  - 1 vCPU のホストでは、1 MiB 近い JSON の検査に約 7 秒かかりました。
  - 検査の時間が `verdict_wait_ms` を超えると、リクエストは 503 になります。検査プロセスは、503 を返した後も、その検査が終わるまで CPU を使います。
  - さらに `stop_after_ms` を超えると、検査プロセスは停止され、再起動します。その間は、そのエンジンへのほかのリクエストも 503 になり、再起動の回数（`restarts`）も消費します。
- ボディが `inspect_body` 以内で終わるときは、全体をバッファリングして検査し、検査した形で転送します。
- 長いボディは、先頭の `inspect_body` バイトだけを検査します。許可されたら、残りをクライアントが送るとおりに、アップストリームへ流します（バッファリングしません）。
  - 先頭より後ろは検査しません。
  - 流すボディは、クライアントが使ったメッセージの区切り（framing。長さか chunked）のまま送ります。
- 検査除外のルートのボディは、`inspect_body` 以内で終わればバッファリングして転送します。それより長ければ、同じように流します。
- gzip のボディは、次のように扱います。
  - 検査するルート: 全体をバッファリングして伸長します。gzip のままの長さも、伸長した長さも、`inspect_body`（ルートの `max_body` がそれより小さければ、その値）までです。どちらかが超えれば 413 です。gzip として読めないボディ、gzip の後ろにバイトが続くボディ、空の gzip のボディは 400 です。伸長したボディを `Content-Encoding` なしで検査し、そのまま転送します。
  - 検査除外のルート: 伸長しません。ほかのボディと同じに扱い、上限は gzip のままの長さで数えます。
- chunked のボディを流している途中で `max_body` を超えたときは、アップストリームへ送り始めているため、413 を返せません。アップストリームへのリクエストを切り、クライアントの接続を閉じて、ログに理由を書きます。
- 予算（`max_buffered_bytes`）の考え方は、次のとおりです。
  - ボディを流す 1 つのリクエストが検査の間に持つのは、先頭の `inspect_body`、検査カーネル用のコピー（先頭とヘッダーフィールド）、流すための小さなバッファー（32 KiB）です。判定が出た後は、先頭の `inspect_body` と 32 KiB のバッファーだけになります。ボディが長くても増えません。検査除外のルートには、検査カーネル用のコピーはありません。
  - この量は同時に進むリクエストの数だけ必要なので、予算は、同時に来ると見込む最大の数に合わせて決めます。
  - 予算とは別に、アップストリームの接続の読み込みバッファー（`upstream_max_head_bytes` まで）にも、流しているボディが入ります。この量はボディが長くても増えませんが、同時に流すリクエストの数だけ増えます。
  - HTTP/2 のウィンドウとバッファーも、予算の外です（上の `http2`）。
- 大きなリクエストの送信時間に関わる設定は、次のとおりです。
  - `request_total_ms` には、ボディを受け終えて、応答のヘッダー部が来るまでの時間が含まれます。たとえば 100 MiB を 60 秒（`request_total_ms` 60000）で受けるには、約 14 Mbit/s が必要です。大きなリクエストを受けるなら、回線の速さに合わせて大きくしてください。
  - `upstream_header_ms` は、ボディの最後の断片をアップストリームへ渡してから数えます。アップストリームが大きなリクエストを長く処理するなら、大きくしてください。
  - ボディを流している間、クライアントからの読み込みの間隔は `body_read_ms` までです。

## ルールセットと世代

- 世代は、`rules import` が作るルールセットの一式で、フィンガープリント（マニフェストの SHA-256）で指します。世代は、作った後は変更しません。
- 世代は、ルールで検査するエンジンも持ちます（`rules import --engine`。省略すると `kernel.default_engine` のエンジンで、それも書いていなければ `coraza`）。このビルドが持つエンジンは、`coraza`（Coraza）と `modsecurity`（ModSecurity v3）です。同じファイルでも、エンジンが違えばマニフェストが変わり、別の世代（別のフィンガープリント）になります。`modsecurity` の世代をインポート、選択、起動できるのは、設定の `kernel.engines` に検査プロセスがあるときだけです。
- 下の「検査プロセスが追加する設定とルール」は、Coraza の世代の決まりです。ModSecurity の世代の決まりは、「ModSecurity の世代」を参照してください。
- ルールストアには、次のものがあります。
  - `generations/<fingerprint>/`: 世代
  - `current.<engine>`（`current.coraza`、`current.modsecurity`）: エンジンごとに選択した世代。以前のバージョンが書いた `current` も読みます（下の「エンジンごとの選択中の世代」）
  - `current.<engine>.new`: 選択の途中で止まったときの残り。次に同じエンジンの世代を選択するときに片付けます
  - `using/<fingerprint>`: 使用中の目印
  - `staging/`: インポートの途中のもの
  - `lock`: コマンドのロック
- ルールストアを変更できるのは、コマンドと管理プロセスのうち、一度に 1 つだけです。途中で止まったコマンドの残りは、次のコマンドが片付けます。
- フィンガープリントで検出できるのは、事故による破損と取り違えです。中身が、動作中のプロキシが保持しているフィンガープリントと違う起動も検出します。一方、同じ OS ユーザーのプロセスがルールストアを書き換えることは防ぎません（検査プロセスも同じ OS ユーザーです）。再起動をまたいだ認証でもありません。
- 起動した後に、使っている世代のファイルが壊れると、検査プロセスの次の再起動が失敗します（ファイルがマニフェストと違えば exit 11、マニフェストが変わればフィンガープリントの不一致）。このとき検査カーネルは、再起動しても直らない失敗として停止し、プロキシも停止します。

### 検知のみのモード

- `rules import --detect-only` で作った世代は、ルールに一致したリクエストも通します。リクエストのログは、`class` が `forwarded`、`reason` が `detected by a rule` になり、`rule` には一致したルールの ID が入ります。
- ブロックする世代と同じルールのファイルを使い、違うのはブロックするかどうかだけです。最初はこの形で動かすことをおすすめします。誤検知を確認し、除外を追加してから、ブロックする世代をインポートし直します。
- 検知のみの世代でも、下の「検査プロセスが追加する設定とルール」のルールはブロックします。
- Coraza の検知のみの世代は、ルールの前と後に目印のルール（ID 4000010、4000011）を追加します。運用者のルールでこれを削除したりスキップしたりすると、そのリクエストは検査できないものとして 503 になります。知らせずにブロックしたり、そのまま通したりすることはありません。ModSecurity の世代は、目印のルールを追加しません。

### 検査プロセスが追加する設定とルール

運用者のルールの後に、検査プロセスが次の設定とルールを追加します。これらは運用者のルールでは変更できません。

- 検査エンジンは On です。ボディを読みます。ボディの上限を超えたら拒否します。JSON の入れ子は 64 段までです。
- ルール ID 4000001〜4000003 は、すべての世代で検査プロセスが使います。順に、ボディの解析の失敗、引数の数の上限、URI の解析の失敗でブロックするルールです。4000010・4000011 は、検知のみの世代で使います。運用者のルールで同じ ID を使うと、その世代のルールセットを組み立てられません。ブロックする世代では 4000010・4000011 を使っても組み立てられますが、検知のみの世代としてインポートし直せなくなるので、使わないでください。
- 次のものを含むルールは受け付けません。判定するのは文字の並びだけで、大文字と小文字は区別せず、`msg` の中の語にも一致します。
  - `Include`、`SecIgnoreRuleCompilationErrors`（引数が `Off` でも）
  - 名前が `SecAuditLog`・`SecDebugLog`・`SecUpload` で始まるディレクティブ
  - `ctl:ruleEngine`・`ctl:requestBodyAccess`・`ctl:requestBodyLimit`
  - `@inspectFile`・`@rbl`・`setenv:`
  - 変数の名前 `reserved_body_cut`
- 運用者のルールがボディの処理（`ctl:requestBodyProcessor` など）を変更したり、上のルールを実行時に外したりして、検査が終わったと検証できないリクエストは 503 になります。ModSecurity の世代で、ほかに検査できないものとして扱うリクエストは、「ModSecurity の世代」を参照してください。

### 運用者の責任範囲

- `ctl:ruleRemoveById`、`SecRuleRemoveById` などで、ブロックするルールを意図的に外すことは、運用者の判断に任せます。拒否はしません。
- ただし Coraza の世代では、`SecMarker` より後ろで `SecRuleRemoveByMsg` を使うと、Coraza が異常終了し、ルールセットを組み立てられません（exit 11）。CRS は `SecMarker` を多く使うので、CRS と一緒には使えません。
- インポートと検査プロセスが検出するのは、マーカーの事故（存在しないマーカーや、前にあるマーカーへの `skipAfter`、名前の打ち間違い）だけです。
- Coraza の推奨設定には、`REQBODY_ERROR`・`MULTIPART_STRICT_ERROR` を見るルール（200002、200003）があります。運用者がこれを追加すると、先頭で切ったボディもブロックします。ボディを途中で切ると、解析が失敗することがあるためです。
  - 検査プロセスのルール 4000001 は、切ったボディの解析の失敗ではブロックしません。
  - CRS 4.23.0 には、これに当たるルールはありません。
- CRS は、デフォルトでは `application/<name>+json` のボディをブロックします。受け付けるには、インポートの前に、`crs-setup.conf` で受け付ける型に追加します。

### ModSecurity の世代

`rules import --engine modsecurity` で作る世代は、libmodsecurity（ModSecurity v3.0.17）でリクエストを検査します。検査プロセスは別の実行ファイル（`tukuyomi-inspector-modsecurity`）で、設定の `kernel.engines.modsecurity.inspector` に書きます（[ビルドと配置](../build/binary-deployment.ja.md)）。インポートの手順、事前検証、`--detect-only`、検査除外のルート、CRS のインポートは、Coraza の世代と同じです。

アップストリームごとにエンジンを選ぶ設定では、同じリクエストでも、エンジンによって結果が違うことがあります。違いはこの節の後半にまとめています。エンジンの選び方は、下の「検査エンジンの選択」を参照してください。

検査プロセスは、次の設定とルールを追加します。これらは運用者のルールでは変更できません。

- 検査エンジンは On、ボディの読み込みは有効、JSON の入れ子は 64 段までです。この 3 つは、検査プロセスが運用者のルールより先に設定します。ModSecurity は最初に設定された値を使うので、ルールに `SecRuleEngine`・`SecRequestBodyAccess`・`SecRequestBodyJsonDepthLimit` を書いても効きません。
- ボディと引数の上限は、ModSecurity には設定せず、検査プロセスが自分で数えます。引数の数は、クエリ、フォームのボディ、JSON のボディのそれぞれで 1000 までで、超えるとルール 4000002 でブロックします（JSON は、値の数と、空でない配列の数を別々に数えます）。multipart のボディは数えません。
- ルール ID 4000001〜4000011 は、検査プロセスのために空けてあります。運用者のルールが使うと、モードを問わず、その世代のルールセットを組み立てられません。ModSecurity の世代は、検知のみの世代でも、目印のルール（4000010、4000011）を追加しません。
- 検査プロセスは、ルール ID 4000001（ボディの解析の失敗）、4000002（引数の数の上限）、4000003（URI の解析の失敗）でブロックします。検知のみの世代でもブロックします。4000001 は、検査する長さで切ったボディではブロックしません。

インポートの事前検証では、検査プロセスがルールのファイルを読んで検証します。次のものがあると、検査プロセスは起動せず（exit 11）、インポートは失敗します。理由の文とルールのファイルの名前は、標準エラーの `rules import: the inspector said:` の行に出ます（管理 API では `trial` の `detail`）。ModSecurity が読める書き方でも、検証できる決まった書き方でなければ受け付けないので、害の無いルールを受け付けないことがあります。

- ファイル: 行の終わりに CR があるもの（CRLF の改行）、NUL を含むもの、最後が改行で終わらないもの
- 書き方: 決まった書き方でないもの。たとえば、`phase:'request'` のようにフェーズを引用符で囲んだものです。
- ディレクティブ: 使えるのは、`SecRule`、`SecAction`、`SecDefaultAction`、`SecMarker`、`SecRuleRemoveById`・`SecRuleRemoveByTag`・`SecRuleRemoveByMsg`、`SecRuleUpdateTargetById`・`SecRuleUpdateTargetByTag`・`SecRuleUpdateTargetByMsg`、`SecRuleEngine`・`SecRequestBodyAccess`・`SecRequestBodyJsonDepthLimit`（受け付けますが効きません）、`SecComponentSignature`、`SecAuditEngine Off`、レスポンスボディのディレクティブ（`SecResponseBodyAccess`・`SecResponseBodyLimit`・`SecResponseBodyLimitAction`・`SecResponseBodyMimeType`・`SecResponseBodyMimeTypesClear`）です。ほかは受け付けません。たとえば次のものです。
  - `Include`、名前が `SecRemoteRules` で始まるディレクティブ、`SecIgnoreRuleCompilationErrors`
  - 名前が `SecAuditLog`・`SecDebugLog`・`SecUpload` で始まるディレクティブ、`SecTmpSaveUploadedFiles`、`SecDataDir`、`SecTmpDir`
  - ボディと引数の上限を決めるディレクティブ（`SecRequestBodyLimit`・`SecRequestBodyNoFilesLimit`・`SecRequestBodyLimitAction`・`SecRequestBodyInMemoryLimit`・`SecArgumentsLimit`）
  - ModSecurity が知らないディレクティブ
- アクション: 使えるのは、`accuracy`・`allow`・`auditlog`・`block`・`capture`・`chain`・`ctl`・`deny`・`drop`・`expirevar`・`id`・`initcol`・`log`・`logdata`・`maturity`・`msg`・`multiMatch`・`noauditlog`・`nolog`・`pass`・`phase`・`redirect`・`rev`・`setrsc`・`setsid`・`setuid`・`setvar`・`severity`・`skip`・`skipAfter`・`status`・`t`・`tag`・`ver`・`xmlns` です。`exec` と `setenv` を含め、ほかは受け付けません。
  - `ctl` で使えるのは、`auditEngine`・`auditLogParts`・`forceRequestBodyVariable`・`parseXmlIntoArgs`・`requestBodyProcessor`・`ruleRemoveById`・`ruleRemoveByTag`・`ruleRemoveTargetById`・`ruleRemoveTargetByTag` です。`ruleEngine`・`requestBodyAccess`・`requestBodyLimit` を含め、ほかは受け付けません。
  - リクエストをブロックするアクション（`deny`・`drop`・`redirect`・`block`）と `nolog`・`noauditlog` を、同じルールに書くと受け付けません。どのルールがブロックしたかが分からなくなるためです。`SecDefaultAction` に `nolog`・`noauditlog` や `skipAfter` を書くことも受け付けません。
  - `skipAfter` が指す `SecMarker` が、その後ろ（同じファイルか、後に読み込むファイル）に無いときは受け付けません。
- 演算子: `@inspectFile`・`@rbl`・`@validateDTD`・`@validateSchema`・`@fuzzyHash`・`@geoLookup`・`@gsbLookup`・`@rsub`・`@validateHash` は受け付けません。ファイルを読む演算子（`@pmFromFile`・`@pmf`・`@ipMatchFromFile`・`@ipMatchF`）は、ルールセットの中にあるファイルを、英数字・`.`・`_`・`-` だけのパスで書いたときだけ使えます。パスは、ルールセットの中のパス（`rules/<name>` など）か、そのルールファイルがあるディレクトリからのパスです。
- 変数と長さ: 変数 `ENV` は受け付けません。1 つの変数の並びは 256 個まで、`chain` でつなぐルールは 64 個までです。
- 文字の並び: 上の読み取りとは別に、ルールの文字から空白と引用符を除いて並びを探します。探す並びは `ctl:ruleEngine`・`ctl:requestBodyAccess`・`ctl:requestBodyLimit`・`exec:`・`setenv:`・`@inspectFile`・`@rbl`・`@validateDTD`・`@validateSchema`・`@fuzzyHash` です。大文字と小文字は区別しません。`msg` の中にあっても受け付けません。
- 読み取りとの不一致: 検査プロセスは、ModSecurity が組み立てたルールを、読み取った内容と照合します。一致しないルールは受け付けません。

`ctl:ruleRemoveById` や `SecRuleRemoveById` などで、ブロックするルールを意図的に外すことは、Coraza の世代と同じく運用者の判断に任せます。拒否はしません。

Coraza の世代と違うところは次のとおりです。同じルールとリクエストでも、結果が違うことがあります。

1. 検知のみの世代では、運用者のルールがリクエストをブロックすると判定した後、ModSecurity はそのフェーズに残っているルールだけをスキップします。そのため、ログの `rules`（一致したルール）と `score` が、Coraza の世代より短く、小さくなることがあります。
2. 検査する長さで切ったボディの解析が失敗したとき、ModSecurity は、解析が止まった所から後のボディをルールに渡しません。`Content-Type` のパラメーターのせいで解析が始まらないとき（たとえば `Boundary=` を大文字で書いたとき）は、ボディを何も渡しません。切っていないボディは、解析が失敗すれば 4000001 でブロックします。
3. 入れ子が 62〜64 段の JSON のボディは、ModSecurity ではブロックされず、Coraza ではブロックされます。65 段からは、どちらもブロックされます（決まりの上限は 64 段です）。
4. ModSecurity では、リクエストをブロックするルールのうち `multiMatch` を付けたものと、リクエストをブロックする `SecAction` のうち `msg` の無いものがブロックしたリクエストは、すべて検査不能として扱われます。これらのリクエストは 503 になり、プロキシは通しません。
5. `ARGS:/re/` のように、変数の選択に書いた正規表現が失敗しても、ModSecurity は失敗の目印を残しません。そのため、リクエストは検査不能として扱われません。
6. `@verifyCC`・`@verifyCPF`・`@verifySSN` の失敗も、5 と同じく、失敗の目印を残しません（CRS はこれらを使いません）。`@rx` の失敗は、検査不能として扱います。
7. JSON のボディの値は、`ARGS` にだけ入り、`ARGS_POST` には入りません（CRS は `ARGS` を読みます）。
8. `REQUEST_URI` は、`%XX` をデコードした URL です（デコードする前の形は `REQUEST_URI_RAW`）。そのため、パスの中に `%XX` でエンコードした攻撃があると、`REQUEST_URI` を見るルールは、Coraza の世代では一致しなくても ModSecurity の世代では一致することがあります。
9. 終わりの境界が無い multipart のボディは、ModSecurity ではボディの解析の失敗として、4000001 でブロックします（切ったボディを除きます）。Coraza は通します。

次のリクエストは、ModSecurity の世代では検査不能として扱われ、503 になります。Coraza の世代ではそうなりません。

- ルールの正規表現が失敗したか、マッチ回数の上限に達したリクエスト（5 と 6 のものを除く）
- 境界が空の multipart のボディ（`boundary=` や `boundary=""`）。ModSecurity は、このボディを何も解析せず、そのことも通知しないためです。
- `Content-Type` を 2 つ以上持つ、空でないボディ。ただし、プロキシが先に 415 で拒否するので（「ボディの型」）、検査プロセスまでは届きません。

ボディの処理を変更するなどして、検査が終わったと検証できないリクエストが 503 になるのは、Coraza の世代と同じです（「検査プロセスが追加する設定とルール」）。

### 検査エンジンの選択

アップストリームごとに、リクエストを検査するエンジンを選べます。エンジンは `coraza` と `modsecurity` です。

- エンジンは、アップストリームの `engine` で選びます。`engine` を省略したアップストリームは、デフォルトのエンジン（`kernel.default_engine`。書いていなければ `coraza`）で検査します。`rules import` の `--engine` を省略したときのエンジンも、デフォルトのエンジンです。書き方と受け付けない値は、上の「`forward`」と「`kernel`」を参照してください。
- リクエストは、行き先のアップストリームが使うエンジンで検査します。使うのはそのエンジンの検査カーネルだけで、別のエンジンへは回しません。その検査カーネルが使えないときは、503 で応答します。
- エンジンによって、同じリクエストでも検知の結果が違うことがあります（「ModSecurity の世代」を参照してください）。
- あるエンジンで選択中の世代が検知のみのモードなら、そのエンジンを使うアップストリームでは、ルールに一致したリクエストもブロックしません。起動、リロード、`config check` のときに、そのアップストリームごとに `upstream <name>: engine <engine>, mode detect` の行を出します（行は `start:`・`reload:`・`config check:` で始まります）。

管理画面のルート:

- `managed` のある設定では、管理画面のルート（`admin.route`）は、デフォルトのエンジンで検査します。
- デフォルトのエンジンの世代には、インポートのルートを検査除外のルートにした世代を使います。理由と、デフォルトのエンジンを変更するときの扱いは、[管理リファレンス](admin-reference.ja.md) の「インポートのルートを検査除外にする」を参照してください。
- `managed` の無い設定では、管理プロセスへ転送するアップストリームを、そのアップストリームのエンジンで検査します（上の「`admin`」）。

同じアドレスのサーバー:

- 同じアドレスのサーバーを持つアップストリームどうしで、エンジンが違う設定は受け付けません（`two upstreams with a server at the same address have different engines`）。これを許すと、クライアントが `Host` を選ぶだけで、同じサーバーへ届くアップストリームのうち、最も弱いエンジンやモードのものを通れてしまうためです。
- アドレスの比べ方は、次のとおりです。IP リテラルで書いたサーバーは、IP アドレスの正規の形とポートで比べます（IPv6 の形で書いた IPv4 アドレスは、IPv4 アドレスと同じとみなします）。名前で書いたサーバーは、名前とポートで比べます。同じ IP アドレスを指す別の名前は、同じアドレスだと見分けられません。別の名前で同じサーバーへ届くアップストリームは、運用者が同じエンジンにそろえてください。

起動するエンジン:

- プロキシは、選択中の世代があり、設定に検査プロセスがあるエンジンのすべてを起動します。デフォルトのエンジンが先で、ほかは名前の順です。どのアップストリームも使わないエンジンも、起動します。
- デフォルトのエンジンとアップストリームのエンジンには、選択中の世代が必要です。無ければ、起動も `config check` も、`rules store refused: no generation is chosen` で受け付けません。
- デフォルトのエンジンに選択中の世代が無く、ほかのエンジンにはあるときは、`rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` で受け付けません。以前のバージョンで ModSecurity の世代を選択していたホストを更新したときなどに、この状態になります。`kernel.default_engine` を書くか、デフォルトのエンジンの世代を選択します（下の「バージョンの更新」）。
- 起動したエンジンは、プロキシが停止するまで止まりません。`rules deactivate` を実行しても同じです。

プロセスの数とメモリの目安:

- 常時稼働するプロセスは、プロキシが 1 つと、起動したエンジンごとの検査プロセスが 1 つずつです。Coraza だけを起動しているときは、検査プロセスは 1 つです。
- 検査プロセスは、次のときに増えます。
  - 世代の切り替えの間は、そのエンジンの検査プロセスが 1 つ増えます。切り替えはプロキシ全体で同時に 1 つだけなので、増えるのは 1 つまでです。そのため、プロキシの子プロセスである検査プロセスの数は、最大でも起動したエンジンの数に 1 を加えた数です。
  - 事前検証（`rules import` と管理 API のインポート）は、検査プロセスを 1 つ起動します。
- 管理プロセスとログ送信プロセスは、これとは別のプロセスです。

メモリの目安は、検査プロセスを 1 つずつ測った値、それらを足し合わせた目安、2 つのエンジンを起動したときの測定値の 3 つに分けて書きます。単位は MiB です。値はホストとリクエストの内容によって変わります。

- 検査プロセスを 1 つずつ測った値です。このバージョンと同じ検査プロセスの実行ファイル、CRS 4.23.0、4 つの論理 CPU と 8 GiB のメモリを持つ Linux ホストで、エンジンを 1 つだけ起動して測りました。

  | プロセス | 起動の直後 | 16 KiB までのリクエストの後 | 1 MiB のボディを流した後 |
  |---|---|---|---|
  | Coraza の検査プロセス | 約 57 | 約 69 | 約 110〜112（最大 約 125）。この後も下がりません |
  | ModSecurity の検査プロセス | 約 43 | 約 43 | 約 43（最大 約 52） |

  1 MiB のボディの列は、`proxy.inspect_body` を 1 MiB にして、1 MiB のボディを流した値です。`inspect_body` が推奨値の 16 KiB のときは、16 KiB までのリクエストの後の値が当てはまります。
- 足し合わせた目安です。上の値のうち同じ条件の値を足したもので、測った合計ではありません。プロキシは含みません。
  - 2 つのエンジンを起動しているときは、通常のリクエストで約 100〜112（Coraza の約 57〜69 と、ModSecurity の約 43 の合計）です。1 MiB のボディを流している間の最大は約 178 です。
  - 世代の切り替え 1 回と事前検証 1 回が重なったときの最悪は、通常のリクエストで約 240、1 MiB のボディを流している間の最大で約 305 です。約 240 と約 305 には、仮定した値が含まれます。事前検証を行うプロセスの本体を、プロキシの起動の直後と同じ約 9 と仮定しました（測っていません）。
- 2 つのエンジンを起動したときの測定値です。Core Rule Set の世代を 2 つのエンジンに選択し、通常のリクエストと SQL インジェクションのリクエストを数回ずつ流しました。その後の常駐メモリ（VmRSS）は、プロキシが約 10、Coraza の検査プロセスが約 52、ModSecurity の検査プロセスが約 43 でした。1 つずつ測った値とは、測った条件（世代とリクエスト）が違うので、同じ値にはなりません。1 MiB のボディは流していません。世代の切り替えの間は、検査プロセスの数が 2 つから最大 3 つに増えました。

どのアップストリームも使わないエンジン:

- 試しに ModSecurity を起動するときなど、どのアップストリームも使わず、デフォルトのエンジンでもないエンジンがあります。そうしたエンジンでも、検査カーネルが失敗するとプロキシ全体が停止し、`stop: the kernel failed: <reason>` の行を出して exit 1 になります（上の「`kernel`」）。たとえば `kernel.restarts` が 0 のとき、そのエンジンの検査プロセスを SIGKILL で止めると、`stop: the kernel failed: BudgetExhausted` の行を出して停止します。
- 試した後は、`rules deactivate` でそのエンジンの選択を解除します。解除すると、次の再起動から、そのエンジンは起動しません。動作中のプロキシは起動したエンジンを止めないので、止めるには再起動します（下の「エンジンごとの選択中の世代」）。

デフォルトのエンジンを変更する手順:

デフォルトのエンジンを変更すると、`engine` を省略したアップストリームの検査エンジンも変わります。変えたくないアップストリームには、先に今のエンジンを `engine` に書いておきます。`kernel` は動作中に変更できないので、`kernel.default_engine` は、プロキシを再起動して変更します。

次の例は、`managed` のある設定で、デフォルトのエンジンを `coraza` から `modsecurity` に変更する手順です。コマンドはサービスと同じ OS ユーザーで実行します。

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

- 新しいデフォルトのエンジンの世代は、先頭の `rules import` で作ります。その世代にも、管理画面の Host での CRS の調整（[管理リファレンス](admin-reference.ja.md) の「管理画面の Host での CRS の調整」）と、インポートのルートを検査から外すルート（「インポートのルートを検査除外にする」）を入れます。
- その世代は、`kernel.default_engine` を書く前に選択します。SIGUSR1 を送らない間は、そのエンジンは起動せず、プロキシは稼働を続けます。
- 世代を選択する前に `kernel.default_engine` を書いて `config check` を実行すると、`rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine`（exit 1）で受け付けません。起動も、同じ文で受け付けません。
- 動作中のプロキシに SIGHUP を送ると、`config check` が `accepted` であっても、`reload: configuration refused: kernel cannot change while running` で拒否されます。変更するには、再起動します。
- 再起動の後の `start: rules engine` の行は、デフォルトのエンジンが先に出ます。管理画面のルートのリクエストは、新しいデフォルトのエンジンで検査します。`engine` を書いたアップストリームのリクエストは、書いたエンジンで検査します（リクエストのログの `engine`）。
- 管理プロセスも設定ファイルの `kernel.default_engine` を読むので、プロキシと一緒に再起動します（[管理リファレンス](admin-reference.ja.md) の「管理画面」）。

### エンジンごとの選択中の世代

ルールストアは、エンジンごとに、選択中の世代を 1 つ持ちます。

- ファイルは `current.coraza` と `current.modsecurity` です。内容は、世代のフィンガープリント（64 桁の小文字の 16 進数）と改行で、65 バイトです。
- `rules activate <config> <fingerprint>` は、その世代のエンジンの `current.<engine>` を書きます。`current.<engine>.new` に書いて同期してから置き換えるので、途中で止まっても、中途半端な内容は読まれません。途中で止まったときに残る `current.<engine>.new` は、どこからも読まれません。次に同じエンジンで実行した `rules activate` が消します。
- `rules list` は、エンジンごとの選択中の世代に `current` の印を付けます。2 つのエンジンの世代を選択していれば、印は 2 行に付きます。

以前のバージョンが書いた `current`:

- このバージョンは、`current` を書きません。以前のバージョンが書いた `current` は、同じエンジンの選択中の世代として読みます。エンジンに `current.<engine>` が無く、`current` が指す世代がそのエンジンの世代なら、その世代がそのエンジンの選択中の世代です。
- `rules activate` は、`current.<engine>` を書いた後に、同じエンジンの世代を指す `current` を消します。そのため、このバージョンで選択した後は、以前のバージョンはそのエンジンの選択中の世代を読めません（下の「バージョンの更新」）。
- 同じエンジンについて `current` と `current.<engine>` の両方があり、別の世代を指しているときは、どちらも選ばずに `the current generation records of the engine disagree` で受け付けません。`rules list`、`config check`、起動、SIGUSR1 のどれも同じです。以前のバージョンで選択し直したときなどに、この状態になります。`rules activate` でそのエンジンの世代を選択し直すと、`current.<engine>` を書いて `current` を消すので、元に戻ります。
- `current.<engine>` が別のエンジンの世代を指しているときと、ファイルの内容が正しくないときは、`the current generation record is broken` で受け付けません。ファイルを読めないときは、`the current generation record cannot be read` で受け付けません。

`rules deactivate <config> <engine>`:

- そのエンジンの選択を解除します。`current.<engine>` と、同じエンジンの世代を指す `current` を消し、解除した世代を `<fingerprint> deactivated` の行に出します。次の再起動から、そのエンジンは起動しません。
- 動作中のプロキシは、起動したエンジンの検査カーネルを止めません。そのエンジンは、プロキシを再起動するまで稼働します。再起動までの SIGUSR1 では、`reload: rules store refused: no generation is chosen` の行が出ます（上の「SIGUSR1（世代の切り替え）」）。
- このコマンドは、設定ファイルと、managed ストアの選択中のバージョンを読みます。デフォルトのエンジンか、どれかのアップストリームのエンジンがそのエンジンなら、`rules deactivate: the configuration uses the engine` の行を出して受け付けません（exit 1）。エンジンに選択中の世代が無いときも、`rules deactivate: no generation is chosen` の行を出して受け付けません（exit 1）。
- `managed` のある設定で、選択中のバージョンを読めないなど、設定を受け付けないときは、`rules deactivate: configuration refused: <reason>` の行を出します（exit 2）。`rules` のコマンドのうち、managed ストアを読むのは、このコマンドだけです。

稼働していないエンジンを使うアップストリームを書く順:

選択中の世代はあるが稼働していないエンジンを、アップストリームに書くときの順です（たとえば、起動のときに ModSecurity の世代を選択していなかったとき）。リロードは検査プロセスを起動せず、稼働していないエンジンのアップストリームを拒否するので、先に SIGUSR1 でそのエンジンを起動します。次の例では、`managed` のある設定で、Coraza だけを起動しているプロキシに ModSecurity のアップストリーム `mod` を追加します。

```text
tukuyomi-proxy rules activate <config> <fingerprint-modsecurity>   # ModSecurity の世代を選択する。SIGUSR1 はまだ送らない
tukuyomi-proxy managed activate <config> <version>                 # アップストリーム mod を書いたバージョン。ModSecurity の世代が選択中なので通る
kill -HUP <proxy-pid>
   reload: SIGHUP
   reload: configuration accepted
   reload: configuration refused: the engine of an upstream is not ready (upstream mod)
kill -USR1 <proxy-pid>                                             # ModSecurity が起動する
   reload: SIGUSR1
   reload: generation <fingerprint-coraza> is already running
   reload: starting generation <fingerprint-modsecurity>
   reload: rules engine modsecurity
   reload: rules mode block
   reload: rules routes 0
   reload: generation <fingerprint-modsecurity> is ready, switched
kill -HUP <proxy-pid>
   reload: SIGHUP
   reload: configuration accepted
   reload: configuration replaced <sha256> managed <version>
```

- 最初の SIGHUP は、ModSecurity が稼働していないので拒否されます。プロキシは前の設定のまま稼働を続け、`tukuyomi_config_reloads_total` の `refused` が 1 増えます。
- 先に SIGUSR1 で ModSecurity を起動してから SIGHUP を送れば、リロードは拒否されません。
- `managed activate` は、バージョンのアップストリームが使うエンジンに選択中の世代が無いと、バージョンを選択せずに拒否します（上の「`managed`」）。そのため、`rules activate` を先に実行します。

### 検査除外のルート

`rules import --routes <file>` のファイルは、次の形の JSON の配列です。

```json
[
  {"host": "app.example.com", "path": "/api/uploads", "action": "bypass"}
]
```

- `host` は省略できます。ほかの設定キーは受け付けません。`action` に書けるのは `bypass` だけです。
- ルートに一致するリクエストは、検査せずにアップストリームへ転送します。
  - プロキシが自分で行う検証（ヘッダー部、ボディのサイズの上限）は、その前に行います。ボディの型は検証しません（下の「ボディの型」）。
  - アップストリームは、検査除外のルートではなく、`forward` のルートかデフォルトのアップストリームで選びます。次のリクエストは、検査除外のルートに一致しても、応答は変わりません。
    - そこで 404・403・421 になるリクエスト
    - 全体の `access` と `rate_limit`、ホストごとの設定で拒否されるリクエスト（403・429）
    - 管理画面のルート（`admin.route`）で拒否されるリクエスト（421・404・403）
  - 検査のスロットを使わないので、検査が混んでいるときや、検査プロセスが止まっているときも通ります。
- ルートは、エンジンの世代ごとに効きます。リクエストに適用されるのは、そのリクエストを検査するエンジン（リクエストのアップストリームのエンジン）で稼働中の世代のルートだけです。ほかのエンジンの世代にあるルートでは、そのリクエストは検査除外になりません。
- `path` と `host` の形と一致の方法は、`forward` のルートと同じです。ほかに、次の決まりがあります。
  - `path` は `/` だけにはできません（すべてのリクエストの検査を外してしまうためです）。2〜255 バイトで書きます。
  - `host` にワイルドカードは書けません。
  - 1 つの世代で 256 個までです。`host` と `path` の同じ組み合わせは書けません。
- `host` を持つ検査除外のルートは、末尾が `.` の `Host`（`app.example.com.`）には一致しないので、そのリクエストは検査します。アップストリームがそれを別のホストとして解釈するかもしれないためです。`host` を持たないルートは、末尾が `.` の `Host` にも一致します。
- パスの読み方が複数あるリクエスト（「`access` を使うときの注意」に挙げた形）は、検査除外のルートに一致しないので、検査します。
- ルートは世代のマニフェストに入り、フィンガープリントの一部になります。動作中のプロキシは、エンジンの世代を切り替えるときに、そのエンジンのルートも切り替えます。

## managed 設定

managed 設定は、一部の設定を、設定ファイルの外にある managed ストアにバージョンとして保存する仕組みです。対象は、サイト（ホストと証明書）、アップストリーム、ルート、デフォルトのアップストリーム、全体のアクセス制御とレート制限、ホストごとの設定です。これらを管理画面と管理 API から編集して、動作中のプロキシに反映できます（[管理リファレンス](admin-reference.ja.md) の「managed 設定の操作」）。

使い始めるには、設定ファイルに `managed` を書きます。`managed` の無い設定ファイルは、これまでと同じように読みます。コマンドについては、上の「`managed`」を参照してください。

### managed 設定を使うかどうか

managed 設定を使うと、できることが増える代わりに、必要なことも増えます。

managed 設定でできることは、次のとおりです。

- **管理画面と管理 API で編集し、反映する**: 上に挙げた設定を、検証してから保存して、動作中のプロキシに反映できます。反映では、プロキシがそのバージョンで設定をリロードできた後でだけ、選択中のバージョンを進めます。そのため、プロキシが拒否したバージョンが、次の起動で使われることはありません（下の「反映」）。
- **保存したバージョンが残る**: 前のバージョンに戻せます（ロールバック、名前を指定した反映）。
- **変更の記録を残す**: 管理画面と管理 API からの反映は管理プロセスの変更履歴に、操作は監査ログに残ります（[管理リファレンス](admin-reference.ja.md) の「設定の変更履歴」と「監査ログ」）。コマンドでの変更は、どちらにも残りません。

その代わりに、次のことが必要になります。

- **設定ファイルに書けなくなる設定キーがある**: `forward` に書けるのは `resolve_timeout_ms` だけになります。TLS のリスナーの `certificates`、全体の `access`・`rate_limit`、`host_policies` も書けず、書くと設定を受け付けません。これらはバージョンに書きます。
- **設定に `admin` があれば、管理画面のルートが必須**: 管理画面のルート（`admin.route`。上の「`admin`」）はプロキシが作り、全体の設定もホストごとの設定も適用されません。適用されるネットワークの制限は、`admin.route.access` の `allow_cidrs` だけです。
- **`managed` を追加するときと外すときは、再起動が必要**: `managed` の有無と `managed.dir` は動作中に変更できない設定キーなので、プロキシと管理プロセスを再起動します。設定のリロードで変更しようとしても、拒否されます。
- **デフォルトのエンジンの世代に、検査除外のルートが必要**: 管理画面のルートへのリクエストも、デフォルトのエンジンで WAF の検査を受けます。管理画面からの検証と保存のリクエストは、証明書と秘密鍵を含むことがあり、ブロックする世代ではブロックされるおそれがあるので、この 2 つのパスを検査除外のルートにした世代を、デフォルトのエンジンの世代として使います（[管理リファレンス](admin-reference.ja.md) の「managed 設定を使う場合の管理画面のルート」）。デフォルトのエンジンを変更するときは、新しいデフォルトのエンジンの世代にも、同じルートを入れます（上の「検査エンジンの選択」）。
- **ACME のサイトの証明書を置く場所**: ACME で発行するサイトの証明書チェーンと秘密鍵は、設定ファイルに書いたパスではなく、managed ストアの `acme/` に置きます（下の「ACME のサイト」）。
- **ログ送信プロセスのビルド**: ログ送信プロセスも設定ファイルを読みます。使うなら、プロキシと同じビルドに入れ替えてから、設定ファイルに `managed` を書きます。`managed` を知らない前のビルドは、未知の設定キーのある設定ファイルを受け付けず、起動しません（下の「ログ送信プロセスの起動」）。`kernel.default_engine` とアップストリームの `engine` も、前のビルドにとっては未知の設定キーです。これらも同じビルドに入れ替えてから書きます（下の「バージョンの更新」）。

設定をファイルだけで管理し、管理画面から変更しないなら、`managed` は必要ありません。

### managed ストアとバージョン

ここでは、managed ストアの置き方と中身、バージョンの形を説明します。

設定キー `managed` が持つのは、`{"dir"}` だけです。`dir` は managed ストアのディレクトリで、3840 バイトまでの絶対パスで書きます。

- **ディレクトリの条件**: シンボリックリンクではないディレクトリであること、所有者がプロキシの OS ユーザーであること、グループとその他のユーザーに権限が無いこと（0700）です。開くたびに検証し、条件に合わなければ受け付けません。このディレクトリはプロキシもコマンドも作らないので、先に作っておきます。
- **ほかのディレクトリとの関係**: ルールストア、`records.dir`、管理データの保存先（`admin.store.dir`）、制御ソケットのあるディレクトリ、`acme.challenge_dir` とは、同じディレクトリにできません。どちらかがもう一方の中にある配置もできません。`acme.account_key_file`・`acme.ca_file` と、管理画面のルートが使う証明書と秘密鍵のファイルは、managed ストアの中に置けません（上の「値どうしの関係」）。

managed ストアの中身は次のとおりです。

| 名前 | 内容 |
|---|---|
| `versions/<version>.json` | バージョン。1 MiB まで |
| `files/<sha256>` | バージョンが指す証明書チェーン、秘密鍵、アップストリームの CA のファイル。1 MiB まで |
| `acme/<hosts-sha256>/chain`、`acme/<hosts-sha256>/key` | ACME のサイトの証明書チェーンと秘密鍵（下の「ACME のサイト」） |
| `current` | 選択中のバージョンの SHA-256（64 桁の 16 進数）と改行 |
| `lock` | managed ストアを変更するコマンドと管理プロセスが持つロック |

- バージョンとファイルの名前は、内容の SHA-256（64 桁の小文字の 16 進数）です。作った後は変更しません。読むたびに名前と内容を照合し、合わないものは使いません。
- `versions/` と `files/` は、無ければインポートのときに作ります。`acme/` は、無ければ `acme renew` が作ります（どれも 0700）。
- バージョン、ファイル、`current` は、`.new` の名前で書き込んで同期してから置き換えるので、途中で止まっても、読む側は前のものか新しいものを丸ごと読みます。
- バージョンとして受け付けるのは、決まった書き方（空白の無い JSON で、オブジェクトの設定キーをバイト順に並べたもの）だけです。同じ内容は、いつも同じ名前のバージョンになります。バージョンは手で書かず、`managed import` か管理画面で作ります。
- `managed list` の時刻は、バージョンのファイルの更新時刻です。

バージョンは次の形の JSON です。

```text
{"sites": [..], "upstreams": {..}, "routes": [..], "default_upstream": "..", "access"?: {..}, "rate_limit"?: {..}, "host_policies"?: [..]}
```

- `upstreams`、`routes`、`default_upstream`、`access`、`rate_limit`、`host_policies` の形と決まりは、`managed` の無い設定ファイルと同じです（上の「`forward`」と、下の「アクセス制御とレート制限」）。受け付けないときの文も同じです。違うのは 1 点だけで、アップストリームの `tls` は `{"ca", "server_name"?}` と書き、`ca` には managed ストアの `files/` にあるファイルの SHA-256 を書きます。アップストリームの `engine` は、`forward` と同じ形で書けます。
- `sites` はサイトの一覧で、0〜64 個です。サイトは `{"name", "hosts", "certificate"}` と書きます。
  - `name` は、アップストリームの名前と同じ決まり（1〜64 文字の英数字・`-`・`_`）で書きます。サイトどうしで同じ名前は書けません。
  - `hosts` は 1〜64 個で、リスナーの証明書の `hosts` と同じように書きます（名前か、`*.` と名前）。同じホストを 2 つのサイトに書くことはできません。
  - `certificate` は、`{"chain", "key"}`（managed ストアの `files/` にある証明書チェーンと秘密鍵の SHA-256）か、`{"acme": {"renew_before_days"}}`（下の「ACME のサイト」）のどちらかです。
- バージョンにパスは書きません。
- バージョンは、設定ファイルと合わせて検証します。
  - アップストリームの `engine` は、設定ファイルの `kernel`（`engines` と `default_engine`）と合わせて検証します。`engine` を省略したアップストリームは、`kernel.default_engine` のエンジンになります。
  - 管理画面のルートのホスト（`admin.route.host`）は、サイトの `hosts` にも、ルートの `host` にも書けません。`*.` のサイトがそのホストを含むのはかまいません。管理画面のルートが先に一致するためです。
  - アップストリームのサーバーには、`admin.listen` のアドレスを使えません。名前を解決したアドレスも同じです。
  - TLS のリスナーがあれば、サイトか管理画面のルートの証明書が 1 つ以上必要です。
- どの TLS のリスナーも、管理画面のルートとすべてのサイトが持つ証明書から、クライアントが SNI で指定したホストに合う証明書を選びます。ホストと同じ名前の証明書を、`*.` で含む証明書より先に選びます。

`managed import` に渡す文書はバージョンと同じ形で、ファイルを SHA-256 ではなくパスで書きます。サイトの `certificate` は `{"chain_file", "key_file"}` か `{"acme": {..}}`、アップストリームの `tls` は `{"ca_file", "server_name"?}` と書きます。パスは 3840 バイトまでの絶対パスです。文書の大きさは 1 MiB までで、空白などの書き方は自由です。

- コマンドは、文書が指すファイル（1 MiB までの通常のファイル）を 1 回ずつ読み、プロキシと同じように検証します。証明書チェーンと秘密鍵が対応していて、サイトのホストを含むこと、CA のファイルが使えることを確認します。検証に通れば、ファイルを `files/` に置き、それを SHA-256 で指すバージョンを `versions/` に置きます。
- インポートした後は、文書と、文書が指すサイトの証明書チェーン・秘密鍵・CA のファイルは使いません。managed ストアにコピーしてあるので、削除してかまいません。

管理画面と管理 API で変更したときの変更履歴は、管理プロセスが別に持ちます（[管理リファレンス](admin-reference.ja.md) の「設定の変更履歴」）。

### managed 設定での初回起動

`managed` のある設定で、初めてプロキシを起動するまでの手順です。

選択中のバージョンが無いと、起動も `config check` も拒否されます（`config check: managed store refused: no managed version is chosen`、exit 1）。そのため、起動の前にバージョンをインポートし、選択しておきます。それ以外の手順は、[ビルドと配置](../build/binary-deployment.ja.md) の「初回起動の手順」と同じです。

ここで例にする構成は次のとおりです（ACME のサイトについては、下の「ACME のサイト」を参照してください）。

- リダイレクトのリスナーと TLS のリスナー
- ファイルの証明書を持つサイト 1 つ
- アップストリーム 1 つ
- 管理画面のルート

1. ディレクトリを作ります。[ビルドと配置](../build/binary-deployment.ja.md) の「OS ユーザーとディレクトリ」にある表のディレクトリに加えて、managed ストアのディレクトリを 0700 で作ります。

   ```bash
   sudo install -d -m 0700 -o tukuyomi -g tukuyomi /var/lib/tukuyomi-core/managed
   ```

2. 証明書のファイルを置きます。
   - 管理画面のルートの証明書と秘密鍵（例: `/var/lib/tukuyomi-core/tls/admin.pem`・`admin.key`）。設定ファイルではこのパスを指定します。
   - サイトの証明書チェーンと秘密鍵（例: `/var/lib/tukuyomi-core/import/www.pem`・`www.key`）。インポートで読み込むファイルなので、サービスの OS ユーザーが読める場所に置きます。
3. 設定ファイルを書きます。`managed` の無い設定ファイルとの違いは次のとおりです（ほかの設定キーは同じように書きます）。

   ```json
   "proxy": {
     "listeners": [
       {"address": "0.0.0.0:80", "redirect": {"https_port": 443}},
       {"address": "0.0.0.0:443", "tls": {"min_version": "1.2"}}
     ]
   },
   "forward": {"resolve_timeout_ms": 5000},
   "managed": {"dir": "/var/lib/tukuyomi-core/managed"},
   "admin": {
     "listen": "127.0.0.1:9100",
     "control": "/var/lib/tukuyomi-core/control/proxy.sock",
     "store": {"kind": "file", "dir": "/var/lib/tukuyomi-core/admin"},
     "origin": "https://admin.example.com",
     "trusted_proxies": ["127.0.0.1/32"],
     "mfa": "required",
     "session_idle_ms": 1800000,
     "session_total_ms": 43200000,
     "route": {
       "host": "admin.example.com",
       "certificate": {
         "cert_file": "/var/lib/tukuyomi-core/tls/admin.pem",
         "key_file": "/var/lib/tukuyomi-core/tls/admin.key"
       },
       "access": {"allow_cidrs": ["203.0.113.0/24"]}
     }
   }
   ```

   - `proxy` は、`listeners` 以外の設定キーを省略して示しています。TLS のリスナーには `certificates` を書きません（`http2` は書けます）。
   - `forward` には、`resolve_timeout_ms` だけを書きます。全体の `access`・`rate_limit` と `host_policies` は、バージョンに書きます。
   - `admin.route.access` の `allow_cidrs` には、管理画面を使う人のネットワークを書きます。
4. バージョンの文書を書きます（例: `/etc/tukuyomi-core/managed-import.json`）。サービスの OS ユーザーが読めるように置きます。

   ```json
   {
     "sites": [
       {
         "name": "www",
         "hosts": ["www.example.com"],
         "certificate": {
           "chain_file": "/var/lib/tukuyomi-core/import/www.pem",
           "key_file": "/var/lib/tukuyomi-core/import/www.key"
         }
       }
     ],
     "upstreams": {
       "web": {"servers": [{"address": "127.0.0.1:8080", "weight": 1, "max_fails": 0, "fail_timeout_ms": 10000, "backup": false}]}
     },
     "routes": [],
     "default_upstream": "web"
   }
   ```

5. ルールセットをインポートし、世代を選択します（[ビルドと配置](../build/binary-deployment.ja.md) の「初回起動の手順」の 2〜4）。
   - この手順は 7 より前に行います。7 の `managed activate` が、バージョンのアップストリームが使うエンジンに選択中の世代があることを確認するためです。
   - `rules import` と `rules activate` は、設定ファイルだけを読み、managed ストアは読まないので、`current` がまだ無くても通ります（6 の後に実行してもかまいません）。
   - `rules deactivate` は、managed ストアの選択中のバージョンも読みます（上の「エンジンごとの選択中の世代」）。
6. バージョンをインポートします。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy managed import /etc/tukuyomi-core/config.json /etc/tukuyomi-core/managed-import.json
   ```

   - `<version> created` が出ます。インポートはバージョンを置くだけで、選択はしません。`current` はまだ無い状態です。
   - この後は、インポートで読んだサイトのファイル（`www.pem`・`www.key`）を使わないので、削除してかまいません。
7. バージョンを選択します。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy managed activate /etc/tukuyomi-core/config.json <version>
   ```

   - 起動と同じ検証を実行し、通ったときだけ選択します。検証するのは、設定ファイルとバージョン、アップストリームの名前解決と CA のファイル、証明書です。`<version> current` が出ます。
8. 設定を検証します。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy config check /etc/tukuyomi-core/config.json
   ```

   - 通れば、標準出力に `accepted` が、標準エラーに `config check: managed version <version>` の行が出ます。
9. サービスを起動します（[ビルドと配置](../build/binary-deployment.ja.md) の「systemd」）。ログに `start: managed version <version>` の行が出ます。
10. 管理プロセスを起動し、最初のユーザーを作成します（[ビルドと配置](../build/binary-deployment.ja.md) の「初回起動の手順」の 7）。管理画面には、`admin.route.access` が許可するネットワークから、`admin.route.host` のホスト名でアクセスします。これ以降の変更は、管理画面か管理 API で行います（下の「反映」）。

### managed 設定への移行

`managed` の無い設定ファイルで動作中のプロキシと管理プロセスを、managed 設定に移行する手順です。移行すると、設定ファイルにあるルートなどはバージョンへ移ります。管理画面のホストへのルートは、`admin.route` へ移ります。変換するコマンドは無いため、設定ファイルとバージョンの文書は手で書きます。

ログ送信プロセスを使っている場合は、先にプロキシと同じビルドの実行ファイルに入れ替えておきます（上の「managed 設定を使うかどうか」）。

何がどこへ移るかは次のとおりです。

| 現在の設定ファイル | 移行後 |
|---|---|
| TLS のリスナーの `certificates` のうち、管理画面のホストの証明書 | `admin.route.certificate`（`cert_file`・`key_file`・`acme` はそのまま） |
| ほかの証明書 | バージョンのサイト。ファイルの証明書は文書の `chain_file`・`key_file`、ACME の証明書は `{"acme": {..}}`（パスは書きません） |
| `forward.upstreams` のうち、`admin.listen` を指すアップストリーム | 外します（バージョンのサーバーには `admin.listen` を書けません） |
| ほかのアップストリーム | バージョンの `upstreams` |
| `forward.routes` のうち、管理画面のホストのルート | 外し、その `access` を `admin.route.access` にコピーします（`allow_cidrs` が必要です） |
| ほかのルートと `default_upstream` | バージョンの `routes`・`default_upstream` |
| 全体の `access`・`rate_limit`、`host_policies` | バージョンの同じ設定キー |
| `forward.resolve_timeout_ms`、`acme`、`admin` のほかの設定キー（`origin` を含む） | 設定ファイルにそのまま残します |

- `admin.route.host` は、現在の管理画面のホスト（`admin.origin` のホスト）にします。
- 管理画面のルートには全体の設定が適用されないので、現在のルートの `access` を正しくコピーしないと、管理画面に到達できる相手が変わります。

手順は次のとおりです。

1. managed ストアのディレクトリを作ります（上の「managed 設定での初回起動」の 1）。
2. 移行後の設定ファイルを、別の名前（例: `/etc/tukuyomi-core/config.managed.json`）で書きます。バージョンの文書（例: `/etc/tukuyomi-core/managed-import.json`）も書きます。
3. 新しい設定ファイルを使って、バージョンをインポートし、選択します。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy managed import /etc/tukuyomi-core/config.managed.json /etc/tukuyomi-core/managed-import.json
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy managed activate /etc/tukuyomi-core/config.managed.json <version>
   ```

   - この時点では ACME のサイトの証明書がまだ managed ストアに無いので、`managed activate` は `managed activate: tls certificate not issued yet (site <name>)` の行を出します。拒否はしません。
4. ACME のサイトごとに、現在の証明書チェーンと秘密鍵を `acme/<hosts-sha256>/` にコピーします。`<hosts-sha256>` の求め方は、下の「ACME のサイト」にあります。コピーしないと、`acme renew` を実行して SIGUSR2 を送るまで、そのサイトのホストに TLS で接続できません。

   ```bash
   sudo -u tukuyomi mkdir -m 0700 /var/lib/tukuyomi-core/managed/acme
   d=/var/lib/tukuyomi-core/managed/acme/$(printf '%s\n' www.example.com | LC_ALL=C sort | sha256sum | cut -d' ' -f1)
   sudo -u tukuyomi mkdir -m 0700 "$d"
   sudo -u tukuyomi install -m 0600 /var/lib/tukuyomi-core/tls/www.pem "$d/chain"
   sudo -u tukuyomi install -m 0600 /var/lib/tukuyomi-core/tls/www.key "$d/key"
   ```

5. 新しい設定ファイルで `config check` を実行します。`accepted` が出て、`not issued yet` の行が出ないことを確認してください。
   なお、`acme renew` を実行したときの結果は、コピーした証明書の有効期限までが `renew_before_days` 日より短くなければ `site <name> valid`、短ければ発行し直して `site <name> renewed` です。
6. 移行前の構成を残しておきます。元の設定ファイルは `config.json.before-managed` などの名前で残し、元の実行ファイルとユニットも残します。
7. 新しい設定ファイルを、元のパス（例: `/etc/tukuyomi-core/config.json`）に置きます。同じディレクトリにコピーしてから、リネームして置き換えます。
8. 管理プロセス、プロキシ、ログ送信プロセスの順に再起動します（`systemctl restart`）。
   - この手順では `admin.route` を追加するので、動作中に変更できない設定キー（`admin.route.host` と `managed`）が変わり、`systemctl reload` は拒否されます（`reload: configuration refused: admin.route.host cannot change while running`）。比較する順序の関係で、`admin.route.host` が先に出ます。
   - 管理プロセスを再起動してからプロキシを再起動するまでの間も、管理画面には元のルートでアクセスできます。この間、managed 設定の変更の依頼は 409 で拒否されます（何も変更されません）。
   - プロキシを再起動している間は、接続が切れます。
9. 次の点を確認します。
   - プロキシのログに `start: managed version <version>` の行が、ログ送信プロセスのログに `records-ship: configuration accepted` の行が出ていること。
   - どのホストにも元と同じ証明書が返り、ルートと `access` が元と同じように効いていること。
   - 管理画面のルートで、管理画面にアクセスできること。

移行前の構成に戻すときは、上の 6 で残したものを使います。移行後に `acme renew` が更新したサイトの証明書は managed ストアにしかなく、元の設定ファイルが指すファイルは古いままです。

### 反映

動作中のプロキシに別のバージョンを使わせる方法は次の 2 つです。

1. **管理画面と管理 API の反映**（保存して反映、名前を指定した反映、ロールバック）: 管理プロセスが制御ソケットで `reload` を依頼し、プロキシにそのバージョンで設定をリロードさせます（上の「制御ソケット」）。`current` をそのバージョンにするのは、プロキシの設定が切り替わった後だけです。プロキシが拒否したバージョンは、`current` になりません。操作と応答については、[管理リファレンス](admin-reference.ja.md) の「managed 設定の操作」を参照してください。
   - 反映している間は、管理プロセスが managed ストアのロックを持ちます。その間に実行した `managed import`・`managed activate`・`managed remove` は拒否されます（`the managed store is in use by another command`）。
   - プロキシは、リロードが終わるのを、動作中の設定の `forward.resolve_timeout_ms` に 5 秒を加えた時間まで待ってから応答します。`resolve_timeout_ms` を長くすると反映にかかる時間も長くなり、その間はコマンドも拒否されます。
   - 管理プロセスが応答を待つ時間と、証明書の検証での拒否（`tls`。`acme renew` が証明書を置き換えている瞬間と重なったときなど）の扱いは、[管理リファレンス](admin-reference.ja.md) の「制御ソケット」を参照してください。
2. **コマンドと SIGHUP**: `managed activate` が、起動と同じ検証を実行して `current` を変更します。コマンドはプロキシに依頼しないので、動作中のプロキシが `current` のバージョンを読むのは、次の SIGHUP（`systemctl reload`）か起動のときです（上の「SIGHUP（設定のリロード）」）。
   - SIGHUP が拒否されても、`current` は、動作中のプロキシが拒否したバージョンのまま残ります。次に起動するときは、そのバージョンが使われます。拒否される理由には、動作中に変更できない設定キーの違い、アップストリームのエンジンが稼働していないこと、新しいリスナーのバインドなどがあります。
   - 動作中のプロキシのバージョンを変更するには、管理画面か管理 API を使います。コマンドで変更したときは、すぐに `systemctl reload` を実行し、`reload: configuration replaced <sha256> managed <version>` の行が出ることを確認します。

どちらの方法にも、次の点は共通です。

- リロードでは、バージョンと一緒に設定ファイルも読み込みます。設定ファイルを書き換えてまだ SIGHUP を送っていなければ、管理画面から反映したときに、その書き換えも効きます。設定ファイルにエラーがあれば、反映も拒否されます（`configuration`）。
- 同じバージョンでも、リロードします。そのときも SIGHUP と同じく、待機中の keep-alive の接続を閉じ、HTTP/2 の接続には `GOAWAY` を送ります。アップストリームのダウン判定と失敗の数も初期化します（上の「SIGHUP（設定のリロード）」）。
- ログには、`reload: control reload <version>`（制御ソケットの依頼で始めたとき）と、SIGHUP と同じ `reload:` の行、`control: reload <version>: <result> (<reason>)` が出ます（下の「ほかのログ」）。

反映が途中で止まったときの状態と直し方は次のとおりです。

| 状態 | 起きる場合 | SIGHUP と再起動 | 直し方 |
|---|---|---|---|
| 使われないバージョンが残る | 管理画面で保存した後、リロードを依頼する前に、管理プロセスが止まった場合 | `current`（前のバージョン）のまま | 害はありません。必要なければ削除します（下の「バージョンの削除」） |
| 何も変更されない | リロードの途中でプロキシが止まった場合、またはリロードが拒否された場合 | `current`（前のバージョン）のまま | 止まったときは再起動し、もう一度反映します |
| プロキシは新しいバージョン、`current` は前のバージョン | プロキシの設定が切り替わった後、`current` を変更する前に管理プロセスが止まった場合、`current` を書けなかった場合、または結果が分からないまま終わった反映で、後からプロキシの設定が切り替わった場合 | 前のバージョンに戻ります | 同じバージョンをもう一度反映します（前のバージョンを反映しても、両者は一致します） |
| プロキシは前のバージョン、`current` は新しいバージョン | プロキシの設定が切り替わった後、`current` を変更するまでの間に SIGHUP が来た場合、またはプロキシが止まって前のバージョンで再起動した場合 | 新しいバージョンに切り替わります | もう一度反映します |

- 稼働中のバージョンは、制御ソケットの `status` の `managed` で分かります。選択中のバージョンは、`managed list` の `current` で分かります。管理画面と管理 API での見え方は、[管理リファレンス](admin-reference.ja.md) の「managed 設定の操作」を参照してください。
- プロキシと管理プロセスは、この不一致を自動では修正しません。どちらのバージョンが正しいかは、止まった理由によって違うためです。

### 配置の注意

ACME のチャレンジのディレクトリ、managed ストア、証明書の置き方についての注意です。

- `acme.challenge_dir` はチャレンジ専用のディレクトリにして、ほかのファイルを置かないでください。ログ送信プロセスの接続文字列のファイル、国のデータベース、アップストリームの CA のファイル、検査プロセスの実行ファイルなども置かないでください。
- `acme.challenge_dir` と managed ストアには、シンボリックリンクを使わないでください。ディレクトリが重なっていないかの検証では、設定に書いたままのパスを比べるためです。
- `acme.account_key_file` と、管理画面のルートが使う証明書と秘密鍵のファイルは、ルールストア、`records.dir`、管理データの保存先、managed ストアの中に置かないでください。`acme renew` は、これらのファイルを書き換えます。

### ACME のサイト

バージョンのサイトの `certificate` を `{"acme": {"renew_before_days": 30}}` にすると、`acme renew` がそのサイトの証明書を発行し、更新します。`renew_before_days` は 1〜60 です。`managed import` の文書にも同じ形で書き、パスは書きません。

- ACME のサイトの `hosts` には名前だけを書き、`*.` は書けません。設定ファイルには `acme` が必要です。
- `managed` のある設定ファイルでは、`acme` を持つ証明書が設定ファイルに無くても、`acme` を書けます。ACME のサイトはバージョンの中にあるためです。
- 証明書チェーンと秘密鍵は、managed ストアの `acme/<hosts-sha256>/chain` と `key` にあります。`<hosts-sha256>` は、サイトの `hosts` をバイト順に並べ、それぞれの後ろに改行を付けてつないだバイト列の SHA-256 です。計算にサイトの名前は入らないので、ホストの組み合わせが同じなら、サイトの名前を変更しても別のバージョンでも同じディレクトリを使います。

  ```bash
  printf '%s\n' www.example.com app.example.com | LC_ALL=C sort | sha256sum | cut -d' ' -f1
  ```

- `acme/` とその中のディレクトリは、無ければ `acme renew` が作ります（0700）。シンボリックリンクなど、ディレクトリでないものがあると、そのサイトは CA に注文せずに `failed` になります。
- `acme renew` は、`current` のバージョンを読みます。`acme` を持つ管理画面のルート、バージョンのサイトの順に処理します。結果の行は、`admin route renewed|valid|failed` と `site <name> renewed|valid|failed` です。
  - `acme` を持つ管理画面のルートも ACME のサイトも無いときは、結果の行を出さずに、標準エラーに 1 行出して exit 0 で終わります。タイマーを失敗させないためです。
  - `current` かバージョンが読めないときは、設定を受け付けずに exit 2 で終わります。設定ファイルにある管理画面のルートの証明書も更新しません。
- ファイルがまだ無いサイトは、証明書をまだ発行していないものとして扱います。起動、設定のリロード、`config check`、`managed activate` は、これを拒否しません。`tls certificate not issued yet (site <name>)` の行を出し、そのサイトのホストに対するハンドシェイクを拒否します。ファイルができた後の SIGUSR2 で、証明書を使い始めます。
- ホストの組み合わせを変更したバージョン（サイトにホストを追加した場合、ホストを変更した場合、`{"chain", "key"}` から `acme` に変更した場合）に反映すると、新しいディレクトリにはまだ証明書が無いので、そのサイトのすべてのホストに TLS で接続できなくなります（以前から接続できたホストも同じです）。反映の後は、すぐに `acme renew` と SIGUSR2 を実行してください。[ビルドと配置](../build/binary-deployment.ja.md) の「証明書の更新のタイマー」のサービスを、`systemctl start tukuyomi-core-acme.service` で実行します。タイマーに任せると、次にタイマーが動くまで接続できません。
- 前のバージョンに戻したとき（ロールバック、名前を指定した反映）は、そのホストの組み合わせに対応するディレクトリに前の証明書が残っていれば、発行し直さずに使います。プロキシは証明書の有効期限を見ないので、有効期限の切れた証明書もそのまま使います。戻した後は `acme renew` を実行してください。有効期限が近ければ、発行し直します。
- プロキシがチャレンジに応答するホストは、`acme` を持つ管理画面のルートのホストと、稼働中のバージョンにある ACME のサイトのホストです。反映でバージョンが切り替わると、応答するホストも一緒に切り替わります。`admin.route.access` はチャレンジには適用されません。CA はどのアドレスからも来るためです。
  - コマンドで `managed activate` を実行した後、SIGHUP を送る前に `acme renew` を実行すると、新しいバージョンだけにあるホストにはプロキシがチャレンジに応答しないので、そのホストは `failed` になります。`managed activate` の後は、すぐに設定をリロードしてください（上の「反映」）。
- 管理画面のルートの証明書に `acme` を付けたときは、ファイルの場所を設定ファイルの `cert_file`・`key_file` に書きます。起動のときにファイルが無くてもかまいません。ファイルが無い間は、管理画面のルートのハンドシェイクを拒否します。初回の発行は下の「ACME」の「初回の発行」と同じです。
- 残ったバージョンのどれにも同じホストの組み合わせのサイトが無ければ、バージョンを削除したときに、その `acme/` のディレクトリも削除されます（下の「バージョンの削除」）。

### バージョンの削除

バージョンは、`managed remove`（上の「`managed`」）か管理 API（[管理リファレンス](admin-reference.ja.md) の「managed 設定の操作」）で削除します。

- 選択中のバージョン（`current`）と使用中のバージョンは、削除できません（`the managed version is the current one`、`the managed version is in use`）。使用中のバージョンは、次のとおりです。
  - プロキシで稼働中のバージョン
  - 設定のリロードで読んでいるバージョン
  - `acme renew` が終わるまで読んでいるバージョン
  - `config check` と `managed activate` が読んでいる間のバージョン
- `acme renew` などが読んでいる間の拒否は、終わった後にもう一度実行すれば通ります。
- 管理 API はロールバック先のバージョンも削除しません。
- 削除と一緒に、どのバージョンからも指されなくなったファイルを片付けます。`files/` の証明書チェーン、秘密鍵、CA のファイルと、`acme/` のディレクトリ（ACME のサイトの証明書と秘密鍵）も削除されます。後で同じホストの組み合わせを持つ ACME のサイトを使うと、証明書を発行し直します。これは CA の発行の回数に数えられます。
- プロキシのビルドを入れ替えたときは、プロキシを新しいビルドで再起動してから、バージョンを削除します。
- managed ストアは、`flock` のロックが使えるファイルシステムに置きます。バージョンの削除とプロキシの読み込みは、バージョンのファイルのロックで保護します。ロックを取得できないと、インポート、削除、起動を拒否します。

## リクエストの処理

プロキシがリクエストのヘッダー部とボディをどう検証するか、転送の前に何を除くか、どんな応答を返すかを説明します。

### ヘッダー部の検証

リクエストのヘッダー部は、HTTP の解析の前に次の順に検証し、最初に違反した決まりに応じて応答します。ただし、ヘッダーフィールドが 64 個を超えるヘッダー部は、1・2 より先に 431 になります。

1. 行の終わりは CRLF だけです。ヘッダー部は空の行で始まりません。
2. メソッドは 1〜32 バイトのトークンで、`CONNECT` ではありません。リクエストターゲットは `/` で始まり、1〜4096 バイトで、`#` を持ちません。パスに `<`・`>`・`` ` ``、クエリに `"`・`<`・`>` を持ちません。バージョンは `HTTP/1.1` か `HTTP/1.0` です。リクエストターゲットが長すぎれば 414 です。
3. ヘッダーフィールドは 64 個までです。名前は 1〜256 バイト、値は 4096 バイトまでで、名前と値の合計は 24 KiB までです。値には HTAB 以外の制御文字を含みません。超えれば 431 です。
4. 空でない `Host` が、ちょうど 1 つあります。
5. `Transfer-Encoding` と `Content-Length` を一緒に持ちません。`Transfer-Encoding` は `chunked` ちょうどの 1 行で、`HTTP/1.0` のリクエストは持ちません。`Content-Length` は数字の 1 行で、ボディの上限を超えません（超えれば 413 です）。
6. `Expect` は無いか、`100-continue` ちょうどの 1 行です。違えば 417 です。
7. `Connection` はトークンの一覧で、`host`、`content-length`、`content-type`、`content-encoding` を挙げません。
8. `Content-Encoding` は無いか、`gzip` ちょうどの 1 行です。違えば 415 です。`Content-Length` が 0 より大きいリクエストは、`Content-Type` を 2 つ以上持ちません。違えば 415 です。

ほかの違反は 400 になります。拒否するときの応答にボディはありません。

- HTTP/1.1 の接続の最初のリクエストを拒否するときは、応答を返して接続を閉じます。
- 2 つ目からのリクエストのヘッダー部を拒否するときは、応答を返しません。前の応答を送り終えてから、接続を閉じます。ログは `class` が `closed`、`status` が 0 の接続のログになります。
- HTTP/2 のストリームのヘッダーフィールドも、HTTP/1.1 のヘッダー部の形に書き直してから、同じ決まりで検証します。拒否するときは、そのストリームにだけ応答を返し、接続は続けます。

ヘッダーについてのほかの決まりは次のとおりです。

- 名前に `_` を含むヘッダーは、検査も転送もしません。アップストリームのサーバーの多くは `X_Forwarded_For` と `X-Forwarded-For` を同じ変数として読み込むため、クライアントがそうした名前でプロキシが付けるアドレスを装えないようにしています。
- `Expect: 100-continue` は受け付けますが、検査する形にも、アップストリームへ送るリクエストにも入れません。プロキシはボディを読み始めるときに 100 を返します。
- リクエストのトレーラーは受け付けません（400）。
- HTTP/1.1 の接続では、次のリクエストが、その接続の最後のリクエストになります。
  - chunked のリクエスト、`Upgrade` を持つリクエスト
  - HTTP/1.0 のリクエスト（応答も HTTP/1.0 で返します）
  - `Connection: close` のリクエスト
  - ボディを読み終えないまま応答したリクエスト（ボディを持ったまま 403・404・415・421・429 で拒否したリクエストなど）
- リクエストとリクエストの間（前のリクエストの後、次のヘッダー部の前）にある空の行は、2 つまで捨てます。

### ボディの型

ボディの型は、ヘッダー部を検証し、ルートを選んだ後に検証します（下の「リクエストの検証の順序」の 10）。決まりは検査するルートかどうかで違います。

- 検査するルートでは、空でないボディに `Content-Type` がちょうど 1 つ必要で、その値は次のどれかです（`;` より前を、大文字と小文字を区別せずに比べます）。違えば 415 です。
  - `application/x-www-form-urlencoded`
  - `multipart/form-data`
  - `application/json`
  - `application/<name>+json`（名前は 1〜122 バイトの英数字・`.`・`-`）
- 検査除外のルートでは、型を検証しません。`Content-Type` の無いボディも、ほかの型のボディも、そのまま流します。ただし、`Content-Type` を 2 つ以上持つ空でないボディは、どのルートでも 415 です。読む側によって、どの行を型として解釈するかが違うためです。
- `Content-Length` のあるボディは、読む前に検証します。chunked のボディは、読むまで空かどうか分からないため、読んだ後に検証します。chunked のボディが検査する長さより長いときは、先頭のその長さを読んだ後に検証します。空のボディは型を問いません。

### 転送の前に除くヘッダー

アップストリームへ転送する前に、接続ごとのヘッダー（`Connection` とそれが挙げるもの、`Keep-Alive`、`TE`、`Transfer-Encoding`、`Upgrade`、`Expect` など）と `Proxy-Authorization` を除きます。上の「クライアントのアドレス」のヘッダーはその後に付けるので、クライアントがそのヘッダーの名前を挙げても、除かせることはできません。

アップストリームの応答のトレーラーは、クライアントへ送りません。

### 応答

プロキシが返すステータスコードと、それぞれを返す場合は次のとおりです。

| ステータスコード | 場合 |
|---|---|
| ルールのステータスコード | ルールがブロックした場合（200〜599 の外なら 500） |
| 400、408、413、414、415、417、431 | ヘッダー部かボディが拒否された場合 |
| 403 | 全体の `access`、ホストごとの設定の `access`、ルートの `access`、管理画面のルートの `admin.route.access`（`denied by route access`）に拒否された場合 |
| 404 | 一致するルートもデフォルトのアップストリームも無い場合、リダイレクトしない `Host` の場合、リダイレクトのリスナーではない平文のリスナーで受けた、管理画面のルートのホストの場合（`admin host over plain http`） |
| 421 | `Host` が TLS の証明書に入っていない場合、管理画面のルートのホストを、その証明書ではない接続で受けた場合（`admin host on another certificate`） |
| 429 | 全体の `rate_limit` かホストごとの設定の `rate_limit` に拒否された場合。応答は `Retry-After` を持ちます |
| 502 | アップストリームに接続できない場合、アップストリームの応答が不正な場合、アップストリームがタイムアウトした場合、アップストリームのどのサーバーも使えない場合 |
| 503 | 検査できない場合（検査プロセスが使えない、検査のスロットの待ちが満杯になった・タイムアウトした）、予算が尽きた場合、リクエストがタイムアウトした場合、プロキシ自身がアップストリームへの接続を作れない場合 |
| 500 | プロキシの内部で不整合が起きた場合（ログに `internal fault` の行も出ます） |

プロキシが自分で作る応答は、ボディが空で `Content-Length: 0` を持ちます（204・304 は `Content-Length` を持ちません。429 は `Retry-After` も持ちます）。ACME のチャレンジの 200 は、チャレンジのファイルをボディに持ちます。

プロキシが返す応答は、すべて `X-Request-ID` にリクエスト ID を 1 つ持ちます。アップストリームの応答、ブロック、ヘッダー部の拒否、リダイレクトも同じです。アップストリームの応答に同じ名前のヘッダーがあれば、置き換えます。リクエスト ID は、そのリクエストのログの `id` と同じです。拒否された人から ID を伝えてもらえば、ログを検索できます。

## アクセス制御とレート制限

設定ファイルの最上位にある `access`、`rate_limit`、`host_policies`、`geo` は、ルートを探す前にリクエストを拒否するポリシーを決めます。`access` と `rate_limit` は、全体の設定（全体のアクセス制御と全体のレート制限）です。`host_policies` はホストごとの設定で、ホストごとに、全体の設定の代わりに適用します。

どれも省略でき、省略したポリシーは適用されません。`managed` のある設定では、`access`・`rate_limit`・`host_policies` を設定ファイルではなく、バージョンに書きます（上の「managed ストアとバージョン」）。値は起動のときと設定のリロードのときに読みます（上の「SIGHUP（設定のリロード）」）。管理画面のルート（`admin.route`）には、どのポリシーも適用されません。

### リクエストの検証の順序

リクエストは、次の順に検証します。最初に拒否した検証で、そのリクエストの応答が決まります。

| 順 | 検証 | 応答 | ログの `reason` |
|---|---|---|---|
| 1 | ヘッダー部の検証（上の「ヘッダー部の検証」） | 400、414、431 など | ヘッダー部の違反ごとに決まった語句 |
| 2 | ACME のチャレンジ（`acme` を持つ証明書があるときの、通常のリスナーとリダイレクトのリスナー） | チャレンジのファイルをボディにした 200、または 404 | `acme challenge` |
| 3 | 管理画面のルート（`managed` のある設定で、`Host` が `admin.route.host` のとき）。TLS の接続でハンドシェイクに管理画面のルートの証明書を使ったか、平文の接続でないか、`admin.route.access` が許すか | 421、404、403 | `admin host on another certificate`、`admin host over plain http`、`denied by route access` |
| 4 | そのリクエストに適用されるアクセス制御（`Host` が一致するホストごとの設定の `access`、無ければ全体の `access`） | 403 | `denied by access` |
| 5 | そのリクエストに適用されるレート制限（同じく、ホストごとの設定か全体の `rate_limit`） | 429（`Retry-After: 1`） | `too many requests` |
| 6 | TLS の接続の `Host` が、ハンドシェイクで使った証明書のホストに入っているか | 421 | `host not covered by the certificate` |
| 7 | ルート（無ければデフォルトのアップストリーム） | 404 | `no route matches` |
| 8 | ルートの `access` | 403 | `denied by route access` |
| 9 | `Content-Length` とルートの `max_body` | 413 | `body over the limit of the route` |
| 10 | ボディの型（上の「ボディの型」） | 415 | `body type not supported` |

10 は、`Content-Length` のあるボディでは読む前に、chunked のボディでは読んだ後に検証します。10 までの検証の後に、検査して転送します。リダイレクトのリスナーは、5 の後にリダイレクトか 404 で応答し、ボディは読みません。

- 3 に当たるリクエストは、4〜9 を通らずに、管理プロセスへ転送します。WAF の検査は受けます。ボディの上限は `proxy.max_body` です。
  - 3 で 421 になるのは、管理画面のホストへのリクエストを、HTTP/2 のクライアントが別のサイトの証明書（`*.example.com` など）の接続で送ったときです。クライアントは正しい SNI で接続し直します。
  - リダイレクトのリスナーは、管理画面のルートのホストへのリクエストを、ポリシーを適用せずに https へリダイレクトします。
- 4 と 5 で適用される設定は、リクエストの `Host` で決まります（下の「ホストごとの設定（`host_policies`）」）。
- 4 と 5 は、検査除外のルートに一致するリクエストにも、リダイレクトのリスナーにも、同じように効きます。検査プロセスが止まっていても、拒否する応答は変わりません。監視用のリスナーには適用されません。
- 拒否するのは、ヘッダー部を読んだ後のリクエストです。接続の受け付けと TLS のハンドシェイクは、拒否するクライアントにも行い、その間は `max_conns` の枠を使います。
- 1 で拒否したリクエストと、2 で応答したチャレンジは、アクセス制御にもレート制限にも数えません。
- 3〜9 で拒否したリクエストには、ボディを読む前に応答します。HTTP/1.1 の接続では、ボディを持つリクエストを拒否すると、応答の後に接続を閉じます。ボディの無いリクエストなら、接続は続きます。HTTP/2 では、そのストリームだけが終わります。
- 拒否したリクエストは、ログに出ます（`class` は `rejected`）。4 と 5 で拒否したリクエストは、全体の設定でもホストごとの設定でも、`/metrics` の `tukuyomi_policy_refusals_total` に数えます。

### クライアントと国

アクセス制御とレート制限で、クライアントのアドレスと国をどう決めるかの注意です。

- 全体の `access`、`rate_limit`、ホストごとの設定、ルートの `access`、`admin.route.access` は、どれも上の「クライアントのアドレス」で決めたアドレスを見ます。国も、そのアドレスから判定します。
- `trusted_proxies` に入る相手でも、`X-Forwarded-For` の行を付けなければ、その相手がクライアントになります。`trusted_proxies` に入れていない相手も同じです。前に置いた中継がクライアントのアドレスを伝えないと、その後ろのクライアントは区別されません。国は中継のアドレスで決まり、レート制限では 1 つのクライアントとして数えます。

### `access`

```text
{"deny_cidrs"?, "allow_cidrs"?, "deny_countries"?, "allow_countries"?}
```

全体のアクセス制御です。形はルートの `access` と同じで、同じ決まりで拒否します。全体の `access` が効くのは、ヘッダー部の検証に通ったリクエストです（ACME のチャレンジと管理画面のルートを除きます）。ただし、ホストごとの設定が自分の `access` を持つ場合、そのホストへのリクエストには、全体の `access` の代わりにその `access` が効きます（下の「ホストごとの設定（`host_policies`）」）。

| 設定キー | 内容 |
|---|---|
| `deny_cidrs`、`allow_cidrs` | ネットワークの一覧。256 個まで。書き方は `trusted_proxies` と同じ |
| `deny_countries`、`allow_countries` | 国の指定。256 個まで。国は ISO 3166-1 alpha-2 の英大文字 2 字（`JP` など）か、`UNKNOWN`。小文字や、2 字でないものは受け付けません。2 字が ISO 3166 の一覧にあるかは検証しません |

- 4 つとも省略できます。省略した設定キーは空の一覧として扱い、4 つとも空なら誰も拒否しません。
- 次のクライアントを拒否します。
  - `deny_cidrs` に入るもの
  - 国が `deny_countries` に入るもの
  - `allow_cidrs` が空でなく、そこに入らないもの
  - `allow_countries` が空でなく、国がそこに入らないもの
- `allow_cidrs` と `allow_countries` を両方書けば、両方に入るクライアントだけが通ります。ネットワークを、国に関係なく通す書き方はありません。
- 拒否するときの応答は、ボディが空の 403 で、`Retry-After` は付けません。
- 国の指定を書くには、`geo` が必要です。

例:

```json
"access": {
  "deny_cidrs": ["198.51.100.0/24"],
  "allow_countries": ["JP", "UNKNOWN"]
}
```

この例は、`198.51.100.0/24` のクライアントと、`JP` と `UNKNOWN` 以外の国のクライアントを拒否します。

### レート制限（`rate_limit`）

```text
{"rate", "burst", "keys", "exempt_cidrs"?}
```

全体のレート制限です。ホストごとの設定が自分の `rate_limit` を持つ場合は、そのホストへのリクエストを、全体のテーブルではなくその設定のテーブルで数えます（下の「ホストごとの設定（`host_policies`）」）。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `rate` | 1〜100000 | 1 つのクライアントが続けてよい、1 秒あたりのリクエスト数 |
| `burst` | 0〜100000 | 休んだ後に、間を空けずに通すリクエストの余裕（バースト）。続けて `burst + 1` 件まで通り、次の 1 件から拒否します |
| `keys` | 1024〜1048576 | 追跡するクライアント数の上限（下の「テーブルのサイズ」） |
| `exempt_cidrs` | 0〜256 個のネットワーク | 数えないクライアント（除外するネットワーク）。書き方は `trusted_proxies` と同じ。省略すると空 |

- **数え方**
  - リクエストを 1 件ずつ数えます（接続ではなく、HTTP/2 ではストリームごと）。
  - 休んでいたクライアントは、間を空けずに `burst + 1` 件まで通ります。次の 1 件は拒否します。その後は、待った時間が 1/`rate` 秒になるごとに 1 件通ります。
  - 1/`rate` 秒はナノ秒に切り上げるので、クライアントが `rate` を超えて通ることはありません。
  - 拒否したリクエストは、そのクライアントのカウントを変えません。
  - 初めて来るクライアントのリクエストは、必ず通ります。
- **クライアントの単位**
  - IPv4 はアドレスごと、IPv6 は上位 64 ビット（/64）ごとです。同じ /64 の中でアドレスを変えても、カウントは増えません。
  - IPv4-mapped IPv6 アドレス（`::ffff:192.0.2.1`）は、IPv4 として数えます。ポートは見ません。
  - 信頼する相手が `X-Forwarded-For` を付けないと、その相手がクライアントになります（上の「クライアントと国」）。そのとき `rate` と `burst` は、その相手を通るすべてのクライアントの合計に対する値になります。
- **拒否するときの応答**: ボディが空の 429 で、`Retry-After` を付けます。値は次の 1 件が通るまでの時間を秒に切り上げたもので、最小は 1 です。`rate` は 1 以上で、次の 1 件までの時間は 1 秒を超えないので、値はいつも `1` になります。
- **除外するネットワーク**: `exempt_cidrs` に入るクライアントは数えません。監視プログラムなどを入れます。ただし、アクセス制御は先に適用されるので、そこで拒否されることはあります。
- **テーブルのサイズ**
  - `keys` は、同時に数えるクライアントの数の上限です。1 クライアントあたり約 100 バイトを使うので、`keys` が 1048576 なら約 100 MB になります。
  - 全体の `keys` と、自分のテーブルを持つホストごとの設定の `keys` の合計は、1048576 までです。超えると、設定を受け付けません（`the rate limits keep count of more than 1048576 clients in all`）。
  - リクエストのたびに、テーブルの古い方から最大 4 クライアントを調べます。カウントが残っていないもの（待ち時間が過ぎたもの）は、テーブルから外します。カウントが残っていないクライアントは新しいクライアントと同じ扱いなので、外しても結果は変わりません。
  - テーブルが満杯のときに、いちばん古いクライアントのカウントがまだ残っていれば、そのクライアントを外して新しいクライアントの場所を作ります。外されたクライアントは、次に来たときに新しいクライアントとして始まり、また `burst + 1` 件まで通ります。つまり、そのクライアントの制限が一度ゆるみます。新しいクライアントが、場所が無いために拒否されることはありません。
  - 外した数は `tukuyomi_rate_limit_evicted_total` に、数えているクライアントの数は `tukuyomi_rate_limit_keys` に出ます。どちらも、すべてのテーブルの合計です。多くのアドレスからリクエストが来ると、実際のクライアントがテーブルから外され、制限がゆるみます。`keys` は同時に来るクライアントの数より十分大きくしてください。
  - テーブルはプロキシのメモリの中にあり、再起動すると空になります。設定のリロードでは、テーブルごとに持ち越します。全体のテーブルが続くのは、新旧の両方に全体の `rate_limit` があり、`keys`・`rate`・`burst` がどれも同じときです（`exempt_cidrs` は新しい値を使います）。どれかが違うか片方に無ければ、新しいテーブルで 0 から数え、`reload: rate limit table started anew` の行を出します。ホストごとの設定のテーブルについては、下の「ホストごとの設定（`host_policies`）」を参照してください。
- **メトリクスとログ**: 拒否したリクエストは、`tukuyomi_policy_refusals_total` の `rate_limit` に数えます。ログの `reason` は `too many requests` です。

### ホストごとの設定（`host_policies`）

```text
[{"name", "hosts", "access"?, "rate_limit"?}, ..]
```

ホストごとに、全体のアクセス制御とレート制限の代わりに適用する設定です。省略できます。`managed` の無い設定ファイルでは、最上位に書きます。`managed` のある設定では、バージョンに書きます（設定ファイルに書くと受け付けません）。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `name` | 1〜64 文字の英数字・`-`・`_` | 名前。項目どうしで同じ名前は書けません。レート制限のテーブルの持ち越しに使います（下） |
| `hosts` | 1〜64 個 | 適用するホスト。ルートの `host` と同じ形で、ポートは書きません（英小文字の名前か、`*.` と名前） |
| `access` | 全体の `access` と同じ形 | このホストのアクセス制御 |
| `rate_limit` | `{}`、または `rate`・`burst`・`keys` を全部書いた全体の `rate_limit` と同じ形 | このホストのレート制限 |

- 項目は 64 個まで、すべての項目のホストは合わせて 1024 個までです。同じホストは、別の項目であっても 2 度書けません。管理画面のルートのホスト（`admin.route.host`）と同じホストも書けません。`*.` のホストがそのホストを含むのはかまいません。管理画面のルートが先に一致するためです。
- `access` も `rate_limit` も無い項目は、受け付けません。
- **一致の方法**: リクエストの `Host` で、ルートと同じ方法で項目を選びます。大文字と小文字は区別せず、末尾の `.` を 1 つ落とし、ポートは見ません。名前のホストは `*.` のホストより先に一致し、長い `*.` のホストは短いものより先に一致します。どの項目にも一致しないリクエストには、全体の設定が適用されます。
- **重ね方**: アクセス制御とレート制限は、それぞれ次の 3 つのどれかになります（管理画面の語も示します）。

| 書き方 | 管理画面の語 | アクセス制御 | レート制限 |
|---|---|---|---|
| 設定キーを書かない | 引き継ぐ | 全体の `access` を適用します | 全体のテーブルで数えます。同じクライアントのリクエストは、ほかのホストへのものと合わせて数えます |
| 値を書く | このホストの設定 | 全体の代わりに、この `access` を適用します | 全体の代わりに、このホストごとの設定のテーブルで数えます |
| `{}` | 使わない | 誰も拒否しません | 数えません |

- 「このホストの設定」か「使わない」にしたホストには、全体の設定による拒否が効きません。急いで追加した `deny_cidrs` も同じです。全体の設定を変更するときは、全体の設定を引き継がないホストごとの設定も見直してください。
- ホストごとの設定は、その `Host` で来たリクエストにだけ適用されます。デフォルトのアップストリーム、`host` の無いルート、`*.` のルートを通ると、ほかの `Host`（IP アドレスの `Host`、どの項目にも無い名前）のリクエストも同じアップストリームに届きます。こうしたリクエストには、全体の設定だけが適用されます。ホストごとにルートを書き、デフォルトのアップストリームを空にすれば、このような届き方は無くなります。
  - IPv6 アドレスの `Host`（`[2001:db8::1]` など）は、どの項目にも一致しません。国際化ドメイン名は、Punycode 形式（`xn--` で始まる名前）で書きます。
- 読めない `Host` は、どのホストへのリクエストにもなりうるものとして扱います。たとえば、ヘッダー部の検証は通るが、ポートが `0` で始まる `www.example.com:0443` などです。アクセス制御では、全体の `access` と、自分の `access` を持つすべての項目の `access` の全部に通らなければ拒否します。レート制限では、全体のテーブルと、自分のテーブルを持つすべての項目のテーブルで順に数え、最初に拒否したテーブルで止めます。
- リダイレクトのリスナーも、同じ方法で、適用される設定を決めます。管理画面のルートには適用されません。
- 国の指定を書くには、`geo` が必要です。
- **レート制限のテーブル**
  - 全体の `keys` と、自分のテーブルを持つ項目の `keys` の合計は、1048576 までです（上の「レート制限（`rate_limit`）」）。
  - テーブルは項目ごとに別なので、ホストをまたいだ合計の上限はありません。1 つのクライアントは、全体の `rate` と、各項目の `rate` を合わせた分まで通せます。
  - 設定のリロードでテーブルを持ち越すのは、同じ `name` の項目がリロードの前も後も自分のテーブルを持ち、`keys`・`rate`・`burst` がどれも同じときです。`hosts` だけを変更したときも、持ち越します。
  - 自分のテーブルを持つ項目のうち、`name` を変更したもの、「引き継ぐ」か「使わない」から「このホストの設定」に切り替えたもの、新しく追加したものは空から数え、`reload: rate limit table of host policy <name> started anew` の行を出します。
  - 2 つの項目の `name` を入れ替えると、テーブルも名前に付いて移ります。
  - `/metrics` の `tukuyomi_rate_limit_keys` と `tukuyomi_rate_limit_evicted_total` は、すべてのテーブルの合計です。全体の設定を引き継ぐホストは、全体のテーブルで数えるので、2 度は数えません。
- ホストごとの設定で拒否したリクエストでも、ログの `reason`（`denied by access`、`too many requests`）と `/metrics` のラベルは、全体の設定のものと同じです。どのホストへのリクエストかは、ログの `host` で分かります。
- `host_policies` を書いた設定ファイルやバージョンを、この設定キーを知らない前のビルドで読むと、未知の設定キーとして受け付けません。ビルドを前に戻すときは注意してください。ログ送信プロセスも設定ファイルを読むので、設定ファイルに `host_policies` を書く前に、ログ送信プロセスをプロキシと同じビルドにします（下の「ログ送信プロセスの起動」）。

例:

```json
"host_policies": [
  {"name": "app", "hosts": ["app.example.com"], "access": {"allow_cidrs": ["203.0.113.0/24"]}},
  {"name": "api", "hosts": ["api.example.com", "*.api.example.com"], "rate_limit": {"rate": 20, "burst": 40, "keys": 65536}},
  {"name": "status", "hosts": ["status.example.com"], "access": {}, "rate_limit": {}}
]
```

この例の意味は次のとおりです。

- `app.example.com` を使えるのは、`203.0.113.0/24` のクライアントだけです（全体の `access` は適用されません）。レート制限は全体のテーブルで数えます。
- `api.example.com` と `*.api.example.com` には、全体の `access` が適用されます。レート制限はこの項目のテーブルで数えます。
- `status.example.com` には、アクセス制御もレート制限も適用されません。

### 国のデータベース（`geo`）

```text
{"country_db", "sha256"}
```

国の指定（`deny_countries`・`allow_countries`）を使うときに、クライアントのアドレスの国を、このデータベースで判定します。設定キーは 2 つとも書きます。

| 設定キー | 内容 |
|---|---|
| `country_db` | 国のデータベースファイルの絶対パス |
| `sha256` | そのファイルの SHA-256。64 桁の小文字の 16 進数 |

例を示します。`sha256` の値は仮のもので、実際にはファイルに `sha256sum` を実行した値を書きます。

```json
"geo": {
  "country_db": "/etc/tukuyomi-core/country.mmdb",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

- **ファイルの形式と用意**: ファイルは MaxMind DB の形式（バージョン 2）です。プロキシはデータベースを同梱せず、取得もしません。運用者が用意して置いてください。データベースの使用許諾は、提供元の条件に従って運用者が守ります。
- **国の決め方**
  - アドレスのレコードの `country.iso_code` で決めます。無ければ、`registered_country.iso_code` で決めます。どちらも無いときと、英大文字 2 字でないときは `UNKNOWN` です。
  - ループバック、プライベート（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`fc00::/7`）、リンクローカル、未指定のアドレスは、データベースを検索せずに `UNKNOWN` にします。データベースが知らないアドレスも `UNKNOWN` です。
  - IPv4-mapped IPv6 アドレスは、IPv4 として検索します。
  - IPv4 のアドレスだけのデータベース（メタデータの `ip_version` が 4）では、IPv6 のクライアントはすべて `UNKNOWN` になります。
- **`UNKNOWN` に注意する**: `allow_countries` に `UNKNOWN` を書かないと、プライベートなアドレスのクライアント（同じネットワークの監視など）も、IPv4 だけのデータベースを使うときの IPv6 のクライアントも、すべて拒否されます。`deny_countries` に `UNKNOWN` を書けば、それらを拒否します。
- **読み込み**
  - 設定の全体を読むコマンドは、`geo` のファイルを読んで検証します。プロキシの起動、`config check`、SIGHUP と制御ソケットの `reload` によるリロード、`acme renew`、`managed import`、`managed activate` です。どれも、サービスの OS ユーザーがファイルを読める必要があります。
  - 設定ファイルだけを読むコマンド（`rules` の各コマンド、`managed list`・`managed remove`、`admin` の各コマンドと管理プロセス、ログ送信プロセス）は、`geo` の値の形だけを検証し、ファイルは読みません。
  - 検証するのは、次の点です。
    - 通常のファイルで、シンボリックリンクでなく、256 MiB までであること。全体を読みます。
    - SHA-256 が `sha256` と一致すること。
    - MaxMind DB として読めること。メタデータのバージョンが 2、レコードのサイズが 24・28・32 ビット、`ip_version` が 4 か 6 で、検索ツリーが壊れていないことを確認します。ツリーが指すレコードをすべて検証し、読めないレコードがあれば受け付けません。
    - 国のデータベースであること。`database_type` に `Country` を含むか、ISO コードを持つレコードが 1 つ以上あれば、国のデータベースとみなします。
  - 国の指定があれば、プロキシは、検証したファイルの全体をメモリに保持します。読むコマンドは、読むたびに全体を検証するので、大きいファイルでは時間とメモリを使います。
  - 国の指定（全体の `access`、`host_policies` の `access`、ルートの `access`）がどこにも無ければ、読んで検証した後で、使わずに捨てます。国の指定があって `geo` が無い設定は、受け付けません（`access has a list of countries while geo is left out`）。
  - プロキシは、起動のときと、SIGHUP と制御ソケットの `reload` によるリロードのたびに読みます。それ以外のときに読み直すことはありません。リロードのたびに全体を検証するので、大きいファイルでは、リロードのたびに時間とメモリを使います。
- **入れ替える手順**: 新しいファイルを別の名前で置き、`country_db` と `sha256` を 1 回の置き換えで書き換えます。`config check` で検証してから、プロキシにリロードさせます（SIGHUP、`systemctl reload`）。管理プロセスはデータベースを読みません。同じ名前のファイルだけを入れ替えて `sha256` が合わなくなると、その間に実行した、設定の全体を読むコマンドと、再起動したプロキシは、設定を受け付けません。プロキシのリロードも拒否されます。

## ログ

ログは標準エラーに 1 行 1 件の JSON で出ます（systemd ではジャーナル）。設定に `records` があれば、同じ行をファイルにも書きます（起動の最初の行の一部を除きます。下の「ログファイル」）。さらに `records.ship` があれば、別のプロセス（ログ送信プロセス）がファイルの行を PostgreSQL か MySQL へ送ります（下の「ログ送信プロセス」）。

ログを残せないときにリクエストを通すか拒否するかは、ルートごとに選べます（下の「ログの残し方」）。短時間で終わるコマンド（`config check`・`rules`・`managed`・`acme`・`admin bootstrap`・`admin reset`）の出力は、人が読む文の行のままです。

どのログも、次の 2 つの項目で始まります。値の無い項目は書きません（`null` にはしません）。

| 項目 | 内容 |
|---|---|
| `ts` | 記録した時刻。UTC の RFC 3339 形式でミリ秒まで（例: `2026-10-27T03:53:27.123Z`） |
| `type` | `request`、`connection`、`tunnel`、`line`、`audit`、`dropped` のどれか |

### リクエストのログ（`request`）

クライアントへ応答を書いたリクエストごとに、1 件出ます。ヘッダー部の拒否、リダイレクト、ACME のチャレンジへの応答も含みます。ログは応答を送り終えたとき（または切れたとき）に書くので、ストリーミング応答のログは、応答の終わりに出ます。

```text
{"ts":"2026-10-27T03:53:27.123Z","type":"request","id":"0186af5443bddbd9-1","conn":1,"listener":0,"proto":"h1","tls":false,"client":"192.0.2.10","method":"GET","host":"example.com","path":"/q","class":"blocked","status":403,"reason":"blocked by a rule","ms":3,"mode":"block","engine":"coraza","generation":"2f3bda9b9ca7db60","rule":949110,"rules":[941100,941110],"severity":2,"score":10,"sent":0}
```

| 項目 | 内容 |
|---|---|
| `id` | リクエスト ID。応答の `X-Request-ID` と、アップストリームへ送る `X-Request-ID` と同じです。起動ごとの乱数 16 桁と、リクエストごとの通し番号を `-` でつないだものです。HTTP/2 ではストリームごとに 1 つです |
| `conn` | 接続の番号 |
| `listener` | 受けたリスナーの番号（設定の `listeners` の順で、0 から） |
| `proto` | `h1` か `h2` |
| `tls` | TLS のリスナーか |
| `client` | 上の「クライアントのアドレス」で決めたアドレス。ヘッダー部を読む前の応答では、接続の相手のアドレス |
| `method`、`host`、`path` | リクエストのメソッド、`Host`（HTTP/2 では `:authority`）、リクエストターゲットの `?` より前（受けたまま）。ヘッダー部の検証に通らなかったリクエストにはありません |
| `cut` | 上限で切った項目の名前の一覧（例: `["path"]`） |
| `class` | 下の表 |
| `status` | 応答したステータスコード（何も応答しなかったときは 0） |
| `reason` | 決まった英語の語句（例: `malformed request head`、`body over the limit`、`inspection queue full`、`upstream connection failed`、`denied by access`、`too many requests`） |
| `ms` | かかった時間（ミリ秒） |
| `upstream`、`server` | アップストリームの名前と、最後に接続を試みたサーバーのアドレス（試していなければ `server` はありません） |
| `mode`、`engine`、`generation` | 判定したルールの世代のモード（`block` か `detect`）と、そのエンジン（`coraza` か `modsecurity`）と、世代のフィンガープリントの先頭 16 桁。検査しなかったリクエスト（検査除外のルートで通したリクエストを含みます）にはありません |
| `rule` | ブロックしたルール、または検知のみのモードで一致したルールの ID |
| `rules` | ほかに一致したルールの ID。評価の順に 16 個まで。ログに記録しないルール（`nolog`）と、検査プロセスが追加するルール（4000001〜4000011）は入りません |
| `rules_more` | 16 個より多く一致したとき `true` |
| `severity` | 一致したルールの重大度のうち、最も重大なもの（0 が最も重大です。ルールの `severity` の値） |
| `score` | CRS のインバウンドの anomaly score（`tx.blocking_inbound_anomaly_score`）。0 のときと、CRS の無いルールセットでは、この項目はありません |
| `body` | ボディの長さ。`Content-Length` があればそれ、無ければそれまでに読んだバイト数（gzip のボディは gzip のままの長さ）。ボディの無いリクエスト、ルートで拒否したリクエスト、ボディの先頭を読み終えられなかったリクエストにはありません |
| `inspected` | 先頭だけを検査して残りを流したリクエストの、検査したバイト数。検査除外のルートで流したボディにはありません |
| `sent` | クライアントへ送った応答のボディのバイト数 |

`class` は次のどれかです。

| `class` | 場合 |
|---|---|
| `forwarded` | アップストリームの応答を返した場合 |
| `blocked` | ルールがブロックした場合 |
| `rejected` | ヘッダー部かボディが拒否された場合。全体の `access`・`rate_limit` とホストごとの設定の 403・429、ルートで拒否した 403・404・421、管理画面のルートで拒否した 421・404・403、リダイレクトのリスナーの 404 も含みます |
| `redirected` | https へリダイレクトした場合 |
| `answered` | ACME のチャレンジに応答した場合 |
| `failed` | こちらの理由で応答できなかった場合（混んでいる、検査できない、アップストリームの失敗） |
| `closed` | 何も応答しなかった場合 |

`forwarded` の `reason` は次のどれかになります。

- `forwarded`: 検査で許可した場合
- `detected by a rule`: 検知のみのモードでルールに一致した場合
- `bypassed by a route`: 検査除外のルートの場合
- `closed while the response was sent`: 応答を送り終える前に切れた場合

リクエストから来る文字（`method`、`host`、`path`）は、次のように記録します。まず、0x21〜0x7e の外のバイトと `"`・`\` を `%XX`（大文字の 16 進数）にします。その後、`method` は 32、`host` は 255、`path` は 1024 バイトで切ります。`%XX` の途中では切りません。受けた `%` はそのまま残すので、受けた `%80` とバイトの 0x80 は、どちらも同じ `%80` になります。

クエリ、ボディ、`Host` 以外のヘッダー（`User-Agent`、`Cookie` など）、ルールに一致した値と変数の名前、ルールの `msg` は記録しません。パスに秘密の値を入れる作りのサイトでは、その値がログに残ります。

### ほかのログ

リクエストのログのほかに、次のログがあります。

| `type` | 項目 | 場合 |
|---|---|---|
| `connection` | `conn`、`listener`、`client`、`class`、`status`、`reason`、`ms`、`streams` | 応答を書かずに終わった接続（リクエストの前に閉じた、2 つ目からのヘッダー部を拒否した、TLS のハンドシェイクに失敗したなど）と、HTTP/2 の接続の終わり（`streams` は受けたストリームの数） |
| `tunnel` | `id`（トンネルを開いたリクエストの ID）、`conn`、`client`、`upstream`、`server`、`end`、`ms`、`to_upstream`、`from_upstream` | WebSocket のトンネルが終わった場合（動く前に終わったときも出ます）。`end` は `closed`（両方の向きが終わった）、`idle`、`total`、`error`、`stop`（停止で打ち切った）のどれか。バイト数はハンドシェイクの後に各向きで読んだ量 |
| `line` | `line` | 下の表の文。512 バイトまでで、長い文は切ります。制御文字は空白にします |
| `audit` | （[管理リファレンス](admin-reference.ja.md) を参照） | 管理プロセスの監査ログ。管理プロセスだけが出します。プロキシのログファイルには入りません |
| `dropped` | `count` | 書けずに捨てたログの数（前の `dropped` のログの後に捨てた分） |

`line` の文は次のとおりです。

| 文 | 場合 |
|---|---|
| `start: ...` | 起動の各段階（`start: managed version <version>`、起動するエンジンごとの `start: rules generation <fingerprint>`・`start: rules engine <name>`・`start: rules mode block`（か `detect`）・`start: rules routes <count>`（デフォルトのエンジンが先）、検知のみの世代を選択しているエンジンへ向くアップストリームごとの `start: upstream <name>: engine <engine>, mode detect`、`start: rules store refused: <reason>`、`start: rules generation refused: <reason>`、`start: tls certificate not issued yet (<place>)`、`start: the kernel is ready`、`start: listening`、`start: record file refused: <reason>`、`start: control socket refused: <reason>` など） |
| `reload: ...` | SIGHUP・SIGUSR1・SIGUSR2 と、制御ソケットの `reload` の依頼を受けたこと（`reload: SIGHUP`、`reload: control reload <version>` など）。設定のリロードの各段階と結果（`reload: configuration replaced <sha256>`、`managed` のある設定では `reload: configuration replaced <sha256> managed <version>`、`reload: configuration refused: <reason>`、`reload: tls certificate not issued yet (<place>)`、`reload: rate limit table started anew`、`reload: rate limit table of host policy <name> started anew`、検知のみの世代を選択しているエンジンへ向くアップストリームごとの `reload: upstream <name>: engine <engine>, mode detect` など。上の「SIGHUP（設定のリロード）」）。切り替え（SIGUSR1 と制御ソケット。エンジンごとに、始めるときに `reload: starting generation <fingerprint>`・`reload: rules engine <name>`・`reload: rules mode block`（か `detect`）・`reload: rules routes <count>`、準備ができたときに `reload: generation <fingerprint> is ready, switched`、前の世代を停止したときに `reload: generation <fingerprint> retired, clean true`（か `false`）、すでに稼働している世代のときに `reload: generation <fingerprint> is already running`、起動に失敗したときに `reload: generation <fingerprint> failed to start: <reason>`、切り替えの途中のときに `reload: a switch is in progress, ignored`、拒否したときに `reload: rules store refused: <reason>`）と、証明書の入れ替えの結果 |
| `control: switch ...`、`control: reload ...` | 制御ソケットの切り替えとリロードの依頼への応答（`control: reload <version>: <result> (<reason>)` など。上の「制御ソケット」） |
| `driver: inspector incarnation changed, inc <count>, restarts <count>` | 検査プロセスが再起動した場合 |
| `driver: stop, engine <engine>, records <count>, held <count>, waiting <count>` | 停止の始めに、起動しているエンジンごとに 1 つ出ます（上の「停止」） |
| `conn <number>: internal fault: <reason>` | プロキシの内部の不整合 |
| `notify: <notice> not sent ...` | systemd への通知を送れなかった場合 |
| `stop: ...` | 停止の理由と、最後の停止の結果 |

- `<sha256>` は設定ファイルの SHA-256、`<version>` は managed 設定のバージョン（どちらも 64 桁の 16 進数）、`<fingerprint>` はルールの世代のフィンガープリントです。`<place>` は、`managed` の無い設定では `listener <number>, certificate <number>`、`managed` のある設定では `admin route` か `site <name>` です。

### ログを書けないとき

ログを書く仕組みと、書けないときの扱いは次のとおりです。

- ログは 1024 件の待ち行列に入れます。書くのは、1 つのスレッドだけです。リクエストの処理と停止は、書き込みを待ちません。
- 待ち行列が満杯になったときは、そのログを捨てて、捨てた数を数えます。書けるようになってから、`dropped` のログを 1 件出します。標準エラーを読む側が止まると、こうなります。
- 書き込みに失敗したとき（`/dev/full` など）は、そのログは失われます。失ったログの数は別に数えます。
- どちらの数も、監視の `/metrics` で見られます（`tukuyomi_records_dropped_total`、`tukuyomi_record_write_errors_total`）。標準エラーが詰まっている間は、ログでは通知できません。
- 1 件の大きさは 4 KiB 未満です。項目ごとの上限があるので、この大きさを超えることはなく、ログを切ることもありません。
- ログファイル（`records`）に書けないときは、その行がファイルに入らないだけで、標準エラーには出ます。件数は `tukuyomi_record_file_errors_total` で見られます（下の「ログファイル」）。
- ここまでは、ログを残せなくてもリクエストを通すデフォルトの扱い（`best_effort`）です。ログを残せないときにリクエストを拒否するルートも選べます（下の「ログの残し方」）。

### ログファイル（`records`）

設定に `records` を書くと、標準エラーに出すログと同じ行を、指定したディレクトリのファイルにも書きます。省略すると、ログは標準エラーにだけ出ます。起動の最初の行のうち、ログファイルを開く前に出る行（`start: configuration accepted` や `start: rules …` の行）は、標準エラーにだけ出ます。管理プロセスは、このファイルを読んでログを検索します。

```text
{"dir", "file_bytes", "files", "keep"?, "sync_ms"?, "ship"?}
```

`dir`、`file_bytes`、`files` は必ず書きます。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `dir` | 絶対パス、3840 バイトまで | ファイルを置くディレクトリ。プロキシは作らないので、先に作ります。条件は、シンボリックリンクでないディレクトリであること、所有者がプロキシの OS ユーザーであること、グループとその他のユーザーの権限が無いことです |
| `file_bytes` | 1 MiB〜1 GiB | 1 つのファイルのサイズ。使用中のファイルがこれを超える行は、次のファイルから書きます |
| `files` | 2〜64 | 残すファイルの数（使用中のものを含む）。`ship` があり、`keep` かルートの `records` に `required` があるときは 3 以上 |
| `keep` | `best_effort`、`required` | 自分の `records` を持たないルートとデフォルトのアップストリームの、ログの残し方（下の「ログの残し方」）。省略すると `best_effort` |
| `sync_ms` | 1〜60000 | 書いた行をディスクへ同期する（`fsync`）間隔の上限。省略すると同期せず、OS に任せます（下の「ファイルに入る行」） |
| `ship` | `{"db_driver", "db_dsn_file", "batch", "interval_ms", "retention_days"}` | ログ送信プロセスの設定（下の「ログ送信プロセス」）。プロキシはログ送信プロセスを動かさず、ログ送信プロセスの遅れを見るだけです |

- **使うディスクの量**: 多くても `file_bytes × files` です。1 件は 4 KiB 未満なので、1 つのファイルが `file_bytes` を超えることはありません。
- **名前とローテーション**
  - 使用中のファイルは `records.log` です。古いファイルは、`records.1.log`、`records.2.log` と続き、`records.<files - 1>.log` が最も古いファイルです。
  - 行を追加すると `file_bytes` を超えるときは、先に次のファイルへローテーションします。まず、`records.log` を `records.rotating` にリネームします。次に、`records.N.log` を `records.N+1.log` にリネームします（N は `files - 2` から 1 まで）。最後に、`records.rotating` を `records.1.log` にして、新しい `records.log` を開きます。いちばん古いファイルは、置き換えられて無くなります。
  - リネームの途中で失敗したら、`records.rotating` を戻します。ローテーションの途中で止まって `records.rotating` が残ったときは、次のローテーションで置き換わります。
  - どのファイルも、行の途中では切れません。
  - `files` を小さくして再起動すると、`records.<files>.log` 以降の古いファイルを、起動のときとローテーションのたびに削除します（`records.63.log` まで）。削除するのは、所有者がプロキシの OS ユーザーである通常のファイルだけです。
- **開き方**
  - `records.log` は、無ければ 0600 で作り、追記で開きます。シンボリックリンク、FIFO、ディレクトリ、別の OS ユーザーのファイルは受け付けません。グループかその他のユーザーの権限があるファイルは、書く前に 0600 にします。
  - 最後の行が改行で終わっていないファイル（書いている途中で落ちたときなど）には、先に改行を書きます。次の行が、途中の行とつながらないようにするためです。
  - 起動のときに開けなければ、`start: record file refused: <reason>` の文を出し、検査プロセスを起動せずに止まります（exit 1）。
- **ファイルに入る行**
  - 標準エラーに出す行を、すべて同じ形で書きます。1 行を 1 回の `write` で書き、標準エラーへ書いた後にファイルへ書きます。
  - ファイルを開く前に出た行（設定の検証からルールの世代までの `start:` の文）は入りません。
  - `sync_ms` が無ければ、ディスクへの同期（`fsync`）はしません。電源が落ちると、OS がまだディスクに書いていない行は失われます。
  - `sync_ms` があれば、同期していない行のうち最も古いものが `sync_ms` だけ待ったときに、ファイルを同期します。後に行が来なくても同期します。ローテーションの前にも、リネームするファイルを同期します。電源が落ちたときに失われるのは、最後の同期より後の行です。同期の失敗は、書き込みの失敗と同じように扱います（下の「ファイルに書けないとき」）。
- **ファイルが外部から動かされたとき**: `records.log` のパスは、1 秒に 1 回まで検証します（ローテーションの前にも検証します）。パスにファイルが無いとき、または開いているものとは別のファイルのときは、開いているファイルを閉じます。そのときの行はファイルに入らず、`tukuyomi_record_file_errors_total` に数えます。次の行で、`records.log` を新しく作って開きます。
- **ファイルに書けないとき**
  - 書き込み、`open`、リネームが失敗すると、その行はファイルに入らず、ファイルを閉じて `tukuyomi_record_file_errors_total` に数えます。行は標準エラーには出ます。リクエストの処理は待ちません。
  - 閉じている間に来た行も、ファイルに入らず、同じように数えます。失敗から 1 秒以上たってから来た最初の行で、ファイルを開き直します。ディスクが壊れたままでも、再試行は 1 秒に 1 回までです。
  - 途中まで書けた行は、書く前のサイズまで切り戻します。
  - 同期（`sync_ms`）が失敗したときも、ファイルを閉じて、同じ件数に数えます。
  - ディレクトリは、開き直す前とローテーションの前に、起動のときと同じように検証します。
- **ログ送信プロセスのファイル**: `ship` があれば、ログ送信プロセスが同じディレクトリに `ship.state`（送った位置）を置きます。書き換えの間だけ、`ship.state.new` も置きます。プロキシは `ship.state` を読むだけで、どちらも削除しません。

### ログの残し方（`keep` とルートの `records`）

ルートごとに、ログを残せないときの扱いと、残すログを選べます。ルートの `records` を書かなければ、全体の `records.keep` に従います。`records.keep` を書かなければ、`best_effort` です。

| 値 | ログを残せないとき | 書くログ |
|---|---|---|
| `best_effort` | ログを捨てて数え、リクエストは通します（上の「ログを書けないとき」） | すべて |
| `required` | そのルートの新しいリクエストを 503 で拒否します | すべて |
| `security` | `best_effort` と同じです | ルールが判定したリクエスト（ブロックと、検知のみのモードで一致したもの）、検査できなかったリクエスト（検査プロセスに依頼できなかった 503 を含みます）、全体の `access`・`rate_limit` とホストごとの設定で拒否したリクエスト、受け付けた後に応答の前に切れたリクエスト（下）だけ。通常どおり通したリクエストのログは書きません |

`required` のルートは、次の 3 つがそろうときだけ、リクエストを受け付けます。

1. ログファイルへの最後の書き込み（と同期）が通っていて、ログを書くスレッドが動作中の状態です。
2. ログ送信プロセス（`ship`）があるなら、ログ送信プロセスがまだ送っていないバイト数が、ファイル `files − 2` 個分（`file_bytes × (files − 2)`）より少ない状態です。送っていないログがローテーションで消える前に拒否するためです。
   ログ送信プロセスの遅れが分からないときも拒否します。`ship.state` が読めないとき、形式が違うとき、90 秒より前に書かれたとき、ログファイルのどれでもないファイルを指すときです。`files` が 3 より少ないときは、遅れでは拒否しません。
3. ログの待ち行列に枠が空いている状態です。枠は待ち行列の 1024 のうち 512 までです。`required` のルートのリクエストを同時に 512 より多く受け付けると、超えた分のリクエストは 503 になります。

- 拒否したリクエストには 503 で応答し、`tukuyomi_records_refused_total` に数えます。拒否したリクエストのログ（`reason` は `records cannot be kept`）は、書けなければ捨てて数える `best_effort` の扱いで書きます。ただし、ログ送信プロセスの遅れで拒否したときは、そのログは書かずに数えるだけです。送っていないログがローテーションで消えるまでの余裕を、拒否したリクエストのログで使わないためです。
- 受け付けたリクエストは、ボディを読む前に枠を確保し、ログを待ち行列に入れるまで持ち続けます。そのリクエストのログは、待ち行列が満杯でも捨てません。
- 受け付けた後に書き込みが失敗したら、失敗を数え、それより後の `required` のリクエストを拒否します。書き込みは失敗の 1 秒後から再試行し、通れば受け付けに戻ります。
- ログ送信プロセスの遅れは、プロキシが見積もります。`ship.state` を 1 秒に 1 回読み、その位置より後のバイト数（指すファイルの残りと、それより新しいファイル）に、読んだ後に書いたバイト数を加えます。遅れが閾値より少なくなれば、受け付けに戻ります。
- ログは応答を送り終えた後に書きます。そのため `required` でも、クライアントに応答する前にログがあることまでは約束しません。次の 2 つのログは、抜けることがあります。
  - 書き込みが失敗し始めたときに、受け付け済みだったリクエストのログ
  - 電源が落ちたときの、最後の同期より後のログ（`sync_ms` が無ければ OS に任せます）
- `required` を使うには、`records` が必要です。`ship` と `required` を両方使うときは、`files` を 3 以上にします（上の「値どうしの関係」）。

次のリクエストのログは、ルートの値と `records.keep` にかかわらず、書けなければ捨てて数える `best_effort` の扱いで書きます（ルートを決める前か、ボディを読まずに応答するリクエストで、どれもアップストリームへは何も送らない応答です）。

- 全体の `access`・`rate_limit` とホストごとの設定の 403 と 429
- TLS の接続で、証明書が `Host` を持たないリクエストの 421
- どのルートにも一致せず、デフォルトのアップストリームも無いリクエストの 404
- ヘッダー部の検証で拒否したリクエスト、https へのリダイレクト、ACME のチャレンジへの応答
- ルートの `access` の 403 と、ルートの `max_body` の 413
- 接続のログ（`connection`）とトンネルのログ（`tunnel`）

受け付けた後で応答の前に切れたリクエスト（HTTP/1.1 でクライアントが接続を閉じた、HTTP/2 でストリームをリセットした）と、ボディの途中でクライアントが切断したリクエストのログは、どのルートでも書きます。アップストリームに届いたかもしれないためです。

### ログを読めるユーザー

ログには、クライアントのアドレスとパスが入ります。ログがどこにあり、誰が読めるかは次のとおりです。

- **ジャーナル**: ジャーナルを読めるユーザー（root と、Ubuntu では `adm`・`systemd-journal` のグループのユーザー）は、ログを読めます。グループに入れる OS ユーザーは最小限にしてください。保存の期間と容量は、journald の設定で決めます（[ビルドと配置](../build/binary-deployment.ja.md) の「systemd」）。
- **ログファイル（`records`）**: 0600 で、0700 のディレクトリにあります。読めるのは、プロキシの OS ユーザーと root です。管理プロセスは、同じ OS ユーザーとしてこのファイルを読み、管理プロセスのユーザーに見せます（[管理リファレンス](admin-reference.ja.md)）。
- **DB のテーブル**: ログ送信プロセスを使うときは、ここにも同じログが入ります。テーブルを読める DB のユーザーも最小限にしてください。

## ログ送信プロセス

ログ送信プロセス（`tukuyomi-records-ship`）は、プロキシとは別のプロセスです。プロキシのログファイルを読み、その行を PostgreSQL か MySQL のテーブルへ順に入れます。プロキシはログ送信プロセスを動かさず、DB にも接続しません。DB に接続するライブラリと DB のパスワードは、ログ送信プロセスの実行ファイルとプロセスにだけあります。

ビルドとユニットは、[ビルドと配置](../build/binary-deployment.ja.md) を参照してください。動作を確認しているのは、PostgreSQL 16・18 と MySQL 8.0 です。

### ログ送信プロセスの起動

```text
tukuyomi-records-ship <config>
```

- `<config>` には、プロキシと同じ設定ファイルを絶対パスで指定します。設定ファイルはプロキシと同じ検証で読み、`records.ship` が必要です。無ければ、`records-ship: configuration refused: there is no records.ship object` の行を出して終わります。
- 読むのは設定ファイルだけです。managed ストアのバージョンと国のデータベースは読みません。
- 未知の設定キーのある設定ファイルは受け付けないので、設定に新しい設定キー（`managed`、`host_policies`、`kernel.default_engine`、アップストリームの `engine` など）を書く前に、ログ送信プロセスをプロキシと同じビルドに入れ替えます（[ビルドと配置](../build/binary-deployment.ja.md) の「ログ送信プロセスのユニット」）。
- プロキシと同じ OS ユーザーで動かします。root では動きません（ユーザー ID の 4 つのどれかが 0 なら起動しません）。ログのディレクトリについても、この OS ユーザーのディレクトリであること、シンボリックリンクでないこと、グループとその他のユーザーに権限が無いことを検証します。`ship.state` をそこに書くためです。
- ログのディレクトリのファイルシステムは、ファイルの作成時刻（`statx` の btime）を返す必要があります。ログ送信プロセスは、ログファイルを inode と作成時刻の組み合わせで見分けるためです（ファイルシステムは、削除したファイルの inode の番号をすぐに使い回します）。作成時刻を返さないファイルシステムでは、ログ送信プロセスは起動せず、プロキシは遅れが分からないものとして `required` のリクエストを拒否します。
- 起動の順は、設定、ログのディレクトリ、接続文字列のファイル（下）、シグナルの受け付けで、`NOTIFY_SOCKET` があれば最後に `READY=1` です。DB には 1 回目の処理で接続します。接続できない DB には、動作中に止まったときと同じように、待って再試行します。

| exit | 場合 |
|---|---|
| 0 | SIGTERM、SIGINT、SIGHUP で停止した場合。動作中の 1 回分を終えてから停止し、`STOPPING=1` を送ります |
| 1 | 接続文字列が読めない、または受け付けられなかった場合。DB がログインを拒否した場合（下の「ログ送信プロセスのエラー」）。そのほかの失敗 |
| 2 | 引数のエラー、設定が受け付けられなかった場合 |

- DB を呼び出している間は、停止のシグナルの処理が待たされます。1 回の呼び出しは 30 秒まで（接続は 10 秒まで）で、1 回分の処理の中に呼び出しが数回あるので、停止するまでに長いと 1〜2 分かかります。
- SIGKILL で停止しても、次の起動は DB に残った位置から続けます。行と位置は、同じトランザクションで DB に入るためです。

### `records.ship`

```text
{"db_driver", "db_dsn_file", "batch", "interval_ms", "retention_days"}
```

5 つとも書きます。

| 設定キー | 範囲 | 意味 |
|---|---|---|
| `db_driver` | `pgsql`、`mysql` | 送る DB の種類 |
| `db_dsn_file` | 絶対パス、3840 バイトまで | 接続文字列のファイル（下）。プロキシはこのファイルを開きません |
| `batch` | 1〜10000 | 1 つのトランザクションに入れる行の数の上限 |
| `interval_ms` | 100〜60000 | 送る行が無かったときに、次の回まで待つ時間。失敗の後に待つ時間の初期値でもあります |
| `retention_days` | 0〜3650 | DB に残す日数。0 なら削除しません |

```json
"records": {
  "dir": "/var/lib/tukuyomi-core/records",
  "file_bytes": 16777216,
  "files": 8,
  "sync_ms": 1000,
  "ship": {
    "db_driver": "pgsql",
    "db_dsn_file": "/etc/tukuyomi-core/records-db.dsn",
    "batch": 500,
    "interval_ms": 1000,
    "retention_days": 90
  }
}
```

### 接続文字列（`db_dsn_file`）

接続文字列はパスワードを含むので、設定ファイルには書かず、別のファイルに置きます。

- **ファイルの条件**: 通常のファイルであること、所有者がログ送信プロセスの OS ユーザーであること、グループとその他のユーザーに権限が無いこと（0600）です。大きさは 16 KiB までで、中身は UTF-8 の文字です。受け付けないときの文には、ファイルの名前も内容も入りません。
- **PostgreSQL**: `host=db.example.com port=5432 user=tukuyomi_ship password=<password> dbname=records` の形式か、`postgresql://` の URL（`tokio-postgres` の形式）で書きます。テーブルは接続の `search_path` の最初のスキーマに作ります。
  - 同じホストの PostgreSQL には、Unix ドメインソケットと peer 認証（OS ユーザーの名前と同じ名前のロール）で接続すれば、パスワードは必要ありません。例: `host=/var/run/postgresql user=tukuyomi dbname=tukuyomi_records sslmode=disable`。
- **MySQL**: `mysql://<user>:<password>@<host>:<port>/<db-name>` の URL（`mysql_async` 0.37 の形式）で書きます。DB の名前が必要で、テーブルはその DB に作ります。URL の中で記号を使う値は、パーセントエンコーディングで書きます。

TLS の扱いは次のとおりです。

| | PostgreSQL | MySQL |
|---|---|---|
| 書かないとき | TLS。証明書とホスト名を検証します | TLS。証明書とホスト名を検証します |
| 受け付ける指定 | `sslmode=require`、`verify-ca`、`verify-full`。どれも証明書とホスト名を検証します（`require` でも検証します） | `require_ssl=true`、`verify_ca=true`、`verify_identity=true` |
| 受け付けない指定 | `sslmode=prefer`、`allow`（相手が TLS を拒否すると平文にフォールバックします） | `verify_ca=false`、`verify_identity=false`（検証を外します） |
| 平文 | `sslmode=disable` と書いたときだけ（ループバックや Unix ドメインソケット向け） | `require_ssl=false` と書いたときだけ。Unix ドメインソケット（`socket`）は、このときだけ使えます |

- 証明書の検証には、システムの認証局を使います。環境変数 `SSL_CERT_FILE` が指すファイルを読み、無ければ、ディストリビューションごとの保存先にあるバンドル（Debian・Ubuntu、Fedora・Red Hat、openSUSE）を読みます。接続文字列では、認証局のファイルを指定できません。自前の認証局の証明書は、`SSL_CERT_FILE` で渡します。
- TLS を提供しないサーバーには、接続しません。
- MySQL では、サーバーが名乗る Unix ドメインソケットへは移らず、接続文字列のアドレスのままで接続します。

### ログのテーブル

ログ送信プロセスは、DB に接続したときにテーブルを探し、無いテーブルだけを作ります。

| テーブル | 内容 |
|---|---|
| `tukuyomi_records` | ログの行ごとに 1 つ。`id`（通し番号）、`ts`、`type`、`request_id`、`client`、`method`、`host`、`path`、`class`、`status`、`reason`、`ms`、`upstream`、`mode`、`engine`、`generation`、`rule`、`rules`（文字列）、`score`、`body`、`sent`、`raw`（行そのもの）、`line_hash`（行の SHA-256。UNIQUE） |
| `tukuyomi_records_state` | ログのディレクトリ（`source`、`records.dir` のパス）ごとの、送った位置（`inode`、`born`、`offset`、`lost_lines`、`updated`） |
| `tukuyomi_records_schema` | スキーマのバージョン（現在は 1） |

- インデックスは、`ts`、`(type, ts)`、`request_id`、`rule` にあります。
- テーブルがそろっていてバージョンの行があれば、ログ送信プロセスは何も作らないので、ログ送信プロセスの DB のユーザーにテーブルを作る権限は必要ありません。
  - 作る権限を渡したくないときは、作る権限のあるユーザーでログ送信プロセスを一度動かし、テーブルを作らせます。その後で、ログ送信プロセスのユーザーを変更します。
  - テーブルを手で作るときは、ログ送信プロセスが作る形（`records-ship/src/store/pgsql.rs`、`records-ship/src/store/mysql.rs` の `CREATE TABLE`）のとおりに作り、バージョンのテーブルに 1 の行も入れます。バージョンの行が無いと、ログ送信プロセスはテーブルを作ろうとするので、作る権限が必要になります。
- `tukuyomi_records_schema` に、このログ送信プロセスより新しいバージョンがあれば、ログ送信プロセスはその DB にログを送りません（`the schema of the database is newer than this program`）。
- 1 つのログのディレクトリには、ログ送信プロセスを 1 つだけ動かします。送った位置は `records.dir` のパスで分けるので、別のホストのプロキシを同じテーブルへ送るときは、`records.dir` のパスを変えるか、別のスキーマや DB にします。
- **PostgreSQL**: テーブルを作る間は、アドバイザリーロックを取得します。
- **MySQL**: テーブルは InnoDB で作ります。文字は `utf8mb4`、照合順序は `utf8mb4_bin`、行フォーマットは `DYNAMIC` で、時刻は UTC の `DATETIME(3)` です。接続ごとに、`sql_mode` を厳格な設定（`STRICT_ALL_TABLES` を含む）にし、タイムゾーンを UTC にします。テーブルを作る間は、`GET_LOCK` でロックを取得します。サーバーの `max_allowed_packet` は、2 MiB 以上にしてください（1 つの `INSERT` に 100 行まで入ります）。`records.dir` のパスは 512 文字までにします。超えると、ログ送信プロセスは `a value does not fit the database` の行を出して止まります。

### 送信の仕組み

- 1 回の処理では、ログファイルの行を `batch` 個まで読みます。1 つのトランザクションで行を入れ、位置のテーブルを進めます。コミットの後に、`ship.state` を書きます。ログ送信プロセスが落ちても、次の回は DB の位置から続けます。
- `batch` 個そろった回の後は、すぐに次の回へ進みます。送る行が無かった回の後は、`interval_ms` 待ちます。失敗の後は、待つ時間を `interval_ms` から倍ずつ、1 分まで延ばします。うまくいった回の後は、元に戻します。
- DB に接続できない間と、送る行が無い間も、`ship.state` を 1 秒に 1 回は書き直します。プロキシはこれを見て、ログ送信プロセスが動作中であると判断します。
- ログファイルは、名前ではなく inode と作成時刻で追跡します。ローテーションでリネームされても、続きから読みます。使用中のファイルの最後にある改行の無い行は、プロキシが書いている途中かもしれないので、次の回に回します。
- すべての `type` の行を送ります。`type` を知っている JSON のオブジェクトの行は、その項目を同じ名前の列に入れます（無い項目と、型の違う項目の列は空です）。それ以外の行は、`type` を `unknown` にして入れます。行そのものは、いつも `raw` に残ります。
- 列の長さは、プロキシが書く上限に合わせてあり、長い値は切ります（`method` 32、`host` 255、`path` 1024、`request_id` 128 バイト）。UTF-8 でない行は、`raw` では不正なバイトを U+FFFD にします。`line_hash` は、元のバイトのハッシュです。
- `line_hash` が UNIQUE なので、二重に送った行は 1 つになります。同じバイト列の行も 1 つになります。
- `retention_days` が 0 でなければ、それより古い行を 1 分に 1 回、1000 行まで削除します。1000 行を削除できたときは、続けて削除します。古さはログの `ts`（プロキシの時計）で決めます。

### 送れないログ

- ログ送信プロセスが読む前に、ローテーションで消えたログファイルの行は失われます。
  - ログ送信プロセスが開いていたファイルなら、失われた行を数えて、位置の `lost_lines` に加えます。`records-ship: a record file was removed before it was shipped, <count> lines lost` の行も出します。
  - ログ送信プロセスが開く前に消えたファイル（DB に長く接続できない間に、プロキシが `files` より多くローテーションしたときなど）の行は、数えられません。`lines may be lost` を含む行だけを出します。この行は、何も失われていないときにも出ることがあります。
- プロキシの `required` のルートは、そうなる前にリクエストを拒否します（上の「ログの残し方」）。`best_effort` と `security` のルートは、拒否しません。
- ログファイルは切り詰めないでください（logrotate の `copytruncate` など）。ログ送信プロセスは、切り詰めたファイルを同じファイルと見て、その先頭の行を送らないことがあります。ローテーションはプロキシが自分で行います。

### ログ送信プロセスのエラー

- ログ送信プロセスのログは、プロキシと同じ 1 行 1 件の JSON で、標準エラーに出ます。`type` は `line` で、文は `records-ship:` で始まります。文には、接続文字列、ログ、サーバーが返した文の値を入れません。DB のエラーは、決まった文と、サーバーが返した SQLSTATE で示します（例: `records-ship: the database refused or failed a request (SQLSTATE 42000)`）。
- DB がログインを拒否したとき（PostgreSQL の SQLSTATE が 28 で始まるもの、MySQL の 1045）は、待っても直らないので、`records-ship: stop: the login is refused, which waiting does not mend` の行を出して終わります（exit 1）。
- ほかの拒否のときは、上の待ち時間を置いて再試行し、そのたびに行を出します。DB が無い、DB への権限が無い、といった拒否もこれに当たります。MySQL の 1130（そのホストからの接続を許可しない）と 3118（アカウントがロックされている）も同じです。

## 監視

設定に `status` を書くと、そのループバックアドレスで次の 3 つのリクエストに応答します。応答に認証はありません。

| リクエスト | 応答 |
|---|---|
| `GET /healthz` | 200 `ok`。プロキシが応答できることだけを示します |
| `GET /readyz` | 準備ができていれば 200 `ready`。でなければ 503 と理由の語: `starting`（リスナーをバインドする前）、`inspector down`（起動しているエンジンの、どれかの検査プロセスが稼働していない。再起動の間も含みます）、`stopping`（停止が始まった後） |
| `GET /metrics` | 200 と、下の表のメトリクス（Prometheus のテキスト形式、`text/plain; version=0.0.4`） |

- 準備ができているのは、起動しているすべてのエンジンの検査プロセスが稼働していて、リスナーをすべてバインドし、停止が始まっていないときです。世代を切り替えている間は、古い世代が応答するので、準備ができた状態のままです。
- `HEAD` には、同じステータスコードで、ボディを付けずに応答します。ほかのメソッドには 405 で応答します。ほかのリクエストターゲット（クエリの付いたものも）には 404、HTTP/1.1 でないリクエストと、4 KiB に収まらないヘッダー部には 400 で応答します。
- 1 つの接続で 1 つのリクエストに応答し、応答したら閉じます。同時に応答する接続は 8 つまでで、転送の `max_conns` とは別に数えます。それを超えた接続は、受けてすぐに閉じます。ヘッダー部を待つのは 2 秒まで、応答を書くのも 2 秒までです。
- 監視のリクエストは、検査も転送もせず、ログにも記録しません。全体の `access` と `rate_limit`、ホストごとの設定も適用されません。
- 監視用のリスナーは、検査プロセスより前にバインドし、停止の 3 の後に閉じます。それまで `/healthz` は 200 を返します。

### メトリクス（`/metrics`）

メトリクスの値はプロキシのメモリの中にあり、再起動すると 0 から数えます。ラベルの値は、決まった語か、設定の名前だけです。リクエストから来る値は、ラベルにしません。

| 名前 | 型 | ラベル | 内容 |
|---|---|---|---|
| `tukuyomi_requests_total` | `counter` | `class` | リクエストの数。ログを書かないリクエストも数えます（`class` はログと同じ 7 つ） |
| `tukuyomi_waf_rule_hits_total` | `counter` | `decision`（`block`、`detect`） | ルールがブロックしたリクエストと、検知のみのモードでルールに一致したリクエスト |
| `tukuyomi_uninspectable_total` | `counter` | `reason` | 検査できなかったリクエスト（`invalid`、`queue_full`、`unavailable`、`wait_deadline`、`verdict_deadline`、`inspector_lost`、`protocol`、`inspector_error`、`not_created`、`cancelled`） |
| `tukuyomi_policy_refusals_total` | `counter` | `policy`（`access`、`rate_limit`） | アクセス制御とレート制限で拒否したリクエスト（全体の設定とホストごとの設定の、アクセス制御の 403 とレート制限の 429）。ルートの `access` と `admin.route.access` の 403 は数えません |
| `tukuyomi_rate_limit_keys` | `gauge` | | レート制限が今数えているクライアントの数。全体とホストごとの設定のすべてのテーブルの合計（`keys` のうち使っている分）。レート制限が無ければ 0 |
| `tukuyomi_rate_limit_evicted_total` | `counter` | | カウントが残っているのに、場所を空けるためにテーブルから外したクライアントの数。すべてのテーブルの合計で、設定のリロードでテーブルが切り替わっても減りません。レート制限が無ければ 0 |
| `tukuyomi_connections_accepted_total` | `counter` | | 受け付けた接続 |
| `tukuyomi_connections_open` | `gauge` | | 開いている接続 |
| `tukuyomi_connection_permit_waits_total` | `counter` | | 接続を受け付けるときに接続の枠を待った回数（`max_conns` に達した回数の目安） |
| `tukuyomi_tls_handshake_failures_total` | `counter` | | TLS のハンドシェイクの失敗とタイムアウト |
| `tukuyomi_body_buffer_bytes` | `gauge` | | ボディなどのバッファリングに使っている予算のバイト数（`max_buffered_bytes` のうち使っている分） |
| `tukuyomi_inspections_waiting` | `gauge` | | 検査のスロットを待っているリクエスト（エンジンごとの `wait_queue` のうち使っている分の、全エンジンの合計） |
| `tukuyomi_inspector_up` | `gauge` | | 起動しているエンジンの検査カーネルが、すべて準備できていれば 1、でなければ 0 |
| `tukuyomi_inspector_restarts_total` | `counter` | | 検査プロセスの再起動（全エンジンの合計） |
| `tukuyomi_inspector_engine_up` | `gauge` | `engine`（`coraza`、`modsecurity`） | エンジンの検査カーネルの準備ができていれば 1、でなければ 0。起動しているエンジンごとに 1 つ |
| `tukuyomi_inspector_engine_restarts_total` | `counter` | `engine`（`coraza`、`modsecurity`） | エンジンの検査プロセスの再起動。起動しているエンジンごとに 1 つ |
| `tukuyomi_rules_generation_info` | `gauge` | `generation`（フィンガープリントの先頭 16 桁）、`mode`、`engine` | リクエストを受けている世代。値はいつも 1。起動しているエンジンごとに 1 つ |
| `tukuyomi_rules_switches_total` | `counter` | `result`（`switched`、`refused`、`failed`） | SIGUSR1 と制御ソケットによる世代の切り替え |
| `tukuyomi_certificate_reloads_total` | `counter` | `result`（`replaced`、`refused`） | SIGUSR2 による証明書の再読み込み |
| `tukuyomi_config_reloads_total` | `counter` | `result`（`replaced`、`refused`） | SIGHUP と制御ソケットの `reload` による設定のリロード。リロードの途中に受けて無視した SIGHUP と、リロードを始めなかった `reload` の依頼（`busy`、`unmanaged`、`error` の応答）は数えません |
| `tukuyomi_upstream_failures_total` | `counter` | `group` | アップストリームのサーバーの失敗。設定のリロードで、0 から数え直します |
| `tukuyomi_records_dropped_total` | `counter` | | 捨てたログ（上の「ログを書けないとき」） |
| `tukuyomi_record_write_errors_total` | `counter` | | 書き込みに失敗したログ |
| `tukuyomi_record_file_errors_total` | `counter` | | ログファイルに書けなかったログと、失敗した同期（上の「ログファイル」） |
| `tukuyomi_records_refused_total` | `counter` | | `required` のルートで、ログを残せないために 503 で拒否したリクエスト（上の「ログの残し方」） |
| `tukuyomi_records_healthy` | `gauge` | | ログファイルへの最後の書き込みが通り、ログを書くスレッドが動作中なら 1、でなければ 0 |
| `tukuyomi_records_admitting` | `gauge` | | `required` のルートのリクエストを今受け付けるなら 1、拒否するなら 0（上の「ログの残し方」の 3 つ）。`required` のルートが無くても出ます |
| `tukuyomi_records_unshipped_bytes` | `gauge` | | ログ送信プロセスがまだ送っていない、ログファイルのバイト数。`records.ship` があるときだけ出ます。ログ送信プロセスの遅れが分からない間は、値がありません |
| `tukuyomi_start_time_seconds` | `gauge` | | 起動した時刻（Unix 時間の秒） |

### systemd への通知

環境に `NOTIFY_SOCKET` があれば、そのソケットへ通知を 1 回ずつ送ります。リスナーをすべてバインドした後に `READY=1` を、停止が始まったときに `STOPPING=1` を送ります。

- `NOTIFY_SOCKET` は、絶対パスか、`@` で始まる名前（Linux の抽象名前空間の名前）です。ほかの値なら、`start:` の文を 1 行出し、通知を送らずに動きます。
- 送れなかったときは、`notify:` の文を 1 行出すだけで、動作は変えません。待たずに送るので、受ける側が読まなくてもプロキシは止まりません。
- 検査プロセスの環境は空なので、検査プロセスは通知を送りません。
- ユニットを `Type=notify` にすると、`systemctl start` は、検査カーネルの準備とリスナーのバインドまで待ちます（[ビルドと配置](../build/binary-deployment.ja.md) の「systemd」）。

## ACME

`acme renew` は、証明書を発行・更新するコマンドです（RFC 8555）。使うチャレンジは HTTP-01 だけです。

### 必要なもの

- CA は、証明書のホストのポート 80 に平文の HTTP で接続してチャレンジを取得するので、ポート 80 で待ち受ける通常のリスナーかリダイレクトのリスナーが必要です。
  - プロキシはポートの番号を検証しません。
- 通常のリスナーとリダイレクトのリスナーは、管理画面のルート、ポリシー（全体の設定とホストごとの設定）、ルート、ルートの `access`、検査、転送、リダイレクトより先に、次のリクエストに応答します。TLS のリスナーは応答しません。
  - メソッドが `GET` か `HEAD` です。
  - リクエストターゲットが `/.well-known/acme-challenge/<token>` で、後ろに何もありません（クエリやエスケープもありません）。トークンは 1〜128 文字の英数字・`-`・`_` です。
  - `Host` が、`acme` を持つ証明書のホスト（大文字と小文字を区別せず、ポートと末尾の `.` は見ません）です。`managed` のある設定では、`acme` を持つ管理画面のルートのホストと、稼働中のバージョンにある ACME のサイトのホストです（上の「ACME のサイト」）。
- 上の形でないリクエストはチャレンジとして扱わず、ほかのリクエストと同じようにルートと検査へ回ります。
- 応答は、`challenge_dir` の `<token>` のファイル（1 KiB までの通常のファイル）をボディにした 200 か、404 です。シンボリックリンクはたどりません。
- `admin.route.access` はチャレンジには適用されません。CA はどのアドレスからも来るためです。
- `ca_file` には、CA の API のサーバー証明書を発行したルート証明書だけを入れます。入れられるのは 100 枚までなので、OS のルート証明書のバンドルをそのまま使うことはできません。

### 初回の発行

1. 設定に `acme` と、`acme` を持つ証明書を書きます。証明書のファイルはまだ無くてかまいません。
   - `managed` の無い設定では、リスナーの証明書に `acme` を付けます。`managed` のある設定では、管理画面のルートの証明書（`admin.route.certificate`）と、バージョンのサイト（上の「ACME のサイト」）に付けます。
   - プロキシは `start: tls certificate not issued yet (<place>)` の行を出し、その証明書をハンドシェイクから外したまま起動します。
   - 試すときは、CA のテスト用の ACME ディレクトリ（Let's Encrypt ならステージング）を `directory_url` に書きます。
2. プロキシを起動します。
3. サービスの OS ユーザーで `acme renew` を実行します。

   ```bash
   sudo -u tukuyomi /opt/tukuyomi-core/bin/tukuyomi-proxy acme renew /etc/tukuyomi-core/config.json
   ```

   `2.1 renewed` のような行が出ます（`managed` のある設定では、`admin route renewed`、`site www renewed` のような行）。
4. `systemctl kill --kill-whom=main -s USR2 tukuyomi-core.service` で SIGUSR2 を送ると、プロキシが証明書を使い始めます。
5. テスト用の CA で通ったら、本番の CA に切り替えます。
   - テスト用の CA の証明書は、有効期限が来ていないため、そのままでは置き換わりません（`valid`）。そこで、その証明書のファイルを削除します。リスナーと管理画面のルートの証明書なら `cert_file` と `key_file`、ACME のサイトなら managed ストアの `acme/<hosts-sha256>/` にある `chain` と `key` です。
   - `directory_url` を、本番の CA のものに変更します。CA の API のサーバー証明書のルート証明書が違うなら、`ca_file` も変更します。
   - もう一度 `acme renew` を実行してから、SIGUSR2 を送ります。ファイルを削除してから `acme renew` が終わるまでの間に SIGUSR2 を送ると、その証明書はハンドシェイクから外れます。証明書も読む設定のリロードでも、同じです。この順を守れば、その間もプロキシは読み込み済みの証明書を使い続けます。
   - `directory_url`・`ca_file`・`contact_email` など、`acme` の多くの設定キーはコマンドだけが読むので、プロキシの再起動は必要ありません。`challenge_dir` と、`acme` を持つ証明書のホストはプロキシも読むので、これらを変更したときはプロキシに設定をリロードさせます（SIGHUP、`systemctl reload`）。ACME のサイトのホストは、バージョンの反映で切り替わります。
6. 毎日動くタイマーを置きます（[ビルドと配置](../build/binary-deployment.ja.md) の「証明書の更新のタイマー」）。

### 注意

- 同じ設定で `acme renew` を 2 つ同時に実行しないでください。同時実行を防ぐ仕組みはありません。
- コマンドの後に SIGUSR2 を送らないと、新しい証明書は使われません。
- 鍵と証明書は別のファイルに書いて同期してから、鍵、証明書の順に置き換えます。
  - 2 つの置き換えの間で止まると、鍵が証明書に対応しない組み合わせが残ります。動作中のプロキシは、SIGUSR2 を受けてもその組み合わせを拒否し、現在のものを使い続けます。組み合わせは次のコマンドが作り直します。ただし、その間にプロキシを起動すると、その組み合わせを拒否して起動しません（exit 1）。
  - 2 つの置き換えの間に、設定のリロード（SIGHUP、制御ソケットの `reload`）、`managed activate`、`config check`、起動が重なると、証明書の検証で拒否されることがあります（`tls refused`）。そのときはもう一度実行します。管理画面と管理 API の反映での扱いは、[管理リファレンス](admin-reference.ja.md) の「制御ソケット」を参照してください。
- `cert_file`・`key_file`・`challenge_dir` を置くディレクトリと managed ストアには、サービスの OS ユーザーが書き込める必要があります（[ビルドと配置](../build/binary-deployment.ja.md) の「OS ユーザーとディレクトリ」）。
  - 鍵は 0600、証明書は 0644 で書きます（umask の分は引かれます）。
- ACME のサイトでホストの組み合わせを変更したバージョンに反映したときと、前のバージョンに戻したときは、すぐに `acme renew` を実行します（上の「ACME のサイト」）。

## バージョンの更新

tukuyomi-core のバージョンを上げる手順と、前のバージョンへ戻す手順です。

1.0 までは、直前のリリースからの更新だけをサポートします。2 つ以上先のリリースへ上げるときは、間のリリースを 1 つずつ順に更新してください。前のバージョンへは、更新前に作成したバックアップを戻して切り戻します（下の「前のバージョンへの切り戻し」）。ユニットの書き方は、[ビルドと配置](../build/binary-deployment.ja.md) の「systemd」を参照してください。

### 更新前のバックアップ

更新の前に、次のもののバックアップを作成します。

- 設定ファイル
- ルールストア（`rules.store.dir`）
- managed ストア（`managed.dir`。managed 設定を使う場合）
- 管理データの保存先（`admin.store.dir`。管理プロセスを使う場合）

バックアップを作成する間は、管理プロセス、プロキシ、ログ送信プロセスと、証明書の更新のタイマーを止めておきます。所有者と権限はそのまま保ちます。ルールストアなどは所有者と権限を検証するためです。

バックアップには、管理データの保存先にあるパスワードのハッシュと API トークン、managed ストアの秘密鍵なども入るので、root だけが読めるディレクトリに置きます。

次は、[ビルドと配置](../build/binary-deployment.ja.md) のディレクトリとユニットの例に合わせた、バックアップの作り方です。使っていないディレクトリは、引数から外してください。

```bash
sudo systemctl stop tukuyomi-core-admin.service tukuyomi-core.service tukuyomi-core-records-ship.service tukuyomi-core-acme.timer
sudo install -d -m 0700 /var/backups/tukuyomi-core
sudo tar -C / -cpf /var/backups/tukuyomi-core/before-update.tar etc/tukuyomi-core/config.json var/lib/tukuyomi-core/store var/lib/tukuyomi-core/managed var/lib/tukuyomi-core/admin
```

ログのディレクトリ（`records.dir`）、証明書と鍵、作業ディレクトリ（`kernel.tmp_root`）は、バックアップに含めません。

### 0.1.0 からの更新

- 上の「更新前のバックアップ」を作成してから、実行ファイルを入れ替えます。
- 実行ファイルを入れ替えるだけで、0.1.0 の設定ファイル、ルールストア、managed ストアをそのまま読めます（0.1.0 で ModSecurity の世代を選択していたときは、下のとおり `kernel.default_engine` が必要です）。新しい設定キー（`kernel.default_engine`、アップストリームの `engine`）を書かなければ、0.1.0 と同じように、1 つのエンジンだけで稼働します。
- **0.1.0 で Coraza の世代を選択していたとき**: `kernel.default_engine` を書く必要はありません。0.1.0 が書いた `current` は、Coraza の選択中の世代として読まれます。`config check` では `accepted` が出て、起動すると `start: rules engine coraza` の行が 1 つだけ出ます。`current` は書き換わらず、`current.*` も増えません。
- **0.1.0 で ModSecurity の世代を選択していたとき**: `kernel.default_engine` に `modsecurity` を書きます。
  - 書かないと、`config check` と起動は、`rules store refused: no generation is chosen for kernel.default_engine, but one is chosen for another engine` の行を出して受け付けません（exit 1）。ルールストアは変わりません。
  - `modsecurity` を書いた設定ファイルは、`config check` を通ります。起動すると、`start: rules engine modsecurity` の行が 1 つだけ出ます。`current` は書き換わらず、`current.*` も増えません。ModSecurity の検査プロセスは、0.1.0 のときから、設定の `kernel.engines` に必要です。
- **管理プロセス、プロキシ、ログ送信プロセスは、同じビルドにそろえる**
  - 更新後の管理プロセスは、以前のバージョンのプロキシに対しては、世代の選択とロールバックを行いません（409）。詳しくは、[管理リファレンス](admin-reference.ja.md) の「選択とロールバック」と「管理画面」を参照してください。
  - ログ送信プロセスは、設定ファイルの未知の設定キーを受け付けません。`kernel.default_engine` やアップストリームの `engine` を書く前に、ログ送信プロセスを同じビルドに入れ替えます。0.1.0 のプロキシも、`kernel.default_engine` のある設定ファイルを、`configuration has an unknown key` で受け付けません（exit 2）。
  - 実行ファイルをすべて同じリリースのものに入れ替えてから、管理プロセス、プロキシ、ログ送信プロセスの順に再起動します（「managed 設定への移行」の手順 8 と同じ順です）。管理プロセスを先に再起動すると、入れ替えの間は、更新後の管理プロセスが以前のプロキシに対する世代の選択とロールバックを 409 で拒否するだけです。ルールストアと切り替えの履歴は変わりません。

### 前のバージョンへの切り戻し

更新前のバックアップを戻して、前のバージョンの実行ファイルで起動します。バージョンごとに違う手順はありません。

1. 管理プロセス、プロキシ、ログ送信プロセスと、証明書の更新のタイマーを止めます。
2. 今の設定ファイルと、バックアップしたディレクトリを、別の名前に退避します（削除せずに残します）。
3. バックアップを戻します。
4. 実行ファイルを前のバージョンに戻し、前のバージョンの `config check` が `accepted` を出すことを確認します。
5. 管理プロセス、プロキシ、ログ送信プロセスの順に起動し、証明書の更新のタイマーを起動します。

上の「更新前のバックアップ」の例で作成したバックアップの場合、2 と 3 は次のとおりです。

```bash
sudo mv /etc/tukuyomi-core/config.json /etc/tukuyomi-core/config.json.after-update
sudo mv /var/lib/tukuyomi-core/store /var/lib/tukuyomi-core/store.after-update
sudo mv /var/lib/tukuyomi-core/managed /var/lib/tukuyomi-core/managed.after-update
sudo mv /var/lib/tukuyomi-core/admin /var/lib/tukuyomi-core/admin.after-update
sudo tar -C / -xpf /var/backups/tukuyomi-core/before-update.tar
```

- 更新の後に変更したもの（インポートや選択をした世代、managed 設定のバージョンと反映、作成したユーザー、API トークン、セッション、管理データの保存先にある監査ログの行）は失われます。監査ログの行は標準エラー（ジャーナル）にも出ています。
- ログのディレクトリは戻しません。更新の後のログは残ります。
- managed ストアの `acme/` にある ACME のサイトの証明書は、バックアップを作成したときのものに戻ります。次の `acme renew` で、有効期間の残りに応じて更新されます（上の「ACME」）。
