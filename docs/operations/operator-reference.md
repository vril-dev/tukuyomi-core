# 運用リファレンス

この文書は、今の実装の命令、合図、設定ファイルの鍵、ルールセットの扱い、要求の扱い、要求の前の方針、記録、監視を、引いて使える形でまとめる。置き方と systemd の例は [実行ファイルの build と配置](../build/binary-deployment.md) に書く。管理のプロセス（`admin` の命令）の設定と API は [管理リファレンス](admin-reference.md) に書き、この文書には proxy から見えるものだけを書く。

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
  2. 設定ファイル（`geo` があれば、国のデータベースの読み込みと確かめも）
  3. 上流の server の名前の解決と、上流の組の CA のファイル
  4. TLS の待ち受けの証明書と鍵
  5. ルールの保管場所と、選んだ世代
  6. 記録のファイル（設定に `records` があるとき）を開く
  7. 監視の待ち受け（設定に `status` があるとき）の bind
  8. 制御 socket（設定に `admin` があるとき）の bind
  9. 検査核の起動と、検査プロセスの準備
  10. 待ち受けの bind
- 記録のファイルは、検査プロセスより前に開く。開けなければ、`start: record file refused: ...` の文を出し、検査プロセスを起動せずに止まる（exit 1）。
- 監視の待ち受けと制御 socket は、検査プロセスより前に bind する。bind できなければ、検査プロセスを起動せずに止まる（exit 1）。制御 socket は `start: control socket refused: ...` の文を出す。
- 待ち受けは、検査核の準備ができてから、全部を bind する。1つでも bind できなければ、どれも使わずに止まる。
- 合図を扱う処理は、6 の後に入る。それより前（名前の解決は最長 `resolve_timeout_ms` かかる）に届いた合図は、どれも proxy をそのまま終わらせる。
- 記録には、準備ができると `start: the kernel is ready`、待ち受けを始めると `start: listening` の文が出る（`line` の記録。下の「記録」）。
- 環境に `NOTIFY_SOCKET` があれば、待ち受けを全部 bind した後に `READY=1` を送る（下の「systemd への知らせ」）。
- exit code は次のとおり。

| exit code | 意味 |
|---|---|
| 0 | 合図で止まり、検査核の停止（検査プロセスの終わりと作業場所の削除）まで確かめられた |
| 1 | ほかの終わり方。root での起動、起動の前の確かめの失敗、引けない上流の名前、使えない CA のファイル、断られた証明書や鍵、断られた保管場所や世代、開けない記録のファイル、bind できない監視の待ち受けや制御 socket も含む（このときは何も起動していない） |
| 2 | 引数の誤り、または設定ファイルが断られた |

### `config check`

```text
tukuyomi-proxy config check <config>
```

- 起動と同じ確かめを、選んだ世代と検査核の設定まで流す（上の 2〜5 と、検査核の設定の値）。起動の前の確かめ（上の 1）は、root でないことだけを見る。
  - 通れば、標準出力に `accepted` の1行が出て exit 0 になる。
  - ほかの行は標準エラーに出て、`config check:` で始まる。引数の誤りのときだけ `config:` で始まり、使い方の行が続く。
  - exit code は起動と同じである。
  - 選んだ世代のエンジンが使えるかも確かめる。使えなければ、`config check: rules generation refused: <理由>` の行を出して exit 1 になる。この build が持つ検査のエンジンは `coraza` と `modsecurity` である。`modsecurity` の世代は、設定の `kernel.engines` に検査プロセスがあるときだけ使える（下の「`kernel`」の `engines`）。
- `geo` があれば、国のデータベースも起動と同じに読んで確かめる（「要求の前の方針」の `geo`）。
- 確かめないもの:
  - SIGCHLD と file descriptor（上の 1 のうち、root でないこと以外）
  - 作業場所（`kernel.tmp_root`）。検査プロセスを起動するときに確かめる
  - 検査プロセスの実行ファイルが起動できること、Landlock が使えること
  - ルールが世代のエンジン（Coraza か ModSecurity）で組めること（起動のときに確かめる。ルールは `rules import` が試してから世代にする）
  - 記録のファイルを開けること（上の 6）
  - 待ち受けと監視の待ち受けの port、制御 socket を bind できること
  - systemd の設定
  - 動いている proxy が SIGHUP の読み直しで断る理由（動いている間に変えられない鍵の違い、新しい待ち受けの bind。下の「SIGHUP（設定の読み直し）」）
- この命令が書くものは1つだけである。起動と同じく、選んだ世代を使う印を保管場所の `using/` に作る（まだ無いとき）。命令が終われば、印の lock は外れる。
- サービスと同じ利用者で流す。別の利用者では、保管場所の持ち主の確かめや、鍵のファイルの読みで断られる。

### `rules`

```text
tukuyomi-proxy rules import <config> [--crs <dir>] [--crs-off <name>]... [--rules <file>]... [--data <file>]... [--routes <file>] [--engine <name>] [--accept-block] [--detect-only]
tukuyomi-proxy rules activate <config> <fingerprint>
tukuyomi-proxy rules remove <config> <fingerprint>
tukuyomi-proxy rules list <config>
```

どれも短い命令で、動いている proxy とは別のプロセスである。動いている proxy は、命令がしたことに気づかない。新しい世代を使わせるには、SIGUSR1 を送る（下の「合図」）。管理のプロセスの API は、世代を選ぶことと、動いている proxy への切り替えの依頼を続けて行う（[管理リファレンス](admin-reference.md)。依頼は「制御 socket」）。

| 命令 | すること | 標準出力 |
|---|---|---|
| `import` | 入力からルールセットを作って保管場所に置き、試しに通れば世代にする。世代を選びはしない | `<指紋> created`、`<指紋> already exists`、`<指紋> recreated, the stored copy was broken` |
| `activate` | 世代を選ぶ。後で起動する proxy と、SIGUSR1 を受けた proxy がそれを使う。世代のエンジンが使えないときは、選ばずに断る（exit 2） | `<指紋> current` |
| `remove` | 選ばれていない世代で、どの proxy も使っていないものを消す | `<指紋> removed` |
| `list` | 世代の一覧 | 指紋、作った時刻（epoch からの秒）、mode（`block`・`detect`、manifest が読めなければ `unknown`）、エンジン（`coraza`・`modsecurity`、manifest が読めなければ `unknown`）、bypass の経路があれば `routes` と数、選ばれた世代に `current` |

`import` の入力は次のとおりである。option の path は、命令を流す場所からの相対でも書ける。

| option | 中身 |
|---|---|
| `--crs <dir>` | `scripts/fetch-crs.sh` で取得した CRS のディレクトリ。`crs-setup.conf`（と任意の `crs-setup.conf.example`）と `rules/` の `.conf`・`.data`・`.example` だけを持つこと。ほかのもの（隠しファイル、`plugins` などのディレクトリ、ほかの拡張子、link）があれば断る |
| `--crs-off <name>` | `crs/rules/` の `.conf` のうち、読み込まないもの。何度でも書ける。`--crs` が要る |
| `--rules <file>` | 運用者のルールのファイル。何度でも書け、CRS の後に書いた順に読み込む |
| `--data <file>` | 運用者のルールが読むデータのファイル。ルールセットに入るが、ルールとしては読み込まない |
| `--routes <file>` | 検査しない経路（bypass）のファイル（下の「検査しない経路」） |
| `--engine <name>` | 世代の検査のエンジンの名前。`coraza` か `modsecurity`（小文字）。省けば `coraza`。これ以外の名前と、設定の `kernel.engines` に検査プロセスが無い `modsecurity` は、何も置かずに断る（exit 2） |
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

exit code は、0 が成功、1 がほかの終わり方（断られた保管場所や入力、失敗した試し、使用中の保管場所、`list` で manifest が読めない世代や選んだ世代が無い保管場所、root での実行）、2 が引数の誤り、断られた設定ファイル、または使えないエンジン（`import` と `activate`）である。

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
- 動いている proxy は、新しい証明書に気づかない。命令の後に SIGUSR2 を送る（`systemctl kill --kill-whom=main -s USR2 tukuyomi-core.service`）。
- exit code は次のとおりである。
  - 0: すべてが `renewed` か `valid`
  - 1: 1つでも `failed`、止められた、流せない、root で流した
  - 2: 引数の誤り、断られた設定ファイル、`acme` を持つ証明書が無い設定ファイル

手順は下の「ACME」にある。

### `admin`（管理のプロセスの命令）

```text
tukuyomi-proxy admin <config>
tukuyomi-proxy admin bootstrap <config> <name>
tukuyomi-proxy admin reset <config> <name>
```

- 管理のプロセスを動かす命令（`admin <config>`）と、その短い命令（`bootstrap`・`reset`）である。設定ファイルに `admin` が要る。鍵、API、命令の中身は [管理リファレンス](admin-reference.md) に書く。
- 動いている proxy とは別のプロセスである。proxy に依頼できるのは、状態を尋ねることと、世代の切り替えだけである（下の「制御 socket」）。
- 起動の前の確かめも、root で流れないことも、proxy と同じである（`host check refused`）。
- 管理のプロセスは、`admin <config>` の間、記録を JSON で標準エラーに出す（systemd では journal）。`bootstrap` と `reset` は、人が読む文の行を出す。
- exit code は、0 が成功、1 がほかの終わり方、2 が引数の誤り、断られた設定ファイル、`admin` の無い設定ファイルである。

## 合図

合図は proxy の主プロセスだけに送る。検査プロセスは、SIGUSR1・SIGUSR2 は無視するが、SIGTERM・SIGINT・SIGHUP が届くと終わる。systemd では `systemctl reload`（unit の `ExecReload` が `config check` の後に主プロセスへ SIGHUP を送るとき）か `systemctl kill --kill-whom=main` を使う。

| 合図 | すること |
|---|---|
| SIGTERM、SIGINT | 止まる（下の「停止」） |
| SIGHUP | 設定ファイルを読み直し、止まらずに新しい設定に替える |
| SIGUSR1 | ルールの保管場所が今選んでいる世代へ切り替える |
| SIGUSR2 | すべての TLS の待ち受けの証明書と鍵のファイルを読み直す |

SIGHUP で止まる前の版から入れ替えるときは、新しい実行ファイルを入れてから unit を替える（[実行ファイルの build と配置](../build/binary-deployment.md) の「systemd」）。前の版は SIGHUP で止まる。

### SIGHUP（設定の読み直し）

- 起動のときと同じ path の設定ファイルを、別の thread で読み直す。起動の段のうち、ルールの保管場所より前の段（設定、上流の server の名前の解決と `ca_file`、待ち受けの証明書と鍵、ACME の challenge、`geo` の国のデータベース）を同じ確かめで流し、行の頭は `reload:` になる。
- すべてが通り、動いている間に変えられない鍵（下）がどれも起動のときと同じなら、新しい設定に一度に替える。最後に `reload: configuration replaced <ファイルの SHA-256>` の文を出す。どのファイルが効いているかは、この SHA-256 で確かめる。
- どこかで断られたら、何も替えず、理由の文を出す（`reload: configuration refused: <理由>`、`reload: upstream refused: <理由>`、`reload: tls refused: <理由>` など）。断った文に、ファイルの値は出さない。
- 通っても断っても、`tukuyomi_config_reloads_total` に数える（`replaced`、`refused`）。
- 替わるもの:
  - `proxy` の鍵（下の変えられない鍵を除く）、待ち受け（足す、外す、並べ替える、TLS と証明書、`http2`、`redirect`）
  - `forward`（上流の組と経路）。上流の server の名前は、読み直すたびに引き直す
  - 上流の組の `ca_file`、待ち受けの証明書と鍵、ACME の challenge
  - 全体の `access`・`rate_limit`・`geo`（国のデータベースを読み直す）
  - `records.keep`
- 動いている間に変えられない鍵: `proxy.max_conns`、`max_buffered_bytes`、`drive_slice_ms`、`ready_wait_ms`、`stop_inspect_ms`、`stop_wait_ms`、`records`（`keep` を除く全部と、有る無し）、`status`、`admin`、`rules.store`、`kernel`（全部）。どれかが起動のときと違う設定は、全体を断る（`reload: configuration refused: <鍵> cannot change while running`）。替えるときは起動し直す。
  - `records`・`status`・`admin`・`rules.store`・`kernel` は、管理のプロセスと記録の送り手も同じファイルから起動のときに読むので、proxy だけが替えると値がずれる。
- 接続:
  - 替えた後に受けた接続は、新しい設定を使う。開いている接続は、受けたときの設定を使い続け、次のように閉じる。要求は断らない。
  - HTTP/1.1: 答えた後で次の要求を待っている接続は、すぐ閉じる。答えの途中の接続は、その答えに `Connection: close` を付けて閉じる。受けたばかりの接続と、次の要求の head を受けかけの接続は、その要求に答えてから閉じる。
  - HTTP/2: `GOAWAY` を送り、開いている stream が終わってから閉じる。
  - WebSocket の tunnel と、経路の `stream` の答えは、前の設定のまま自分の期限まで続く。
- 待ち受け:
  - 新しい設定の address のうち、今は待っていないものを、替える前にすべて bind する。1つでも bind できなければ、全体を断る（`reload: configuration refused: listener <番号> cannot be bound`。番号は新しい設定の中の位置で、1 から数える）。
  - 今もある address は、同じ socket のまま新しい並びの位置へ移る。その address への接続は断られない。
  - 消えた address は、替えた後に閉じる。そこでまだ始まっていない接続（system の backlog にあるもの、接続の枠を待っているもの）は切れる。開いている接続は上のとおり続く。
  - 今待っている address と重なる address は bind できず、全体を断る。たとえば `0.0.0.0:8080` で待っているときの `127.0.0.1:8080`（逆も同じ）、`127.0.0.1:8080` のときの `[::ffff:127.0.0.1]:8080` である。替えるときは、外す読み直しと足す読み直しに分けるか、起動し直す。
  - 記録の `listener` は、その接続を受けたときの設定の中の番号である。並びを替えた後は、同じ番号が別の待ち受けを指すことがある。
- 持ち越すもの:
  - 流量の制限の表は、新旧の両方に `rate_limit` があり、`keys`・`rate`・`burst` がどれも同じなら続く（`exempt_cidrs` は新しい値を使う）。どれかが違うか、片方に無ければ、新しい表で 0 から数え、`reload: rate limit table started anew` の文を出す。
  - 上流の組の外れの印と失敗の数、上流への待機中の接続、待ち受けの TLS の session は作り直す。`tukuyomi_upstream_failures_total` は 0 から数え直す。
  - ルールの世代には触れない。動いている世代はそのままで、保管場所も読まない（世代を替えるのは SIGUSR1）。
- 同じ中身のファイルでも、上のとおり作り直し、待っている接続を閉じる。
- 読み直しの途中に受けた SIGHUP は、`reload: a configuration reload is in progress, ignored` の文を出すだけである。合図の処理が入ってから待ち受けを bind するまでの間と、停止の間に受けた SIGHUP も、文を1つ出すだけである。
- 読み直しの途中に受けた SIGUSR2 は、読み直しが終わった後（替えたときも断ったときも）に、今の設定の証明書を読む。`reload: SIGUSR2` の文は、そのときに出る。
- 読み直しの途中に停止が始まったら、読み直しは捨てる。
- SIGHUP の処理が入る前（起動の 6 より前）に届いた SIGHUP は、ほかの合図と同じく proxy を終わらせる。

### SIGUSR1（世代の切り替え）

- proxy は保管場所を読み、選ばれた世代で新しい検査核と検査プロセスを起動する。新しい方の準備ができたら、新しい要求をそちらへ回す。
  - 古い方は、持っている要求を `stop_inspect` まで検査してから止まる。
  - 新しい方が起動に失敗するか、`ready_wait` の中に準備できなければ、古い方がそのまま検査を続ける。
  - 新しい検査プロセスは、その世代のエンジンの実行ファイル（Coraza は `kernel.inspector`、ModSecurity は `kernel.engines`）で起動する。エンジンが替わる切り替えも、proxy を止めずにできる。
  - 選ばれた世代のエンジンが使えないときは、切り替えない。`reload: rules store refused: <理由>` の文を出し、古い方がそのまま検査を続ける。`rules activate` と管理のプロセスは、そのような世代を選ばない。
- 検査しない経路の表は、新しい世代が要求を受け始めるときに一緒に入れ替わる。
- 切り替えの間は検査プロセスが2つになり、メモリもおよそ2倍になる。CRS 4.23.0 で測った Coraza の検査プロセスは、1つ約 52 MB だった（ModSecurity の検査プロセスは測っていない）。
- 合図の処理が入ってから待ち受けを bind するまでの間、切り替えの途中、停止の間に受けた SIGUSR1 は、記録に文を1つ出すだけで何もしない。今と同じ世代が選ばれているときも、その旨の文を出すだけである。
- 使っている間、proxy は世代の印（保管場所の `using/<指紋>`）に共有の lock を持つ。そのため `rules remove` は、使用中の世代を消せない。
- 管理のプロセスは、制御 socket でも同じ切り替えを依頼できる（下の「制御 socket」）。切り替えの手順と、`tukuyomi_rules_switches_total` の数え方は SIGUSR1 と同じである。

### SIGUSR2（証明書の読み直し）

- 読み直したすべての証明書と鍵が確かめに通ったときだけ、まとめて入れ替える（確かめの中身は下の `proxy.listeners` の `cert_file`・`key_file`）。入れ替えた後に始まる handshake から、新しいものを使う。開いている接続は、今のものを使い続ける。
- 1つでも通らなければ、どれも入れ替えず、どれが通らなかったかの文を記録に出す。
- `acme` を持つ証明書でファイルが無いものは、断る理由にならない。行を出して handshake から外し、ファイルができた後の SIGUSR2 で使い始める。動いている間にファイルを消してから SIGUSR2 を送ると、その証明書も handshake から外れ、その host への接続は失敗する。
- 上流の組の CA のファイルは、SIGUSR2 では読み直さない（SIGHUP で読み直す）。
- 証明書と鍵だけを読ませたいとき（ACME の更新の後など）は、SIGHUP でなく SIGUSR2 を送る。SIGHUP は設定ファイル全体を読むので、書きかけの設定を拾うことがある。
- 合図の処理が入ってから待ち受けを bind するまでの間と、停止の間に受けた SIGUSR2 は、記録に文を1つ出すだけである。SIGUSR1 とは関係しない。

### 読み直さないもの

次のものは起動のときに読み、proxy を起動し直すまでそのままである。

- 上の「SIGHUP（設定の読み直し）」の、動いている間に変えられない鍵（`records` の場所と大きさ、`status`、`admin` の制御 socket の path、`rules.store`、`kernel` など）
- 管理のプロセスと記録の送り手は、設定を読み直さない（どちらも SIGHUP では止まる）。設定を替えたら、それらは起動し直す（[管理リファレンス](admin-reference.md)、下の「記録の送り手」）。

## 停止

最初の止める理由（合図、起動か driver の失敗）の時刻を t0 とする。

1. 待ち受けを閉じ、新しい要求を断る。制御 socket も閉じて、そのファイルを消す（答えを待っていた client は、答えを受けない）。次の要求を待っている接続は閉じる。`/readyz` は 503 `stopping` になり、`NOTIFY_SOCKET` があれば `STOPPING=1` を送る。
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
{"proxy": {..}, "forward": {..}, "kernel": {..}, "rules": {"store": {..}}, "acme": {..}, "status": {..}, "records": {..}, "access": {..}, "rate_limit": {..}, "geo": {..}, "admin": {..}}
```

- `acme`、`status`、`records`、`access`、`rate_limit`、`geo`、`admin` は省いてよい（下のそれぞれの節）。

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
- `geo` は、国の一覧（全体の `access` か、経路の `access` の `deny_countries`・`allow_countries`）が1つでもあるときは、必ず書く。

### 例

TLS の待ち受け（HTTP/2 と ACME の証明書）、https への redirect の待ち受け、1つの上流の組、記録のファイル、流量の制限の例を示す。省いてよい鍵のうち、この例に入れたのは `acme`、`records`、`rate_limit` だけである。ほかの鍵は、下のそれぞれの節に書く。値は動かすときの目安で、受け入れる範囲は下の表にある。

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
| `response_idle_ms` | 上流への接続が黙っていてよい時間と、client が受け取らない時間の上限。応答の本文の間だけでなく、上流の応答の head を待つ間にも効く（本文を流す要求では、応答の head が来るまで効かない）。そのため、本文をためる要求では、`upstream_header_ms` をこれより長くしても効かない |
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
- `redirect` があるとき: すべての要求に https への redirect（308）か 404 で答え、何も転送しない。全体の `access` や `rate_limit` に断られた client には、403 か 429 で答える（下の「要求の前の方針」）。
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
| `cert_file`、`key_file` | 絶対の path、3840 バイトまで | 証明書の chain と秘密鍵のファイル。起動のとき、SIGHUP と SIGUSR2 で読む |
| `hosts` | 1〜64 個 | 証明書が受け持つ名前（小文字の英字・数字・`-`・`.`）か、`*.` と名前。IP の literal は書けない。1つの待ち受けの中で同じ host は1回だけ |
| `acme` | `{"renew_before_days"}`（1〜60） | `acme renew` で発行・更新する証明書の印。host に `*.` は書けない。ファイルは起動のときに無くてもよい |
| `http2` | object | HTTP/2 を受ける（下の `http2`）。無ければ HTTP/1.1 だけ |

- `cert_file` と `key_file` は、起動のとき、SIGHUP と SIGUSR2 で、次を確かめる。
  - どちらも 1 MiB までの普通のファイルである。
  - 証明書のファイルは PEM の証明書を 1〜10 枚持ち、先頭が host の証明書である。鍵のファイルは鍵をちょうど1つ持つ。
  - 鍵が先頭の証明書と対になり、先頭の証明書が `hosts` のすべてを受け持つ。
  - 有効期間は確かめない。
- handshake では、client が送った server name で、`hosts` から証明書を選ぶ。名前が、wildcard より先に当たる。server name の無い handshake と、合う host の無い handshake は失敗する。
- `*.` と名前は、名前の前のちょうど1つの label に当たる（`*.a.example` は `www.a.example` に当たり、`a.example` と `x.y.a.example` には当たらない）。英字の大小は区別しない。
- TLS の接続の要求は、`Host` が handshake で使った証明書の host に入っていなければ 421 で答える（全体の `access` と `rate_limit` の後、経路を引く前）。

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
- 全体の `access` と `rate_limit` に断られた client は、redirect も 404 も受けず、403 か 429 を受ける（下の「要求の前の方針」）。この判定は、ACME の challenge の後、redirect の前にする。
- ACME の challenge の要求には、redirect より先に答える（下の「ACME」）。

### `forward`

```text
{"resolve_timeout_ms", "upstreams": {"<名前>": {..}}, "routes": [..], "default_upstream"}
```

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `resolve_timeout_ms` | 1 ms〜3600 s | 起動のときと SIGHUP の読み直しで、上流の server の名前を引き終える時間 |
| `upstreams` | 1〜64 組 | 組の名前（1〜64 文字の英字・数字・`-`・`_`）から `{"servers", "tls"?}` へ |
| `routes` | 0〜1024 個 | 要求の `Host` と path から組を選ぶ経路 |
| `default_upstream` | 組の名前か空の文字列 | どの経路にも当たらない要求の組。空なら、そうした要求は 404 |

server は `{"address", "weight", "max_fails", "fail_timeout_ms", "backup"}` で、すべての鍵を書く。1つの組に 1〜64 個書ける。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `address` | IP の literal と port、または名前と port（`name:port`） | 名前は、小文字の英字・数字・`-`・`_`・`.` で 253 バイトまで。各 label は 1〜63 バイトで、最後の label は英字で始まる。port は 1〜65535 で、先頭に 0 を付けない。IP の literal には、未指定の address（`0.0.0.0`、`::`）、multicast の address、待ち受けの address（待ち受けが未指定の address なら、その port の loopback）は書けない。管理のプロセスの待ち受け（`admin.listen`）は書いてよい（proxy の経路から管理のプロセスへ入れるようにするため） |
| `weight` | 1〜100 | 重み |
| `max_fails` | 0〜100 | `fail_timeout_ms` の中にこの回数失敗したら、server を `fail_timeout_ms` の間外す。0 なら数えない |
| `fail_timeout_ms` | 1 ms〜3600 s | 上の失敗を数える時間と、外す時間 |
| `backup` | true、false | ほかのどの server も使えないときだけ使う |

- 名前は起動のときと SIGHUP の読み直しのたびに引き、その間は引き直さない（SIGUSR1 でも引き直さない）。
  - 名前の address が変わったら（コンテナの名前など）、SIGHUP で読み直す。
  - 名前の address はどれも、書いた server と同じ値を持つ、組の server になる。名前を引いた後で、組の server は 64 個までである。
  - 名前が引けないとき、address が無いとき、未指定・multicast・待ち受けの address を指すとき、時間の中に引き終わらないときは、起動しない。SIGHUP の読み直しでは、その設定を断る。
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
- `ca_file` は、信じる root の証明書を持つ PEM のファイルである。絶対の path で 3840 バイトまで、ファイルは 1 MiB までで、1〜100 枚を持つ。起動のときと SIGHUP の読み直しで読む（SIGUSR2 では読まない）。
- `server_name` は、小文字の名前で、TLS が使える形であること。あれば、server をその名前で確かめる。無ければ、書いた名前で確かめる。IP の literal で書いた server は、その address で確かめる。
- 上流へは TLS 1.2 と 1.3 で、ALPN は `http/1.1` だけである（上流へ HTTP/2 は話さない）。client の証明書は送らない。

経路は `{"host"?, "path"?, "upstream", "access"?, "rewrite"?, "stream"?, "max_body"?, "records"?}` である。

| 鍵 | 意味 |
|---|---|
| `host` | 小文字の名前と、任意で `:port`（`*.` と port を含めて 253 バイトまで）。port を書けばその port だけに、書かなければどの port にも当たる。`*.` で始めると、前の1つ以上の label に当たる |
| `path` | `/` で始まる 1〜255 バイトの path。`/` で終われば、それで始まる path すべてに当たり、そうでなければその path だけに当たる。使えるバイトは英数字と `-._~!$&'()*+,=:@/%` で、`%` の後は16進数2桁。読み方が複数ある形（下の「`access` を使うときの注意」）は書けない |
| `upstream` | 組の名前 |
| `access` | `{"deny_cidrs"?, "allow_cidrs"?, "deny_countries"?, "allow_countries"?}`。network は一覧ごとに 256 個まで、国は一覧ごとに 256 個まで（下の「要求の前の方針」の `access`） |
| `rewrite` | 上流へ送る要求と、返す応答の書き換え（下） |
| `stream` | `{"idle_ms", "total_ms", "websocket"}`。3つとも書く（下の「長い応答と WebSocket」） |
| `max_body` | その経路の本文の上限。`proxy.max_body` 以下で、下げることしかできない。0 なら本文を受けない |
| `records` | `best_effort`、`required`、`security` のどれか。その経路の要求の記録の残し方。省けば `records.keep` に従う（下の「記録」の「記録の残し方」） |

- 経路は、要求の `Host` と、target の最初の `?` までを、受けたバイトのまま比べる。
  - デコードや整形はしない。path の英字の大小は区別する。
  - host の英字の大小は区別せず、名前の末尾の `.` は1つ落とす。
- 同じ `host` と `path` の経路は、2つ書けない。
- 読み方が複数ある path の target（下の「`access` を使うときの注意」に挙げた形）は、`path` を持つ経路には当たらない。host だけの経路か、既定の組へ回る。
- 当たる経路のうち、最も詳しいものを使う。
  - 先に host で決める。名前が wildcard より先、長い wildcard が短いものより先、port のある経路が無いものより先、host のある経路が無いものより先である。
  - 次に path で決める。その path だけの経路が接頭辞より先、長い接頭辞が短いものより先、path のある経路が無いものより先である。
- 既定の組には、`access`・`rewrite`・`stream`・`max_body`・`records` は無い。既定の組へ回る要求の記録は、`records.keep` に従う。
- 経路を引く前に、全体の `access`・`rate_limit` と、TLS の接続の `Host` の確かめがある（下の「要求の前の方針」の「要求の確かめの順」）。
- 経路を引いた後、本文を読む前と検査の前に、次を答える。
  - どの経路にも当たらず既定の組も無い: 404
  - `access` に断られた client: 403
  - `Content-Length` が経路の `max_body` を超える: 413
- `access`: client の address（下の「client の address」）が `deny_cidrs` に入るか、その国が `deny_countries` に入れば断る。`allow_cidrs` が空でなく、client がそこに入らなければ断り、`allow_countries` が空でなく、その国がそこに入らなくても断る。`allow_cidrs` と `allow_countries` を両方書けば、両方に入る client だけが通る。国は、全体の `geo` のデータベースで引く。国の一覧を書くには `geo` が要る（下の「要求の前の方針」の `geo`）。

`access` を使うときの注意:

- 経路は受けたバイトで引くが、上流のアプリケーションは別の綴りを同じ path と読むことがある（`/priv%61te/x` を `/private/x` と読むなど）。そのため、どれかの経路が `access` を持つ間は、要求は「その要求と取り違えられうる経路」すべての `access` に通らなければならない。国の一覧だけを持つ `access` も、`access` として数える。次の決まりも同じである。
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
- 信じる相手でも、`X-Forwarded-For` の行が無い要求では、その相手が client である。
- この client の address を、検査、全体の `access`、`rate_limit`、国の判定、経路の `access`、記録に使う。

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
| `inspector` | 絶対の path | Coraza の検査プロセスの実行ファイル。省けない鍵で、ModSecurity の世代だけを使うホストでも書く |
| `engines` | 省いてよい。`{"modsecurity": {"inspector": <絶対の path>}}` の形で、どちらの段の鍵も要る。path は 4095 バイトまで | ModSecurity の検査プロセスの実行ファイル。`modsecurity` の世代を使うときに起動する。省くと、`modsecurity` の世代は、取り込み、選択、起動のどれでも `kernel.engines has no inspector for the engine of the generation` で断る |
| `tmp_root` | 絶対の path、3840 バイトまで | 起動ごとの作業場所を作る親。本物のディレクトリで、持ち主が proxy の利用者、group と other の権限が無く、setgid が無いこと |
| `gomaxprocs` | 1〜65535 | 検査プロセスの `GOMAXPROCS`。ModSecurity の検査プロセスは、1つの thread で動くので使わない（受けた値を最初の知らせで返すだけ） |
| `gomemlimit` | 1〜9223372036854775807（バイト） | 検査プロセスの `GOMEMLIMIT`。ModSecurity の検査プロセスは、使わない（受けた値を最初の知らせで返すだけで、メモリの上限にはならない） |
| `slots` | 1〜4 | 同時に検査する要求の数 |
| `wait_queue` | 1 以上、`max_conns` 以下 | 検査の枠を待つ要求の数 |
| `records` | `slots + wait_queue` 以上 | 同時に持つ要求の記録の数。最上位の `records`（記録のファイル）とは別の鍵である |
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

### `admin`

管理のプロセス（`tukuyomi-proxy admin`）の設定である。省いてよい。省けば、管理のプロセスは無く、proxy は制御 socket を作らない。

```text
{"listen", "control", "store", "origin", "trusted_proxies", "mfa", "session_idle_ms", "session_total_ms", "crs_dir"?}
```

- proxy と管理のプロセスは、同じ設定ファイルを読む。proxy が使う鍵は `listen` と `control` で、ほかの鍵は値を確かめるだけである。proxy と管理のプロセスが、同じファイルを同じに受けるか断るかにするためである。ほかの鍵の意味と範囲は [管理リファレンス](admin-reference.md) に書く。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `listen` | loopback の IP（`127.0.0.0/8` か `::1`）と port（0 は不可） | 管理のプロセスの待ち受けの address。`::ffff:127.0.0.1` の形は loopback と見なさない。待ち受け（`proxy.listeners`）とも監視の待ち受けとも重ならない（待ち受けどうしと同じ決まり）。上流の server は、この address にしてよい |
| `control` | 絶対の path、107 バイトまで | 管理のプロセスが proxy に依頼を送る制御 socket の path（下） |

- `rules.store.dir`、`records.dir`、`admin.store.dir`、`admin.control` のあるディレクトリの重なりは、断る（下の「値どうしの関係」）。記録のファイルの回しが、同じディレクトリにある socket を置き換えてしまうなど、一方が他方の中身を替えないようにするためである。

#### 制御 socket

管理のプロセスが、proxy に状態を尋ね、世代の切り替えを依頼するための Unix domain socket である。

- 作り方:
  - socket のあるディレクトリは、本物のディレクトリで、持ち主が proxy の利用者、group と other の権限が無いこと（ルールの保管場所と同じ確かめ）。socket は 0600 で作る。
  - 検査核を起動する前に bind する。path に既にあるものが、proxy の利用者の socket で、待っているプロセスが無い（接続を断られる）ときだけ、消して作り直す。待っているプロセスがあるもの、socket でないもの、別の利用者のものは、`start: control socket refused: ...` の文を出して断る（exit 1）。
  - 停止では、待ち受けを閉じる段で一緒に閉じて、ファイルを消す。ファイルが、作ったものと同じときだけ消す。
- 使える人: proxy と同じ利用者で動くプロセスは、どれも使える。socket の先に認証は無く、守るのはディレクトリの権限と socket の 0600 だけである。管理のプロセスは、proxy と同じ利用者で動かす。
- 1つの接続は、2 秒の中に JSON の1行（4 KiB まで）を送り、1行の答えを受けて閉じる。同時に 4 接続まで答え、それを超えた接続は、受けてすぐ閉じる。行が来ない接続と、切れた接続には、答えない。

依頼と答えは次のとおりである。

| 依頼 | 答え |
|---|---|
| `{"op":"status"}` | `{"generation", "mode", "engine", "phase", "switching", "ready"}`。使っている世代の指紋（64 桁）、その世代のモード（`block`、`detect`）、その世代のエンジン（`coraza` か `modsecurity`）、検査核の段（`starting`、`ready`、`stopping`、`stopped`、`failed`）、切り替えの途中か、`/readyz` が `ready` と答える状態か |
| `{"op":"switch","expect":"<指紋 64 桁>"}` | ルールの保管場所が今選んでいる世代が `expect` と同じときだけ、SIGUSR1 と同じ切り替えをする。切り替えが終わってから、`{"result", "reason"?, "generation"}` で答える。`generation` は、答えるときに使っている世代である |
| ほかの行 | `{"result":"error","reason":..}`。`reason` は `line too long`、`malformed request`、`unknown op`、`bad expect` |

`switch` の `result` は次のとおりである。

| `result` | `reason` | とき |
|---|---|---|
| `switched` | 無し | 切り替えが終わり、選ばれた世代で動いている |
| `unchanged` | `already serving` | 選ばれた世代を、もう使っている |
| `refused` | `current changed` | ルールの保管場所が選んでいる世代が、`expect` と違う。何もしない |
| `refused` | `store refused` | 保管場所か設定が断った |
| `failed` | `driver did not take the order`、`not switched` | 切り替えを始められなかった、または新しい世代が起動しなかった |
| `busy` | `starting`、`switch under way`、`too many orders`、`stopping` | 検査核の準備ができる前、別の切り替えの途中、依頼が多すぎる、停止の間 |

- 切り替えの結果は、SIGUSR1 と同じに `tukuyomi_rules_switches_total` に数える。数えないのは、`unchanged`、`busy`、`current changed` の答えだけである。`store refused` は `refused` に、`driver did not take the order` と `not switched` は `failed` に数える。
- 切り替えの依頼は、`ready_wait_ms` に 5 秒を足した時間まで答えを待つ。それを過ぎると `busy`（`switch under way`）で答え、切り替えは続く。
- 状態の問いに 2 秒の中に答えられないとき（依頼が多すぎるとき、停止の間を含む）は、`{"result":"error","reason":"no answer"}` を返す。
- 切り替えの依頼は、答えるたびに、記録に `control: switch expect <指紋>: <result> (<reason>), serving <指紋>` の文を1つ出す。`busy` の答えも含む。`busy` で答えた切り替えが後で終わると、終わったときにもう1つ出る。

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
| `kernel.records ≥ slots + wait_queue` | 検査核の記録 |
| `tick ≤ 1 s`、`tick` はほかの検査核のどの時間以下 | 検査核の1歩 |
| 国の一覧（全体の `access` と経路の `access` の `deny_countries`・`allow_countries`）があれば `geo` もある | 国を引くデータベースが要る |
| `rules.store.dir`、`records.dir`、`admin.store.dir`、`admin.control` のあるディレクトリは、互いに同じでなく、どれも他の中にない。`admin.control` 自身は前の3つの中にない | 一方の回しや書き換えが、他方の中身を置き換えないため |
| `admin.listen` は `proxy.listeners` と `status.listen` に重ならない | 同じ port を2つの待ち受けで bind できない |
| 経路の `records` が `required` なら `records` がある | 残す先のファイルが要る |
| `records.ship` があり、`records.keep` か経路の `records` に `required` があれば `records.files ≥ 3` | 送り手の遅れで断る閾値（ファイル `files − 2` 個分）が 0 にならないため |

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
- 世代は、ルールを検査するエンジンも持つ（`rules import --engine`。省けば `coraza`）。この build が持つエンジンは `coraza`（Coraza）と `modsecurity`（ModSecurity v3）である。同じファイルでも、エンジンが違えば manifest が変わり、別の世代（別の指紋）になる。`modsecurity` の世代は、設定の `kernel.engines` に検査プロセスがあるときだけ、取り込み、選択、起動ができる。
- 「検査プロセスが足す決まり」は、Coraza の世代の決まりである。ModSecurity の世代の決まりは、「ModSecurity の世代」にある。
- 保管場所の中身:
  - `generations/<指紋>/`: 世代
  - `current`: 選んだ世代
  - `using/<指紋>`: 使用中の印
  - `staging/`: 取り込みの途中
  - `lock`: 命令の lock
- 命令と管理のプロセスは、一度に1つだけ保管場所を変えられる。途中で止まった命令の残りは、次の命令が片付ける。
- 指紋が捕まえるのは、事故による壊れと取り違えと、動いている proxy が覚えている指紋と中身が違う起動である。同じ利用者のプロセス（検査プロセスも同じ利用者）が保管場所を書き換えることは防がない。起動し直しをまたいだ認証でもない。
- 起動の後に使っている世代のファイルが壊れると、検査プロセスの次の起動し直しが失敗する（ファイルが manifest と違えば exit 11、manifest が替われば指紋の不一致）。そのとき、検査核は決まった失敗として止まり、proxy も止まる。

### 検知だけのモード

- `rules import --detect-only` で作った世代は、規則に当たった要求も通す。要求の記録は class `forwarded`、reason `detected by a rule` で、`rule` に当たった規則の id が入る。
- 遮断の世代と同じルールのファイルで、遮断するかどうかだけが違う。最初はこの形で動かし、誤検知を見て除外を足してから、遮断の世代を取り込み直すとよい。
- 検知だけの世代でも、下の「検査プロセスが足す決まり」の規則は遮断する。
- Coraza の検知だけの世代は、ルールの前と後に印の規則（id 4000010、4000011）を足す。運用者の規則でこれを消したり飛ばしたりすると、その要求は検査できないとして 503 になる。黙って遮断や素通しにはならない。ModSecurity の世代は、印の規則を足さない。

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
- 運用者の規則が本文の処理（`ctl:requestBodyProcessor` など）を替えたり、上の規則を実行時に外したりして、検査が終わったと確かめられない要求は、503 になる。ModSecurity の世代で、ほかに検査できないとする要求は、「ModSecurity の世代」にある。

### 運用者に任せていること

- `ctl:ruleRemoveById`、`SecRuleRemoveById` などで遮断の規則をわざと外すことは、運用者の方針として断らない。
- ただし Coraza の世代では、`SecRuleRemoveByMsg` は、前に `SecMarker` があると Coraza が異常終了し、ルールセットが組めない（exit 11）。CRS は `SecMarker` を多く使うので、CRS と一緒には使えない。
- 取り込みと検査プロセスが捕まえるのは、marker の事故（無い marker や前にある marker への `skipAfter`、名前の打ち違い）だけである。
- Coraza の推奨の設定にある、`REQBODY_ERROR`・`MULTIPART_STRICT_ERROR` を見る規則（200002、200003）を運用者が足すと、先頭で切った本文も遮断する。本文の途中で切ると、解析が失敗することがあるためである。
  - 検査プロセスの規則 4000001 は、切った本文の解析の失敗では遮断しない。
  - CRS 4.23.0 には、これに当たる規則は無い。
- CRS の既定は、`application/<名前>+json` の本文を遮断する。受けるなら、取り込みの前に `crs-setup.conf` で受け付ける型に足す。

### ModSecurity の世代

`rules import --engine modsecurity` で作る世代は、libmodsecurity（ModSecurity v3.0.17）で要求を検査する。検査プロセスは別の実行ファイル（`tukuyomi-inspector-modsecurity`）で、設定の `kernel.engines.modsecurity.inspector` に書く（[実行ファイルの build と配置](../build/binary-deployment.md)）。取り込みの手順、試し、`--detect-only`、検査しない経路、CRS の取り込みは、Coraza の世代と同じである。

検査プロセスが足す決まり（運用者のルールで替えることはできない）:

- 検査の engine は On、本文は読む、JSON の入れ子は 64 段まで。この3つは、検査プロセスが運用者のルールより先に設定する。ModSecurity は最初に設定された値を使うので、ルールに `SecRuleEngine`・`SecRequestBodyAccess`・`SecRequestBodyJsonDepthLimit` を書いても効かない。
- 本文と引数の上限は、ModSecurity には設定せず、検査プロセスが自分で数える。引数の数は、query、form の本文、JSON の本文のそれぞれで 1000 までで、超えると規則 4000002 で遮断する（JSON は、値の数と空でない配列の数を別々に数える）。multipart の本文は数えない。
- 規則の id 4000001〜4000011 は、検査プロセスのために空けてある。運用者の規則が使うと、モードを問わず、その世代のルールセットは組めない。ModSecurity の世代は、検知だけの世代でも印の規則（4000010、4000011）を足さない。
- 規則の id 4000001（本文の解析の失敗）、4000002（引数の数の上限）、4000003（URI の解析の失敗）で遮断する。検知だけの世代でも遮断する。4000001 は、検査する長さで切った本文では遮断しない。

取り込みの試しで、検査プロセスは、ルールのファイルを読んで確かめる。次のものがあると、検査プロセスは起動を断り（exit 11）、取り込みは失敗する。標準エラーの `rules import: the inspector said:` の行（管理 API では `trial` の `detail`）に、理由の文と、ルールのファイルの名前が出る。ModSecurity が読める書き方でも、確かめられる決まった書き方でなければ断るので、害の無いルールを断ることがある。

- ファイル: 行の終わりに CR がある（CRLF の改行）、NUL を含む、最後が改行で終わらない。
- 書き方: 決まった書き方でないもの。たとえば、`phase:'request'` のように phase を引用符で囲んだもの。
- 指示: 使えるのは、`SecRule`、`SecAction`、`SecDefaultAction`、`SecMarker`、`SecRuleRemoveById`・`SecRuleRemoveByTag`・`SecRuleRemoveByMsg`、`SecRuleUpdateTargetById`・`SecRuleUpdateTargetByTag`・`SecRuleUpdateTargetByMsg`、`SecRuleEngine`・`SecRequestBodyAccess`・`SecRequestBodyJsonDepthLimit`（受け付けるが効かない）、`SecComponentSignature`、`SecAuditEngine Off`、応答の本文の指示（`SecResponseBodyAccess`・`SecResponseBodyLimit`・`SecResponseBodyLimitAction`・`SecResponseBodyMimeType`・`SecResponseBodyMimeTypesClear`）である。ほかは断る。たとえば次のものである。
  - `Include`、名前が `SecRemoteRules` で始まる指示、`SecIgnoreRuleCompilationErrors`
  - 名前が `SecAuditLog`・`SecDebugLog`・`SecUpload` で始まる指示、`SecTmpSaveUploadedFiles`、`SecDataDir`、`SecTmpDir`
  - 本文と引数の上限を決める指示（`SecRequestBodyLimit`・`SecRequestBodyNoFilesLimit`・`SecRequestBodyLimitAction`・`SecRequestBodyInMemoryLimit`・`SecArgumentsLimit`）
  - ModSecurity が知らない指示
- アクション: 使えるのは、`accuracy`・`allow`・`auditlog`・`block`・`capture`・`chain`・`ctl`・`deny`・`drop`・`expirevar`・`id`・`initcol`・`log`・`logdata`・`maturity`・`msg`・`multiMatch`・`noauditlog`・`nolog`・`pass`・`phase`・`redirect`・`rev`・`setrsc`・`setsid`・`setuid`・`setvar`・`severity`・`skip`・`skipAfter`・`status`・`t`・`tag`・`ver`・`xmlns` である。`exec` と `setenv` を含め、ほかは断る。
  - `ctl` で使えるのは、`auditEngine`・`auditLogParts`・`forceRequestBodyVariable`・`parseXmlIntoArgs`・`requestBodyProcessor`・`ruleRemoveById`・`ruleRemoveByTag`・`ruleRemoveTargetById`・`ruleRemoveTargetByTag` である。`ruleEngine`・`requestBodyAccess`・`requestBodyLimit` を含め、ほかは断る。
  - 要求を止めるアクション（`deny`・`drop`・`redirect`・`block`）と `nolog`・`noauditlog` を、同じ規則に書くと断る。どの規則が止めたかが分からなくなるためである。`SecDefaultAction` に `nolog`・`noauditlog` や `skipAfter` を書くことも断る。
  - `skipAfter` が指す `SecMarker` が、その後ろ（同じファイルか、後に読み込むファイル）に無いときは断る。
- 演算子: `@inspectFile`・`@rbl`・`@validateDTD`・`@validateSchema`・`@fuzzyHash`・`@geoLookup`・`@gsbLookup`・`@rsub`・`@validateHash` は断る。ファイルを読む演算子（`@pmFromFile`・`@pmf`・`@ipMatchFromFile`・`@ipMatchF`）は、ルールセットの中にあるファイルを、英数字・`.`・`_`・`-` だけの path で書いたときだけ使える。path は、ルールセットの中の path（`rules/<名前>` など）か、そのルールのファイルのあるディレクトリからの path である。
- 変数と長さ: 変数 `ENV` は断る。1つの変数の並びは 256 個まで、`chain` でつなぐ規則は 64 個までである。
- 文字の並び: 上の読み取りとは別に、規則の文字から空白と引用符を除き、大小を区別せずに、`ctl:ruleEngine`・`ctl:requestBodyAccess`・`ctl:requestBodyLimit`・`exec:`・`setenv:`・`@inspectFile`・`@rbl`・`@validateDTD`・`@validateSchema`・`@fuzzyHash` を探す。`msg` の中にあっても断る。
- 読み取りとの食い違い: 検査プロセスは、ModSecurity が組んだ規則を、読み取った内容と照らす。食い違うルールは断る。

`ctl:ruleRemoveById` や `SecRuleRemoveById` などで遮断の規則をわざと外すことは、Coraza の世代と同じく、運用者の方針として断らない。

Coraza の世代と違うところは次のとおりである。同じルールと要求でも、結果が違うことがある。

1. 検知だけの世代では、運用者の規則が要求を止める判定をした後、ModSecurity は、その phase の残りの規則だけを飛ばす。そのため、記録の `rules`（当たった規則）と `score` が、Coraza の世代より短く、小さくなることがある。
2. 検査する長さで切った本文の解析が失敗したとき、ModSecurity は、解析が止まった所から後の本文を、規則に渡さない。`Content-Type` の parameter のせいで解析が始まらないとき（たとえば `Boundary=` を大文字で書いたとき）は、本文を何も渡さない。切っていない本文は、解析が失敗すれば 4000001 で遮断する。
3. 入れ子が 62〜64 段の JSON の本文は、ModSecurity では止まらず、Coraza では止まる。65 段からは、どちらも止まる（決まりの上限は 64 段である）。
4. `multiMatch` を付けた、要求を止める規則と、`msg` の無い、要求を止める `SecAction` は、ModSecurity では、それが止めた要求がすべて検査できない扱いになる。503 になり、proxy は通さない。
5. `ARGS:/re/` のように、変数の選択に書いた正規表現が失敗しても、ModSecurity は失敗の印を残さない。そのため、要求は検査できない扱いにならない。
6. `@verifyCC`・`@verifyCPF`・`@verifySSN` の失敗も、5 と同じで、失敗の印を残さない（CRS は使わない）。`@rx` の失敗は、検査できない扱いにする。
7. JSON の本文の値は、`ARGS` にだけ入り、`ARGS_POST` には入らない（CRS は `ARGS` を読む）。
8. `REQUEST_URI` は、`%XX` をほどいた URL である（ほどく前の形は `REQUEST_URI_RAW`）。そのため、`REQUEST_URI` を見る規則は、path の中にある `%XX` で符号化した攻撃に、Coraza の世代では当たらなくても、ModSecurity の世代では当たることがある。
9. 終わりの境界が無い multipart の本文は、ModSecurity では本文の解析の失敗として、4000001 で遮断する（切った本文を除く）。Coraza は通す。

次の要求は、ModSecurity の世代では検査できない扱いになり、503 になる。Coraza の世代ではそうならない。

- 規則の正規表現が失敗したか、match の回数の上限に当たった要求（5 と 6 のものを除く）。
- 境界が空の multipart の本文（`boundary=` や `boundary=""`）。ModSecurity は、この本文を何も解析せず、そのことも知らせないためである。
- `Content-Type` を2つ以上持つ空でない本文。ただし、proxy が先に 415 で断る（「本文の型」）ので、検査プロセスまでは届かない。

本文の処理を替えるなどで、検査が終わったと確かめられない要求が 503 になることは、Coraza の世代と同じである（「検査プロセスが足す決まり」）。

### 検査しない経路

`rules import --routes <file>` のファイルは、次の形の JSON の配列である。

```json
[
  {"host": "app.example.com", "path": "/api/uploads", "action": "bypass"}
]
```

- `host` は省ける。ほかの鍵は取らない。`action` は `bypass` だけである。
- 経路に当たる要求は検査せず、上流へ転送する。
  - proxy が自分でする確かめ（head、本文の大きさの上限）は、その前にする。本文の型は確かめない（下の「本文の型」）。
  - 上流は、検査しない経路ではなく、`forward` の経路か既定の組で選ぶ。そこで 404・403・421 になる要求と、全体の `access` と `rate_limit` で断られる要求（403・429）は、検査しない経路に当たっても答えは変わらない。
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
8. `Content-Encoding` は無いか、`gzip` ちょうどの1行。違えば 415。`Content-Length` が 0 より大きい要求は、`Content-Type` を2つ以上持たない。違えば 415。

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
  - 本文を読み終えないまま答えた要求（本文を持ったまま 403・404・415・421・429 で断った要求など）
- 前の要求の後の、次の head の前の空の行は、2つまで捨てる。

### 本文の型

本文の型は、head の確かめの後、経路を引いてから確かめる（下の「要求の確かめの順」の 9）。検査する経路かどうかで、決まりが違う。

- 検査する経路では、空でない本文は `Content-Type` をちょうど1つ持ち、それは次のどれかである（`;` より前を、大小を区別せずに比べる）。違えば 415。
  - `application/x-www-form-urlencoded`
  - `multipart/form-data`
  - `application/json`
  - `application/<名前>+json`（名前は 1〜122 バイトの英数字・`.`・`-`）
- 検査しない経路では、型を確かめない。`Content-Type` の無い本文も、ほかの型の本文も、そのまま流す。ただし、`Content-Type` を2つ以上持つ空でない本文は、どの経路でも 415 である。読む側によって、どの行を型と読むかが違うためである。
- `Content-Length` のある本文は、本文を読む前に確かめる。chunked の本文は、空かどうかが読むまで分からないので、読んだ後に確かめる（検査する長さより長い本文は、先頭のその長さを読んだ後）。空の本文は、型を問わない。

### 転送の前に外すもの

接続に属する field（`Connection` とそれが挙げるもの、`Keep-Alive`、`TE`、`Transfer-Encoding`、`Upgrade`、`Expect` など）と `Proxy-Authorization` は外す。その後に上の「client の address」の field を付けるので、client が名前を挙げて外させることはできない。上流の応答の trailer は、client へ送らない。

### 答え

| 状態 | とき |
|---|---|
| 規則の状態コード | 規則が遮断した（200〜599 の外なら 500） |
| 400、408、413、414、415、417、431 | head か本文が断られた |
| 403 | 全体の `access` か、経路の `access` に断られた |
| 404 | 当たる経路も既定の組も無い。redirect しない `Host` |
| 421 | `Host` が TLS の証明書に入っていない |
| 429 | 全体の `rate_limit` に断られた。`Retry-After` を持つ |
| 502 | 上流につながらない、上流の応答の誤り、上流の時間切れ、組のどの server も使えない |
| 503 | 検査できない（検査プロセスが使えない、検査の待ちが満ちた・時間切れ）、予算が尽きた、要求の時間が尽きた、proxy 自身が上流への接続を作れない |
| 500 | proxy の中の不整合（記録に `internal fault` の行も出る） |

proxy が自分で作る答えは、本文が空で `Content-Length: 0` を持つ（204・304 は `Content-Length` を持たない。429 は `Retry-After` も持つ）。ACME の challenge の 200 は、そのファイルを本文に持つ。

proxy が返すすべての応答（上流の応答、遮断、head の拒否、redirect も含む）は、要求の番号を `X-Request-ID` に1つ持つ。上流の応答に同じ名前の field があれば置き換える。番号は、その要求の記録の `id` と同じなので、断られた人が番号を伝えれば記録を引ける。

## 要求の前の方針

設定ファイルの最上位の `access`、`rate_limit`、`geo` は、経路を探す前に要求を断る方針を決める。3つとも省いてよく、省いた方針は無い。値は起動のときと SIGHUP の読み直しで読む（上の「SIGHUP（設定の読み直し）」）。

### 要求の確かめの順

要求は、次の順に確かめる。最初に断った確かめが、その要求の答えになる。

| 順 | 確かめ | 答え | 記録の `reason` |
|---|---|---|---|
| 1 | head の確かめ（上の「head の確かめ」） | 400、414、431 など | head ごとに決まった語句 |
| 2 | ACME の challenge（`acme` を持つ証明書があるときの、普通の待ち受けと redirect の待ち受け） | challenge のファイルを本文にした 200、または 404 | `acme challenge` |
| 3 | 全体の `access` | 403 | `denied by access` |
| 4 | `rate_limit` | 429（`Retry-After: 1`） | `too many requests` |
| 5 | TLS の接続の `Host` が、handshake で使った証明書の host に入っているか | 421 | `host not covered by the certificate` |
| 6 | 経路（無ければ既定の組） | 404 | `no route matches` |
| 7 | 経路の `access` | 403 | `denied by route access` |
| 8 | `Content-Length` と経路の `max_body` | 413 | `body over the limit of the route` |
| 9 | 本文の型（上の「本文の型」） | 415 | `body type not supported` |

9 は、`Content-Length` のある本文では本文を読む前に、chunked の本文では読んだ後に確かめる。その後に、検査し、転送する。redirect の待ち受けは、4 の後に redirect か 404 で答え、本文を読まない。

- 3 と 4 は、検査しない経路に当たる要求にも、redirect の待ち受けにも、同じに効く。検査プロセスが止まっていても、断る答えは変わらない。監視の待ち受けには掛からない。
- 断るのは、head を読んだ後の要求である。接続を受けることと TLS の handshake は、断る client にも行い、その間は `max_conns` の枠を使う。
- 1 で断った要求と、2 で答えた challenge は、`access` にも `rate_limit` にも数えない。
- 3〜8 で断った要求は、本文を読む前に答える。HTTP/1.1 の接続では、本文を持つ要求を断ると、答えの後に接続を閉じる。本文の無い要求なら、接続は続く。HTTP/2 では、その stream だけが終わる。
- 断った要求は、要求の記録に出る（`class` は `rejected`）。3 と 4 で断った要求は、`/metrics` の `tukuyomi_policy_refusals_total` にも数える。

### client と国

- 全体の `access`、`rate_limit`、経路の `access` は、どれも上の「client の address」で決めた address を見る。国も、その address から引く。
- `trusted_proxies` に入る相手でも、`X-Forwarded-For` の行を付けなければ、その相手が client である。`trusted_proxies` に入れない相手も同じである。前に置いた中継が client の address を伝えないと、その後ろの client は区別されず、国は中継の address で決まり、流量の制限は1つの client として数える。

### `access`

```text
{"deny_cidrs"?, "allow_cidrs"?, "deny_countries"?, "allow_countries"?}
```

経路の `access` と同じ形で、同じ決まりで断る。全体の `access` は、head の確かめに通った要求（ACME の challenge を除く）に効く。

| 鍵 | 中身 |
|---|---|
| `deny_cidrs`、`allow_cidrs` | network の一覧。256 個まで。書き方は `trusted_proxies` と同じ |
| `deny_countries`、`allow_countries` | 国の一覧。256 個まで。国は、ISO 3166-1 alpha-2 の英大文字2字（`JP` など）か、`UNKNOWN`。小文字や、2字でないものは断る。2字が ISO 3166 の一覧にあるかは見ない |

- 4つとも省いてよい。省いた鍵は空の一覧で、4つとも空なら、誰も断らない。
- 次の client を断る。
  - `deny_cidrs` に入る
  - 国が `deny_countries` に入る
  - `allow_cidrs` が空でなく、そこに入らない
  - `allow_countries` が空でなく、国がそこに入らない
- `allow_cidrs` と `allow_countries` を両方書けば、両方に入る client だけが通る。network を国に関係なく通す書き方は無い。
- 断るときの答えは、本文が空の 403 で、`Retry-After` は付けない。
- 国の一覧を書くには、`geo` が要る。

例:

```json
"access": {
  "deny_cidrs": ["198.51.100.0/24"],
  "allow_countries": ["JP", "UNKNOWN"]
}
```

この例は、`198.51.100.0/24` の client と、`JP` と `UNKNOWN` 以外の国の client を断る。

### 流量の制限（`rate_limit`）

```text
{"rate", "burst", "keys", "exempt_cidrs"?}
```

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `rate` | 1〜100000 | 1つの client が続けてよい、1秒あたりの要求の数 |
| `burst` | 0〜100000 | 休んだ後に、間を空けずに通す要求の余裕。続けて `burst + 1` 件まで通り、次の1件から断る |
| `keys` | 1024〜1048576 | 数える client の数の上限（下の「表の大きさ」） |
| `exempt_cidrs` | 0〜256 個の network | 数えない client。書き方は `trusted_proxies` と同じ。省けば空 |

- 数え方:
  - 要求を1件ずつ数える（接続ではなく、HTTP/2 では stream ごと）。
  - 休んでいた client は、間を空けずに `burst + 1` 件まで通る。次の1件は断る。その後は、待った時間が 1/`rate` 秒になるごとに1件通る。
  - 1/`rate` 秒は、ナノ秒に切り上げる。そのため、client が `rate` を超えて通ることは無い。
  - 断られた要求は、client の count を変えない。
  - 初めて来る client の要求は、必ず通る。
- client の単位:
  - IPv4 は address ごと。IPv6 は上位 64 bit（/64）ごとである。同じ /64 の中で address を変えても、count は増えない。
  - IPv4-mapped IPv6 address（`::ffff:192.0.2.1`）は、IPv4 として数える。port は見ない。
  - 信じる相手が `X-Forwarded-For` を付けないと、その相手が client になる（上の「client と国」）。そのとき `rate` と `burst` は、その相手を通るすべての client の合計に対する値になる。
- 断るときの答え: 本文が空の 429 で、`Retry-After` を付ける。値は、次の1件が通るまでの時間を秒に切り上げたもので、最小は 1 である。`rate` は 1 以上で、次の1件までは 1 秒を超えないので、いつも `1` になる。
- `exempt_cidrs` に入る client は、数えない。ただし、全体の `access` には先に断られる。監視の program などを入れる。
- 表の大きさ:
  - `keys` は、同時に数える client の数の上限である。1 client は約 100 バイトで、`keys` が 1048576 なら約 100 MB になる。
  - 要求のたびに、表の古い方から最大 4 client を調べ、count が残っていないもの（待ち時間が過ぎたもの）を外す。count が残っていない client は新しい client と同じ扱いなので、外しても結果は変わらない。
  - 表が満ちていて、いちばん古い client の count がまだ残っているときは、その client を外して、新しい client の場所を作る。外された client は、次に来たときに新しい client として始まり、また `burst + 1` 件まで通る。つまり、その client の制限が一度ゆるむ。新しい client が、場所が無いために断られることは無い。
  - 外した数は `tukuyomi_rate_limit_evicted_total` に、数えている client の数は `tukuyomi_rate_limit_keys` に出る。多くの address から要求が来ると、実際の client の count が外れてゆるむ。`keys` は、同時に来る client の数より十分大きくする。
  - 表は proxy のメモリの中にあり、起動し直すと空になる。SIGHUP の読み直しでは、`keys`・`rate`・`burst` がどれも同じなら続き、どれかが違えば空から数える。
- 断った要求は、`tukuyomi_policy_refusals_total` の `rate_limit` に数える。記録の `reason` は `too many requests` である。

### 国のデータベース（`geo`）

```text
{"country_db", "sha256"}
```

2つとも書く。国の一覧が、client の address の国を引くのに使う。

| 鍵 | 中身 |
|---|---|
| `country_db` | 国のデータベースのファイルの絶対の path |
| `sha256` | そのファイルの SHA-256。64 桁の小文字の16進数 |

例（`sha256` の値は例である。ファイルに `sha256sum` を流した値を書く）:

```json
"geo": {
  "country_db": "/etc/tukuyomi-core/country.mmdb",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

- ファイルは、MaxMind DB の形式（版 2）である。proxy はデータベースを同梱せず、取得もしない。運用者が用意して置く。データベースの使用許諾は、提供元の条件に従って運用者が守る。
- 国の決め方:
  - address の記録の `country.iso_code` で決める。無ければ `registered_country.iso_code` で決める。どちらも無いとき、英大文字2字でないときは `UNKNOWN` である。
  - loopback、private（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`fc00::/7`）、link-local、未指定の address は、データベースを引かずに `UNKNOWN` にする。データベースが知らない address も `UNKNOWN` である。
  - IPv4-mapped IPv6 address は、IPv4 として引く。
  - IPv4 の address だけのデータベース（metadata の `ip_version` が 4）では、IPv6 の client はすべて `UNKNOWN` になる。
- `UNKNOWN` に気を付ける。`allow_countries` に `UNKNOWN` を書かないと、private な address の client（同じ network の監視など）も、IPv4 だけのデータベースでの IPv6 の client も、すべて断られる。`deny_countries` に `UNKNOWN` を書けば、それらを断る。
- 読むとき:
  - 設定ファイルを読む命令は、すべて `geo` のファイルを読んで確かめる。proxy の起動、`config check`、`rules` の各命令、`acme renew`、`admin` の各命令である。どれも、サービスの利用者がファイルを読めること。
  - 次を確かめる。
    - 普通のファイルで、link でなく、256 MiB までである。全体を読む。
    - SHA-256 が `sha256` と合う。
    - MaxMind DB として読める。metadata の版が 2、record の大きさが 24・28・32 bit、`ip_version` が 4 か 6、検索の木が壊れていない。木が指す記録をすべて確かめ、読めない記録があれば断る。
    - 国のデータベースである。`database_type` に `Country` を含むか、ISO コードを持つ記録が1つ以上ある。
  - 国の一覧があれば、proxy と管理のプロセスは、確かめたファイルの全体をメモリに持つ。どの命令も読むたびに全体を確かめるので、大きいファイルでは時間とメモリを使う。
  - 国の一覧がどこにも無ければ、読んで確かめた後で使わずに捨てる。国の一覧があって `geo` が無い設定は断る（`access has a list of countries while geo is left out`）。
  - proxy は、起動のときと SIGHUP の読み直しのたびに読む。その間は読み直さない。読み直すたびに全体を確かめるので、大きいファイルでは読み直しのたびに時間とメモリを使う。
- 替える手順: 新しいファイルを別の名前で置き、`country_db` と `sha256` を1回の置き換えで書き換え、`config check` で確かめてから、proxy に読み直させる（SIGHUP、`systemctl reload`）。管理のプロセスは、起動のときに設定とデータベースを確かめるので、その後に起動し直す。同じ名前のファイルだけを替えて `sha256` が合わないと、その間に流す命令と、起動し直したプロセスは設定を断り、proxy の読み直しも断られる。

## 記録

記録は、標準エラーに1行1件の JSON で出る（systemd では journal）。設定に `records` があれば、同じ行をファイルにも書く（下の「記録のファイル」）。さらに `records.ship` があれば、別のプロセス（記録の送り手）がファイルの行を PostgreSQL か MySQL へ送る（下の「記録の送り手」）。記録を残せないときに要求を通すか断るかは、経路ごとに選べる（下の「記録の残し方」）。短い命令（`config check`・`rules`・`acme`・`admin bootstrap`・`admin reset`）の出力は、人が読む文の行のままである。

どの記録も、次の2つの項目で始まる。値の無い項目は書かない（`null` にしない）。

| 項目 | 中身 |
|---|---|
| `ts` | 記録した時刻。UTC の RFC 3339 で ms まで（例: `2026-10-27T03:53:27.123Z`） |
| `type` | `request`、`connection`、`tunnel`、`line`、`audit`、`dropped` のどれか |

### 要求の記録（`request`）

client へ答えを書いた要求ごとに1件出る。head の拒否、redirect、ACME の challenge の答えも含む。応答を送り終えたとき（または切れたとき）に書くので、長い応答の記録は応答の終わりに出る。

```text
{"ts":"2026-10-27T03:53:27.123Z","type":"request","id":"0186af5443bddbd9-1","conn":1,"listener":0,"proto":"h1","tls":false,"client":"192.0.2.10","method":"GET","host":"example.com","path":"/q","class":"blocked","status":403,"reason":"blocked by a rule","ms":3,"mode":"block","engine":"coraza","generation":"2f3bda9b9ca7db60","rule":949110,"rules":[941100,941110],"severity":2,"score":10,"sent":0}
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
| `reason` | 決まった英語の語句（例: `malformed request head`、`body over the limit`、`inspection queue full`、`upstream connection failed`、`denied by access`、`too many requests`） |
| `ms` | かかった時間（ミリ秒） |
| `upstream`、`server` | 上流の組の名前と、最後に試した server の address（試していなければ `server` は無い） |
| `mode`、`engine`、`generation` | 判定したルールの世代のモード（`block` か `detect`）と、そのエンジン（`coraza` か `modsecurity`）と、世代の指紋の先頭16桁。検査しなかった要求には無い |
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
| `rejected` | head か本文が断られた。全体の `access` の 403 と `rate_limit` の 429、経路で断った 403・404・421、redirect の待ち受けの 404 も含む |
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
| `audit` | （[管理リファレンス](admin-reference.md) に書く） | 管理のプロセスの監査の記録。管理のプロセスだけが出す。proxy の記録のファイルには入らない |
| `dropped` | `count` | 書けずに捨てた記録の数（前の `dropped` の記録の後に捨てた分） |

`line` の文は次のとおり。

| 文 | とき |
|---|---|
| `start: ...` | 起動の各段（`start: rules generation <指紋>`、`start: rules engine <名前>`、`start: rules mode <block か detect>`、`start: rules generation refused: <理由>`、`start: the kernel is ready`、`start: listening`、`start: record file refused: <理由>`、`start: control socket refused: <理由>` など） |
| `reload: ...` | SIGHUP・SIGUSR1・SIGUSR2 を受けたこと、設定の読み直しの各段と結果（`reload: configuration replaced <SHA-256>`、`reload: configuration refused: <理由>`、`reload: rate limit table started anew` など。上の「SIGHUP（設定の読み直し）」）、切り替え（SIGUSR1 と制御 socket。始めるときに `reload: rules engine <名前>`、断られたときに `reload: rules store refused: <理由>`）と証明書の入れ替えの結果 |
| `control: switch ...` | 制御 socket の切り替えの依頼への答え（上の「制御 socket」） |
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
- 記録のファイル（`records`）に書けないときは、その行がファイルに入らないだけで、標準エラーには出る。数は `tukuyomi_record_file_errors_total` で見られる（下の「記録のファイル」）。
- ここまでは、記録を残せなくても要求を通す既定の扱い（`best_effort`）である。記録を残せないときに要求を断る経路も選べる（下の「記録の残し方」）。

### 記録のファイル（`records`）

設定に `records` を書くと、標準エラーに出す記録と同じ行を、ディレクトリのファイルにも書く。省けば、記録は標準エラーだけに出る。管理のプロセスは、このファイルを読んで記録を引く。

```text
{"dir", "file_bytes", "files", "keep"?, "sync_ms"?, "ship"?}
```

`dir`、`file_bytes`、`files` は必ず書く。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `dir` | 絶対の path、3840 バイトまで | ファイルを置くディレクトリ。proxy は作らないので、先に作る。本物のディレクトリで、持ち主が proxy の利用者、group と other の権限が無いこと |
| `file_bytes` | 1 MiB〜1 GiB | 1つのファイルの大きさ。使用中のファイルがこれを超える行は、次のファイルから書く |
| `files` | 2〜64 | 残すファイルの数（使用中のものを含む）。`ship` があり、`keep` か経路の `records` に `required` があるときは 3 以上 |
| `keep` | `best_effort`、`required` | 自分の `records` を持たない経路と既定の組の、記録の残し方（下の「記録の残し方」）。省けば `best_effort` |
| `sync_ms` | 1〜60000 | 書いた行をディスクへ同期する（fsync）間隔の上限。省けば同期せず、OS に任せる（下の「入る行」） |
| `ship` | `{"db_driver", "db_dsn_file", "batch", "interval_ms", "retention_days"}` | 記録の送り手の設定（下の「記録の送り手」）。proxy は送り手を動かさず、送り手の遅れを見るだけである |

- 使うディスクは、多くても `file_bytes × files` である。1件は 4 KiB 未満なので、1つのファイルが `file_bytes` を超えることは無い。
- 名前と回し:
  - 使用中のファイルは `records.log` である。古いファイルは、`records.1.log`、`records.2.log` と続き、`records.<files - 1>.log` が最も古い。
  - 行を足すと `file_bytes` を超えるときは、先に次のファイルへ回す。`records.log` を `records.rotating` に改名し、`records.N.log` を `records.N+1.log` に改名し（N は `files - 2` から 1 まで）、`records.rotating` を `records.1.log` にして、新しい `records.log` を開く。いちばん古いファイルは、置き換えられて無くなる。
  - 改名の途中で失敗したら、`records.rotating` を戻す。回しの途中で止まって `records.rotating` が残ったときは、次の回しで置き換わる。
  - どのファイルも、行の途中では切れない。
  - `files` を小さくして起動し直すと、`records.<files>.log` 以降の古いファイルは、持ち主が proxy の利用者の普通のファイルなら、起動のときと回すたびに消す（`records.63.log` まで）。
- 開き方:
  - `records.log` は、無ければ 0600 で作り、追記で開く。link、FIFO、ディレクトリ、別の利用者のファイルは断る。group か other の権限があるファイルは、書く前に 0600 にする。
  - 最後の行が改行で終わっていないファイル（書いている途中で落ちたときなど）には、先に改行を書く。次の行が途中の行とつながらないようにするためである。
  - 起動のときに開けなければ、`start: record file refused: <理由>` の文を出し、検査プロセスを起動せずに止まる（exit 1）。
- 入る行:
  - 標準エラーに出す行を、すべて同じ形で、1行ごとに1回の write で書く。標準エラーの後に書く。
  - ファイルを開く前に出た行（設定の確かめからルールの世代までの `start:` の文）は入らない。
  - `sync_ms` が無ければ、ディスクへの同期（fsync）はしない。電源が落ちると、OS がまだディスクに書いていない行は失われる。
  - `sync_ms` があれば、同期していない行のうち最も古いものが `sync_ms` だけ待ったときに、ファイルを同期する。後に行が来なくても同期する。回す前にも、改名するファイルを同期する。電源が落ちて失うのは、最後の同期より後の行である。同期の失敗は、書き込みの失敗と同じに扱う（下の「書けないとき」）。
- ファイルが外から動かされたとき: `records.log` の path は、1秒に1回まで確かめる（回す前にも確かめる）。path にファイルが無いとき、または開いているのと別のファイルのときは、開いているファイルを閉じる。その行はファイルに入らず、`tukuyomi_record_file_errors_total` に数える。次の行が `records.log` を新しく作って開く。
- 書けないとき:
  - 書き込み、open、改名が失敗すると、その行はファイルに入らず、ファイルを閉じて、`tukuyomi_record_file_errors_total` に数える。標準エラーには出る。要求の処理は待たない。
  - 閉じている間に来た行も、ファイルに入らず、同じに数える。失敗から1秒以上後に来た最初の行が、開き直す。ディスクが壊れたままでも、試すのは1秒に1回までである。
  - 途中まで書けた行は、書く前の大きさまで切り戻す。
  - 同期（`sync_ms`）が失敗したときも、ファイルを閉じて、同じ数に数える。
  - ディレクトリは、開き直す前と回す前に、起動のときと同じに確かめる。
- 送り手（`ship`）があれば、送り手が同じディレクトリに `ship.state`（送った位置）を置き、書き換えの間だけ `ship.state.new` を置く。proxy は `ship.state` を読むだけで、どちらも消さない。

### 記録の残し方（`keep` と経路の `records`）

経路ごとに、記録を残せないときの扱いと、残す記録を選べる。経路の `records` を書かなければ、全体の `records.keep` に従う。`records.keep` を書かなければ `best_effort` である。

| 値 | 記録を残せないとき | 書く記録 |
|---|---|---|
| `best_effort` | 記録を捨てて数え、要求は通す（上の「書けないとき」） | すべて |
| `required` | その経路の新しい要求を 503 で断る | すべて |
| `security` | `best_effort` と同じ | 規則が判定した要求（遮断と、検知だけのモードで当たったもの）、検査できなかった要求（検査プロセスに頼めなかった 503 を含む）、受け付けた後に答えの前に切れた要求（下）だけ。普通に通した要求の記録は書かない |

`required` の経路は、次の3つがそろうときだけ要求を受け付ける。

1. 記録のファイルへの最後の書き込み（と同期）が通っていて、記録を書く thread が動いている。
2. 送り手（`ship`）があるなら、送り手がまだ送っていないバイト数が、ファイル `files − 2` 個分（`file_bytes × (files − 2)`）より少ない。送っていない記録が回しで消える前に断るためである。送り手の遅れが分からないとき（`ship.state` が読めない、形が違う、90 秒より前に書かれた、記録のファイルのどれでもないファイルを指す）も断る。`files` が 3 より少ないときは、遅れでは断らない。
3. 記録の待ち行列に席が空いている。席は、待ち行列の 1024 のうち 512 までである。`required` の経路の要求を同時に 512 より多く受け付けると、それを超えた要求は 503 になる。

- 断った要求には 503 で答え、`tukuyomi_records_refused_total` に数える。断った要求の記録（reason は `records cannot be kept`）は「できる限り」で書く。ただし、送り手の遅れで断ったときは、その記録は書かずに数えるだけにする。送っていない記録が回しで消えるまでの余白を、断った記録で使わないためである。
- 受け付けた要求は、本文を読む前に席を取り、記録を待ち行列に入れるまで持つ。その要求の記録は、待ち行列が満ちても捨てない。
- 受け付けた後に書き込みが失敗したら、数えて、それより後の `required` の要求を断る。書き込みは失敗の1秒後から試し直し、通れば受け付けに戻る。
- 送り手の遅れは、proxy が `ship.state` を1秒に1回読み、その位置より後のバイト数（指すファイルの残りと、それより新しいファイル）に、読んだ後に書いたバイトを足して見積もる。閾値より少なくなれば、受け付けに戻る。
- 記録は応答を送り終えた後に書く。そのため `required` は、client に答える前に記録があることは約束しない。次の2つの記録は抜けることがある。
  - 書き込みが失敗し始めたときに、受け付け済みだった要求の記録
  - 電源が落ちたときの、最後の同期より後の記録（`sync_ms` が無ければ OS に任せる）
- `required` を使うには `records` が要る。`ship` と `required` を両方使うときは、`files` を 3 以上にする（上の「値どうしの関係」）。

経路を決める前、または本文を読まずに答える次の要求は、経路の値と `records.keep` にかかわらず、記録を「できる限り」で書く。どれも上流へ何も送らない答えである。

- 全体の `access` の 403 と `rate_limit` の 429
- TLS の接続で、証明書が `Host` を持たない要求の 421
- どの経路にも当たらず、既定の組も無い要求の 404
- head の確かめで断った要求、https への redirect、ACME の challenge の答え
- 経路の `access` の 403 と、経路の `max_body` の 413
- 接続の記録（`connection`）と tunnel の記録（`tunnel`）

受け付けた後に答えの前に切れた要求（HTTP/1.1 で client が接続を閉じた、HTTP/2 で stream を reset した）と、本文の途中で client が去った要求は、どの経路でも記録を書く。上流に届いたかもしれないためである。

### 記録を読める人

記録には、client の address と path が入る。journal を読める利用者（root と、Ubuntu では `adm`・`systemd-journal` の組の利用者）は、それを読める。組に入れる人を絞る。保存の期間と容量は journald の設定で決める（[実行ファイルの build と配置](../build/binary-deployment.md) の「systemd」）。記録のファイル（`records`）は 0600 で、0700 のディレクトリにある。読めるのは、proxy の利用者と root である。管理のプロセスは、同じ利用者としてこのファイルを読み、管理の利用者に見せる（[管理リファレンス](admin-reference.md)）。送り手を使うときは、DB の表にも同じ記録が入る。表を読める DB の利用者も絞る。

## 記録の送り手

記録の送り手（`tukuyomi-records-ship`）は、proxy の記録のファイルを読み、行を PostgreSQL か MySQL の表へ順に入れる、別のプロセスである。proxy は送り手を動かさず、DB にもつながない。DB につなぐ部品と DB のパスワードは、送り手の実行ファイルとプロセスにだけある。build と unit は [実行ファイルの build と配置](../build/binary-deployment.md) にある。試したのは PostgreSQL 16・18 と MySQL 8.0 である。

### 送り手の起動

```text
tukuyomi-records-ship <config>
```

- `<config>` は proxy と同じ設定ファイルで、絶対の path で書く。proxy と同じ確かめで読み、`records.ship` が要る。無ければ `records-ship: configuration refused: there is no records.ship object` の行を出して終わる。
- proxy と同じ利用者で動かす。root では動かない（user id の4つのどれかが 0 なら断る）。記録のディレクトリが、この利用者の本物のディレクトリで、group と other の権限が無いことも確かめる。`ship.state` をそこに書くためである。
- 記録のディレクトリのファイルシステムは、ファイルの生まれた時刻（`statx` の btime）を返すこと。送り手は、記録のファイルを inode と生まれた時刻の組で見分ける（ファイルシステムは、消したファイルの inode の番号をすぐに使い回す）。返さないファイルシステムでは、送り手は起動を断り、proxy は遅れを「分からない」として `required` の要求を断る。
- 起動の順は、設定、記録のディレクトリ、接続の文字列のファイル（下）、合図の受け付け、`NOTIFY_SOCKET` があれば `READY=1` である。DB には最初の回でつなぐ。届かない DB は、動いている間に止まったときと同じに、待って試し直す。

| exit | とき |
|---|---|
| 0 | SIGTERM、SIGINT、SIGHUP で止まった。動いている1回分を終えてから止まり、`STOPPING=1` を送る |
| 1 | 接続の文字列が読めない、または断られた。DB がログインを断った（下の「送り手の誤り」）。そのほかの失敗 |
| 2 | 引数の誤り、設定が断られた |

- 止める合図は、DB を呼んでいる間は待たされる。1回の呼び出しは 30 秒まで（つなぐのは 10 秒まで）で、1回分の中に呼び出しが数回あるので、止まるまでに長いと1〜2分かかる。SIGKILL で止めても、次の起動は DB に残った位置から続ける。行と位置は、同じ transaction で DB に入るためである。

### `records.ship`

```text
{"db_driver", "db_dsn_file", "batch", "interval_ms", "retention_days"}
```

5つとも書く。

| 鍵 | 範囲 | 意味 |
|---|---|---|
| `db_driver` | `pgsql`、`mysql` | 送る DB の種類 |
| `db_dsn_file` | 絶対の path、3840 バイトまで | 接続の文字列のファイル（下）。proxy はこのファイルを開かない |
| `batch` | 1〜10000 | 1つの transaction に入れる行の数の上限 |
| `interval_ms` | 100〜60000 | 送る行が無かったときに、次の回まで待つ時間。失敗の後に待つ時間の始まりでもある |
| `retention_days` | 0〜3650 | DB に残す日数。0 なら消さない |

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

### 接続の文字列（`db_dsn_file`）

接続の文字列はパスワードを含むので、設定ファイルには書かず、別のファイルに置く。

- 普通のファイルで、持ち主が送り手の利用者、group と other の権限が無いこと（0600）。16 KiB まで、UTF-8 の文字である。断るときの文には、ファイルの名前も中身も入れない。
- PostgreSQL: `host=db.example.com port=5432 user=tukuyomi_ship password=<パスワード> dbname=records` の形か、`postgresql://` の URL（`tokio-postgres` の形）。表は、接続の `search_path` の最初の schema に作る。
  - 同じホストの PostgreSQL には、unix socket と peer 認証（OS の利用者の名前と同じ名前の role）でつなげば、パスワードが要らない。例: `host=/var/run/postgresql user=tukuyomi dbname=tukuyomi_records sslmode=disable`。
- MySQL: `mysql://<利用者>:<パスワード>@<host>:<port>/<DB の名前>` の URL（`mysql_async` 0.37 の形）。DB の名前が要り、表はその DB に作る。URL の中で記号を使う値は、percent-encoding で書く。

TLS は次のとおりである。

| | PostgreSQL | MySQL |
|---|---|---|
| 書かないとき | TLS。証明書と名前を確かめる | TLS。証明書と名前を確かめる |
| 受け付ける指定 | `sslmode=require`、`verify-ca`、`verify-full`。どれも証明書と名前を確かめる（`require` でも確かめる） | `require_ssl=true`、`verify_ca=true`、`verify_identity=true` |
| 断る指定 | `sslmode=prefer`、`allow`（相手が TLS を断ると平文に落ちる） | `verify_ca=false`、`verify_identity=false`（確かめを外す） |
| 平文 | `sslmode=disable` と書いたときだけ（loopback や unix socket 向け） | `require_ssl=false` と書いたときだけ。unix socket（`socket`）は、このときだけ使える |

- 証明書を確かめる認証局は、システムのものである。環境の `SSL_CERT_FILE` が指すファイル、無ければ distribution の置き場の bundle（Debian・Ubuntu、Fedora・Red Hat、openSUSE）を読む。接続の文字列では、認証局のファイルを指せない。自前の認証局の証明書は、`SSL_CERT_FILE` で渡す。
- TLS を出さない server には、つながない。
- MySQL では、server が名乗る unix socket へ移らず、接続の文字列の address のままつなぐ。

### 送り手の表

送り手は、DB につないだときに表を探し、無い表だけを作る。

| 表 | 中身 |
|---|---|
| `tukuyomi_records` | 記録の行ごとに1つ。`id`（通し番号）、`ts`、`type`、`request_id`、`client`、`method`、`host`、`path`、`class`、`status`、`reason`、`ms`、`upstream`、`mode`、`engine`、`generation`、`rule`、`rules`（文字列）、`score`、`body`、`sent`、`raw`（行そのもの）、`line_hash`（行の SHA-256。UNIQUE） |
| `tukuyomi_records_state` | 記録のディレクトリ（`source`、`records.dir` の path）ごとの、送った位置（`inode`、`born`、`offset`、`lost_lines`、`updated`） |
| `tukuyomi_records_schema` | 表の形の版（今は 1） |

- 索引は、`ts`、`(type, ts)`、`request_id`、`rule` にある。
- 表がそろっていて版の行があれば、何も作らないので、送り手の DB の利用者に表を作る権限は要らない。作る権限を渡したくないときは、作る権限のある利用者で送り手を一度動かして表を作らせ、その後で送り手の利用者を替える。表を手で作るときは、送り手が作る形（`records-ship/src/store/pgsql.rs`、`records-ship/src/store/mysql.rs` の `CREATE TABLE`）のとおりに作り、版の表に 1 の行も入れる。版の行が無いと、送り手は表を作ろうとして、作る権限を求める。
- 版の表に、この送り手より新しい版があれば断る（`the schema of the database is newer than this program`）。
- 1つの記録のディレクトリには、送り手を1つだけ動かす。位置は `records.dir` の path で分けるので、別のホストの proxy を同じ表へ送るときは、`records.dir` の path を変えるか、別の schema や DB にする。
- PostgreSQL: 表を作る間は advisory lock を取る。
- MySQL: 表は InnoDB、文字は `utf8mb4`、照合順序は `utf8mb4_bin`、行の形は `DYNAMIC` で作り、時刻は UTC の `DATETIME(3)` である。接続ごとに `sql_mode` を厳しい形（`STRICT_ALL_TABLES` を含む）にし、時間帯を UTC にする。表を作る間は `GET_LOCK` を取る。server の `max_allowed_packet` は 2 MiB 以上にする（1つの `INSERT` に 100 行まで入る）。`records.dir` の path は 512 文字までにする。越えると、送り手は `a value does not fit the database` の行を出して止まる。

### 送り方

- 1回で、記録のファイルの行を `batch` 個まで読み、1つの transaction で、行を入れて位置の表を進める。commit の後に `ship.state` を書く。送り手が落ちても、次の回は DB の位置から続ける。
- `batch` 個そろった回の後はすぐ次の回へ進み、送る行が無かった回の後は `interval_ms` 待つ。失敗の後は、待つ時間を `interval_ms` から倍にして1分まで延ばし、うまくいった回の後に戻す。
- DB に届かない間と、送る行が無い間も、`ship.state` を1秒に1回は書き直す。proxy は、それで送り手が動いていることを知る。
- 記録のファイルは、名前ではなく inode と生まれた時刻で追う。回しで改名されても、続きから読む。使用中のファイルの最後の、改行の無い行は、proxy が書いている途中かもしれないので、次の回に回す。
- すべての type の行を送る。type を知っている JSON の object の行は、その項目を同じ名前の列に入れる（無い項目と、型の違う項目の列は空）。ほかの行は type `unknown` で入れる。行そのものは、いつも `raw` に残る。
- 列の長さは proxy が書く上限に合わせ、長い値は切る（`method` 32、`host` 255、`path` 1024、`request_id` 128 バイト）。UTF-8 でない行は、`raw` では不正なバイトを U+FFFD にする（`line_hash` は元のバイトの hash）。
- `line_hash` が UNIQUE なので、二重に送った行は1つになる。同じバイト列の行も1つになる。
- `retention_days` があれば、1分に1回、それより古い行を 1000 行まで消す（1000 行消せたときは続けて消す）。古さは記録の `ts`（proxy の時計）で決める。

### 送れない記録

- 送り手が読む前に、回しで消えた記録のファイルの行は失われる。
  - 送り手が開いていたファイルなら、失われた行を数えて位置の `lost_lines` に足し、`records-ship: a record file was removed before it was shipped, <数> lines lost` の行を出す。
  - 送り手が開く前に消えたファイル（DB に長く届かない間に、proxy が `files` より多く回したときなど）の行は、数えられない。`lines may be lost` を含む行だけを出す。この行は、何も失われていないときにも出ることがある。
- proxy の `required` の経路は、そうなる前に要求を断る（上の「記録の残し方」）。`best_effort` と `security` の経路は断らない。
- 記録のファイルを切り詰めない（logrotate の `copytruncate` など）。送り手は、切り詰めたファイルを同じファイルと見て、その先頭の行を送らないことがある。回しは proxy が自分でする。

### 送り手の誤り

- 送り手の記録は、proxy と同じ1行1件の JSON（type `line`、文は `records-ship:` で始まる）で、標準エラーに出る。文には、接続の文字列、記録、server の文の値を入れない。DB の誤りは、決まった文と、server が返した SQLSTATE である（例: `records-ship: the database refused or failed a request (SQLSTATE 42000)`）。
- DB がログインを断ったとき（PostgreSQL の SQLSTATE が 28 で始まるもの、MySQL の 1045）は、待っても直らないので、`records-ship: stop: the login is refused, which waiting does not mend` の行を出して終わる（exit 1）。
- ほかの断りは、上の間を置いて試し直し、そのたびに行を出す。DB が無い、DB への権限が無い、MySQL の、その host からの接続を許さない（1130）・アカウントが lock されている（3118）なども、これに入る。

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
- 監視の要求は、検査も転送もせず、記録もしない。全体の `access` と `rate_limit` も掛からない。
- 監視の待ち受けは、検査プロセスより前に bind し、停止の 3 の後に閉じる。それまで `/healthz` は 200 を返す。

### 数（`/metrics`）

数は proxy のメモリの中にあり、起動し直すと 0 から数える。label の値は、決まった語か、設定の名前だけである（要求から来る値は label にしない）。

| 名前 | 型 | label | 中身 |
|---|---|---|---|
| `tukuyomi_requests_total` | counter | `class` | 要求の記録の数（`class` は記録と同じ7つ） |
| `tukuyomi_waf_rule_hits_total` | counter | `decision`（`block`、`detect`） | 規則が遮断した要求と、検知だけのモードで規則に当たった要求 |
| `tukuyomi_uninspectable_total` | counter | `reason` | 検査できなかった要求（`invalid`、`queue_full`、`unavailable`、`wait_deadline`、`verdict_deadline`、`inspector_lost`、`protocol`、`inspector_error`、`not_created`、`cancelled`） |
| `tukuyomi_policy_refusals_total` | counter | `policy`（`access`、`rate_limit`） | 要求の前の方針で断った要求（全体の `access` の 403、`rate_limit` の 429）。経路の `access` の 403 は数えない |
| `tukuyomi_rate_limit_keys` | gauge | | 流量の制限が今数えている client の数（`keys` のうち使っている分）。`rate_limit` が無ければ 0 |
| `tukuyomi_rate_limit_evicted_total` | counter | | count が残っているのに、場所を空けるために表から外した client の数。`rate_limit` が無ければ 0 |
| `tukuyomi_connections_accepted_total` | counter | | 受けた接続 |
| `tukuyomi_connections_open` | gauge | | 開いている接続 |
| `tukuyomi_connection_permit_waits_total` | counter | | 受付が接続の枠を待った回数（`max_conns` に届いた回数の目安） |
| `tukuyomi_tls_handshake_failures_total` | counter | | TLS の handshake の失敗と時間切れ |
| `tukuyomi_body_buffer_bytes` | gauge | | 本文などをためている予算のバイト数（`max_buffered_bytes` のうち使っている分） |
| `tukuyomi_inspections_waiting` | gauge | | 検査の待ちの席を持っている要求（`wait_queue` のうち使っている分） |
| `tukuyomi_inspector_up` | gauge | | 要求を受けている検査核の準備ができていれば 1、でなければ 0 |
| `tukuyomi_inspector_restarts_total` | counter | | 検査プロセスの起動し直し |
| `tukuyomi_rules_generation_info` | gauge | `generation`（指紋の先頭16桁）、`mode`、`engine` | 要求を受けている世代。値はいつも 1 |
| `tukuyomi_rules_switches_total` | counter | `result`（`switched`、`refused`、`failed`） | SIGUSR1 と制御 socket による世代の切り替え |
| `tukuyomi_certificate_reloads_total` | counter | `result`（`replaced`、`refused`） | SIGUSR2 による証明書の読み直し |
| `tukuyomi_config_reloads_total` | counter | `result`（`replaced`、`refused`） | SIGHUP による設定の読み直し。読み直しの途中に受けて捨てた SIGHUP は数えない |
| `tukuyomi_upstream_failures_total` | counter | `group` | 上流の組の server の失敗。SIGHUP の読み直しで、0 から数え直す |
| `tukuyomi_records_dropped_total` | counter | | 捨てた記録（上の「書けないとき」） |
| `tukuyomi_record_write_errors_total` | counter | | 書き込みに失敗した記録 |
| `tukuyomi_record_file_errors_total` | counter | | 記録のファイルに書けなかった記録と、失敗した同期（上の「記録のファイル」） |
| `tukuyomi_records_refused_total` | counter | | `required` の経路で、記録を残せないために 503 で断った要求（上の「記録の残し方」） |
| `tukuyomi_records_healthy` | gauge | | 記録のファイルへの最後の書き込みが通り、記録を書く thread が動いていれば 1、でなければ 0 |
| `tukuyomi_records_admitting` | gauge | | `required` の経路の要求を今受け付けるなら 1、断るなら 0（上の「記録の残し方」の3つ）。`required` の経路が無くても出る |
| `tukuyomi_records_unshipped_bytes` | gauge | | 送り手がまだ送っていない、記録のファイルのバイト数。`records.ship` があるときだけ出る。送り手の遅れが分からない間は、値が無い |
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
- 普通の待ち受けと redirect の待ち受けは、次の要求に、全体の `access` と `rate_limit`・経路・経路の `access`・検査・転送・redirect より先に答える。TLS の待ち受けは答えない。
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
4. `systemctl kill --kill-whom=main -s USR2 tukuyomi-core.service`（SIGUSR2）で、proxy が証明書を使い始める。
5. 試験用の CA で通ったら、本番の CA へ替える。
   - 試験用の CA の証明書は、期限が来ていないので、そのままでは置き換わらない（`valid`）。その証明書の `cert_file` と `key_file` を消す。
   - `directory_url` を本番の CA のものに替える。CA の API の server 証明書の root が違うなら、`ca_file` も替える。
   - もう一度 `acme renew` を流してから、SIGUSR2 を送る。ファイルを消してから `acme renew` が終わるまでの間に SIGUSR2 を送ると（証明書も読む SIGHUP の読み直しも含む）、その証明書は handshake から外れる。この順を守れば、その間も proxy は読み込み済みの証明書を使い続ける。
   - `directory_url`・`ca_file`・`contact_email` など、`acme` の多くの鍵は命令だけが読むので、proxy の起動し直しは要らない。`challenge_dir` と、`acme` を持つ証明書の host は proxy も読むので、替えたときは proxy に読み直させる（SIGHUP、`systemctl reload`）。
6. 毎日の timer を置く（[実行ファイルの build と配置](../build/binary-deployment.md) の「証明書の更新の timer」）。

### 注意

- 同じ設定で `acme renew` を2つ同時に流さない。止める仕組みが無い。
- 命令の後に SIGUSR2 を送らないと、新しい証明書は使われない。
- 鍵と証明書は別のファイルに書いて同期してから、鍵、証明書の順に置き換える。
  - 2つの置き換えの間で止まると、鍵が証明書に合わない組が残る。動いている proxy は、SIGUSR2 でその組を断って今のものを使い続け、次の命令が作り直す。ただし、その間に proxy を起動すると、その組を断って起動しない（exit 1）。
- `cert_file`・`key_file`・`challenge_dir` の置かれたディレクトリに、サービスの利用者が書けること（[実行ファイルの build と配置](../build/binary-deployment.md) の「利用者と置き場」）。
  - 鍵は 0600、証明書は 0644 で書く（umask の分は引かれる）。
