# tukuyomi-core

Coraza／ModSecurity 搭載の WAF リバースプロキシ

[English](README.md) | [日本語](README.ja.md)

## 概要

`tukuyomi-core` は、WAF（Web Application Firewall）を組み込んだ HTTP／HTTPS のリバースプロキシです。受信したリクエストを Coraza または ModSecurity v3 で検査して、アップストリームへ転送します。検査には OWASP Core Rule Set（CRS）などのルールセットを使います。[tukuyomi](https://github.com/vril-dev/tukuyomi) から派生した製品で、WAF の機能に特化することを目指しています。

主な機能は次のとおりです。

- HTTP/1.1 と HTTP/2（TLS）のリクエストの受信と、アップストリームへの転送
- Coraza または ModSecurity v3 によるリクエストの検査（ルールセットの世代の管理と、検知のみのモード）
- IP アドレスと国によるアクセス制御と、レート制限（全体とホストごと）
- ACME（HTTP-01）による証明書の発行と更新
- 管理 API と管理画面（managed 設定の編集と、プロキシを止めずに行う反映、ルールセットの世代の操作、ログの検索、監査ログ）
- ログファイルへの出力と、PostgreSQL／MySQL へのログ送信

どの機能が実装済みで、どの機能が未実装かは、[システム概要](docs/detailed-design/00_overview/system-overview.ja.md) の「現在の状態」で確認してください。

> 製品全体のセキュリティ評価は、まだ行っていません。

## インストール

動作を確認しているのは、Landlock が有効な Linux x86_64 だけです。

事前に、次のものが必要です。

- Linux 5.13 以上で、Landlock が有効になっていること
- glibc 2.39 以上（リリースのバイナリを使う場合。ModSecurity の検査プロセスには libstdc++ も必要です）

[GitHub のリリース](https://github.com/vril-dev/tukuyomi-core/releases) から、tarball とチェックサムのファイルをダウンロードします。チェックサムを確認してから、展開してください。

```bash
sha256sum -c tukuyomi-core_v0.2.0_linux_amd64.tar.gz.sha256
tar -xzf tukuyomi-core_v0.2.0_linux_amd64.tar.gz
```

CRS は同梱していません。`scripts/fetch-crs.sh` でダウンロードしてください。

配置、初回の起動、ソースからのビルドの手順は、[docs/build/binary-deployment.ja.md](docs/build/binary-deployment.ja.md) にあります。ソースからビルドするには、Rust 1.94.1 と Go 1.27.2 が必要です。

## ドキュメント

ドキュメントは英語と日本語で用意しています。

- ドキュメントの索引: [docs/README.ja.md](docs/README.ja.md)
- ビルドと配置: [docs/build/binary-deployment.ja.md](docs/build/binary-deployment.ja.md)
- 運用リファレンス: [docs/operations/operator-reference.ja.md](docs/operations/operator-reference.ja.md)
- 管理リファレンス: [docs/operations/admin-reference.ja.md](docs/operations/admin-reference.ja.md)
- システム概要: [docs/detailed-design/00_overview/system-overview.ja.md](docs/detailed-design/00_overview/system-overview.ja.md)

## ライセンス

tukuyomi-core は BSD 2-Clause License で公開しています。詳しくは [LICENSE](LICENSE) を参照してください。

実行ファイルには、サードパーティのソフトウェアが含まれています。それらのライセンスと著作権表示は、[NOTICE](NOTICE) と [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES) にあります。
