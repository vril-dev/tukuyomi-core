# tukuyomi-core

Coraza／ModSecurity 搭載の WAF リバースプロキシ

[English](README.md) | [日本語](README.ja.md)

## 概要

`tukuyomi-core` は、WAF（Web Application Firewall）を組み込んだ HTTP／HTTPS のリバースプロキシです。受信したリクエストを Coraza または ModSecurity v3 で検査し、アップストリームへ転送します。検査には OWASP Core Rule Set（CRS）などのルールセットを使います。[tukuyomi](https://github.com/vril-dev/tukuyomi) から派生し、WAF の機能に特化した製品を目指しています。

主な機能は次のとおりです。

- HTTP/1.1 と HTTP/2（TLS）のリクエストの受信と、アップストリームへの転送
- Coraza または ModSecurity v3 によるリクエストの検査（ルールセットの世代の管理、検知のみのモード）
- IP アドレスと国によるアクセス制御、レート制限（全体とホストごと）
- ACME（HTTP-01）による証明書の発行と更新
- 管理 API と管理画面（managed 設定の編集と、プロキシを止めない反映、ルールセットの世代の操作、ログの検索、監査ログ）
- ログファイルへの出力と、PostgreSQL／MySQL へのログ送信

実装済みの機能と未実装の機能は、[システム概要](docs/detailed-design/00_overview/system-overview.md) の「現在の状態」を参照してください。

> 0.1.0 は最初のリリースです。製品全体のセキュリティ評価は、まだ行っていません。

## インストール

動作を確認しているのは、Landlock が有効な Linux x86_64 だけです。

事前に必要なもの:

- Linux 5.13 以上で、Landlock が有効なこと
- glibc 2.39 以上（リリースのバイナリを使う場合。ModSecurity の検査プロセスには libstdc++ も必要です）

[GitHub のリリース](https://github.com/vril-dev/tukuyomi-core/releases) から tarball とチェックサムのファイルを取得し、チェックサムを確認してから展開します。

```bash
sha256sum -c tukuyomi-core_v0.1.0_linux_amd64.tar.gz.sha256
tar -xzf tukuyomi-core_v0.1.0_linux_amd64.tar.gz
```

CRS は同梱していません。`scripts/fetch-crs.sh` で取得してください。

配置、初回の起動、ソースからのビルド（Rust 1.94.1 と Go 1.27.2 が必要です）の手順は、[docs/build/binary-deployment.md](docs/build/binary-deployment.md) を参照してください。

## ドキュメント

ドキュメントは日本語のみです。

- ドキュメントの索引: [docs/README.md](docs/README.md)
- ビルドと配置: [docs/build/binary-deployment.md](docs/build/binary-deployment.md)
- 運用リファレンス: [docs/operations/operator-reference.md](docs/operations/operator-reference.md)
- 管理リファレンス: [docs/operations/admin-reference.md](docs/operations/admin-reference.md)
- システム概要: [docs/detailed-design/00_overview/system-overview.md](docs/detailed-design/00_overview/system-overview.md)

## ライセンス

tukuyomi-core は BSD 2-Clause License で公開しています。詳細は [LICENSE](LICENSE) を参照してください。

実行ファイルに含まれるサードパーティのソフトウェアのライセンスと著作権表示は、[NOTICE](NOTICE) と [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES) を参照してください。
