---
title: "tukuyomi core"
subtitle: "運用ガイド ── 日本語版"
language: ja
audience: "tukuyomi core を導入・運用するエンジニア（インフラ／SRE／プラットフォーム担当）"
version: "0.2.0 ベース"
build: "pandoc → EPUB 3"
---

# tukuyomi core 運用ガイド（日本語版）

本書は、tukuyomi core のリポジトリにある日本語のドキュメント（`README.ja.md` と `docs/**/*.ja.md`）を、上から順に読み通せる書籍の形に組み直したものです。設定キーや振る舞いの正確な定義はドキュメントにあり、本書はそこへ案内します。

## 本書の方針

- **対象読者**: tukuyomi core を導入・運用するエンジニア（インフラ、SRE、プラットフォームの担当）。Linux、HTTP/HTTPS、TLS、systemd の基礎は既知とします。
- **文体**: です・ます で統一します。技術用語は、ドキュメントと同じ語を使います。
- **構成**: 各章は「概要 → 仕組み → 設定例 → 運用上の注意」の流れにそろえます。
- **整合**: 設定キー、コマンド、ログの文、画面の語は、ドキュメントと一致させます。本書に書く事実は、ドキュメントと、公開したリリースノート（付録C）にあるものだけです。
- **範囲**: 0.2.0 で実装している機能だけを書きます。実装していない機能や決まっていないことは、そうと分かるように書きます。

## 目次

- **はじめに** — 本書の範囲と読み方、表記、ドキュメントとの関係
- **第1章　tukuyomi core 入門** — 何をする製品か、構成要素、実装していないもの
  （source: docs/detailed-design/00_overview/system-overview.ja.md、README.ja.md）
- **第2章　クイックスタート** — リリースの tarball から、最初の世代で起動し、ブロックを確かめるまで
  （source: README.ja.md、docs/build/binary-deployment.ja.md の「初回起動の手順」）
- **第3章　systemd での配置** — OS ユーザーとディレクトリ、ユニット、起動前の検証、検査プロセスの権限の制限
  （source: docs/build/binary-deployment.ja.md）
- **第4章　ルールセットと世代** — インポート、選択と切り替え、検知のみのモード、検査除外のルート、検査エンジンの選択
  （source: docs/operations/operator-reference.ja.md の「コマンド」「シグナル」「ルールセットと世代」）
- **第5章　managed 設定と管理画面** — 管理プロセスの用意、ユーザーとロール、managed 設定のバージョンと反映、管理画面
  （source: docs/operations/operator-reference.ja.md の「managed 設定」、docs/operations/admin-reference.ja.md）
- **第6章　アクセス制御とレート制限** — `access`、レート制限、ホストごとの設定、国のデータベース
  （source: docs/operations/operator-reference.ja.md の「アクセス制御とレート制限」）
- **第7章　ログとログ送信** — リクエストのログ、ログファイル、ログ送信プロセス
  （source: docs/operations/operator-reference.ja.md の「ログ」「ログ送信プロセス」）
- **第8章　ACME による証明書** — 必要なもの、初回の発行、更新
  （source: docs/operations/operator-reference.ja.md の「ACME」「ACME のサイト」）
- **第9章　運用** — 監視、設定のリロード、停止、バージョンの更新と切り戻し
  （source: docs/operations/operator-reference.ja.md の「シグナル」「停止」「監視」「バージョンの更新」）
- **付録A　運用リファレンス** — docs/operations/operator-reference.ja.md を、本を作るときに取り込みます
- **付録B　管理リファレンス** — docs/operations/admin-reference.ja.md を、本を作るときに取り込みます
- **付録C　リリースノート** — 0.2.0 と 0.1.0

## ファイル配置

```
docs/guide/
├── build-epub.sh          … EPUB を作る台本
├── book.css               … EPUB の体裁
└── ja/
    ├── index.md           … 本ファイル（方針・目次）
    ├── 00-preface.md      … はじめに
    ├── 01-introduction.md … 第1章
    ├── 02-quickstart.md   … 第2章
    ├── 03-…〜09-….md     … 第3〜9章
    └── C-release-notes.md … 付録C
```

付録A と付録B のファイルは置きません。`build-epub.sh` が、ドキュメントの運用リファレンスと管理リファレンスを取り込んで作ります。

## 作り方（メモ）

- 章のファイルを目次の順に pandoc でつなぎ、EPUB 3 を作ります。目次、扉、章の改ページを付けます。
- 付録A・付録B は、ドキュメントの文書の題を付録の題に替えて取り込みます。2 つの文書の間のリンクは本の中の付録へのリンクに、ほかのドキュメントへのリンクは、文書の名前とリポジトリの中の path（例: ビルドと配置（`docs/build/binary-deployment.ja.md`））に替えます。
- 表紙は文字だけ（題、副題、版）にします。
