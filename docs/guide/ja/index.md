---
title: "tukuyomi core"
subtitle: "運用ガイド ── 日本語版"
language: ja
audience: "tukuyomi core を導入・運用するエンジニア（インフラ／SRE／プラットフォーム担当）"
version: "0.2.0 ベース"
build: "pandoc → EPUB 3、pandoc → HTML → Chrome → PDF"
---

# tukuyomi core 運用ガイド（日本語版）

本書は、tukuyomi core のリポジトリにある日本語のドキュメント（`README.ja.md` と `docs/**/*.ja.md`）を組み直して、最初から順に読み通せる書籍の形にしたものです。
設定キーや振る舞いの正確な定義はドキュメントにあり、本書はそこへの道案内です。

## 本書の方針

- **対象読者**: tukuyomi core を導入・運用するエンジニア（インフラ、SRE、プラットフォームの担当）。
  Linux、HTTP/HTTPS、TLS、systemd の基礎は知っているものとします。
- **文体**: です・ます調で統一し、技術用語はドキュメントと同じ語を使います。
- **構成**: 各章は「概要 → 仕組み → 設定例 → 運用上の注意」の流れにそろえます。
- **整合**: 設定キー、コマンド、ログの文、画面の語は、ドキュメントと一致させます。
  本書に書く事実は、ドキュメントと、公開したリリースノート（付録C）にあるものだけです。
- **範囲**: 0.2.0 で実装している機能だけを扱います。
  実装していない機能や決まっていないことは、そうと分かるように書きます。

## 目次

- **はじめに** — 本書の範囲と読み方、表記、ドキュメントとの関係
- **第1章　tukuyomi core 入門** — 何をする製品か、構成要素、実装していないもの
  （source: docs/detailed-design/00_overview/system-overview.ja.md、README.ja.md）
- **第2章　クイックスタート** — リリースの tarball から最初の世代で起動し、ブロックされることを確認するまで
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
- **付録A　運用リファレンス** — 本を作るときに、docs/operations/operator-reference.ja.md を取り込みます
- **付録B　管理リファレンス** — 本を作るときに、docs/operations/admin-reference.ja.md を取り込みます
- **付録C　リリースノート** — 0.2.0 と 0.1.0

## ファイル配置

```
docs/guide/
├── build-epub.sh          … EPUB を作るスクリプト
├── build-pdf.sh           … PDF を作るスクリプト
├── book.css               … EPUB の体裁
├── book-pdf.css           … PDF の体裁
├── cjk-line-breaks.lua    … 日本語の文の間の改行を消す pandoc のフィルター
├── lib/guide_book.sh      … 2 つのスクリプトが使う章の並び、題、付録の取り込み
└── ja/
    ├── index.md           … 本ファイル（方針・目次）
    ├── 00-preface.md      … はじめに
    ├── 01-introduction.md … 第1章
    ├── 02-quickstart.md   … 第2章
    ├── 03-…〜09-….md     … 第3〜9章
    └── C-release-notes.md … 付録C
```

付録A と付録B のファイルはありません。
`build-epub.sh` と `build-pdf.sh` が、ドキュメントの運用リファレンスと管理リファレンスを取り込んで作ります。

## 作り方（メモ）

- 章のファイルを目次の順に pandoc でつなぎ、EPUB 3 を作ります。
  目次、扉、章ごとの改ページを付けます。
- PDF は、同じ章と付録を pandoc で 1 つの HTML にまとめ、Google Chrome（headless）で A4 の PDF にします。Chrome と、フォントの Noto Sans CJK JP が必要です。
- 環境変数 `SOURCE_DATE_EPOCH`（1970-01-01 UTC からの秒数）を渡すと、本の日付はその日（UTC）になります。渡さないときは、作った日です。
  `SOURCE_DATE_EPOCH` を渡したときは、同じファイルから作った EPUB が毎回まったく同じものになります。
  Chrome は PDF に作成の時刻と識別子を書き込むので、PDF は作るたびにその部分が変わります。
- 付録A と付録B は、ドキュメントの文書の題を付録の題に替えて取り込み、リンクも書き換えます。
  2 つの文書の間のリンクは、本に収めた付録へのリンクにします。
  ほかのドキュメントへのリンクは、文書の名前とリポジトリの中のパスにします（例: ビルドと配置（`docs/build/binary-deployment.ja.md`））。
- 表紙は文字だけ（題、副題、版）にします。
