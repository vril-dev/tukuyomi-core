# tukuyomi-core 設計文書

tukuyomi-core の設計文書を置くディレクトリ。tukuyomi-core は、tukuyomi（tukuyomi WAF）から派生し、WAF 機能に特化したシステムを目指す。

現時点で実装しているのは、初回の検査核、HTTP・HTTPS の受付と転送、要求の前の方針、管理のプロセス（管理 API と管理画面）である。Rust のライブラリ [`kernel/`](../kernel/)、Go の検査プロセス [`inspector/`](../inspector/)、HTTP の実行体 [`proxy/`](../proxy/)（管理のプロセスと、その画面 [`proxy/admin-ui/`](../proxy/admin-ui/) を含む）のソースがあり、配布物はまだない。`detailed-design/` の文書は初期草案で、目標・前提・候補・未決事項を記録している。実装済みの範囲は [システム概要](detailed-design/00_overview/system-overview.md) の「現在の状態」に書く。`build/` と `operations/` の文書は、今の実装の動かし方を書く。

## 作成済みの文書

| 文書 | 内容 |
|---|---|
| [システム概要](detailed-design/00_overview/system-overview.md) | 目的、現在の状態、前提・候補・未決定の区別、検討の対象とする範囲、用語 |
| [アーキテクチャ概要](detailed-design/00_overview/architecture.md) | 構成の候補、責務の分担、障害の影響範囲、要求処理の流れの例、設計上の義務、状態 × 操作、採用判断に必要な検証の候補 |
| [設計方針・制約](detailed-design/00_overview/design-principles.md) | 設計原則とその適用、検査モードと技術障害の区別、fail-closed の適用範囲、記録と管理機能の扱い、移植と前例、版の方針 |
| [実行ファイルの build と配置](build/binary-deployment.md) | 要るもの、build、CRS の取得、利用者と置き場、国のデータベース、初めて起動する手順、systemd の例（管理のプロセスを含む）、検査プロセスの絞り |
| [運用リファレンス](operations/operator-reference.md) | 命令、合図、停止、設定ファイルの鍵と値どうしの関係、本文と予算、ルールセットと世代、要求の扱い、要求の前の方針（全体の許可・拒否、流量の制限、国のデータベース）、記録の行と記録のファイル、監視、ACME |
| [管理リファレンス](operations/admin-reference.md) | 管理のプロセスの命令と待ち受け、設定の `admin`、外から使う経路、利用者と役割、ログインと第二要素、API の token、監査、世代の操作、切り替えの履歴、記録の読み出し、管理画面、API の path の一覧 |

未決事項は設計文書の末尾に表でまとめ、文書をまたいで一意な ID を付けている（システム概要は OV-、アーキテクチャ概要は AR-、設計方針・制約は DP-）。

## 文書の構成（予定）

次のツリーは、予定している文書の構成である。作成済みの文書は上の表の6つだけで、ツリーのほかのファイルとディレクトリ（`detailed-design/README.md` を含む）は、まだ作成していない。内容を書く時点で作成する。

```text
docs/
├── build/                              # build と配置
│   └── binary-deployment.md            # 実行ファイルの build と配置
│
├── operations/                         # 運用
│   ├── operator-reference.md           # 運用リファレンス
│   └── admin-reference.md              # 管理リファレンス
│
└── detailed-design/                    # 詳細設計書ルート
    ├── 00_overview/                    # 概要・全体方針
    │   ├── system-overview.md          # システム概要
    │   ├── architecture.md             # アーキテクチャ概要
    │   └── design-principles.md        # 設計方針・制約
    │
    ├── 01_requirements/                # 要件とのトレーサビリティ
    │   ├── functional-requirements.md  # 機能要件との対応
    │   └── non-functional.md           # 非機能要件との対応
    │
    ├── 02_architecture/                # アーキテクチャ設計
    │   ├── high-level.md               # 全体構成
    │   ├── component-diagram.md        # コンポーネント図
    │   ├── sequence-diagrams/          # シーケンス図
    │   ├── data-flow.md                # データフロー
    │   └── deployment.md               # デプロイメント構成
    │
    ├── 03_modules/                     # モジュール／コンポーネント詳細
    │
    ├── 04_data/                        # データ設計
    │   ├── er-diagram.md               # ER図
    │   ├── table-definitions.md        # テーブル定義
    │   ├── data-dictionary.md          # データ辞書
    │   └── file-formats.md             # ファイル／外部データ形式
    │
    ├── 05_api/                         # API設計
    │   ├── rest-api.md                 # REST API仕様
    │   ├── internal-api.md             # 内部API
    │   └── message-formats.md          # メッセージ／イベント形式
    │
    ├── 06_ui/                          # UI設計（必要な場合）
    │   ├── screen-list.md              # 画面一覧
    │   ├── screen-transitions.md       # 画面遷移
    │   └── components.md               # UIコンポーネント
    │
    ├── 07_security/                    # セキュリティ設計
    │   ├── authentication.md
    │   ├── authorization.md
    │   └── data-protection.md
    │
    ├── 08_error-handling/              # エラー処理・例外設計
    │   └── error-codes.md
    │
    ├── 09_performance/                 # 性能・スケーラビリティ
    │   └── performance-design.md
    │
    ├── 10_ops/                         # 運用・監視設計
    │   ├── logging.md
    │   ├── monitoring.md
    │   └── backup-recovery.md
    │
    ├── appendices/                     # 付録
    │   ├── glossary.md                 # 用語集
    │   ├── references.md               # 参考資料
    │   └── change-history.md           # 変更履歴
    │
    └── README.md                       # このフォルダの説明・読み方
```
