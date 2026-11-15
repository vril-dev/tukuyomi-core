# ドキュメントの索引

tukuyomi-core のドキュメントの一覧です。tukuyomi-core は、tukuyomi（tukuyomi WAF）から派生し、WAF の機能に特化した製品を目指しています。

現在実装している主な機能は、WAF によるリクエストの検査、HTTP／HTTPS の受信と転送、IP アドレスと国によるアクセス制御とレート制限、管理プロセス（管理 API と管理画面）、managed 設定、ログ送信プロセスです。ソースは次のディレクトリにあります。

- [`kernel/`](../kernel/): 検査プロセスの起動と監視、検査の受け渡しを担う Rust のライブラリ
- [`inspector/`](../inspector/): Coraza を使う Go の検査プロセス
- [`inspector-modsecurity/`](../inspector-modsecurity/): ModSecurity v3 を使う検査プロセス
- [`proxy/`](../proxy/): プロキシ（管理プロセスと、管理画面の [`proxy/admin-ui/`](../proxy/admin-ui/) を含む）
- [`records-ship/`](../records-ship/): ログ送信プロセス

0.1.0 から、Linux x86_64 用の 4 つの実行ファイルを 1 つの tarball にまとめ、GitHub のリリースで配布しています（[ビルドと配置](build/binary-deployment.md) の「リリースの tarball」）。

`build/` と `operations/` の文書は、現在の実装の使い方を説明します。`detailed-design/` の文書は初期草案で、目標、前提、候補、未決事項を記録しています。実装済みの範囲は、[システム概要](detailed-design/00_overview/system-overview.md) の「現在の状態」を参照してください。

## 文書の一覧

| 文書 | 内容 |
|---|---|
| [システム概要](detailed-design/00_overview/system-overview.md) | 製品の目的、現在の状態（実装済みの範囲と未実装の機能）、前提・候補・未決定の区別、検討の対象とする範囲、用語 |
| [アーキテクチャ概要](detailed-design/00_overview/architecture.md) | 構成の候補、権限と資源の境界、障害の影響範囲、リクエスト処理の流れの例、設計上の義務、状態と操作の組み合わせ、採用の判断に必要な検証の候補 |
| [設計方針・制約](detailed-design/00_overview/design-principles.md) | 設計原則とその適用、検査モードと技術的な障害の区別、fail-closed の適用範囲、ログと管理機能の扱い、移植と前例の扱い、依存・ルール・設定のバージョン、コードの構成 |
| [ビルドと配置](build/binary-deployment.md) | 必要な環境、リリースの tarball、ソースからのビルド、CRS の取得、OS ユーザーとディレクトリ、国のデータベース、初回起動の手順、systemd のユニットファイルの例（管理プロセスとログ送信プロセスを含む）、Landlock などによる検査プロセスの権限の制限 |
| [運用リファレンス](operations/operator-reference.md) | コマンド、シグナル、停止、設定ファイルの設定キーと値の関係、リクエストボディの上限と検査する大きさ、ルールセットと世代、managed 設定（使うかどうかの判断、managed ストアとバージョン、初回起動、設定ファイルからの移行、反映）、リクエストの処理、IP アドレスと国によるアクセス制御とレート制限（全体とホストごと）、ログの行とログファイル、ログ送信プロセス（PostgreSQL・MySQL）、監視、ACME |
| [管理リファレンス](operations/admin-reference.md) | 管理プロセスのコマンドとリスナー、設定キー `admin`、外部からの利用（managed 設定を使う場合の管理画面のルートを含む）、ユーザーとロール、ログインと二要素認証、ロックアウトと試行回数の制限、セッション、CSRF 対策と Origin の確認、API トークン、監査ログ、世代の操作、managed 設定の操作、切り替えの履歴、設定の変更履歴、ログの読み出し、管理画面、API のパスの一覧とレスポンスの形式 |

未決事項は、設計文書の末尾の表にまとめ、文書をまたいで重複しない ID を付けています（システム概要は OV-、アーキテクチャ概要は AR-、設計方針・制約は DP-）。

## 文書の構成（予定）

次のツリーは、予定している文書の構成です。作成済みの文書は上の表の 6 つだけで、ツリーのほかのファイルとディレクトリ（`detailed-design/README.md` を含む）は、まだ作成していません。内容を書く時点で作成します。

```text
docs/
├── build/                              # ビルドと配置
│   └── binary-deployment.md            # ビルドと配置
│
├── operations/                         # 運用
│   ├── operator-reference.md           # 運用リファレンス
│   └── admin-reference.md              # 管理リファレンス
│
└── detailed-design/                    # 詳細設計
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
    │   ├── er-diagram.md               # ER 図
    │   ├── table-definitions.md        # テーブル定義
    │   ├── data-dictionary.md          # データ辞書
    │   └── file-formats.md             # ファイル／外部データ形式
    │
    ├── 05_api/                         # API 設計
    │   ├── rest-api.md                 # REST API 仕様
    │   ├── internal-api.md             # 内部 API
    │   └── message-formats.md          # メッセージ／イベント形式
    │
    ├── 06_ui/                          # UI 設計（必要な場合）
    │   ├── screen-list.md              # 画面一覧
    │   ├── screen-transitions.md       # 画面遷移
    │   └── components.md               # UI コンポーネント
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
    └── README.md                       # このディレクトリの説明と読み方
```
