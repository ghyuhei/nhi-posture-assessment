# 評価基準 — ネイティブ機能で到達できる限界

判定の根拠となるモデル。詳細版は `~/nhi-native-capabilities-aws-azure.html` (rev.2)。
`docRef` はこのモデルの項番を指す。

## 前提となる非対称

| 領域 | AWS | Azure / Entra |
|---|---|---|
| 静的シークレットの**予防的禁止** | SCP の `iam:CreateAccessKey` Deny のみ。既存キーに遡及しない | application management policy でテナント既定として作成禁止・最大寿命を強制できる |
| 権限の**右サイズ化** | Access Analyzer の unused access(追跡期間 1〜365 日)→ policy generation → custom policy checks で CI まで完結 | Defender CSPM の CIEM 推奨事項のみ |
| **最終利用の可視化** | IAM last accessed は直近 400 日 | サインインログは Free 7 日 / P1・P2 30 日。長期退避が無いと廃止判断ができない |
| **漏洩検出** | 公開リポジトリの IAM ユーザーキーに quarantine を適用(キー無効化ではない) | ID Protection がダークウェブ・paste サイト・公開 GitHub を対象に漏洩資格情報を検出 |
| **同意統制** | リソースベースポリシー + `sts:ExternalId` | permission grant policy / 管理者同意ワークフローで Graph 権限付与を承認制にできる |

## 主要な構造的欠陥(finding の `docRef`)

- **F-01 所有者がネイティブに存在しない** — AWS のロールに所有者概念は無く、タグは強制されない。
  Azure の `owners` も退職者が残る。**廃止判断が止まる根本原因**。
- **F-02 AWS にテナント級のシークレット禁止が無い** — OWASP NHI7 に対する予防手段が無い。
- **F-03 NHI 再利用の検出機構が両クラウドとも無い** — 侵害時の影響範囲を最も左右する要因が不可視。
- **F-04 IMDSv2 未強制** — ワークロード資格情報窃取の主経路。アカウント既定は
  **リージョン単位のオプトイン**で既存インスタンスに遡及しない。**他の施策より先に閉じる**。
- **F-05 ローテーションは保有者次第** — マネージド ID は有効期間 90 日の証明書を約 45 日で
  自動更新し閲覧も取得もできない。自分が保有するシークレットを自動ローテーションする機構は
  両クラウドとも無い。周期短縮ではなく保有をやめる。
- **F-06 PIM は NHI の JIT にならない** — サービスプリンシパル / マネージド ID に
  eligible 割り当てはできない。NHI 向け JIT は両クラウドとも未実装。
- **F-07 Conditional Access はマネージド ID に効かない** — 単一テナントアプリのみが対象。
- **F-08 Azure はログ保持を先に手当てしないと棚卸しできない** — AWS はこの問題を持たない。
- **F-09 フェデレーション信頼条件** — 2026-02 から AWS STS が provider 固有クレーム
  (GitHub の不変リポジトリ ID 等)を検証できるが**オプトイン**で、既存ロールは取り残される。
- **F-10 漏洩鍵の自動対応を過信できない** — quarantine は制限ポリシーの付与でありキー無効化ではない。
- **F-11 Private CA のコスト構造** — CA 単位課金が用途別分割という正しい設計を高コスト化する。

## OWASP NHI Top 10 (2025) の到達点

| | AWS | Azure | 備考 |
|---|---|---|---|
| NHI1 Improper Offboarding | △ | ○ | 所有者データの品質に全依存 |
| NHI2 Secret Leakage | △ | ◎ | Azure が明確に先行 |
| NHI3 Vulnerable Third-Party NHI | △ | △ | **ネイティブ解なし。相手側の侵害は検知不能** |
| NHI4 Insecure Authentication | ○ | ○ | データ面はポリシーで縛れない |
| NHI5 Overprivileged NHI | ◎ | △ | JIT は両者とも不可 |
| NHI6 Insecure Cloud Deployment | ◎ | ○ | AWS の新条件キーはオプトイン |
| NHI7 Long-Lived Secrets | × | ◎ | IAM アクセスキーに有効期限の概念が無い |
| NHI8 Environment Isolation | ○ | △ | アプリ登録はテナント単位 |
| NHI9 NHI Reuse | × | × | **予防も検出も無い** |
| NHI10 Human Use of NHI | △ | △ | ログ上は正規の NHI サインインにしか見えない |

**NHI3 と NHI9、および所有者管理がネイティブの空白**。専用 NHI 製品の要否は、
自組織のリスクがこの 3 点に集中しているかで判断する。

## 評価順序

1. **IMDSv2 強制**(F-04)— 空いたままでは権限削減の効果が資格情報窃取で無効化される
2. **ログ長期保管**(F-08)— 後回しにすると廃止判断が誤った根拠で行われる
3. **予防ポリシー**(F-02)— 先に打たないと削除した端から再生成される
4. 権限削減 → 棚卸し → 検知

## 能力 ID(finding の `docRef`)

構造的欠陥 `F-xx` に紐づかない finding は、次の能力 ID を参照する。

| ID | 能力 | 到達点 |
|---|---|---|
| `CAP-PREVENT` | 静的キー・共有キーの予防的禁止 | AWS △ / Azure ◎ |
| `CAP-RIGHTSIZE` | 実使用実績に基づく権限の右サイズ化 | AWS ◎ / Azure △ |
| `CAP-FEDERATION` | フェデレーション信頼条件の精度と上限 | AWS ○(2026-02 以降)/ Azure △(FIC 20 件上限) |
| `CAP-CONSENT` | 権限付与・同意の統制 | AWS ○(`sts:ExternalId`)/ Azure ◎(permission grant policy) |
| `CAP-THIRDPARTY` | サードパーティへの権限委譲 | 両者 △。相手側の侵害は検知できない (OWASP NHI3) |
| `CAP-ISOLATION` | 環境分離 | AWS ○(アカウント分離)/ Azure △(アプリ登録はテナント単位) |
| `CAP-EVIDENCE` | 証跡カバレッジ | 未取得を「問題なし」と読み替えないための枠 |
