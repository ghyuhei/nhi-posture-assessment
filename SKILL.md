---
name: nhi-posture-assessment
description: >-
  AWS / Azure (Entra ID) の NHI (Non-Human Identity / 非人間アイデンティティ) 設定を読み取り専用で証跡化し、
  OWASP Non-Human Identities Top 10 (2025) にマッピングして評価する Skill。CodeQL 型の構成で、証跡を正規化
  データベース (nhi-db.json) にし、宣言的ルールパックをクエリとして実行して findings.json を出し、
  完全オフラインの対話型 HTML レポートを生成する。IAM ロール/ユーザー、アクセスキー、OIDC 信頼ポリシー、
  IMDSv2、SCP、Access Analyzer、アプリ登録、クライアントシークレット、マネージド ID、FIC、Graph
  アプリケーション権限、同意統制、サインインログ保持を対象にする。
when_to_use: >-
  NHI / 非人間アイデンティティ / マシンアイデンティティ / サービスアカウント / ワークロード ID の棚卸し・
  リスク評価、シークレット残存率の測定、OWASP NHI Top 10 準拠確認、静的クレデンシャル撲滅、
  IMDSv2 強制状況の確認、OIDC 信頼ポリシー監査、サービスプリンシパル棚卸し、NHI 監査レポート作成を
  依頼されたとき。
effort: high
---

# NHI ポスチャ評価 Skill

AWS と Azure (Entra ID) の NHI 設定を **現状 (Current) / あるべき状態 (Expected) / 差分 (Gap) / リスク /
対処 / 確認方法** の形で評価する。判断基準は `references/control-model.md`(ネイティブ機能で到達できる限界を
含む)、分類軸は OWASP Non-Human Identities Top 10 (2025)。

構成は CodeQL と同じ 4 段:

```
collect_evidence.py  →  build_db.py  →  scan.py       →  render_report.py
(読み取り専用収集)      (正規化 DB)     (ルール実行)      (オフライン HTML)
    evidence/          nhi-db.json    findings.json      *.html
```

## 絶対ルール

- **既定は読み取り専用**。設定変更・削除・修復系 API は、ユーザーが明示的に依頼しない限り実行しない。
  `collect_evidence.py` は AWS の `get-*`/`list-*`/`describe-*`、`az` の `show`/`list`/`rest --method get`
  以外を実行時に拒否する。この保護を迂回するコマンドを手書きしない。
- **クラウド API・CLI の実行前に必ず承認を得る**。対象アカウント/テナント、profile、リージョン、
  実行する読み取り専用 Action の種別、保存先、想定される機微情報を短く説明する。まず `--dry-run` を見せる。
- **未取得を「問題なし」と読み替えない**。権限不足・未収集・リージョン外は `coverageGaps` と
  `_unknown` として記録され、該当ルールの確度は自動的に `low` に落ちる。レポート冒頭の未取得バナーを
  必ずユーザーに提示する。
- **機微情報**: アカウント ID、テナント ID、AccessKeyId、アプリ ID/オブジェクト ID、UPN/メールアドレス、
  リソース名、公網 IP。外部共有時は HTML レポートの「公開用マスク」を使う。
- **推測で埋めない**。証跡で確認できた事実・公式仕様・こちらの推論を明確に分ける。
- サブエージェントはユーザーが明示しない限り使わない。

## まず分類する

1. **Artifact review** — Terraform / ARM / Bicep / エクスポート済み JSON だけで評価する。収集は行わない。
2. **Read-only live assessment** — 読み取り専用の認証情報で実環境から証跡を集める。
3. **Delta review** — 過去の `findings.json` と比較し、新規 / 継続 / 解消を出す
   (`scan.py --baseline <前回の findings.json>`)。90 日ロードマップの進捗測定に使う。
4. **Remediation planning** — 変更は実行せず、順序・影響範囲・検証手順を作る。

あわせて次を固定する。**クラウド**(AWS / Azure / 両方)、**スコープ**(単一アカウント/テナントか、
Organizations / 管理グループ全体か)、**リージョン**(IMDS のアカウント既定は**リージョン単位**の設定であり、
指定しなかったリージョンは未評価になる)。

## 手順

### 1 コマンドで回す(通常はこれ)

```bash
# まず dry-run を見せて承認を得る(実行される読み取り専用コマンドが全部出る)
python3 "${CLAUDE_SKILL_DIR}/scripts/assess.py" --dry-run \
  --cloud both --aws-profile <profile> --regions ap-northeast-1,us-east-1

# 収集 → 正規化 → 判定 → レポートまで一括
python3 "${CLAUDE_SKILL_DIR}/scripts/assess.py" \
  --cloud both --aws-profile <profile> --regions ap-northeast-1,us-east-1
```

出力は 1 ディレクトリにまとまる(`evidence/` `nhi-db.json` `findings.json` `report.html`)。
最後に表示される `report.html` をブラウザで開く。

よく使うオプション:

| オプション | 用途 |
|---|---|
| `--from-evidence <dir>` | 収集を省略して既存証跡から作り直す(ルール調整の試行に使う) |
| `--baseline <前回のfindings.json>` | 新規 / 継続 / 解消を出す。進捗測定用 |
| `--fail-on critical` | CI ゲート。該当があれば終了コード 2 |
| `--max-principals 25` | 初回はこれで小さく試す |
| `--rules <path>` | 独自ルールパックを使う(既定は Skill 同梱の `rules/`)。複数指定可 |
| `--force` | 出力ディレクトリの既存 `findings.json` を上書きする。**既定では拒否**する(差分レビューの基準を失うため) |
| `--regions` | **IMDS のアカウント既定はリージョン単位**。対象リージョンを全て挙げる |

### 段階を分けたいとき

```bash
python3 scripts/collect_evidence.py --cloud both --aws-profile <p> -o ./evidence
python3 scripts/build_db.py ./evidence -o nhi-db.json
python3 scripts/scan.py nhi-db.json -o findings.json
python3 scripts/render_report.py findings.json -o report.html
```

必要な読み取り権限と実行コマンドの一覧は `references/evidence-commands.md`。

### 前提と落とし穴

- **認証は CLI のセッションを借りる**。ツールに鍵を渡す設計ではない。事前に
  `aws sts get-caller-identity` と `az account get-access-token --resource https://graph.microsoft.com`
  が通ることを確認する。**`az account show` はキャッシュから応答するため生存確認にならない**
  (失効セッションでも成功する。コレクタは実トークン取得で検証する)。
- **未使用判定はサインインログの標本の深さに依存する**。標本が 30 日分遡れない場合、
  該当判定は確度 `low` に落ちて `sample_too_shallow` のギャップが出る。
  正確に測るには診断設定で長期退避したログが要る(P1 以上)。
- **収集が失敗したら評価対象ゼロの DB は生成しない**。部分収集が安心なレポートに化けるのを防ぐため。
- **未使用判定の追跡期間は既定 180 日**。四半期バッチ・年次ジョブがある環境では
  `rules/nhi-core.json` の `thresholds.identityUnusedDays` を 365 に上げる。
- 恒久的に許容するリソース(break-glass 等)はルールの `exceptions` に glob を書く。
  **抑止件数はレポートに残る**ので握りつぶしにはならない。

## 自動判定で埋まらない論点(必ず人手で見る)

自動ルールは「機械的に判定できるもの」に限られる。以下はネイティブ API から判定できないか、
判定してもノイズになるため、証跡を見て人手で評価する。

- **所有者の実在性** — Azure の `owners` は埋まっていても退職者のことがある。AWS のロールには
  所有者概念が無い。タグ運用の有無と、その真実性を確認する。
- **NHI の再利用 (OWASP NHI9)** — `attachedTo` のファンアウトは検出できるが、「別チームの別用途で
  同じロールを使っている」ことはメタデータに出ない。設計資料と突き合わせる。
- **サードパーティ NHI (OWASP NHI3)** — GitHub PAT、CI ランナートークン、SaaS 連携キーは
  どちらのクラウドのコンソールにも現れない。台帳の母数に含まれているかを必ず確認する。
- **データ面の ID** — RDS の DB ユーザー、MSK SCRAM、SQL contained user、Cosmos キーは
  IAM / Entra の棚卸しから完全に漏れる。
- **人間による NHI 利用 (OWASP NHI10)** — ログ上は正規の NHI サインインにしか見えない。
  `sts:SourceIdentity` の必須化状況と、共有シークレットの配布実態を確認する。
- **AI エージェント ID** — AgentCore / Entra Agent ID 由来の NHI が台帳に入っているか。
  委譲チェーンの監査可否は現状どちらのクラウドでも弱い。

## 報告の型

各 finding は `Current / Expected / Gap / Risk / Remediation / Validation` に落とす
(`references/finding-schema.md`)。最終報告では次を必ず含める。

1. **母数とカバレッジ** — 評価した NHI 件数と、**台帳に載っていない NHI 種別の明示リスト**。
   これを書かない報告は「NHI 棚卸し」ではなく「IAM 棚卸し」である。
2. **Critical / High の実害** — 何が起きうるかを攻撃経路で書く。
3. **未取得領域** — `coverageGaps` をそのまま提示する。
4. **ネイティブで埋まらない残余** — OWASP NHI3 / NHI9 / 所有者管理。専用製品の要否判断はここで行う。

## 自己診断

```bash
python3 "${CLAUDE_SKILL_DIR}/scripts/selftest.py"
```

ルールパック整合性、述語の意味論、読み取り専用ガード、同梱フィクスチャに対する
検出/非検出の一致、証跡不足時の確度降格、レポートのオフライン性を検証する。
ルールを追加・変更したら必ず実行する。
