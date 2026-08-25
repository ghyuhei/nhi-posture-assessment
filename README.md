# NHI Posture Assessment

AWS / Azure (Entra ID) の **NHI (Non-Human Identity / 非人間アイデンティティ)** を読み取り専用で
証跡化し、OWASP Non-Human Identities Top 10 (2025) に対応づけて評価するツールと、その判断基準。

- **判断基準**: [`docs/nhi-native-capabilities-aws-azure.html`](docs/nhi-native-capabilities-aws-azure.html)
  — AWS と Azure のネイティブ機能で NHI 対策がどこまで到達するかを 21 領域で整理した資料
- **実装**: Claude Code Skill（`SKILL.md` 以下）— 上の資料を判定基準にしたスキャナ
- **出力例**: [`docs/nhi-posture-report-sample.html`](docs/nhi-posture-report-sample.html)

## 構成

CodeQL と同じ 4 段構成。証跡をデータベース化し、宣言的なルールパックをクエリとして実行する。

```
collect_evidence.py  →  build_db.py  →  scan.py      →  render_report.py
(読み取り専用収集)      (正規化 DB)     (ルール判定)     (オフライン HTML)
```

`scripts/assess.py` が 1 コマンドの入口。

## 使い方

```bash
# 何を実行するか確認（読み取り専用コマンドが全部出る）
python3 scripts/assess.py --dry-run --cloud both --aws-profile <profile> --regions ap-northeast-1

# 収集 → 正規化 → 判定 → レポートまで一括
python3 scripts/assess.py --cloud both --aws-profile <profile> --regions ap-northeast-1
```

認証情報は渡さない。`aws` / `az` CLI のログイン済みセッションを借りる。
書き込み系コマンドは実行時ガードで拒否される。

Skill として使う場合は `~/.claude/skills/nhi-posture-assessment/` に配置する。

## 設計上の約束

- **既定は読み取り専用**。AWS は `get-*`/`list-*`/`describe-*`/`generate-*`、Azure は
  `show`/`list`/`rest --method get` 以外を実行時に拒否する
- **未取得を「問題なし」と読み替えない**。権限不足・未収集・リージョン外は `coverageGaps` として
  記録され、該当ルールの確度は自動的に `low` に落ちる
- **評価対象ゼロのデータベースは生成しない**。部分収集が安心なレポートに化けるのを防ぐ
- **証跡は外に出ない**。収集結果もレポートもローカル完結（HTML は外部 CDN を一切参照しない）

## 検証

```bash
python3 scripts/selftest.py     # 648 checks
```

ルールパック整合性、述語の意味論、読み取り専用ガード、同梱フィクスチャに対する検出/非検出の一致、
証跡不足時の確度降格、レポートのオフライン性、ドキュメントとコードの乖離を検証する。

Microsoft Graph の 40 プロパティは公開 OData メタデータと、AWS の 13 コマンドと応答形状は
インストール済み CLI (aws-cli 2.32.34) と照合済み。

## 既知の限界

- **実データでの挙動は未検証**。実際の `@odata.nextLink` ページング、スロットリング、
  大規模テナントでの挙動は確認していない。初回は `--max-principals 25` から試すこと
- **実効権限は解決していない**。ポリシー名ベースの判定であり、SCP・権限境界・継承を
  展開していない。CNAPP の CIEM とはここが決定的に違う
- **相関分析がない**。1 エンティティ 1 ルールの独立評価で、攻撃経路グラフは持たない
- OWASP NHI3（サードパーティ NHI）と NHI9（NHI 再利用）はクラウドネイティブでは
  原理的に検出しきれない。詳細は判断基準の資料を参照
