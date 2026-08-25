# データスキーマ

## nhi-db.json(`build_db.py` の出力)

```jsonc
{
  "schemaVersion": "1.0",
  "generatedAt": "2026-08-25T00:00:00+00:00",   // 証跡の収集時刻。日数計算の基準
  "evidenceDir": "./nhi-evidence-20260825",     // 由来の証跡ディレクトリ
  "scopes":    [ /* アカウント / リージョン / テナント単位の設定 */ ],
  "identities":[ /* NHI 本体 */ ],
  "resources": [ /* NHI を露出させうるリソース */ ],
  "coverageGaps":[ {"area": "...", "reason": "...", "detail": "..."} ]
}
```

### 共通フィールド

| フィールド | 意味 |
|---|---|
| `key` | 一意キー。**全エンティティが必ず持つ**。`aws:<account>:role/<name>` / `azure:<tenant>:app/<appId>` / スコープは `aws:<account>[:<region>]` `azure:<tenant>` / ギャップは `gap:<area>`。差分レビューとルール例外の突合に使うため、null にしてはならない |
| `cloud` | `aws` / `azure` |
| `scopeId` | 所属アカウント / テナント |
| `type` | `aws.iam_user` `aws.iam_role` `aws.ec2_instance` `aws.account` `aws.account_region` `azure.app_registration` `azure.service_principal` `azure.managed_identity` `azure.storage_account` `azure.tenant` |
| `_unknown` | **証跡から確定できなかったフィールドのパス一覧**。ルールがこれに触れると finding の `confidence` が `low` になり `evidenceIncomplete: true` が付く |

### identities の主なフィールド

| フィールド | 意味 |
|---|---|
| `owner` / `owners` | 所有者。AWS はタグ由来のため通常 `null` |
| `lastUsedDays` | 最終利用からの日数。IAM ユーザーは**アクセスキーの最終利用**(コンソールログインではない) |
| `credentials[]` | `type` (`access_key`/`password`/`certificate`)、`status`、`ageDays`、`lifetimeDays`、`expiresAt`、`lastUsedDays` |
| `maxCredentialAgeDays` | 最も古い資格情報の経過日数 |
| `trust` | `federated` / `providers[]` / `wildcardSubject` / `unconditionalFederation` / `externalPrincipal` / `hasExternalId` / `orgFenced` / `conditionKeys[]`。`externalPrincipal` は同一 AWS Organizations のアカウントを除外して判定する(組織を列挙できなかった場合は除外できず `_unknown` が付く)。`orgFenced` は `aws:PrincipalOrgID` / `aws:PrincipalOrgPaths` 条件で組織に閉じていることを示す |
| `attachedTo[]` | このアイデンティティを使うワークロード。再利用 (NHI9) 検出に使う |
| `permissions` | `adminLike`、`policies[]`、`graphAppRoles[]` |
| `federatedCredentials[]` | FIC。20 件上限への接近を見る |
| `signInAudience` | Azure。`AzureADMyOrg` 以外は環境分離 (NHI8) の論点 |

### coverageGaps の `reason`

`permission_denied` / `not_collected` / `unreadable` / `truncated` /
`command_failed` / `exec_failed` / `cli_missing` / `scope_limited`

同一 `area` は 1 件に集約され、原因がより具体的なもの(`permission_denied` 等)が残る。

## findings.json(`scan.py` の出力)

```jsonc
{
  "schemaVersion": "1.0",
  "generatedAt": "...", "dbGeneratedAt": "...",
  "packs": [{"name": "nhi-core", "version": "1.0.0"}],
  "scopes": [{"cloud": "aws", "id": "1111...", "type": "aws.account"}],
  "coverageGaps": [ ... ],
  "summary":      {"critical": 6, "high": 13, "medium": 8, "low": 1, "info": 3, "total": 31},
  "suppressed":   [{"ruleId": "...", "resourceKey": "...", "pattern": "..."}],  // 例外で抑止した件
  "baseline":     "previous-findings.json",  // --baseline を渡したときのみ
  "resolved":     [{"ruleId": "...", "resourceKey": "...", "severity": "...", "title": "..."}],
  "owaspSummary": {"NHI1": {"count": 4, "worst": "medium", "rules": ["NHI-AWS-003", ...]}},
  "findings": [{
    "id": "NHI-AWS-005-0007",      // ruleId + 連番
    "ruleId": "NHI-AWS-005",
    "severity": "critical",
    "confidence": "high",           // 証跡不足なら low
    "evidenceIncomplete": false,
    "owasp": ["NHI6", "NHI8"],
    "docRef": "F-09",               // 評価基準ドキュメントの該当箇所
    "cloud": "aws", "scopeId": "111122223333",
    "resourceKey": "aws:111122223333:role/github-deploy",
    "resourceName": "github-deploy", "resourceType": "aws.iam_role",
    "state": "new",                 // --baseline 指定時のみ。new / existing
    "message": "...",   // Current
    "expected": "...", "remediation": "...", "validation": "...", "caveat": null
  }]
}
```

### 差分レビュー

`--baseline <前回の findings.json>` を付けると、各 finding に `state`(`new` / `existing`)が付き、
前回あって今回消えたものが `resolved` に入る。突合キーは `(ruleId, resourceKey)`。
**`resolved` は「検出されなくなった」ことしか意味しない。**証跡が取得できなくなった場合も
解消に見えるため、必ず `coverageGaps` と併せて読む。baseline が読めない場合は終了コード 1 で止まる
(差分のつもりが全件 new になる事故を防ぐ)。

### ルール例外

ルールに `"exceptions": ["<key の glob パターン>"]` を書くと、一致するエンティティを抑止できる。
**抑止は握りつぶしではない**: 件数とパターンが `suppressed` に残り、レポート冒頭にも表示される。

`--fail-on <severity>` を付けると、その重大度以上の finding があるとき終了コード 2 を返す
(CI ゲート用)。`--only` / `--exclude` に未知のルール ID を渡すと警告し、
`--only` が 1 件も一致しない場合は終了コード 1 で止まる(タイポで「検出ゼロ」を
成功と誤読しないため)。
