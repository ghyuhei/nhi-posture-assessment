# ルールの書き方(クエリ言語仕様)

ルールパックは `rules/*.json`。`scan.py` が全ファイルを読み、`target` で指定した
コレクションの各要素に対して `where` 述語を評価する。CodeQL のクエリに相当する。

## ルールの形

```json
{
  "id": "NHI-AWS-005",
  "title": "OIDC 信頼ポリシーの sub がワイルドカードを許している",
  "severity": "critical",
  "owasp": ["NHI6", "NHI8"],
  "docRef": "F-09",
  "target": "identities",
  "where": { ... },
  "message": "ロール {name} の信頼ポリシーが sub のワイルドカードを許容している。",
  "expected": "...", "remediation": "...", "validation": "...",
  "caveat": "任意。判定を信じてよい前提条件を書く。"
}
```

- `severity`: `critical` / `high` / `medium` / `low` / `info`
- `target`: `identities` / `resources` / `scopes` / `coverageGaps`
- `message` 内の `{path}` は対象要素の値で置換される(解決できなければ `?`)

## 述語

論理結合は `{"all":[...]}` / `{"any":[...]}` / `{"none":[...]}`。
葉は `{"field": "<path>", "op": "<op>", "value": <v>}`。

### パス

`.` 区切り。セグメント末尾の `[]` はリストを展開する。

| パス | 意味 |
|---|---|
| `type` | スカラー |
| `permissions.adminLike` | ネスト |
| `credentials[].status` | `credentials` の各要素の `status` を平坦化 |
| `attachedTo` | リスト自体を 1 個の値として返す(`count_*` 用) |

展開時、キーが存在しない要素は `None` のスロットとして保持される。これにより
「どれか 1 つでも欠けている」を `missing` で判定できる。

### 演算子

| op | 意味 |
|---|---|
| `eq` / `ne` | 一致 / 不一致 |
| `gt` / `gte` / `lt` / `lte` | 数値比較 |
| `in` / `nin` | 値が集合に含まれる / 含まれない |
| `contains` / `ncontains` | 文字列・リストの部分一致 |
| `regex` / `startswith` | 文字列マッチ |
| `exists` / `missing` | 値の有無 |
| `count_gte` / `count_lte` | リスト長の比較 |

**重要な意味論が 2 つある。**

1. **コレクションに対する比較は存在量化**。`credentials[].status eq "Active"` は
   「どれか 1 つでも Active」を意味する。
2. **`ne` は fail-closed**。値が取得できていない場合 `ne` は真になる。
   統制の有無を見るルール(`settings.* ne required` 等)で、
   **未取得を「統制あり」と誤読しない**ための設計。未取得であることは
   `coverageGaps` と `_unknown` で別途明示され、finding の確度は `low` に落ちる。

### forEach — 要素スコープの量化子

複数条件を**同一要素**に束縛したいときに使う。使わないと、条件ごとに別の要素が
マッチしてしまう。

```jsonc
// NG: 「新しい有効なキー」と「古い無効なキー」の組み合わせでも成立してしまう
{"all": [
  {"field": "credentials[].status",  "op": "eq", "value": "Active"},
  {"field": "credentials[].ageDays", "op": "gt", "value": 90}]}

// OK: 1 本のキーが Active かつ 90 日超であることを要求する
{"forEach": "credentials",
 "where": {"all": [
   {"field": "status",  "op": "eq", "value": "Active"},
   {"field": "ageDays", "op": "gt", "value": 90}]}}
```

## しきい値

`value` に `"@name"` と書くとパック先頭の `thresholds` を参照する。
組織のポリシーに合わせるときは `thresholds` だけを直せばよい。

```json
"thresholds": { "accessKeyMaxAgeDays": 90, "identityUnusedDays": 90,
                "credentialMaxLifetimeDays": 180, "sharedIdentityFanout": 3,
                "ficNearLimit": 16 }
```

## 例外(抑止)

break-glass ロールなど、恒久的に許容するリソースはルールに `exceptions` を書く。
`key` に対する glob(`fnmatch`)で照合する。

```json
"exceptions": ["aws:*:user/break-glass-*", "aws:111122223333:role/vendor-approved"]
```

**抑止された件数とパターンは `findings.json` の `suppressed` に残り、HTML レポートの冒頭にも
表示される。**黙って消えることはない。恒久例外は定期的に妥当性を見直すこと。

## 追加時のチェックリスト

1. `id` は `NHI-<AWS|AZ|X>-<連番>`。既存 ID を再利用しない。
2. `owasp` に OWASP NHI Top 10 のカテゴリを付ける。付けられないなら、
   そのルールが本当に NHI の問題かを再考する。
3. 同一要素への束縛が必要なら `forEach` を使う。
4. **より具体的なルールを足したら、汎用ルール側で除外して二重報告を防ぐ**
   (例: `NHI-AWS-005B` を足したので `NHI-AWS-005` は
   `trust.unconditionalFederation ne true` を条件に加えている)。
5. 到達可能性で severity を変えるなら別ルールに分ける
   (例: `NHI-AWS-009` はロール付き=critical、`NHI-AWS-009B` はロール無し=medium)。
6. `examples/fixture-evidence` に**検出される例と検出されない例の両方**を足す。
7. `scripts/selftest.py` の期待値を更新し、実行して緑にする。
