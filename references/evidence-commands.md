# 収集コマンドと必要権限

`collect_evidence.py` が実行するコマンドと、その根拠。すべて読み取り専用。
**実行前に `--dry-run` で一覧を提示し、承認を得ること。**

## AWS

必要権限は概ね `ReadOnlyAccess` + `SecurityAudit`。組織ポリシーの列挙は
管理アカウントまたは委任管理者が必要で、メンバーアカウントでは
`coverageGaps` に落ちる(それが正しい挙動)。

| 目的 | コマンド | 備考 |
|---|---|---|
| アカウント特定 | `sts get-caller-identity` | |
| IAM ユーザー | `iam list-users` → `iam list-access-keys` → `iam get-access-key-last-used` → `iam list-attached-user-policies` | ユーザーごとに追加呼び出し。`--max-principals` で上限 |
| IAM ロール | `iam list-roles` → `iam get-role` → `iam list-attached-role-policies` | `get-role` は `RoleLastUsed` と信頼ポリシーの取得に必要 |
| 権限分析 | `accessanalyzer list-analyzers` | `UNUSED_ACCESS` 型の有無を見る |
| ガードレール | `organizations list-policies --filter SERVICE_CONTROL_POLICY` → `organizations describe-policy` | 管理/委任アカウントのみ |
| IMDS 既定 | `ec2 get-instance-metadata-defaults` | **リージョン単位の設定**。評価対象リージョンごとに実行 |
| インスタンス | `ec2 describe-instances` | `MetadataOptions.HttpTokens` と `IamInstanceProfile` を見る |

`--regions` で指定しなかったリージョンは未評価になり、`aws:scope` の
`scope_limited` ギャップとして明示される。

### 手動で補う証跡(任意)

| ファイル | 内容 | 無いとどうなるか |
|---|---|---|
| `aws/<account>/role-usage.json` | `{"<RoleName>": ["<workload>", ...]}` | `attachedTo` が不明になり NHI9(再利用)判定が確度 `low` になる |

## Azure / Entra ID

必要権限は Microsoft Graph の `Application.Read.All`、`Directory.Read.All`、
`AuditLog.Read.All`、`Policy.Read.All`、および Azure RBAC の `Reader`。
サインインログの Graph 取得には **Entra ID P1 以上**が必要で、
無い場合は `coverageGaps` に落ち、未使用判定 (`NHI-AZ-004`) の確度が下がる。

| 目的 | コマンド | 備考 |
|---|---|---|
| 認証の生存確認 | `az account get-access-token --resource https://graph.microsoft.com` | **必須**。`az account show` はローカルキャッシュから応答するため、refresh token 失効時も成功してしまう(実測: AADSTS700082)。取得したトークンは証跡に保存しない |
| テナント特定 | `az account show` | キャッシュ応答なので生存確認には使えない |
| アプリ登録 | `az rest --url .../applications?$expand=owners` | 所有者を同時取得 |
| FIC | `az rest --url .../applications/{id}/federatedIdentityCredentials` | 20 件上限への接近を見る |
| サービスプリンシパル | `az rest --url .../servicePrincipals` | |
| Graph 権限カタログ | `az rest --url .../servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'&$select=id,appId,appRoles` | `appRoleId` を名前に解決するために必須 |
| 付与済み権限 | `az rest --url .../servicePrincipals/{id}/appRoleAssignments` | SP ごとに実行 |
| シークレット統制 | `az rest --url .../policies/defaultAppManagementPolicy` | |
| 同意統制 | `az rest --url .../policies/authorizationPolicy` | ユーザー同意の制限状況 |
| ログ退避 | `az rest --url https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview` | サインインログの長期保管 |
| SP サインイン | `az rest --url .../auditLogs/signIns?$filter=signInEventTypes/any(t:t eq 'servicePrincipal')` | P1 以上 |
| マネージド ID | `az identity list` | |
| ストレージ | `az storage account list` | `allowSharedKeyAccess` |

### 手動で補う証跡(任意)

| ファイル | 内容 | 無いとどうなるか |
|---|---|---|
| `azure/<tenant>/managed-identity-usage.json` | `{"<identity resourceId>": ["<resource>", ...]}` | `attachedTo` が不明になり NHI9 判定の確度が下がる |

Resource Graph で作る例:

```bash
az graph query -q "Resources | where isnotnull(identity) | project id, identity" -o json
```

## 実行時ガード

`collect_evidence.py` は次を**実行時に拒否**する。

- AWS: `get-` / `list-` / `describe-` / `generate-` 以外の動詞
  (グローバルオプションの位置に関わらず動詞を正しく解決する)
- Azure: `show` / `list` 以外の末尾サブコマンド、および `az rest --method` が `get` 以外
- `aws` / `az` 以外のバイナリ
