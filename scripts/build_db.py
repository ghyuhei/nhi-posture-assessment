#!/usr/bin/env python3
"""Normalize raw AWS/Azure evidence into an NHI database (nhi-db.json).

Offline and read-only: reads only files under the evidence directory. Anything
that could not be collected becomes a coverageGap plus an `_unknown` marker on
the affected entity, so the rule engine can lower confidence instead of
silently reporting a clean result.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

SCHEMA_VERSION = "1.0"
ADMIN_POLICY_HINTS = ("AdministratorAccess", "PowerUserAccess", "IAMFullAccess")
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
# A sign-in sample must reach back at least this far before absence from it
# can be read as disuse.
SIGNIN_MIN_REACH_DAYS = 30


def parse_time(value):
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days_between(later, earlier):
    if not later or not earlier:
        return None
    return max(0, int((later - earlier).total_seconds() // 86400))


def load_json(path: Path, gaps, area, required=True):
    if not path.exists():
        if required:
            gaps.append({"area": area, "reason": "not_collected",
                         "detail": f"{path.name} が証跡に存在しない"})
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        gaps.append({"area": area, "reason": "unreadable", "detail": f"{path.name}: {exc}"})
        return None


def unwrap(payload, *keys):
    """AWS CLI and Graph wrap results differently; accept both shapes."""
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    for key in (*keys, "value", "Items"):
        if isinstance(payload, dict) and isinstance(payload.get(key), list):
            return payload[key]
    return []


# --------------------------------------------------------------------------
# AWS
# --------------------------------------------------------------------------
def decode_policy(doc):
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            return json.loads(unquote(doc))
        except json.JSONDecodeError:
            return {}
    return {}


def analyze_trust(doc, account_id, org_accounts=None):
    """Classify an IAM role trust policy for federation and third-party risk.

    `org_accounts` is the set of account ids in the same AWS Organization. A
    sibling account is not a third party, and flagging it as one buries the
    genuine external-trust findings in noise. When the organization cannot be
    enumerated the caller marks the result as unknown rather than guessing.
    """
    org_accounts = org_accounts or set()
    trust = {"federated": False, "providers": [], "wildcardSubject": False,
             "externalPrincipal": False, "hasExternalId": False,
             "unconditionalFederation": False, "orgFenced": False, "conditionKeys": []}
    for stmt in doc.get("Statement", []) or []:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {}) or {}
        if isinstance(principal, str):
            principal = {"AWS": principal}
        federated = principal.get("Federated")
        if federated:
            trust["federated"] = True
            for p in (federated if isinstance(federated, list) else [federated]):
                provider = str(p).split("/", 1)[-1] if "oidc-provider/" in str(p) else str(p)
                if provider not in trust["providers"]:
                    trust["providers"].append(provider)
        for arn in _as_list(principal.get("AWS")):
            arn = str(arn)
            if arn == "*":
                trust["externalPrincipal"] = True
            elif arn.startswith("arn:") and account_id:
                parts = arn.split(":")
                owner = parts[4] if len(parts) > 4 else ""
                if owner and owner != account_id and owner not in org_accounts:
                    trust["externalPrincipal"] = True

        condition = stmt.get("Condition", {}) or {}
        for operator, mapping in condition.items():
            if not isinstance(mapping, dict):
                continue
            for key, value in mapping.items():
                lowered = key.lower()
                if lowered not in trust["conditionKeys"]:
                    trust["conditionKeys"].append(lowered)
                if lowered == "sts:externalid":
                    trust["hasExternalId"] = True
                if lowered in ("aws:principalorgid", "aws:principalorgpaths"):
                    # Access is already fenced to the organization.
                    trust["orgFenced"] = True
                if lowered.endswith(":sub"):
                    values = _as_list(value)
                    if operator.startswith("StringLike") or any("*" in str(v) for v in values):
                        trust["wildcardSubject"] = True
        if federated and not condition:
            # No condition at all on a federated Allow accepts every workload
            # that provider can mint a token for.
            trust["wildcardSubject"] = True
            trust["unconditionalFederation"] = True
    return trust


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def policy_names(entry):
    names = []
    for item in _as_list(entry.get("AttachedPolicies")):
        if isinstance(item, dict):
            names.append(item.get("PolicyName") or item.get("PolicyArn", ""))
        else:
            names.append(str(item))
    names.extend(str(n) for n in _as_list(entry.get("InlinePolicyNames")))
    return [n for n in names if n]


def build_aws(root: Path, now, gaps, identities, resources, scopes, regions):
    aws_root = root / "aws"
    if not aws_root.is_dir():
        return
    for account_dir in sorted(p for p in aws_root.iterdir() if p.is_dir()):
        account_id = account_dir.name
        unknown_scope = []
        settings = {}

        analyzers = load_json(account_dir / "access-analyzers.json", gaps,
                              f"aws:{account_id}:access-analyzer")
        if analyzers is None:
            unknown_scope.append("settings.unusedAccessAnalyzer")
        else:
            settings["unusedAccessAnalyzer"] = any(
                "UNUSED_ACCESS" in str(a.get("type", "")).upper()
                for a in unwrap(analyzers, "analyzers"))

        scps = load_json(account_dir / "scp-effective.json", gaps, f"aws:{account_id}:scp")
        if scps is None:
            unknown_scope.append("settings.scpDeniesCreateAccessKey")
        else:
            settings["scpDeniesCreateAccessKey"] = _scp_denies(scps, "iam:CreateAccessKey")

        scopes.append({"key": f"aws:{account_id}", "cloud": "aws", "id": account_id,
                       "type": "aws.account", "name": account_id, "settings": settings,
                       "_unknown": unknown_scope})

        imds_files = sorted(account_dir.rglob("imds-defaults.json"))
        if not imds_files:
            gaps.append({"area": f"aws:{account_id}:imds-defaults", "reason": "not_collected",
                         "detail": "IMDS のアカウント既定を取得できていない"})
        for imds_path in imds_files:
            imds = load_json(imds_path, gaps, f"aws:{account_id}:imds-defaults") or {}
            region = imds.get("Region") or imds_path.parent.name
            scopes.append({
                "key": f"aws:{account_id}:{region}",
                "cloud": "aws", "id": account_id, "type": "aws.account_region",
                "name": f"{account_id}/{region}", "region": region,
                "settings": {"imdsDefaultHttpTokens": imds.get("HttpTokens")},
                "_unknown": [] if imds else ["settings.imdsDefaultHttpTokens"]})

        _aws_users(account_dir, account_id, now, gaps, identities)
        _aws_roles(account_dir, account_id, now, gaps, identities)
        _aws_instances(account_dir, account_id, gaps, resources, regions)


def _scp_denies(payload, action):
    """True only for an unconditional Deny that covers `action` on all resources.

    A conditional Deny (for example "deny everything outside ap-northeast-1")
    also matches on Action alone, so counting it would report a guardrail that
    does not actually exist. When in doubt this returns False, which surfaces
    the finding rather than hiding it.
    """
    service = action.split(":", 1)[0]
    for policy in unwrap(payload, "Policies", "policies"):
        doc = decode_policy(policy.get("Content") or policy.get("Document") or policy)
        for stmt in doc.get("Statement", []) or []:
            if stmt.get("Effect") != "Deny" or stmt.get("Condition"):
                continue
            if stmt.get("NotAction"):
                continue
            actions = [str(a) for a in _as_list(stmt.get("Action"))]
            if not (action in actions or f"{service}:*" in actions or "*" in actions):
                continue
            resources = [str(r) for r in _as_list(stmt.get("Resource"))]
            if "*" in resources:
                return True
    return False


def _aws_users(account_dir, account_id, now, gaps, identities):
    payload = load_json(account_dir / "iam-users.json", gaps, f"aws:{account_id}:iam-users")
    for user in unwrap(payload, "Users"):
        name = user.get("UserName", "unknown")
        creds = []
        for key in _as_list(user.get("AccessKeys")):
            created = parse_time(key.get("CreateDate"))
            creds.append({
                "type": "access_key",
                "id": key.get("AccessKeyId"),
                "status": key.get("Status"),
                "createdAt": key.get("CreateDate"),
                "ageDays": days_between(now, created),
                "lastUsedDays": days_between(now, parse_time(key.get("LastUsedDate"))),
                "expiresAt": None,
            })
        policies = policy_names(user)
        identities.append({
            "key": f"aws:{account_id}:user/{name}",
            "cloud": "aws", "scopeId": account_id, "type": "aws.iam_user", "name": name,
            "owner": _tag(user, "Owner"), "createdAt": user.get("CreateDate"),
            "lastUsedDays": min([c["lastUsedDays"] for c in creds
                                 if c["lastUsedDays"] is not None], default=None),
            "consoleLastUsedDays": days_between(now, parse_time(user.get("PasswordLastUsed"))),
            "credentials": creds,
            "maxCredentialAgeDays": max([c["ageDays"] for c in creds if c["ageDays"] is not None], default=None),
            "attachedTo": [],
            "permissions": {"policies": policies,
                            "adminLike": any(h in p for p in policies for h in ADMIN_POLICY_HINTS)},
            "_unknown": [] if "AccessKeys" in user else ["credentials"],
        })


def _aws_roles(account_dir, account_id, now, gaps, identities):
    payload = load_json(account_dir / "iam-roles.json", gaps, f"aws:{account_id}:iam-roles")
    org = load_json(account_dir / "org-accounts.json", gaps, f"aws:{account_id}:org-accounts",
                    required=False)
    org_accounts = {str(a.get("Id")) for a in unwrap(org, "Accounts") if a.get("Id")}
    usage = load_json(account_dir / "role-usage.json", gaps, f"aws:{account_id}:role-usage",
                      required=False) or {}
    for role in unwrap(payload, "Roles"):
        name = role.get("RoleName", "unknown")
        doc = decode_policy(role.get("AssumeRolePolicyDocument"))
        trust = analyze_trust(doc, account_id, org_accounts)
        last_used = parse_time((role.get("RoleLastUsed") or {}).get("LastUsedDate"))
        policies = policy_names(role)
        attached = usage.get(name) or usage.get(role.get("Arn", "")) or []
        identities.append({
            "key": f"aws:{account_id}:role/{name}",
            "cloud": "aws", "scopeId": account_id, "type": "aws.iam_role", "name": name,
            "owner": _tag(role, "Owner"), "createdAt": role.get("CreateDate"),
            "lastUsedDays": days_between(now, last_used),
            "serviceLinked": str(role.get("Path", "")).startswith("/aws-service-role/"),
            "credentials": [], "attachedTo": attached,
            "trust": trust,
            "permissions": {"policies": policies,
                            "adminLike": any(h in p for p in policies for h in ADMIN_POLICY_HINTS)},
            "_unknown": ([] if usage else ["attachedTo"])
                        + ([] if org_accounts or not trust["externalPrincipal"]
                           else ["trust.externalPrincipal"]),
        })


def _aws_instances(account_dir, account_id, gaps, resources, regions):
    scanned = {p.parent.name for p in account_dir.rglob("ec2-instances.json")}
    for region in regions:
        if region not in scanned:
            gaps.append({"area": f"aws:{account_id}:{region}:ec2-instances",
                         "reason": "not_collected",
                         "detail": f"リージョン {region} のインスタンスを取得できていない"})
    for path in sorted(account_dir.rglob("ec2-instances.json")):
        payload = load_json(path, gaps, f"aws:{account_id}:ec2-instances")
        reservations = unwrap(payload, "Reservations")
        instances = []
        for res in reservations:
            instances.extend(res.get("Instances", []) if isinstance(res, dict) else [])
        if not instances:
            instances = [i for i in reservations if isinstance(i, dict) and "InstanceId" in i]
        for inst in instances:
            meta = inst.get("MetadataOptions", {}) or {}
            has_role = bool(inst.get("IamInstanceProfile"))
            resources.append({
                "key": f"aws:{account_id}:instance/{inst.get('InstanceId')}",
                "cloud": "aws", "scopeId": account_id, "type": "aws.ec2_instance",
                "name": inst.get("InstanceId"),
                "imdsHttpTokens": meta.get("HttpTokens"),
                "imdsEndpoint": meta.get("HttpEndpoint"),
                "hasInstanceRole": has_role,
                "_unknown": [] if meta else ["imdsHttpTokens"],
            })


def _tag(entry, key):
    for tag in _as_list(entry.get("Tags")):
        if isinstance(tag, dict) and tag.get("Key", "").lower() == key.lower():
            return tag.get("Value")
    return None


# --------------------------------------------------------------------------
# Azure
# --------------------------------------------------------------------------
def build_azure(root: Path, now, gaps, identities, resources, scopes):
    az_root = root / "azure"
    if not az_root.is_dir():
        return
    for tenant_dir in sorted(p for p in az_root.iterdir() if p.is_dir()):
        tenant_id = tenant_dir.name
        unknown_scope = []
        settings = {}

        policy = load_json(tenant_dir / "default-app-mgmt-policy.json", gaps,
                           f"azure:{tenant_id}:app-mgmt-policy")
        if policy is None:
            unknown_scope.append("settings.appMgmtPolicyRestrictsPasswords")
        else:
            settings["appMgmtPolicyRestrictsPasswords"] = _restricts_passwords(policy)

        authz = load_json(tenant_dir / "authorization-policy.json", gaps,
                          f"azure:{tenant_id}:authorization-policy")
        if authz is None:
            unknown_scope.append("settings.userConsentRestricted")
        else:
            grants = ((authz.get("defaultUserRolePermissions") or {})
                      .get("permissionGrantPoliciesAssigned") or [])
            # An empty list means user consent is disabled. The "legacy" policy
            # permits consent to any permission and is the risky default.
            legacy = any(str(g).endswith("microsoft-user-default-legacy") for g in grants)
            settings["userConsentRestricted"] = (not grants) or (not legacy)

        diag = load_json(tenant_dir / "diagnostic-settings.json", gaps,
                         f"azure:{tenant_id}:diagnostic-settings")
        if diag is None:
            unknown_scope.append("settings.signInLogExport")
        else:
            settings["signInLogExport"] = _exports_signins(diag)

        scopes.append({"key": f"azure:{tenant_id}", "cloud": "azure", "id": tenant_id,
                       "type": "azure.tenant", "name": tenant_id, "settings": settings,
                       "_unknown": unknown_scope})

        signins = load_json(tenant_dir / "sp-signins.json", gaps,
                            f"azure:{tenant_id}:sp-signins", required=False)
        last_signin, signin_reach = _last_signin_map(signins, now)
        if signins is not None and (signin_reach is None or signin_reach < SIGNIN_MIN_REACH_DAYS):
            gaps.append({
                "area": f"azure:{tenant_id}:sp-signins",
                "reason": "sample_too_shallow",
                "detail": (f"サインインの標本が過去 {signin_reach} 日分しか遡れていない"
                           f"(必要 {SIGNIN_MIN_REACH_DAYS} 日)。未使用判定はできない。"
                           f"診断設定で長期退避したログを使うこと。")})
        approles = _app_role_map(load_json(tenant_dir / "app-role-assignments.json", gaps,
                                           f"azure:{tenant_id}:app-role-assignments", required=False),
                                 load_json(tenant_dir / "graph-app-roles.json", gaps,
                                           f"azure:{tenant_id}:graph-app-roles", required=False))

        signin_usable = (signins is not None and signin_reach is not None
                         and signin_reach >= SIGNIN_MIN_REACH_DAYS)
        _azure_apps(tenant_dir, tenant_id, now, gaps, identities, last_signin, approles,
                    signin_usable)
        _azure_managed_identities(tenant_dir, tenant_id, gaps, identities)
        _azure_storage(tenant_dir, tenant_id, gaps, resources)


def _restricts_passwords(policy):
    """True when the tenant default policy restricts secret creation or lifetime.

    The policy carries both applicationRestrictions and servicePrincipalRestrictions;
    either one in place counts as the guardrail existing.
    """
    wanted = ("passwordAddition", "customPasswordAddition", "passwordLifetime",
              "symmetricKeyAddition", "symmetricKeyLifetime")
    for block in ("applicationRestrictions", "servicePrincipalRestrictions"):
        for r in ((policy.get(block) or {}).get("passwordCredentials") or []):
            if r.get("state") == "enabled" and r.get("restrictionType") in wanted:
                return True
    return False


def _exports_signins(diag):
    for setting in unwrap(diag, "value"):
        props = setting.get("properties") if isinstance(setting.get("properties"), dict) else setting
        for log in props.get("logs", []) or []:
            category = log.get("category", "")
            if log.get("enabled") and category in ("SignInLogs", "ServicePrincipalSignInLogs"):
                return True
    return False


def _last_signin_map(signins, now):
    """Return (lastUsedDays per appId, how far back the sample reaches in days).

    The sign-in query returns the most recent events tenant-wide, so a service
    principal missing from the sample may simply have signed in before the
    window starts. The reach is returned so the caller can refuse to judge
    disuse on a sample that is too shallow.
    """
    out, oldest = {}, None
    for entry in unwrap(signins, "value"):
        app_id = entry.get("appId") or entry.get("servicePrincipalId")
        stamp = parse_time(entry.get("createdDateTime") or entry.get("lastSignInDateTime"))
        if not app_id or not stamp:
            continue
        if app_id not in out or stamp > out[app_id]:
            out[app_id] = stamp
        if oldest is None or stamp < oldest:
            oldest = stamp
    reach = days_between(now, oldest) if oldest else None
    return {k: days_between(now, v) for k, v in out.items()}, reach


def _app_role_map(assignments, catalog):
    role_names = {}
    for sp in unwrap(catalog, "value"):
        if sp.get("appId") == GRAPH_APP_ID or "appRoles" in sp:
            for role in sp.get("appRoles", []) or []:
                role_names[role.get("id")] = role.get("value")
    out = {}
    for a in unwrap(assignments, "value"):
        principal = a.get("principalId")
        value = a.get("appRoleValue") or role_names.get(a.get("appRoleId"))
        if not principal or not value:
            continue
        out.setdefault(principal, []).append(value)
    return out


def _azure_apps(tenant_dir, tenant_id, now, gaps, identities, last_signin, approles, have_signins):
    apps = load_json(tenant_dir / "applications.json", gaps, f"azure:{tenant_id}:applications")
    sps = {sp.get("appId"): sp for sp in unwrap(
        load_json(tenant_dir / "service-principals.json", gaps,
                  f"azure:{tenant_id}:service-principals", required=False), "value")}
    for app in unwrap(apps, "value"):
        name = app.get("displayName", "unknown")
        app_id = app.get("appId")
        sp = sps.get(app_id, {})
        creds = []
        for cred, kind in ((app.get("passwordCredentials") or [], "password"),
                           (app.get("keyCredentials") or [], "certificate")):
            for c in cred:
                start = parse_time(c.get("startDateTime"))
                end = parse_time(c.get("endDateTime"))
                creds.append({
                    "type": kind, "id": c.get("keyId"),
                    "createdAt": c.get("startDateTime"), "expiresAt": c.get("endDateTime"),
                    "ageDays": days_between(now, start),
                    "lifetimeDays": days_between(end, start),
                    "expiredDays": days_between(now, end) if end and end < now else None,
                    "status": "Expired" if end and end < now else "Active",
                })
        owners = [o.get("id") or o.get("userPrincipalName")
                  for o in (app.get("owners") or []) if isinstance(o, dict)]
        unknown = []
        if "owners" not in app:
            unknown.append("owners")
        if not have_signins or (app_id not in last_signin):
            unknown.append("lastUsedDays")
        if not sps:
            unknown.append("permissions.graphAppRoles")
        if "federatedIdentityCredentials" not in app:
            unknown.append("federatedCredentials")
        identities.append({
            "key": f"azure:{tenant_id}:app/{app_id}",
            "cloud": "azure", "scopeId": tenant_id, "type": "azure.app_registration",
            "name": name, "appId": app_id, "owners": owners,
            "owner": owners[0] if owners else None,
            "createdAt": app.get("createdDateTime"),
            "signInAudience": app.get("signInAudience"),
            "federatedCredentials": app.get("federatedIdentityCredentials") or [],
            "credentials": creds,
            "lastUsedDays": last_signin.get(app_id),
            "attachedTo": [],
            "permissions": {"graphAppRoles": approles.get(sp.get("id"), [])},
            "_unknown": unknown,
        })


def _azure_managed_identities(tenant_dir, tenant_id, gaps, identities):
    payload = load_json(tenant_dir / "managed-identities.json", gaps,
                        f"azure:{tenant_id}:managed-identities", required=False)
    usage = load_json(tenant_dir / "managed-identity-usage.json", gaps,
                      f"azure:{tenant_id}:managed-identity-usage", required=False) or {}
    for mi in unwrap(payload, "value"):
        mid = mi.get("id") or mi.get("principalId")
        identities.append({
            "key": f"azure:{tenant_id}:mi/{mi.get('name') or mid}",
            "cloud": "azure", "scopeId": tenant_id, "type": "azure.managed_identity",
            "name": mi.get("name") or mid, "owners": [], "owner": None,
            "credentials": [],
            "attachedTo": usage.get(mid, []),
            "federatedCredentials": mi.get("federatedIdentityCredentials") or [],
            "permissions": {},
            "_unknown": ([] if usage else ["attachedTo"]) + ["federatedCredentials"],
        })


def _azure_storage(tenant_dir, tenant_id, gaps, resources):
    payload = load_json(tenant_dir / "storage-accounts.json", gaps,
                        f"azure:{tenant_id}:storage-accounts", required=False)
    for acct in unwrap(payload, "value"):
        resources.append({
            "key": f"azure:{tenant_id}:storage/{acct.get('name')}",
            "cloud": "azure", "scopeId": tenant_id, "type": "azure.storage_account",
            "name": acct.get("name"),
            "allowSharedKeyAccess": acct.get("allowSharedKeyAccess"),
            "_unknown": [] if "allowSharedKeyAccess" in acct else ["allowSharedKeyAccess"],
        })


# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Normalize NHI evidence into nhi-db.json")
    ap.add_argument("evidence", help="evidence directory produced by collect_evidence.py")
    ap.add_argument("-o", "--output", default="nhi-db.json")
    args = ap.parse_args(argv)

    root = Path(args.evidence)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1

    have_aws = (root / "aws").is_dir()
    have_azure = (root / "azure").is_dir()
    if not (have_aws or have_azure):
        print(f"error: {root} に aws/ も azure/ も無い。証跡が空のデータベースは"
              f"『問題なし』と誤読されるため生成しない。", file=sys.stderr)
        return 1

    gaps, identities, resources, scopes = [], [], [], []
    meta = load_json(root / "meta.json", gaps, "meta", required=False) or {}
    now = parse_time(meta.get("collectedAt")) or datetime.now(timezone.utc)
    gaps.extend(meta.get("coverageGaps", []) or [])

    regions = [r.strip() for r in str(meta.get("regions", "")).split(",") if r.strip()]
    if regions and (root / "aws").is_dir():
        gaps.append({"area": "aws:scope", "reason": "scope_limited",
                     "detail": f"収集対象リージョン: {', '.join(regions)}。"
                               f"これ以外のリージョンは未評価。"})
    build_aws(root, now, gaps, identities, resources, scopes, regions)
    build_azure(root, now, gaps, identities, resources, scopes)

    # One area is one gap. A collector-reported cause (permission_denied) is
    # more informative than the normalizer noticing the file is absent.
    ranked = {"not_collected": 0, "unreadable": 1, "truncated": 2,
              "command_failed": 3, "exec_failed": 3, "cli_missing": 4,
              "scope_limited": 4, "permission_denied": 5, "auth_expired": 6}
    best: dict = {}
    for gap in gaps:
        area = gap.get("area")
        if area not in best or ranked.get(gap.get("reason"), 1) > ranked.get(best[area].get("reason"), 1):
            best[area] = gap
    gaps = [{**g, "key": f"gap:{g.get('area')}"} for g in best.values()]

    db = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": now.isoformat(timespec="seconds"),
        "evidenceDir": str(root),
        "scopes": scopes,
        "identities": identities,
        "resources": resources,
        "coverageGaps": gaps,
    }
    for scope in scopes:
        if scope.get("type") not in ("aws.account", "azure.tenant"):
            continue
        owned = unowned = 0
        for ident in identities:
            if ident.get("scopeId") != scope.get("id") or ident.get("serviceLinked"):
                continue
            if ident.get("owner") or (ident.get("owners") or []):
                owned += 1
            else:
                unowned += 1
        total = owned + unowned
        scope["settings"]["identityCount"] = total
        scope["settings"]["identitiesWithoutOwner"] = unowned
        scope["settings"]["ownershipRatio"] = round(owned / total, 3) if total else None
        if not total:
            scope.setdefault("_unknown", []).append("settings.ownershipRatio")

    # A hollow scope can be created from an empty account directory, so scopes
    # alone are not substance. With no identity and no resource there is nothing
    # to assess, and a near-empty database scans clean.
    if not (identities or resources):
        print("error: 証跡から NHI もリソースも 1 件も構築できなかった。収集が失敗しているか、"
              "ディレクトリ構成が想定と異なる。評価対象の無いデータベースは生成しない。",
              file=sys.stderr)
        for gap in gaps:
            print(f"  GAP {gap.get('area')}: {gap.get('reason')}", file=sys.stderr)
        return 1

    Path(args.output).write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"scopes={len(scopes)} identities={len(identities)} resources={len(resources)} "
          f"coverageGaps={len(gaps)}")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
