#!/usr/bin/env python3
"""Read-only NHI evidence collector for AWS and Azure.

Every command executed is on an explicit allow-list of read-only operations.
Anything that fails is recorded as a coverage gap rather than skipped silently,
so a permission problem can never be mistaken for a clean result.

Always run with --dry-run first and show the command list to the operator.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

AWS_READONLY_VERBS = ("get-", "list-", "describe-", "generate-")
AWS_VALUED_OPTIONS = {"--profile", "--region", "--output", "--endpoint-url", "--ca-bundle",
                     "--cli-read-timeout", "--cli-connect-timeout", "--query"}
AZ_READONLY = {"show", "list", "rest", "get-access-token"}
AZ_VALUED_OPTIONS = {"--method", "--url", "--subscription", "--output", "--query", "--body",
                    "--headers", "--resource", "-o"}
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


class CredentialError(RuntimeError):
    """Authentication is not usable; collecting further would yield a hollow tree."""


class Collector:
    def __init__(self, outdir: Path, dry_run: bool, timeout: int):
        self.outdir = outdir
        self.dry_run = dry_run
        self.timeout = timeout
        self.gaps: list[dict] = []
        self.commands: list[str] = []

    # -- process -----------------------------------------------------------
    @staticmethod
    def _positional(argv, valued_options):
        """Return the non-option tokens, skipping global options and their values."""
        tokens, i = [], 1
        while i < len(argv):
            tok = argv[i]
            if tok.startswith("-"):
                i += 2 if tok in valued_options else 1
                continue
            tokens.append(tok)
            i += 1
        return tokens

    def _guard(self, argv):
        if argv[0] == "aws":
            tokens = self._positional(argv, AWS_VALUED_OPTIONS)
            verb = tokens[1] if len(tokens) > 1 else ""
            if not verb.startswith(AWS_READONLY_VERBS):
                raise PermissionError(f"refusing non-read-only AWS command: {' '.join(argv)}")
        elif argv[0] == "az":
            tokens = self._positional(argv, AZ_VALUED_OPTIONS)
            leaf = tokens[-1] if tokens else ""
            head = tokens[0] if tokens else ""
            if not (leaf in AZ_READONLY or head == "rest"):
                raise PermissionError(f"refusing non-read-only az command: {' '.join(argv)}")
            if "--method" in argv:
                method = argv[argv.index("--method") + 1] if argv.index("--method") + 1 < len(argv) else ""
                if method.lower() != "get":
                    raise PermissionError(f"refusing az rest --method {method}")
        else:
            raise PermissionError(f"unsupported binary: {argv[0]}")

    @staticmethod
    def _shellsafe(argv):
        """Render a command so an operator can paste it without shell mangling."""
        return " ".join(shlex.quote(a) if any(ch in a for ch in "$&?*()<>| '\"") else a
                        for a in argv)

    def run(self, argv, area):
        self._guard(argv)
        self.commands.append(self._shellsafe(argv))
        if self.dry_run:
            return None
        env = dict(os.environ, AWS_RETRY_MODE="adaptive", AWS_MAX_ATTEMPTS="10",
                   AWS_PAGER="")
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=self.timeout, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.gap(area, "exec_failed", str(exc))
            return None
        if proc.returncode != 0:
            if _expired(proc.stderr):
                self.gap(area, "auth_expired", proc.stderr.strip()[:400])
                raise CredentialError(
                    "認証セッションが失効している。再認証してから実行すること。"
                    f" 詳細: {proc.stderr.strip().splitlines()[0][:200]}")
            reason = "permission_denied" if _denied(proc.stderr) else "command_failed"
            self.gap(area, reason, proc.stderr.strip()[:400])
            return None
        if not proc.stdout.strip():
            return {}
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            self.gap(area, "unparsable", f"{exc}")
            return None

    def probe_token(self, resource):
        """Force a real token request. The token value is never stored."""
        argv = ["az", "account", "get-access-token", "--resource", resource,
                "--query", "expiresOn", "-o", "tsv"]
        self._guard(argv)
        self.commands.append(self._shellsafe(argv))
        if self.dry_run:
            return
        env = dict(os.environ, AZURE_CORE_OUTPUT="tsv")
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=self.timeout, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CredentialError(f"Azure トークン取得に失敗した: {exc}") from exc
        if proc.returncode != 0:
            self.gap("azure:token", "auth_expired", proc.stderr.strip()[:400])
            raise CredentialError(
                "Azure の認証セッションが失効している(`az account show` はキャッシュのため成功する)。"
                " `az login` で再認証してから実行すること。")

    def note_repeated(self, template, per):
        """Record a per-item call shape so --dry-run shows what really runs."""
        if self.dry_run:
            self.commands.append(f"{template}   # {per} ごとに繰り返し")

    def gap(self, area, reason, detail=""):
        self.gaps.append({"area": area, "reason": reason, "detail": detail})

    def write(self, relpath, payload):
        if self.dry_run or payload is None:
            return
        path = self.outdir / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    # -- graph paging ------------------------------------------------------
    def graph(self, url, area, page_limit=20):
        items, pages = [], 0
        while url and pages < page_limit:
            payload = self.run(["az", "rest", "--method", "get", "--url", url], area)
            if payload is None:
                return None
            items.extend(payload.get("value", []) if isinstance(payload, dict) else [])
            url = payload.get("@odata.nextLink") if isinstance(payload, dict) else None
            pages += 1
        if url:
            self.gap(area, "truncated", f"page limit {page_limit} reached")
        return {"value": items}


def _denied(stderr: str) -> bool:
    lowered = (stderr or "").lower()
    return any(t in lowered for t in ("accessdenied", "not authorized", "unauthorized",
                                      "forbidden", "authorizationfailed", "insufficient privileges"))


def _expired(stderr: str) -> bool:
    lowered = (stderr or "").lower()
    return any(t in lowered for t in ("invalidclienttokenid", "expiredtoken",
                                      "the security token included in the request is invalid",
                                      "unable to locate credentials", "sso session associated",
                                      "please run 'az login'", "az login",
                                      "aadsts700082", "aadsts700081", "aadsts50173",
                                      "refresh token has expired", "token has expired",
                                      "re-authentication", "interactionrequired"))


# --------------------------------------------------------------------------
def collect_aws(c: Collector, profile, regions, max_principals):
    base = ["aws"] + (["--profile", profile] if profile else [])
    ident = c.run(base + ["sts", "get-caller-identity"], "aws:identity")
    if ident is None and not c.dry_run:
        raise CredentialError(
            "AWS の認証に失敗した。`aws sts get-caller-identity` が通る状態にしてから再実行する。"
            f"{' profile=' + profile if profile else ''}")
    account = (ident or {}).get("Account", "unknown-account")
    root = f"aws/{account}"

    c.note_repeated(" ".join(base + ["iam", "list-access-keys", "--user-name", "<user>"]), "IAM ユーザー")
    c.note_repeated(" ".join(base + ["iam", "get-access-key-last-used", "--access-key-id", "<key>"]), "アクセスキー")
    c.note_repeated(" ".join(base + ["iam", "list-attached-user-policies", "--user-name", "<user>"]), "IAM ユーザー")
    c.note_repeated(" ".join(base + ["iam", "list-user-tags", "--user-name", "<user>"]), "IAM ユーザー(Tags 未取得時のみ)")
    c.note_repeated(" ".join(base + ["iam", "get-role", "--role-name", "<role>"]),
                    "IAM ロール(RoleLastUsed/Tags 未取得時のみ)")
    c.note_repeated(" ".join(base + ["iam", "list-attached-role-policies", "--role-name", "<role>"]), "IAM ロール")
    c.note_repeated(" ".join(base + ["organizations", "describe-policy", "--policy-id", "<policy>"]), "SCP")
    users = c.run(base + ["iam", "list-users"], f"aws:{account}:iam-users")
    if users is not None:
        enriched = []
        for user in users.get("Users", [])[:max_principals]:
            name = user["UserName"]
            keys = c.run(base + ["iam", "list-access-keys", "--user-name", name],
                         f"aws:{account}:access-keys") or {}
            merged = []
            for key in keys.get("AccessKeyMetadata", []):
                used = c.run(base + ["iam", "get-access-key-last-used",
                                     "--access-key-id", key["AccessKeyId"]],
                             f"aws:{account}:key-last-used") or {}
                key["LastUsedDate"] = (used.get("AccessKeyLastUsed") or {}).get("LastUsedDate")
                merged.append(key)
            user["AccessKeys"] = merged
            pol = c.run(base + ["iam", "list-attached-user-policies", "--user-name", name],
                        f"aws:{account}:user-policies") or {}
            user["AttachedPolicies"] = pol.get("AttachedPolicies", [])
            if "Tags" not in user:
                tags = c.run(base + ["iam", "list-user-tags", "--user-name", name],
                             f"aws:{account}:user-tags")
                user["Tags"] = (tags or {}).get("Tags", [])
            enriched.append(user)
        c.write(f"{root}/iam-users.json", {"Users": enriched})

    roles = c.run(base + ["iam", "list-roles"], f"aws:{account}:iam-roles")
    if roles is not None:
        enriched = []
        for role in roles.get("Roles", [])[:max_principals]:
            name = role["RoleName"]
            if "RoleLastUsed" not in role or "Tags" not in role:
                detail = c.run(base + ["iam", "get-role", "--role-name", name],
                               f"aws:{account}:role-detail")
                if detail:
                    role.update(detail.get("Role", {}))
            pol = c.run(base + ["iam", "list-attached-role-policies", "--role-name", name],
                        f"aws:{account}:role-policies") or {}
            role["AttachedPolicies"] = pol.get("AttachedPolicies", [])
            enriched.append(role)
        c.write(f"{root}/iam-roles.json", {"Roles": enriched})

    # Needed to tell an in-organization sibling account from a genuine third party.
    c.write(f"{root}/org-accounts.json",
            c.run(base + ["organizations", "list-accounts"], f"aws:{account}:org-accounts"))

    analyzers = c.run(base + ["accessanalyzer", "list-analyzers"],
                      f"aws:{account}:access-analyzer")
    c.write(f"{root}/access-analyzers.json", analyzers)

    policies = c.run(base + ["organizations", "list-policies",
                             "--filter", "SERVICE_CONTROL_POLICY"], f"aws:{account}:scp")
    if policies is not None:
        docs = []
        for pol in policies.get("Policies", [])[:50]:
            detail = c.run(base + ["organizations", "describe-policy",
                                   "--policy-id", pol["Id"]], f"aws:{account}:scp-detail")
            if detail:
                docs.append({"Id": pol["Id"], "Name": pol.get("Name"),
                             "Content": (detail.get("Policy") or {}).get("Content")})
        c.write(f"{root}/scp-effective.json", {"Policies": docs})

    for region in regions:
        rbase = base + ["--region", region]
        defaults = c.run(rbase + ["ec2", "get-instance-metadata-defaults"],
                         f"aws:{account}:{region}:imds-defaults")
        if defaults is not None:
            payload = defaults.get("AccountLevel", defaults) or {}
            payload["Region"] = region
            c.write(f"{root}/{region}/imds-defaults.json", payload)
        instances = c.run(rbase + ["ec2", "describe-instances",
                                   "--filters", "Name=instance-state-name,Values=running,stopped"],
                          f"aws:{account}:{region}:ec2-instances")
        c.write(f"{root}/{region}/ec2-instances.json", instances)


def collect_azure(c: Collector, tenant, max_principals):
    acct = c.run(["az", "account", "show"], "azure:account")
    # `az account show` is served from the local profile cache, so it can
    # succeed against a dead session. Force a real token request before
    # collecting anything.
    c.probe_token("https://graph.microsoft.com")
    if acct is None and not c.dry_run:
        raise CredentialError("Azure の認証に失敗した。`az login` を実行してから再実行する。")
    tenant_id = tenant or (acct or {}).get("tenantId", "unknown-tenant")
    root = f"azure/{tenant_id}"

    c.note_repeated(f"az rest --method get --url {GRAPH}/applications/<id>/federatedIdentityCredentials",
                    "アプリ登録")
    c.note_repeated(f"az rest --method get --url {GRAPH}/applications/<id>/owners?$select=id",
                    "アプリ登録($expand=owners が失敗した場合のみ)")
    c.note_repeated(f"az rest --method get --url {GRAPH}/servicePrincipals/<id>/appRoleAssignments",
                    "サービスプリンシパル")
    apps = c.graph(f"{GRAPH}/applications?$expand=owners&$top=100",
                   f"azure:{tenant_id}:applications")
    expanded = apps is not None
    if apps is None:
        # $expand can be rejected or throttled; without owners the ownership
        # ratio would report every application as unowned.
        apps = c.graph(f"{GRAPH}/applications?$top=100", f"azure:{tenant_id}:applications")
    if apps is not None:
        for app in apps["value"][:max_principals]:
            if not expanded:
                owners = c.graph(f"{GRAPH}/applications/{app['id']}/owners?$select=id",
                                 f"azure:{tenant_id}:app-owners")
                if owners is None:
                    app.pop("owners", None)   # unknown, not empty
                else:
                    app["owners"] = owners["value"]
            fic = c.graph(f"{GRAPH}/applications/{app['id']}/federatedIdentityCredentials",
                          f"azure:{tenant_id}:fic")
            app["federatedIdentityCredentials"] = (fic or {}).get("value", [])
        c.write(f"{root}/applications.json", apps)

    sps = c.graph(f"{GRAPH}/servicePrincipals?$top=100", f"azure:{tenant_id}:service-principals")
    c.write(f"{root}/service-principals.json", sps)

    # appRoleId is a GUID; the resolvable names live on the Microsoft Graph
    # service principal itself, so collect that catalog or role names stay unresolved.
    catalog = c.graph(f"{GRAPH}/servicePrincipals?$filter=appId eq '{GRAPH_APP_ID}'"
                      f"&$select=id,appId,appRoles", f"azure:{tenant_id}:graph-app-roles")
    c.write(f"{root}/graph-app-roles.json", catalog)

    assignments = []
    if sps is not None:
        for sp in sps["value"][:max_principals]:
            granted = c.graph(f"{GRAPH}/servicePrincipals/{sp['id']}/appRoleAssignments",
                              f"azure:{tenant_id}:app-role-assignments")
            if granted:
                assignments.extend(granted["value"])
    c.write(f"{root}/app-role-assignments.json", {"value": assignments})
    c.write(f"{root}/default-app-mgmt-policy.json",
            c.run(["az", "rest", "--method", "get",
                   "--url", f"{GRAPH}/policies/defaultAppManagementPolicy"],
                  f"azure:{tenant_id}:app-mgmt-policy"))
    c.write(f"{root}/authorization-policy.json",
            c.run(["az", "rest", "--method", "get",
                   "--url", f"{GRAPH}/policies/authorizationPolicy"],
                  f"azure:{tenant_id}:authorization-policy"))
    c.write(f"{root}/diagnostic-settings.json",
            c.run(["az", "rest", "--method", "get",
                   "--url", "https://management.azure.com/providers/microsoft.aadiam/"
                            "diagnosticSettings?api-version=2017-04-01-preview"],
                  f"azure:{tenant_id}:diagnostic-settings"))
    c.write(f"{root}/sp-signins.json",
            c.graph(f"{GRAPH}/auditLogs/signIns?$filter=signInEventTypes/any(t:t eq "
                    f"'servicePrincipal')&$top=500", f"azure:{tenant_id}:sp-signins"))
    c.write(f"{root}/managed-identities.json",
            {"value": c.run(["az", "identity", "list"], f"azure:{tenant_id}:managed-identities") or []})
    c.write(f"{root}/storage-accounts.json",
            {"value": c.run(["az", "storage", "account", "list"],
                            f"azure:{tenant_id}:storage-accounts") or []})


# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Collect read-only NHI evidence from AWS and/or Azure.")
    ap.add_argument("-o", "--outdir", default=f"nhi-evidence-{datetime.now():%Y%m%d}")
    ap.add_argument("--cloud", choices=["aws", "azure", "both"], default="both")
    ap.add_argument("--aws-profile")
    ap.add_argument("--regions", default="us-east-1",
                    help="comma separated AWS regions (IMDS defaults are per region)")
    ap.add_argument("--azure-tenant")
    ap.add_argument("--max-principals", type=int, default=500)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the commands that would run, execute nothing")
    args = ap.parse_args(argv)

    outdir = Path(args.outdir)
    c = Collector(outdir, args.dry_run, args.timeout)

    want_aws = args.cloud in ("aws", "both")
    want_azure = args.cloud in ("azure", "both")
    if want_aws and not shutil.which("aws") and not args.dry_run:
        c.gap("aws", "cli_missing", "aws CLI not found on PATH")
        want_aws = False
    if want_azure and not shutil.which("az") and not args.dry_run:
        c.gap("azure", "cli_missing", "az CLI not found on PATH")
        want_azure = False

    try:
        if want_aws:
            collect_aws(c, args.aws_profile,
                        [r.strip() for r in args.regions.split(",") if r.strip()],
                        args.max_principals)
        if want_azure:
            collect_azure(c, args.azure_tenant, args.max_principals)
    except CredentialError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print("# dry run — these read-only commands would be executed:")
        for cmd in c.commands:
            print(cmd)
        return 0

    outdir.mkdir(parents=True, exist_ok=True)
    try:
        outdir.chmod(0o700)
    except OSError:
        pass
    (outdir / "meta.json").write_text(json.dumps({
        "collectedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cloud": args.cloud,
        "regions": args.regions,
        "commandCount": len(c.commands),
        "coverageGaps": c.gaps,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"evidence written to {outdir}")
    print(f"commands executed: {len(c.commands)}  coverage gaps: {len(c.gaps)}")
    for gap in c.gaps:
        print(f"  GAP {gap['area']}: {gap['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
