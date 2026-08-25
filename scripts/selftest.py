#!/usr/bin/env python3
"""Self-test for the NHI posture assessment skill.

Runs entirely offline against the bundled fixtures. Verifies rule-pack
integrity, operator semantics, the read-only command guard, end-to-end scan
results (positives AND negatives), degraded-evidence confidence handling, and
that the rendered report is self-contained.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import assess  # noqa: E402
import build_db  # noqa: E402
import collect_evidence  # noqa: E402
import render_report  # noqa: E402
import scan  # noqa: E402

PASS, FAIL = [], []


def check(name, condition, detail=""):
    (PASS if condition else FAIL).append(f"{name}{(' — ' + detail) if detail and not condition else ''}")


def section(title):
    print(f"\n--- {title} ---")


# ---------------------------------------------------------------- rule pack
def _documented_refs():
    """Every docRef must exist in control-model.md, or the citation is dead."""
    text = (ROOT / "references" / "control-model.md").read_text(encoding="utf-8")
    import re
    return set(re.findall(r"\b(F-\d{2}|CAP-[A-Z]+)\b", text))


DOC_REFS = _documented_refs()


def test_rule_pack():
    section("rule pack integrity")
    check("control-model.md defines reference ids", len(DOC_REFS) >= 10, str(sorted(DOC_REFS)))
    packs = scan.load_packs([str(ROOT / "rules")])
    check("rule packs load", bool(packs))
    ids, refs = [], []
    for pack in packs:
        thresholds = pack.get("thresholds", {})
        for rule in pack["rules"]:
            rid = rule["id"]
            ids.append(rid)
            for key in ("title", "severity", "target", "where", "message",
                        "expected", "remediation", "validation"):
                check(f"{rid} has {key}", key in rule and rule[key] not in (None, ""))
            check(f"{rid} severity valid", rule["severity"] in scan.SEVERITY_ORDER,
                  rule["severity"])
            check(f"{rid} docRef resolvable", rule.get("docRef") in DOC_REFS,
                  f"{rule.get('docRef')} is not documented in control-model.md")
            check(f"{rid} owasp tagged",
                  rule["target"] == "coverageGaps" or bool(rule.get("owasp")),
                  "every substantive rule must map to an OWASP NHI category")
            check(f"{rid} target valid", rule["target"] in scan.TARGET_COLLECTIONS,
                  rule["target"])
            try:
                bound = scan.bind_thresholds(rule["where"], thresholds)
                scan.evaluate(bound, {}, set())
                refs.append(rid)
            except scan.RuleError as exc:
                check(f"{rid} predicate valid", False, str(exc))
    check("rule ids unique", len(ids) == len(set(ids)),
          f"{len(ids)} ids, {len(set(ids))} unique")
    check("all predicates evaluable", len(refs) == len(ids))
    check("rule count is meaningful", len(ids) >= 25, f"only {len(ids)}")


# ---------------------------------------------------------------- operators
def test_operators():
    section("operator semantics")
    entity = {"a": 1, "list": [{"s": "x", "n": 5}, {"s": "y"}], "empty": [], "nul": None}
    check("dotted resolve", scan.resolve("a", entity) == [1])
    check("flatten resolve", scan.resolve("list[].s", entity) == ["x", "y"])
    check("absent key yields None slot", scan.resolve("list[].n", entity) == [5, None])
    check("count on list", scan.apply_op("count_gte", scan.resolve("list", entity), 2))
    check("count on empty list", scan.apply_op("count_lte", scan.resolve("empty", entity), 0))
    check("count on absent", scan.apply_op("count_lte", scan.resolve("nope", entity), 0))
    # regression: only the first slot was inspected, so [None, 5] counted as 0
    check("count over flattened slots ignores holes",
          scan._count(scan.resolve("list[].n", entity)) == 1,
          f"got {scan._count(scan.resolve('list[].n', entity))}")
    check("count of a two-element list", scan._count(scan.resolve("list", entity)) == 2)
    # regression: a list substituted into a message printed as a Python repr
    check("list renders as a readable join",
          scan.render_message("{roles}", {"roles": ["A", "B"]}) == "A, B",
          scan.render_message("{roles}", {"roles": ["A", "B"]}))
    check("empty list renders as a word",
          scan.render_message("{roles}", {"roles": []}) == "(なし)")
    check("absent field renders as ?", scan.render_message("{nope}", {}) == "?")
    check("eq existential", scan.apply_op("eq", scan.resolve("list[].s", entity), "y"))
    check("missing detects None slot", scan.apply_op("missing", scan.resolve("list[].n", entity)  , None))
    check("exists on present", scan.apply_op("exists", scan.resolve("a", entity), None))
    check("ne is fail-closed on absent",
          scan.apply_op("ne", scan.resolve("nope", entity), "required"),
          "an uncollected control must not read as compliant")
    check("ne false when equal", not scan.apply_op("ne", [("required")], "required"))
    check("regex", scan.apply_op("regex", ["AWSCompromisedKeyQuarantineV3"], "Quarantine"))

    # forEach must bind conditions to a single element.
    two_keys = {"credentials": [{"status": "Active", "ageDays": 5},
                                {"status": "Inactive", "ageDays": 900}]}
    flat = {"all": [{"field": "credentials[].status", "op": "eq", "value": "Active"},
                    {"field": "credentials[].ageDays", "op": "gt", "value": 90}]}
    scoped = {"forEach": "credentials",
              "where": {"all": [{"field": "status", "op": "eq", "value": "Active"},
                                {"field": "ageDays", "op": "gt", "value": 90}]}}
    check("flat predicate over-matches across elements", scan.evaluate(flat, two_keys, set()))
    check("forEach binds to one element", not scan.evaluate(scoped, two_keys, set()),
          "an active-but-new key and an old-but-inactive key must not combine")
    one_bad = {"credentials": [{"status": "Active", "ageDays": 900}]}
    check("forEach still matches a genuine hit", scan.evaluate(scoped, one_bad, set()))


# ---------------------------------------------------------------- guard
def test_readonly_guard():
    section("read-only command guard")
    c = collect_evidence.Collector(Path("/tmp"), dry_run=True, timeout=5)
    allowed = [
        ["aws", "iam", "list-users"],
        ["aws", "--profile", "prod", "iam", "list-roles"],
        ["aws", "--profile", "prod", "--region", "ap-northeast-1", "ec2", "describe-instances"],
        ["az", "account", "show"],
        ["az", "storage", "account", "list"],
        ["az", "rest", "--method", "get", "--url", "https://graph.microsoft.com/v1.0/applications"],
    ]
    for argv in allowed:
        try:
            c._guard(argv)
            check(f"allows: {' '.join(argv[:4])}", True)
        except PermissionError as exc:
            check(f"allows: {' '.join(argv[:4])}", False, str(exc))

    refused = [
        ["aws", "iam", "delete-user", "--user-name", "x"],
        ["aws", "iam", "create-access-key", "--user-name", "x"],
        # regression: a profile shifted the verb position and bypassed the guard
        ["aws", "--profile", "prod", "iam", "delete-role", "--role-name", "x"],
        ["aws", "--region", "us-east-1", "ec2", "terminate-instances"],
        ["az", "ad", "app", "delete", "--id", "x"],
        # regression: any subcommand containing "rest" used to pass regardless of method
        ["az", "rest", "--method", "post", "--url", "https://graph.microsoft.com/v1.0/applications"],
        ["az", "rest", "--method", "delete", "--url", "https://example.invalid"],
        ["curl", "https://example.invalid"],
    ]
    for argv in refused:
        try:
            c._guard(argv)
            check(f"refuses: {' '.join(argv[:4])}", False, "command was allowed")
        except PermissionError:
            check(f"refuses: {' '.join(argv[:4])}", True)


# ---------------------------------------------------------------- end to end
def run_pipeline(fixture, workdir):
    db_path = workdir / f"{fixture.name}-db.json"
    out_path = workdir / f"{fixture.name}-findings.json"
    rc = build_db.main([str(fixture), "-o", str(db_path)])
    assert rc == 0, "build_db failed"
    rc = scan.main([str(db_path), "-r", str(ROOT / "rules"), "-o", str(out_path)])
    assert rc == 0, "scan failed"
    return json.loads(db_path.read_text(encoding="utf-8")), \
        json.loads(out_path.read_text(encoding="utf-8"))


def test_main_fixture(workdir):
    section("end-to-end: representative estate")
    db, report = run_pipeline(ROOT / "examples" / "fixture-evidence", workdir)
    hits = {}
    for f in report["findings"]:
        hits.setdefault(f["ruleId"], set()).add(f["resourceName"])

    expected = {
        "NHI-AWS-001": {"legacy-batch", "rotated-user", "shared-ops-account"},
        "NHI-AWS-014": {"shared-ops-account"},
        "NHI-AWS-002": {"legacy-batch"},
        "NHI-AWS-003": {"legacy-batch"},
        "NHI-AWS-004": {"legacy-batch"},
        "NHI-AWS-005": {"github-deploy"},
        "NHI-AWS-005B": {"wide-open-oidc"},
        "NHI-AWS-006": {"vendor-access"},
        "NHI-AWS-007": {"stale-role"},
        "NHI-AWS-008": {"shared-role"},
        "NHI-AWS-009": {"i-0a1"},
        "NHI-AWS-009B": {"i-0a3"},
        "NHI-AWS-010": {"111122223333/ap-northeast-1"},
        "NHI-AWS-012": {"111122223333"},
        "NHI-AWS-013": {"quarantined-role"},
        "NHI-AZ-001": {"legacy-batch-app"},
        "NHI-AZ-002": {"legacy-batch-app"},
        "NHI-AZ-003": {"legacy-batch-app"},
        "NHI-AZ-004": {"legacy-batch-app"},
        "NHI-AZ-005": {"graph-admin-app"},
        "NHI-AZ-006": {"multi-tenant-app"},
        "NHI-AZ-007": {"shared-mi"},
        "NHI-AZ-008": {"graph-admin-app"},
        "NHI-AZ-009": {"contoso-tenant"},
        "NHI-AZ-010": {"contoso-tenant"},
        "NHI-AZ-012": {"stlegacy001"},
        "NHI-X-002": {"111122223333", "contoso-tenant"},
    }
    for rid, want in expected.items():
        check(f"{rid} matches exactly", hits.get(rid) == want,
              f"expected {sorted(want)}, got {sorted(hits.get(rid, set()))}")

    unexpected = set(hits) - set(expected) - {"NHI-X-001"}
    check("no unexpected rules fired", not unexpected, str(sorted(unexpected)))

    section("end-to-end: required negatives")
    everyone = {n for names in hits.values() for n in names}
    for name, why in [
        ("clean-user", "IAM ユーザーだがキーを持たない"),
        ("cognito-pool-role", "aud 条件のみのフェデレーションを誤検知しない"),
        ("AWSServiceRoleForAutoScaling", "サービスリンクロールを未使用判定から除外"),
        ("i-0a2", "IMDSv2 必須のインスタンス"),
        ("111122223333/us-east-1", "IMDSv2 既定が設定済みのリージョン"),
        ("sthardened01", "共有キー無効のストレージ"),
        ("single-mi", "共有されていないマネージド ID"),
        ("clean-app", "証明書資格情報・所有者あり・最近サインイン"),
        ("sibling-access", "同一組織内のアカウントは第三者ではない"),
        ("org-fenced-access", "aws:PrincipalOrgID で組織に閉じている"),
    ]:
        check(f"negative: {name} ({why})", name not in everyone)

    check("NHI-AWS-011 silent when SCP denies key creation", "NHI-AWS-011" not in hits)
    check("IMDSv1 severity reflects reachability",
          next(f["severity"] for f in report["findings"] if f["ruleId"] == "NHI-AWS-009") == "critical"
          and next(f["severity"] for f in report["findings"] if f["ruleId"] == "NHI-AWS-009B") == "medium",
          "role-attached must outrank roleless")
    areas = {g["area"] for g in report["coverageGaps"]}
    check("unscanned region declared", "aws:111122223333:us-east-1:ec2-instances" in areas,
          str(sorted(areas)))
    check("region scope limitation declared", "aws:scope" in areas, str(sorted(areas)))
    check("owasp rollup present", bool(report.get("owaspSummary")))
    scopes = {s["name"]: s for s in db["scopes"]}
    aws_ratio = scopes["111122223333"]["settings"]["ownershipRatio"]
    # 4 owner-tagged of 13 non-service-linked identities in the account.
    check("ownership ratio computed from owner tags", abs(aws_ratio - 0.308) < 0.01,
          f"got {aws_ratio}")
    check("service-linked roles excluded from ownership denominator",
          scopes["111122223333"]["settings"]["identityCount"] == 13,
          str(scopes["111122223333"]["settings"]["identityCount"]))
    check("azure ownership uses owners list",
          abs(scopes["contoso-tenant"]["settings"]["ownershipRatio"] - 0.5) < 0.01,
          str(scopes["contoso-tenant"]["settings"]["ownershipRatio"]))
    ratio_msg = next(f["message"] for f in report["findings"] if f["ruleId"] == "NHI-X-002"
                     and f["resourceName"] == "111122223333")
    check("ratio finding states the numbers", "9" in ratio_msg and "13" in ratio_msg, ratio_msg)
    check("owasp rollup keyed by category", "NHI7" in report.get("owaspSummary", {}),
          str(list(report.get("owaspSummary", {}))))
    covered = {c for r in scan.load_packs([str(ROOT / "rules")])
               for rule in r["rules"] for c in rule.get("owasp", [])}
    missing = {f"NHI{i}" for i in range(1, 11)} - covered
    check("every OWASP NHI category has at least one rule", not missing,
          f"uncovered: {sorted(missing)}")
    check("NHI-AZ-011 silent when sign-in export configured", "NHI-AZ-011" not in hits)
    ext = next(f for f in report["findings"] if f["ruleId"] == "NHI-AWS-006")
    check("genuine third-party trust reported at full confidence",
          ext["resourceName"] == "vendor-access" and not ext["evidenceIncomplete"],
          f"{ext['resourceName']} incomplete={ext['evidenceIncomplete']}")
    check("wide-open-oidc not double-reported by 005",
          "wide-open-oidc" not in hits.get("NHI-AWS-005", set()))

    section("end-to-end: database shape")
    by_key = {i["key"]: i for i in db["identities"]}
    gh = by_key["aws:111122223333:role/github-deploy"]
    check("wildcard subject detected", gh["trust"]["wildcardSubject"])
    check("provider recorded", "token.actions.githubusercontent.com" in gh["trust"]["providers"])
    legacy = by_key["aws:111122223333:user/legacy-batch"]
    check("credential age computed", legacy["maxCredentialAgeDays"] > 500,
          str(legacy["maxCredentialAgeDays"]))
    check("user last-used derives from key usage, not console",
          legacy["lastUsedDays"] is not None and legacy["lastUsedDays"] > 500)
    app = by_key["azure:contoso-tenant:app/11111111-1111-1111-1111-111111111111"]
    check("credential lifetime computed", app["credentials"][0]["lifetimeDays"] > 1000,
          str(app["credentials"][0]["lifetimeDays"]))
    admin = by_key["azure:contoso-tenant:app/44444444-4444-4444-4444-444444444444"]
    check("graph app role resolved to a name",
          "RoleManagement.ReadWrite.Directory" in admin["permissions"]["graphAppRoles"],
          str(admin["permissions"]["graphAppRoles"]))
    keys = [f["resourceKey"] for f in report["findings"]]
    check("every finding has a resource key", all(keys), "null keys break delta and exceptions")
    check("finding identity is unique",
          len({(f["ruleId"], f["resourceKey"]) for f in report["findings"]}) == len(report["findings"]),
          "duplicate (ruleId, resourceKey) pairs make delta review ambiguous")
    check("coverage gaps deduplicated",
          len(db["coverageGaps"]) == len({(g["area"], g["reason"]) for g in db["coverageGaps"]}))
    return report


def test_degraded_fixture(workdir):
    section("end-to-end: degraded evidence")
    db, report = run_pipeline(ROOT / "examples" / "fixture-degraded", workdir)
    low = {f["ruleId"] for f in report["findings"] if f["evidenceIncomplete"]}
    for rid in ("NHI-AWS-011", "NHI-AWS-012", "NHI-AZ-003", "NHI-AZ-009",
                "NHI-AZ-010", "NHI-AZ-011"):
        check(f"{rid} downgraded to low confidence", rid in low, str(sorted(low)))
    for f in report["findings"]:
        if f["evidenceIncomplete"]:
            check(f"{f['ruleId']} confidence is low", f["confidence"] == "low")
    check("coverage gaps reported", len(report["coverageGaps"]) >= 5)
    check("gap findings emitted",
          any(f["ruleId"] == "NHI-X-001" for f in report["findings"]))
    check("no region scope invented without evidence",
          not any(s["type"] == "aws.account_region" for s in db["scopes"]))
    check("NHI-AWS-010 silent when region evidence is missing",
          not any(f["ruleId"] == "NHI-AWS-010" for f in report["findings"]),
          "must not assert a per-region setting that was never collected")
    check("gaps deduplicated across meta and detection",
          len(db["coverageGaps"]) == len({(g["area"], g["reason"]) for g in db["coverageGaps"]}))


def test_report(report, workdir):
    section("report rendering")
    out = workdir / "report.html"
    render_report.main([str(workdir / "fixture-evidence-findings.json"), "-o", str(out)])
    text = out.read_text(encoding="utf-8")
    check("report written", out.exists() and len(text) > 3000)
    for token in ("http://", "https://"):
        check(f"no external {token} reference", token not in text,
              "the report must open offline")
    blocks = text.count('class="f ')
    check("every finding rendered", blocks == len(report["findings"]),
          f'{blocks} blocks vs {len(report["findings"])} findings')
    check("coverage banner present", "gapbox" in text)
    check("status control present", "localStorage" in text)
    from html.parser import HTMLParser

    class V(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.stack, self.errors = [], []
        def handle_starttag(self, tag, attrs):
            if tag not in {"meta", "br", "hr", "img", "input", "link"}:
                self.stack.append(tag)
        def handle_endtag(self, tag):
            if tag in {"meta", "br", "hr", "img", "input", "link"}:
                return
            if self.stack and self.stack[-1] == tag:
                self.stack.pop()
            else:
                self.errors.append(tag)
    v = V(); v.feed(text); v.close()
    check("report HTML well formed", not v.errors and not v.stack,
          f"errors={v.errors[:3]} unclosed={v.stack[:3]}")


def test_suppression(workdir):
    section("rule exceptions")
    pack = {"packName": "test-exceptions", "packVersion": "0.0.1", "thresholds": {},
            "rules": [{"id": "TEST-SUP-001", "title": "t", "severity": "high",
                       "owasp": ["NHI7"], "docRef": "F-02", "target": "identities",
                       "where": {"field": "type", "op": "eq", "value": "aws.iam_user"},
                       "exceptions": ["aws:*:user/clean-*"],
                       "message": "{name}", "expected": "e", "remediation": "r",
                       "validation": "v"}]}
    packdir = workdir / "testpack"
    packdir.mkdir(exist_ok=True)
    (packdir / "pack.json").write_text(json.dumps(pack), encoding="utf-8")
    db = json.loads((workdir / "fixture-evidence-db.json").read_text(encoding="utf-8"))
    findings, suppressed = scan.scan(db, scan.load_packs([str(packdir)]))
    names = {f["resourceName"] for f in findings}
    check("exception removes the matching resource", "clean-user" not in names, str(sorted(names)))
    check("non-matching resources still reported", "legacy-batch" in names)
    check("suppression is recorded, not silent",
          any(x["resourceKey"].endswith("user/clean-user") for x in suppressed),
          str(suppressed))
    check("suppression records the pattern used",
          suppressed and suppressed[0]["pattern"] == "aws:*:user/clean-*")


def test_signin_sample_depth():
    section("sign-in sample depth")
    from datetime import datetime, timezone
    now = datetime(2026, 8, 25, tzinfo=timezone.utc)
    deep = {"value": [{"appId": "a", "createdDateTime": "2026-08-20T00:00:00Z"},
                      {"appId": "b", "createdDateTime": "2026-01-01T00:00:00Z"}]}
    mapping, reach = build_db._last_signin_map(deep, now)
    check("last sign-in per app computed", mapping["a"] == 5, str(mapping))
    check("sample reach measured", reach == 236, str(reach))

    # A busy tenant returns only the most recent events, so the window can be
    # minutes wide. Absence from it must not be read as disuse.
    shallow = {"value": [{"appId": "a", "createdDateTime": "2026-08-24T23:00:00Z"}]}
    _, shallow_reach = build_db._last_signin_map(shallow, now)
    check("shallow sample detected", shallow_reach < build_db.SIGNIN_MIN_REACH_DAYS,
          f"reach={shallow_reach}")

    empty, none_reach = build_db._last_signin_map({"value": []}, now)
    check("empty sample has no reach", none_reach is None and empty == {})


def test_shallow_signin_fixture(workdir):
    section("shallow sign-in evidence downgrades the unused judgement")
    import shutil
    src = ROOT / "examples" / "fixture-evidence"
    dst = workdir / "shallow-evidence"
    shutil.copytree(src, dst)
    (dst / "azure" / "contoso-tenant" / "sp-signins.json").write_text(json.dumps(
        {"value": [{"appId": "22222222-2222-2222-2222-222222222222",
                    "createdDateTime": "2026-08-24T22:00:00Z"}]}), encoding="utf-8")
    db_path = workdir / "shallow-db.json"
    out_path = workdir / "shallow-findings.json"
    build_db.main([str(dst), "-o", str(db_path)])
    scan.main([str(db_path), "-r", str(ROOT / "rules"), "-o", str(out_path)])
    report = json.loads(out_path.read_text(encoding="utf-8"))
    reasons = {g["reason"] for g in report["coverageGaps"]}
    check("shallow sample recorded as a coverage gap", "sample_too_shallow" in reasons,
          str(sorted(reasons)))
    az004 = [f for f in report["findings"] if f["ruleId"] == "NHI-AZ-004"]
    check("unused-identity findings are downgraded, not asserted",
          all(f["evidenceIncomplete"] for f in az004),
          "a shallow sample must not produce a confident disuse claim")


def test_app_mgmt_policy_shapes():
    section("app management policy shapes")
    app_only = {"applicationRestrictions": {"passwordCredentials": [
        {"restrictionType": "passwordAddition", "state": "enabled"}]}}
    check("applicationRestrictions counts", build_db._restricts_passwords(app_only))
    # verified against the Graph OData schema: the policy also carries
    # servicePrincipalRestrictions, which was previously ignored
    sp_only = {"servicePrincipalRestrictions": {"passwordCredentials": [
        {"restrictionType": "passwordAddition", "state": "enabled"}]}}
    check("servicePrincipalRestrictions counts", build_db._restricts_passwords(sp_only),
          "a tenant restricting only service principals read as having no guardrail")
    lifetime = {"applicationRestrictions": {"passwordCredentials": [
        {"restrictionType": "passwordLifetime", "state": "enabled", "maxLifetime": "P90D"}]}}
    check("passwordLifetime counts", build_db._restricts_passwords(lifetime))
    disabled = {"applicationRestrictions": {"passwordCredentials": [
        {"restrictionType": "passwordAddition", "state": "disabled"}]}}
    check("a disabled restriction does not count", not build_db._restricts_passwords(disabled))
    check("empty policy does not count", not build_db._restricts_passwords({}))


def test_owner_evidence_semantics():
    section("owner evidence semantics")
    # An application whose owners were never retrieved must be unknown, not
    # unowned; otherwise the ownership ratio silently reads as zero.
    from datetime import datetime, timezone
    now = datetime(2026, 8, 25, tzinfo=timezone.utc)
    gaps, ids = [], []
    import tempfile as _tf
    with _tf.TemporaryDirectory() as td:
        d = Path(td) / "azure" / "t1"
        d.mkdir(parents=True)
        (d / "applications.json").write_text(json.dumps({"value": [
            {"id": "a1", "appId": "x", "displayName": "no-owner-key",
             "passwordCredentials": [], "keyCredentials": []},
            {"id": "a2", "appId": "y", "displayName": "empty-owner-list", "owners": [],
             "passwordCredentials": [], "keyCredentials": []},
        ]}), encoding="utf-8")
        build_db._azure_apps(d, "t1", now, gaps, ids, {}, {}, True)
    by = {i["name"]: i for i in ids}
    check("absent owners key is unknown", "owners" in by["no-owner-key"]["_unknown"],
          "never-retrieved owners must not count as unowned")
    check("empty owners list is a real answer",
          "owners" not in by["empty-owner-list"]["_unknown"])
    check("both have no owner recorded",
          not by["no-owner-key"]["owners"] and not by["empty-owner-list"]["owners"])


def test_trust_classification():
    section("trust classification")
    org = {"222233334444"}
    sibling = {"Statement": [{"Effect": "Allow", "Principal":
               {"AWS": "arn:aws:iam::222233334444:root"}, "Action": "sts:AssumeRole"}]}
    check("in-organization account is not a third party",
          not build_db.analyze_trust(sibling, "111122223333", org)["externalPrincipal"])
    check("without the org list the same trust is external",
          build_db.analyze_trust(sibling, "111122223333", set())["externalPrincipal"],
          "unknown organization membership must fail closed")
    outsider = {"Statement": [{"Effect": "Allow", "Principal":
                {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}]}
    check("outside account is external",
          build_db.analyze_trust(outsider, "111122223333", org)["externalPrincipal"])
    fenced = {"Statement": [{"Effect": "Allow", "Principal":
              {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole",
              "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-x"}}}]}
    check("aws:PrincipalOrgID marks the trust org-fenced",
          build_db.analyze_trust(fenced, "111122223333", set())["orgFenced"])
    star = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole"}]}
    check("wildcard principal is external",
          build_db.analyze_trust(star, "111122223333", org)["externalPrincipal"])
    svc = {"Statement": [{"Effect": "Allow", "Principal":
           {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    check("service principal is not external",
          not build_db.analyze_trust(svc, "111122223333", org)["externalPrincipal"])


def test_gating_is_shared():
    section("severity gate")
    findings = [{"severity": "medium"}, {"severity": "high"}]
    check("gate trips at threshold", scan.exceeds(findings, "high"))
    check("gate does not trip above threshold", not scan.exceeds(findings, "critical"))
    check("gate trips below threshold", scan.exceeds(findings, "low"))
    check("empty findings never trip", not scan.exceeds([], "info"))


def test_scp_strictness():
    section("guardrail detection strictness")
    conditional = {"Policies": [{"Content": json.dumps({"Statement": [
        {"Effect": "Deny", "Action": "*", "Resource": "*",
         "Condition": {"StringNotEquals": {"aws:RequestedRegion": "ap-northeast-1"}}}]})}]}
    check("conditional Deny is not credited as a guardrail",
          not build_db._scp_denies(conditional, "iam:CreateAccessKey"),
          "a region-restriction SCP must not read as denying key creation")
    no_resource = {"Policies": [{"Content": json.dumps({"Statement": [
        {"Effect": "Deny", "Action": "iam:CreateAccessKey"}]})}]}
    check("Deny without Resource is not credited",
          not build_db._scp_denies(no_resource, "iam:CreateAccessKey"))
    not_action = {"Policies": [{"Content": json.dumps({"Statement": [
        {"Effect": "Deny", "NotAction": "iam:CreateAccessKey", "Resource": "*"}]})}]}
    check("NotAction is not credited", not build_db._scp_denies(not_action, "iam:CreateAccessKey"))
    genuine = {"Policies": [{"Content": json.dumps({"Statement": [
        {"Effect": "Deny", "Action": ["iam:CreateAccessKey"], "Resource": "*"}]})}]}
    check("explicit unconditional Deny is credited",
          build_db._scp_denies(genuine, "iam:CreateAccessKey"))
    wildcard_service = {"Policies": [{"Content": json.dumps({"Statement": [
        {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]})}]}
    check("service wildcard Deny is credited",
          build_db._scp_denies(wildcard_service, "iam:CreateAccessKey"))


def test_masking(workdir):
    section("public masking")
    findings_path = workdir / "fixture-evidence-findings.json"
    report = json.loads(findings_path.read_text(encoding="utf-8"))
    html_text = render_report.render(report, "t")
    target = next(f for f in report["findings"] if f["resourceName"] == "github-deploy")
    check("resource name inside the message is maskable",
          '<span class="mask">github-deploy</span>' in html_text,
          "a masking control that leaves the name visible in prose is worse than none")
    check("account id inside a gap line is maskable",
          '<span class="mask">111122223333</span>' in html_text)
    check("masking does not corrupt escaping", "&lt;script" not in html_text)
    check("finding still carries its identity", target["ruleId"] in html_text)


def test_delta(workdir):
    section("delta review against a baseline")
    db = workdir / "fixture-evidence-db.json"
    first = workdir / "delta-first.json"
    scan.main([str(db), "-r", str(ROOT / "rules"), "-o", str(first)])

    # Drop one finding from the baseline so it must come back as "new", and add
    # a fabricated one that must come back as "resolved".
    data = json.loads(first.read_text(encoding="utf-8"))
    dropped = data["findings"].pop(0)
    data["findings"].append({"ruleId": "NHI-AWS-999", "resourceKey": "aws:0:role/gone",
                             "severity": "high", "title": "gone"})
    baseline = workdir / "delta-baseline.json"
    baseline.write_text(json.dumps(data), encoding="utf-8")

    second = workdir / "delta-second.json"
    scan.main([str(db), "-r", str(ROOT / "rules"), "-o", str(second),
               "--baseline", str(baseline)])
    out = json.loads(second.read_text(encoding="utf-8"))
    states = {(f["ruleId"], f["resourceKey"]): f.get("state") for f in out["findings"]}
    check("removed-from-baseline finding is marked new",
          states.get((dropped["ruleId"], dropped["resourceKey"])) == "new",
          str(states.get((dropped["ruleId"], dropped["resourceKey"]))))
    check("unchanged findings are marked existing",
          sum(1 for v in states.values() if v == "existing") == len(out["findings"]) - 1)
    check("baseline-only finding is reported resolved",
          any(r["ruleId"] == "NHI-AWS-999" for r in out["resolved"]), str(out["resolved"]))
    check("baseline path recorded", out["baseline"] == str(baseline))

    html_text = render_report.render(out, "delta")
    check("delta section rendered", "前回との差分" in html_text)
    check("resolved caveat present", "取得できなくなった場合も解消に見える" in html_text)
    check("new findings tagged in report", ">新規<" in html_text)

    missing = scan.main([str(db), "-r", str(ROOT / "rules"),
                         "-o", str(workdir / "x.json"), "--baseline",
                         str(workdir / "does-not-exist.json")])
    check("missing baseline is an error, not a silent full-new report", missing == 1,
          f"rc={missing}")


def test_threshold_coherence():
    section("threshold coherence with the assessment model")
    pack = scan.load_packs([str(ROOT / "rules")])[0]
    check("unused window exceeds a quarter",
          pack["thresholds"]["identityUnusedDays"] >= 180,
          "the model warns that a 90-day window misjudges quarterly batch jobs")
    by = {r["id"]: r for r in pack["rules"]}
    for rid in ("NHI-AWS-003", "NHI-AWS-007", "NHI-AZ-004"):
        check(f"{rid} warns about the tracking window",
              "365" in (by[rid].get("caveat") or ""),
              "an unused-identity rule must state how to widen the window")


def _guard_ok(argv):
    c = collect_evidence.Collector(Path("/tmp"), dry_run=True, timeout=5)
    try:
        c._guard(argv)
        return True
    except PermissionError:
        return False


def test_collector_hardening():
    section("collector hardening")
    check("expired AWS token recognised",
          collect_evidence._expired("An error occurred (InvalidClientTokenId) when calling "
                                    "the GetCallerIdentity operation"))
    check("missing AWS credentials recognised",
          collect_evidence._expired("Unable to locate credentials"))
    check("azure logout recognised", collect_evidence._expired("Please run 'az login' to setup account"))
    check("denial is not mistaken for expiry",
          not collect_evidence._expired("AccessDenied: not authorized to perform iam:ListUsers"))
    check("denial still classified as denial",
          collect_evidence._denied("AccessDenied: not authorized to perform iam:ListUsers"))

    # Found on a live tenant: `az account show` answers from the profile cache
    # and succeeds with a dead refresh token, so it is not a liveness check.
    aadsts = ("ERROR: AADSTS700082: The refresh token has expired due to inactivity. "
              "The token was issued on 2025-12-29T13:36:19Z")
    check("AADSTS700082 recognised as expiry", collect_evidence._expired(aadsts),
          "an expired session was classified as a generic command failure")
    check("AADSTS expiry is not read as a permission problem",
          not collect_evidence._denied(aadsts))
    check("token probe is allowed by the read-only guard",
          _guard_ok(["az", "account", "get-access-token", "--resource",
                     "https://graph.microsoft.com", "--query", "expiresOn", "-o", "tsv"]))
    check("guard still refuses writes after allowing the probe",
          not _guard_ok(["az", "ad", "app", "delete", "--id", "x"]))

    class ExpiredRun(collect_evidence.Collector):
        def run(self, argv, area):
            self.commands.append(" ".join(argv))
            raise collect_evidence.CredentialError("session expired")

    expired = ExpiredRun(Path("/tmp"), dry_run=False, timeout=5)
    try:
        collect_evidence.collect_azure(expired, None, 10)
        check("expired session aborts collection", False, "collection continued")
    except collect_evidence.CredentialError:
        check("expired session aborts collection", True)

    class DeadAuth(collect_evidence.Collector):
        def run(self, argv, area):
            self.commands.append(" ".join(argv))
            return None

    dead = DeadAuth(Path("/tmp"), dry_run=False, timeout=5)
    try:
        collect_evidence.collect_aws(dead, None, ["us-east-1"], 10)
        check("unusable AWS credentials abort collection", False,
              "collection continued and would produce a hollow evidence tree")
    except collect_evidence.CredentialError:
        check("unusable AWS credentials abort collection", True)
    check("abort happens before enumerating principals", len(dead.commands) == 1,
          f"ran {len(dead.commands)} commands before failing")

    dead2 = DeadAuth(Path("/tmp"), dry_run=False, timeout=5)
    try:
        collect_evidence.collect_azure(dead2, None, 10)
        check("unusable Azure credentials abort collection", False)
    except collect_evidence.CredentialError:
        check("unusable Azure credentials abort collection", True)


def test_bad_input(workdir):
    section("hostile input handling")
    empty = workdir / "empty-evidence"
    empty.mkdir()
    out = workdir / "should-not-exist.json"
    rc = build_db.main([str(empty), "-o", str(out)])
    check("empty evidence directory is an error", rc == 1, f"rc={rc}")
    check("no database written from empty evidence", not out.exists(),
          "an empty database scans clean and would be read as 'no problems'")

    hollow = workdir / "hollow-evidence"
    (hollow / "aws" / "000000000000").mkdir(parents=True)
    rc = build_db.main([str(hollow), "-o", str(out)])
    check("evidence with no parseable content is an error", rc == 1, f"rc={rc}")
    check("no database written from unparseable evidence", not out.exists())

    rc = scan.main([str(workdir / "no-such-db.json"), "-r", str(ROOT / "rules"),
                    "-o", str(out)])
    check("missing database is a clean error", rc == 1, f"rc={rc}")

    badpack = workdir / "badpack"
    badpack.mkdir()
    (badpack / "broken.json").write_text("not json", encoding="utf-8")
    rc = scan.main([str(workdir / "fixture-evidence-db.json"), "-r", str(badpack),
                    "-o", str(out)])
    check("malformed rule pack is a clean error", rc == 1, f"rc={rc}")

    notapack = workdir / "notapack"
    notapack.mkdir()
    (notapack / "x.json").write_text('{"hello": 1}', encoding="utf-8")
    rc = scan.main([str(workdir / "fixture-evidence-db.json"), "-r", str(notapack),
                    "-o", str(out)])
    check("JSON that is not a rule pack is a clean error", rc == 1, f"rc={rc}")

    bad = workdir / "bad-findings.json"
    bad.write_text("{oops", encoding="utf-8")
    rc = render_report.main([str(bad), "-o", str(workdir / "bad.html")])
    check("malformed findings is a clean error", rc == 1, f"rc={rc}")

    wrong = workdir / "wrong-shape.json"
    wrong.write_text('{"something": []}', encoding="utf-8")
    rc = render_report.main([str(wrong), "-o", str(workdir / "wrong.html")])
    check("valid JSON of the wrong shape is rejected", rc == 1, f"rc={rc}")


def test_one_command(workdir):
    section("one-command entry point")
    out = workdir / "oneshot"
    rc = assess.main(["--from-evidence", str(ROOT / "examples" / "fixture-evidence"),
                      "-o", str(out)])
    check("assess.py completes", rc == 0, f"rc={rc}")
    for artifact in ("nhi-db.json", "findings.json", "report.html"):
        check(f"produces {artifact}", (out / artifact).exists())
    data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    check("same result as the four-step pipeline", data["summary"]["total"] == 33,
          str(data["summary"]))

    rc = assess.main(["--from-evidence", str(ROOT / "examples" / "fixture-evidence"),
                      "-o", str(out)])
    check("re-running into the same directory is refused", rc == 1,
          "overwriting findings.json destroys the baseline for delta review")
    rc = assess.main(["--from-evidence", str(ROOT / "examples" / "fixture-evidence"),
                      "-o", str(out), "--force"])
    check("--force allows a deliberate overwrite", rc == 0, f"rc={rc}")

    rc = assess.main(["--from-evidence", str(workdir / "nope"), "-o", str(workdir / "o2")])
    check("missing evidence directory is an error", rc == 1, f"rc={rc}")

    rc = assess.main(["--from-evidence", str(ROOT / "examples" / "fixture-evidence"),
                      "-o", str(workdir / "o3"), "--fail-on", "critical"])
    check("--fail-on gates the whole run", rc == 2, f"rc={rc}")

    # Degraded (but non-empty) evidence must still produce a report — with the
    # coverage banner and low-confidence markers. That is the design.
    rc = assess.main(["--from-evidence", str(ROOT / "examples" / "fixture-degraded"),
                      "-o", str(workdir / "o4")])
    check("degraded evidence still yields a report", rc == 0, f"rc={rc}")
    check("degraded report exists", (workdir / "o4" / "report.html").exists())
    degraded = json.loads((workdir / "o4" / "findings.json").read_text(encoding="utf-8"))
    check("degraded report carries coverage gaps", degraded["coverageGaps"])

    # Evidence that builds nothing must stop the run before a report exists.
    hollow = workdir / "hollow-run"
    (hollow / "aws" / "000000000000").mkdir(parents=True)
    rc = assess.main(["--from-evidence", str(hollow), "-o", str(workdir / "o5")])
    check("evidence that builds nothing stops the run", rc == 1, f"rc={rc}")
    check("no report produced from unusable evidence",
          not (workdir / "o5" / "report.html").exists(),
          "a failed collection must never become a reassuring report")


def test_docs_match_code(workdir):
    section("documentation matches the code")
    schema = (ROOT / "references" / "finding-schema.md").read_text(encoding="utf-8")
    db = json.loads((workdir / "fixture-evidence-db.json").read_text(encoding="utf-8"))
    report = json.loads((workdir / "fixture-evidence-findings.json").read_text(encoding="utf-8"))

    for key in db:
        check(f"nhi-db key documented: {key}", key in schema,
              "finding-schema.md must describe every field the code emits")
    for key in report:
        check(f"findings key documented: {key}", key in schema)
    finding_keys = {k for f in report["findings"] for k in f}
    for key in finding_keys:
        check(f"finding field documented: {key}", key in schema)

    trust_keys = set()
    for ident in db["identities"]:
        trust_keys |= set(ident.get("trust") or {})
    for key in trust_keys:
        check(f"trust field documented: {key}", key in schema)

    reasons = {g["reason"] for g in db["coverageGaps"]}
    ranked = (ROOT / "scripts" / "build_db.py").read_text(encoding="utf-8")
    for reason in reasons:
        check(f"gap reason documented: {reason}", reason in schema)
        check(f"gap reason ranked: {reason}", f'"{reason}"' in ranked)

    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    for script in ("assess.py", "collect_evidence.py", "build_db.py", "scan.py",
                   "render_report.py", "selftest.py"):
        check(f"SKILL.md mentions {script}", script in skill)

    import argparse as _ap
    for mod, name in ((assess, "assess.py"), (scan, "scan.py")):
        parser_flags = set()
        for line in (ROOT / "scripts" / name).read_text(encoding="utf-8").splitlines():
            if 'add_argument("--' in line:
                parser_flags.add(line.split('add_argument("')[1].split('"')[0])
        documented = skill + (ROOT / "references" / "finding-schema.md").read_text(encoding="utf-8")
        for flag in parser_flags - {"--dry-run", "--title", "--azure-tenant", "--cloud",
                                    "--aws-profile", "--output", "--only", "--exclude"}:
            check(f"{name} flag documented: {flag}", flag in documented,
                  "a flag nobody documents is a flag nobody uses correctly")


def test_cli(workdir):
    section("CLI behaviour")
    proc = subprocess.run([sys.executable, str(HERE / "collect_evidence.py"),
                           "--dry-run", "--cloud", "aws", "--aws-profile", "demo",
                           "--regions", "ap-northeast-1"],
                          capture_output=True, text=True)
    check("dry-run exits cleanly", proc.returncode == 0, proc.stderr[:200])
    check("dry-run prints commands", "aws --profile demo iam list-users" in proc.stdout)
    check("dry-run discloses per-item calls", "ごとに繰り返し" in proc.stdout,
          "the operator approving a dry run must see the per-principal calls")
    check("dry-run discloses per-user key lookups",
          "list-access-keys --user-name <user>" in proc.stdout)
    check("dry-run discloses user tag lookup", "list-user-tags" in proc.stdout,
          "owner tags are the only AWS ownership signal; the call must be disclosed")
    check("dry-run marks get-role as conditional",
          "RoleLastUsed/Tags 未取得時のみ" in proc.stdout,
          "list-roles already carries these fields; get-role must not be unconditional N+1")
    check("dry-run writes nothing", not list(workdir.glob("nhi-evidence-*")))

    az_proc = subprocess.run([sys.executable, str(HERE / "collect_evidence.py"),
                              "--dry-run", "--cloud", "azure"],
                             capture_output=True, text=True)
    check("azure dry-run exits cleanly", az_proc.returncode == 0, az_proc.stderr[:200])
    check("dry-run commands are paste-safe",
          "'https://graph.microsoft.com/v1.0/applications?$expand=owners&$top=100'" in az_proc.stdout,
          "unquoted $ in a pasted URL is expanded by the shell and changes the request")
    check("token probe disclosed in dry-run", "get-access-token" in az_proc.stdout,
          "the liveness probe contacts AAD and must be shown before approval")

    db = workdir / "fixture-evidence-db.json"
    proc = subprocess.run([sys.executable, str(HERE / "scan.py"), str(db),
                           "-r", str(ROOT / "rules"),
                           "-o", str(workdir / "gate.json"), "--fail-on", "critical"],
                          capture_output=True, text=True)
    check("--fail-on critical returns 2", proc.returncode == 2, f"rc={proc.returncode}")
    proc = subprocess.run([sys.executable, str(HERE / "scan.py"), str(db),
                           "-r", str(ROOT / "rules"), "-o", str(workdir / "gate2.json"),
                           "--only", "NHI-AWS-009", "--fail-on", "critical"],
                          capture_output=True, text=True)
    check("--only narrows the run", '"NHI-AWS-009' in
          (workdir / "gate2.json").read_text(encoding="utf-8"))
    data = json.loads((workdir / "gate2.json").read_text(encoding="utf-8"))
    check("--only excludes other rules",
          {f["ruleId"] for f in data["findings"]} == {"NHI-AWS-009"})


def main():
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        test_rule_pack()
        test_operators()
        test_readonly_guard()
        report = test_main_fixture(workdir)
        test_degraded_fixture(workdir)
        test_suppression(workdir)
        test_signin_sample_depth()
        test_shallow_signin_fixture(workdir)
        test_owner_evidence_semantics()
        test_trust_classification()
        test_gating_is_shared()
        test_app_mgmt_policy_shapes()
        test_scp_strictness()
        test_masking(workdir)
        test_delta(workdir)
        test_threshold_coherence()
        test_report(report, workdir)
        test_collector_hardening()
        test_bad_input(workdir)
        test_one_command(workdir)
        test_docs_match_code(workdir)
        test_cli(workdir)

    print(f"\n{'=' * 60}")
    print(f"passed: {len(PASS)}   failed: {len(FAIL)}")
    if FAIL:
        print("\nFAILURES:")
        for f in FAIL:
            print(f"  ✗ {f}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
