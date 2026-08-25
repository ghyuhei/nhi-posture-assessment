#!/usr/bin/env python3
"""NHI posture rule engine.

Evaluates a declarative rule pack against a normalized NHI database and emits
findings.json. Completely offline: reads only local files, performs no network
or cloud API calls.

Design mirrors CodeQL: `build_db.py` creates the database, this script runs the
query pack against it, and `render_report.py` presents the results.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from fnmatch import fnmatch
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

TARGET_COLLECTIONS = {
    "identities": "identities",
    "resources": "resources",
    "scopes": "scopes",
    "coverageGaps": "coverageGaps",
}


class RuleError(Exception):
    pass


# --------------------------------------------------------------------------
# path resolution
# --------------------------------------------------------------------------
def resolve(path: str, obj):
    """Resolve a dotted path into a list of values.

    A segment ending in `[]` flattens a list, preserving one slot per element
    (absent keys yield None) so that existential operators behave predictably.
    A path that does not end in `[]` but lands on a list returns that list as a
    single value, which is what the count_* operators consume.
    """
    current = [obj]
    for segment in path.split("."):
        flatten = segment.endswith("[]")
        key = segment[:-2] if flatten else segment
        nxt = []
        for item in current:
            if isinstance(item, dict):
                value = item.get(key)
            else:
                value = None
            if flatten:
                if isinstance(value, list):
                    nxt.extend(value if value else [])
                elif value is None:
                    nxt.append(None)
                else:
                    nxt.append(value)
            else:
                nxt.append(value)
        current = nxt
    return current


def _nonnull(values):
    return [v for v in values if v is not None]


# --------------------------------------------------------------------------
# operators
# --------------------------------------------------------------------------
def _count(values):
    """Length of a resolved container, or the number of non-null resolved values.

    A path that lands on a list yields that list as a single value, so its
    length is the count. A flattened path yields one slot per element and the
    count is the number of slots that actually held a value.
    """
    if not values:
        return 0
    if len(values) == 1 and isinstance(values[0], list):
        return len(values[0])
    return len(_nonnull(values))


def _cmp(values, want, fn):
    for v in _nonnull(values):
        try:
            if fn(v, want):
                return True
        except TypeError:
            continue
    return False


def apply_op(op: str, values, want):
    live = _nonnull(values)
    if op == "exists":
        return bool(live)
    if op == "missing":
        # Existential on collections: any absent slot counts as missing.
        return (not values) or any(v is None for v in values)
    if op == "count_gte":
        return _count(values) >= want
    if op == "count_lte":
        return _count(values) <= want
    if op == "eq":
        return any(v == want for v in live)
    if op == "ne":
        # Fail-closed: an absent control value means the control is not in place.
        return (not live) or any(v != want for v in live)
    if op == "gt":
        return _cmp(values, want, lambda a, b: a > b)
    if op == "gte":
        return _cmp(values, want, lambda a, b: a >= b)
    if op == "lt":
        return _cmp(values, want, lambda a, b: a < b)
    if op == "lte":
        return _cmp(values, want, lambda a, b: a <= b)
    if op == "in":
        want_set = want if isinstance(want, list) else [want]
        return any(v in want_set for v in live)
    if op == "nin":
        want_set = want if isinstance(want, list) else [want]
        return (not live) or any(v not in want_set for v in live)
    if op == "contains":
        return any(want in v for v in live if isinstance(v, (str, list)))
    if op == "ncontains":
        return not any(want in v for v in live if isinstance(v, (str, list)))
    if op == "regex":
        rx = re.compile(want)
        return any(rx.search(v) for v in live if isinstance(v, str))
    if op == "startswith":
        return any(v.startswith(want) for v in live if isinstance(v, str))
    raise RuleError(f"unknown operator: {op}")


def evaluate(pred, entity, touched: set) -> bool:
    if not isinstance(pred, dict):
        raise RuleError(f"predicate must be an object, got {type(pred).__name__}")
    if "all" in pred:
        return all(evaluate(p, entity, touched) for p in pred["all"])
    if "any" in pred:
        return any(evaluate(p, entity, touched) for p in pred["any"])
    if "none" in pred:
        return not any(evaluate(p, entity, touched) for p in pred["none"])
    if "forEach" in pred:
        # Element-scoped quantifier: the inner predicate must hold for a SINGLE
        # element. Without this, `credentials[].status == Active` and
        # `credentials[].ageDays > 90` could be satisfied by two different keys.
        collection = pred["forEach"]
        touched.add(collection.replace("[]", ""))
        inner = pred.get("where")
        if inner is None:
            raise RuleError(f"forEach predicate missing 'where': {pred}")
        for value in resolve(collection, entity):
            items = value if isinstance(value, list) else ([] if value is None else [value])
            for item in items:
                sub: set = set()
                if evaluate(inner, item, sub):
                    touched.update(f"{collection}.{f}" for f in sub)
                    return True
        return False
    field = pred.get("field")
    if field is None:
        raise RuleError(f"predicate missing 'field': {pred}")
    touched.add(field.replace("[]", ""))
    return apply_op(pred.get("op", "exists"), resolve(field, entity), pred.get("value"))


# --------------------------------------------------------------------------
# thresholds and templating
# --------------------------------------------------------------------------
def bind_thresholds(pred, thresholds):
    if isinstance(pred, dict):
        out = {}
        for k, v in pred.items():
            if k == "value" and isinstance(v, str) and v.startswith("@"):
                name = v[1:]
                if name not in thresholds:
                    raise RuleError(f"undefined threshold: {v}")
                out[k] = thresholds[name]
            else:
                out[k] = bind_thresholds(v, thresholds)
        return out
    if isinstance(pred, list):
        return [bind_thresholds(v, thresholds) for v in pred]
    return pred


_TEMPLATE = re.compile(r"\{([A-Za-z0-9_.\[\]]+)\}")


def render_message(template: str, entity) -> str:
    def sub(match):
        vals = _nonnull(resolve(match.group(1), entity))
        if not vals:
            return "?"
        value = vals[0]
        if isinstance(value, list):
            return ", ".join(str(v) for v in value) if value else "(なし)"
        return str(value)
    return _TEMPLATE.sub(sub, template)


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------
def entity_label(entity, collection):
    if collection == "coverageGaps":
        return entity.get("area", "unknown")
    return entity.get("name") or entity.get("key") or entity.get("id") or "unknown"


def scan(db, packs, only=None, exclude=None):
    findings, suppressed = [], []
    seq = 0
    for pack in packs:
        thresholds = dict(pack.get("thresholds", {}))
        for rule in pack.get("rules", []):
            rid = rule["id"]
            if only and rid not in only:
                continue
            if exclude and rid in exclude:
                continue
            collection = TARGET_COLLECTIONS.get(rule.get("target", "identities"))
            if collection is None:
                raise RuleError(f"{rid}: unknown target {rule.get('target')}")
            where = bind_thresholds(rule["where"], thresholds)
            patterns = rule.get("exceptions", []) or []
            for entity in db.get(collection, []) or []:
                touched: set = set()
                if not evaluate(where, entity, touched):
                    continue
                key = entity.get("key") or entity.get("id") or ""
                matched = next((p for p in patterns if fnmatch(key, p)), None)
                if matched:
                    suppressed.append({"ruleId": rid, "resourceKey": key, "pattern": matched})
                    continue
                unknown = set(entity.get("_unknown", []) or [])
                incomplete = bool(touched & unknown)
                seq += 1
                findings.append({
                    "id": f"{rid}-{seq:04d}",
                    "ruleId": rid,
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "confidence": "low" if incomplete else rule.get("confidence", "high"),
                    "evidenceIncomplete": incomplete,
                    "owasp": rule.get("owasp", []),
                    "docRef": rule.get("docRef"),
                    "cloud": entity.get("cloud"),
                    "scopeId": entity.get("scopeId") or entity.get("id"),
                    "resourceKey": entity.get("key"),
                    "resourceName": entity_label(entity, collection),
                    "resourceType": entity.get("type", collection),
                    "message": render_message(rule["message"], entity),
                    "expected": rule.get("expected"),
                    "remediation": rule.get("remediation"),
                    "validation": rule.get("validation"),
                    "caveat": rule.get("caveat"),
                })
    order = {s: i for i, s in enumerate(reversed(SEVERITY_ORDER))}
    findings.sort(key=lambda f: (order.get(f["severity"], 99), f["ruleId"], f["resourceName"]))
    return findings, suppressed


def exceeds(findings, level):
    """True when any finding is at or above `level`. Single source of truth for gating."""
    cut = SEVERITY_ORDER.index(level)
    return any(SEVERITY_ORDER.index(f["severity"]) >= cut for f in findings)


def summarize(findings):
    summary = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    summary["total"] = len(findings)
    return summary


def summarize_owasp(findings):
    """Findings per OWASP NHI Top 10 category, worst severity first."""
    rollup: dict = {}
    for f in findings:
        for tag in f.get("owasp", []) or []:
            entry = rollup.setdefault(tag, {"count": 0, "worst": "info", "rules": []})
            entry["count"] += 1
            if SEVERITY_ORDER.index(f["severity"]) > SEVERITY_ORDER.index(entry["worst"]):
                entry["worst"] = f["severity"]
            if f["ruleId"] not in entry["rules"]:
                entry["rules"].append(f["ruleId"])
    return dict(sorted(rollup.items(), key=lambda kv: int(kv[0].replace("NHI", "") or 0)))


def _unique_scopes(scopes):
    seen, out = set(), []
    for s in scopes:
        marker = (s.get("cloud"), s.get("id"))
        if marker in seen:
            continue
        seen.add(marker)
        out.append({"cloud": s.get("cloud"), "id": s.get("id"), "type": s.get("type")})
    return out


def load_packs(paths):
    packs = []
    for p in paths:
        path = Path(p)
        files = sorted(path.glob("*.json")) if path.is_dir() else [path]
        for f in files:
            with open(f, encoding="utf-8") as fh:
                pack = json.load(fh)
            if "rules" not in pack:
                raise RuleError(f"{f}: not a rule pack (no 'rules' key)")
            packs.append(pack)
    if not packs:
        raise RuleError("no rule packs loaded")
    return packs


def main(argv=None):
    ap = argparse.ArgumentParser(description="Evaluate NHI rule packs against an NHI database.")
    ap.add_argument("db", help="nhi-db.json produced by build_db.py")
    ap.add_argument("-r", "--rules", action="append", default=[], help="rule pack file or directory (repeatable)")
    ap.add_argument("-o", "--output", default="findings.json")
    ap.add_argument("--only", action="append", default=[], help="run only these rule IDs")
    ap.add_argument("--exclude", action="append", default=[], help="skip these rule IDs")
    ap.add_argument("--baseline", help="previous findings.json; marks new / resolved findings")
    ap.add_argument("--fail-on", choices=SEVERITY_ORDER, help="exit 2 if a finding at or above this severity exists")
    args = ap.parse_args(argv)

    if not args.rules:
        args.rules = [str(Path(__file__).resolve().parent.parent / "rules")]

    try:
        with open(args.db, encoding="utf-8") as fh:
            db = json.load(fh)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"error: cannot read database {args.db}: {exc}", file=sys.stderr)
        return 1
    try:
        packs = load_packs(args.rules)
    except (RuleError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"error: cannot load rule packs: {exc}", file=sys.stderr)
        return 1

    known = {r["id"] for p in packs for r in p.get("rules", [])}
    for flag, values in (("--only", args.only), ("--exclude", args.exclude)):
        unknown = sorted(set(values) - known)
        if unknown:
            print(f"warning: {flag} references unknown rule ids: {', '.join(unknown)}",
                  file=sys.stderr)
    if args.only and not (set(args.only) & known):
        print("error: --only matched no rules in the loaded packs", file=sys.stderr)
        return 1

    try:
        findings, suppressed = scan(db, packs, set(args.only) or None, set(args.exclude) or None)
    except RuleError as exc:
        print(f"error: rule evaluation failed: {exc}", file=sys.stderr)
        return 1

    resolved = []
    if args.baseline:
        try:
            with open(args.baseline, encoding="utf-8") as fh:
                previous = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read baseline {args.baseline}: {exc}", file=sys.stderr)
            return 1
        seen_before = {(f.get("ruleId"), f.get("resourceKey"))
                       for f in previous.get("findings", [])}
        seen_now = {(f["ruleId"], f["resourceKey"]) for f in findings}
        for f in findings:
            f["state"] = "existing" if (f["ruleId"], f["resourceKey"]) in seen_before else "new"
        resolved = [{"ruleId": f.get("ruleId"), "resourceKey": f.get("resourceKey"),
                     "severity": f.get("severity"), "title": f.get("title")}
                    for f in previous.get("findings", [])
                    if (f.get("ruleId"), f.get("resourceKey")) not in seen_now]

    report = {
        "schemaVersion": "1.0",
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dbGeneratedAt": db.get("generatedAt"),
        "packs": [{"name": p.get("packName"), "version": p.get("packVersion")} for p in packs],
        "scopes": _unique_scopes(db.get("scopes", [])),
        "coverageGaps": db.get("coverageGaps", []),
        "summary": summarize(findings),
        "suppressed": suppressed,
        "baseline": args.baseline,
        "resolved": resolved,
        "owaspSummary": summarize_owasp(findings),
        "findings": findings,
    }
    Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    s = report["summary"]
    print(f"findings: {s['total']} "
          f"(critical={s['critical']} high={s['high']} medium={s['medium']} low={s['low']} info={s['info']})")
    if args.baseline:
        new_count = sum(1 for f in findings if f.get("state") == "new")
        print(f"vs baseline: new={new_count} existing={len(findings) - new_count} "
              f"resolved={len(resolved)}")
    if suppressed:
        print(f"suppressed by rule exceptions: {len(suppressed)} — 抑止は握りつぶしではない。"
              f"レポートに件数が残る")
    if report["coverageGaps"]:
        print(f"coverage gaps: {len(report['coverageGaps'])} — 未取得領域を『問題なし』と読み替えないこと")
    print(f"wrote {args.output}")

    if args.fail_on and exceeds(findings, args.fail_on):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
