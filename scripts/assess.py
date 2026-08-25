#!/usr/bin/env python3
"""One-command NHI posture assessment: collect, normalize, scan, report.

    python3 assess.py --dry-run --cloud both --aws-profile prod --regions ap-northeast-1
    python3 assess.py --cloud both --aws-profile prod --regions ap-northeast-1
    python3 assess.py --from-evidence ./nhi-assessment-20260825/evidence
    python3 assess.py --cloud azure --baseline ./last-run/findings.json

Everything lands in one output directory. Any step that fails stops the run and
says why, so a partial collection never turns into a reassuring report.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_db  # noqa: E402
import collect_evidence  # noqa: E402
import render_report  # noqa: E402
import scan  # noqa: E402

STEP = "\n\033[1m[{n}/4] {title}\033[0m" if sys.stdout.isatty() else "\n[{n}/4] {title}"


def step(n, title):
    print(STEP.format(n=n, title=title))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="NHI ポスチャ評価を 1 コマンドで実行する(収集→正規化→判定→レポート)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("-o", "--outdir",
                    default=f"nhi-assessment-{datetime.now():%Y%m%d-%H%M%S}",
                    help="出力ディレクトリ(証跡・DB・findings・レポートを収める)")
    ap.add_argument("--cloud", choices=["aws", "azure", "both"], default="both")
    ap.add_argument("--aws-profile")
    ap.add_argument("--regions", default="us-east-1",
                    help="カンマ区切り。IMDS のアカウント既定はリージョン単位なので必ず対象を全て挙げる")
    ap.add_argument("--azure-tenant")
    ap.add_argument("--max-principals", type=int, default=500)
    ap.add_argument("--from-evidence", help="収集を省略し、既存の証跡ディレクトリから再実行する")
    ap.add_argument("--rules", action="append", default=[],
                    help="ルールパック(既定はこの Skill の rules/)")
    ap.add_argument("--baseline", help="前回の findings.json。新規/継続/解消を出す")
    ap.add_argument("--fail-on", choices=scan.SEVERITY_ORDER,
                    help="この重大度以上があれば終了コード 2(CI ゲート用)")
    ap.add_argument("--title", default="NHI ポスチャ評価レポート")
    ap.add_argument("--force", action="store_true",
                    help="出力ディレクトリの既存 findings.json を上書きする")
    ap.add_argument("--dry-run", action="store_true",
                    help="収集で実行する読み取り専用コマンドを表示して終了する")
    args = ap.parse_args(argv)

    if args.dry_run:
        return collect_evidence.main(
            ["--dry-run", "--cloud", args.cloud, "--regions", args.regions]
            + (["--aws-profile", args.aws_profile] if args.aws_profile else [])
            + (["--azure-tenant", args.azure_tenant] if args.azure_tenant else []))

    outdir = Path(args.outdir)
    if (outdir / "findings.json").exists() and not args.force:
        print(f"error: {outdir}/findings.json が既にある。上書きすると差分レビューの"
              f"基準を失う。別の -o を指定するか、前回分を --baseline に渡すこと"
              f"(意図的に潰すなら --force)。", file=sys.stderr)
        return 1
    outdir.mkdir(parents=True, exist_ok=True)
    evidence = Path(args.from_evidence) if args.from_evidence else outdir / "evidence"
    db_path = outdir / "nhi-db.json"
    findings_path = outdir / "findings.json"
    report_path = outdir / "report.html"

    if args.from_evidence:
        step(1, f"収集をスキップし既存の証跡を使う: {evidence}")
        if not evidence.is_dir():
            print(f"error: 証跡ディレクトリが無い: {evidence}", file=sys.stderr)
            return 1
    else:
        step(1, "証跡の収集(読み取り専用)")
        rc = collect_evidence.main(
            ["--cloud", args.cloud, "--regions", args.regions,
             "--max-principals", str(args.max_principals), "-o", str(evidence)]
            + (["--aws-profile", args.aws_profile] if args.aws_profile else [])
            + (["--azure-tenant", args.azure_tenant] if args.azure_tenant else []))
        if rc != 0:
            print("\n収集に失敗した。認証と権限を直してから再実行すること。", file=sys.stderr)
            return rc

    step(2, "証跡の正規化")
    if build_db.main([str(evidence), "-o", str(db_path)]) != 0:
        print("\n正規化に失敗した。上のギャップを見て収集をやり直すこと。", file=sys.stderr)
        return 1

    step(3, "ルール判定")
    scan_args = [str(db_path), "-o", str(findings_path)]
    for r in (args.rules or [str(HERE.parent / "rules")]):
        scan_args += ["-r", r]
    if args.baseline:
        scan_args += ["--baseline", args.baseline]
    rc_scan = scan.main(scan_args)
    if rc_scan == 1:
        return 1

    step(4, "レポート生成")
    if render_report.main([str(findings_path), "-o", str(report_path),
                           "--title", args.title]) != 0:
        return 1

    print(f"\n完了。ブラウザで開く: {report_path}")
    print(f"  証跡    {evidence}")
    print(f"  DB      {db_path}")
    print(f"  findings {findings_path}")
    print("\n自動判定は起点であって完成ではない。到達可能性・業務上の意図・データの機微度を")
    print("証跡で確認して severity を確定し、未取得領域を『問題なし』と読み替えないこと。")

    if args.fail_on:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        if scan.exceeds(data["findings"], args.fail_on):
            print(f"\n{args.fail_on} 以上の指摘があるため終了コード 2 を返す。")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
