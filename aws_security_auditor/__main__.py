"""CLI entry point; offline mode does not import the AWS SDK."""

import argparse
import json
from pathlib import Path
import re
import sys

from .engine import evaluate
from .models import timestamp
from .offline import read_fixture
from .reporting import build_report, exit_code, write_reports


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only AWS configuration audit: seven controls for EC2, EBS, S3, IAM. IAM runs globally once."
    )
    parser.add_argument("--mode", choices=("offline", "live"), default="offline")
    parser.add_argument("--fixture", type=Path, help="Offline fixture (default: fixtures/demo.json).")
    parser.add_argument("--profile", help="Named AWS profile; required for live mode.")
    parser.add_argument("--regions", nargs="+", help="Commercial AWS regions; required for live mode.")
    parser.add_argument("--expected-account", help="12-digit target account guard; required for live mode.")
    parser.add_argument("--output", type=Path, default=Path("reports/demo"))
    parser.add_argument(
        "--max-key-age-days",
        type=int,
        default=90,
        help="Active-key review threshold, 1..36500 (default: 90).",
    )
    parser.add_argument(
        "--now", help="Offline-only evaluation time with timezone; defaults to fixture generated_at."
    )
    args = parser.parse_args(argv)
    if not 1 <= args.max_key_age_days <= 36500:
        parser.error("--max-key-age-days must be between 1 and 36500.")
    if args.mode == "live":
        if args.fixture is not None or args.now is not None:
            parser.error("--fixture and --now are only valid in offline mode.")
        if not args.profile or not args.regions or not args.expected_account:
            parser.error("Live mode requires --profile, --regions, and --expected-account.")
        if not re.fullmatch(r"\d{12}", args.expected_account):
            parser.error("--expected-account must contain exactly 12 digits.")
        if len(set(args.regions)) != len(args.regions):
            parser.error("Duplicate regions are not allowed.")
        if any(not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", x) for x in args.regions):
            parser.error("Invalid region code.")
    elif args.profile is not None or args.regions is not None or args.expected_account is not None:
        parser.error("--profile, --regions, and --expected-account require --mode live.")
    try:
        if args.mode == "offline":
            scan = read_fixture(args.fixture or Path("fixtures/demo.json"))
        else:
            try:
                from .collectors import collect_live
            except ImportError:
                raise ValueError("Live mode requires Boto3. Install requirements.txt first.") from None
            scan = collect_live(args.profile, args.regions, args.expected_account)
        now = timestamp(args.now or scan.generated_at)
        assessments = evaluate(scan, now, args.max_key_age_days)
        report = build_report(scan, assessments, args.max_key_age_days, now.isoformat())
        write_reports(report, args.output)
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        print(f"Audit error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "mode": scan.mode,
                "summary": report["summary"],
                "complete": report["coverage"]["evaluation_complete"],
                "reports": str(args.output),
            },
            sort_keys=True,
        )
    )
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
