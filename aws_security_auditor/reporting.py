"""Deterministic JSON and Markdown reports with explicit collection coverage."""

from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .engine import CHECKS

LIMITATIONS = [
    "Seven project baselines, not compliance certification or proof of exploitability.",
    "One commercial AWS account; EC2/EBS and general purpose S3 buckets in requested regions; IAM once globally.",
    "Directory buckets, access points, Outposts, root credentials, SSO users, and role sessions are outside scope.",
    "Ingress checks examine individual explicit /0 rules; no aggregate CIDR, prefix-list expansion, routing, ACL, or reachability analysis.",
    "S3 public access block is a configuration baseline, not full policy/ACL authorization analysis.",
    "Registered MFA does not prove session MFA enforcement. APIs are not an atomic snapshot; races can occur.",
    "Read-only collection; remediation must be reviewed and applied separately.",
]


def build_report(scan, assessments, max_age_days=90, evaluated_at=None):
    counts = Counter(a.status for a in assessments)
    severity = Counter(a.severity for a in assessments if a.status == "FAIL")
    errors = [
        dict(
            service=inv.service,
            region=inv.region,
            **{k: v for k, v in error.items() if k not in {"service", "region"}},
        )
        for inv in scan.inventories
        for error in inv.errors
    ]
    errors.sort(
        key=lambda x: (x["service"], x["region"], x.get("operation", ""), x.get("resource", ""), x["code"])
    )
    coverage = [
        {
            "kind": inv.kind,
            "service": inv.service,
            "region": inv.region,
            "collected_at": inv.collected_at,
            "complete": inv.complete and not inv.errors,
            "resource_count": len(inv.records),
            "error_count": len(inv.errors),
        }
        for inv in scan.inventories
    ]
    coverage.sort(key=lambda x: (x["service"], x["region"], x["kind"]))
    services = sorted({x["service"] for x in coverage})
    complete_services = [s for s in services if all(x["complete"] for x in coverage if x["service"] == s)]
    complete_regions = [
        r for r in scan.regions if all(x["complete"] for x in coverage if x["region"] in (r, "global"))
    ]
    collection_complete = all(x["complete"] for x in coverage)
    complete = collection_complete and all(a.evaluation_complete for a in assessments)
    items = [asdict(a) for a in assessments]
    checks = sorted({check for inv in scan.inventories for check in CHECKS[inv.kind]})
    return {
        "schema_version": "1.0",
        "mode": scan.mode,
        "generated_at": scan.generated_at,
        "evaluated_at": evaluated_at or scan.generated_at,
        "scope": {
            "account_id": scan.account_id,
            "requested_regions": scan.regions,
            "requested_services": services,
            "checks_run": checks,
            "max_key_age_days": max_age_days,
        },
        "coverage": {
            "collection_complete": collection_complete,
            "evaluation_complete": complete,
            "completed_regions": complete_regions,
            "completed_services": complete_services,
            "resource_count": sum(len(inv.records) for inv in scan.inventories),
            "access_key_count": sum(
                len(u.get("AccessKeys", []))
                for inv in scan.inventories
                if inv.kind == "users"
                for u in inv.records
                if isinstance(u.get("AccessKeys"), list)
            ),
            "assessment_count": len(items),
            "unknown_count": counts["UNKNOWN"],
            "incomplete_assessment_count": sum(not a.evaluation_complete for a in assessments),
            "inventories": coverage,
            "skipped": scan.skipped,
        },
        "summary": {s: counts[s] for s in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")},
        "failed_by_severity": {s: severity[s] for s in ("HIGH", "MEDIUM", "LOW")},
        "assessments": items,
        "findings": [a for a in items if a["status"] == "FAIL"],
        "scan_errors": errors,
        "approved_exceptions": [],
        "limitations": LIMITATIONS,
    }


def safe(value):
    text = (
        str(value)
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    for char in ("\\", "`", "*", "_", "[", "]", "|", "#"):
        text = text.replace(char, "\\" + char)
    return text


def markdown(report):
    scope, coverage = report["scope"], report["coverage"]
    lines = [
        "# AWS Security Configuration Auditor",
        "",
        f"Data source: **{report['mode'].upper()}**. "
        + (
            "Invented local fixtures; not a live AWS audit."
            if report["mode"] == "offline"
            else "Read-only AWS API observations."
        ),
        "",
        f"Account: {safe(scope['account_id'])}",
        f"Requested regions: {', '.join(map(safe, scope['requested_regions']))}; IAM global.",
        f"Checks: {', '.join(scope['checks_run'])}; active-key threshold: {scope['max_key_age_days']} days.",
        f"Collection complete: **{coverage['collection_complete']}**; evaluation complete: **{coverage['evaluation_complete']}**.",
        f"Collected at: {safe(report['generated_at'])}; evaluated at: {safe(report['evaluated_at'])}.",
        "",
        "A complete scan means these selected checks evaluated the collected scope. Zero findings or zero resources does not prove the account is secure.",
        "",
        "## Summary",
        "",
        "| PASS | FAIL | UNKNOWN | NOT APPLICABLE |",
        "| ---: | ---: | ---: | ---: |",
        "| "
        + " | ".join(str(report["summary"][s]) for s in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"))
        + " |",
        "",
        f"Inventory resources: {coverage['resource_count']}; access-key records: {coverage['access_key_count']}; assessments: {coverage['assessment_count']}.",
        "Inventory resources count groups, instances, volumes, buckets, and users once per scope; access keys are counted separately.",
        "",
        "## Collection coverage",
        "",
        "| Inventory | Region | Resources | Complete | Errors |",
        "| --- | --- | ---: | --- | ---: |",
    ]
    for inv in coverage["inventories"]:
        lines.append(
            f"| {inv['kind']} | {safe(inv['region'])} | {inv['resource_count']} | {inv['complete']} | {inv['error_count']} |"
        )
    lines += ["", "## Failed findings", ""]
    for severity in ("HIGH", "MEDIUM", "LOW"):
        lines.append(f"### {severity}: {report['failed_by_severity'][severity]}")
        lines.append("")
        for finding in report["findings"]:
            if finding["severity"] != severity:
                continue
            lines += [
                f"#### {finding['check_id']} — {safe(finding['resource_id'])}",
                "",
                f"Region: {safe(finding['region'])}; stable ID: {finding['id']}.",
                "",
            ]
            lines.extend(f"- Evidence: {safe(e)}" for e in finding["evidence"])
            lines += [
                f"- Risk: {safe(finding['risk'])}",
                f"- Recommendation: {safe(finding['recommendation'])}",
                f"- Verification: {safe(finding['verification'])}",
                "",
            ]
    lines += ["## UNKNOWN assessments", ""]
    unknowns = [a for a in report["assessments"] if a["status"] == "UNKNOWN"]
    if not unknowns:
        lines += ["None.", ""]
    for item in unknowns:
        lines += [
            f"- {item['check_id']} {safe(item['resource_id'])} ({safe(item['region'])}): "
            + "; ".join(map(safe, item["evidence"]))
        ]
    lines += ["", "## Incomplete compound evaluations", ""]
    mixed = [a for a in report["assessments"] if a["status"] != "UNKNOWN" and not a["evaluation_complete"]]
    if not mixed:
        lines.append("None.")
    for item in mixed:
        lines.append(
            f"- {item['check_id']} {safe(item['resource_id'])}: {item['status']} is established, but other rule input is incomplete. See evidence."
        )
    lines += ["", "## Collection errors", ""]
    if not report["scan_errors"]:
        lines.append("None.")
    for error in report["scan_errors"]:
        lines.append(
            f"- {safe(error['service'])}/{safe(error['region'])} {safe(error['operation'])}: {safe(error['code'])}; resource={safe(error.get('resource', 'scope'))}."
        )
    lines += ["", "## Skipped scope", ""]
    lines += ["- " + safe(item) for item in coverage["skipped"]] or ["None."]
    lines += ["", "## Limitations and exceptions", ""]
    lines += ["- " + safe(item) for item in report["limitations"]]
    lines += [
        "",
        "No approved exceptions are configured. Failed results retain their original status.",
        "",
        "## All assessments",
        "",
        "| Check | Region | Resource | Status |",
        "| --- | --- | --- | --- |",
    ]
    lines += [
        f"| {a['check_id']} | {safe(a['region'])} | {safe(a['resource_id'])} | {a['status']} |"
        for a in report["assessments"]
    ]
    return "\n".join(lines) + "\n"


def write_reports(report, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    # Serialize both outputs before replacing either destination file.
    body = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    md = markdown(report)
    with TemporaryDirectory(prefix=".audit-", dir=output) as temp:
        root = Path(temp)
        (root / "report.json").write_text(body, encoding="utf-8")
        (root / "report.md").write_text(md, encoding="utf-8")
        (root / "report.json").replace(output / "report.json")
        (root / "report.md").replace(output / "report.md")


def exit_code(report):
    if not report["coverage"]["evaluation_complete"]:
        return 2
    return 1 if report["summary"]["FAIL"] else 0
