# scanner.py

import argparse
import os
import webbrowser

from file_loader import find_files_to_scan
from rules import scan_code
from report_generator import (
    generate_report,
    generate_html_dashboard,
    create_severity_summary,
    calculate_risk_score,
    get_risk_level,
)
from ai_fix_coach import enrich_findings_with_ai
from history_manager import add_scan_record, load_scan_history


def read_file(file_path):
    """
    Reads a file and returns its content as text.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        return file.read()


def filter_findings_by_min_severity(findings, min_severity):
    """
    Keeps only findings that are equal to or higher than the selected severity.

    Example:
        min_severity = HIGH
        keeps HIGH only

        min_severity = MEDIUM
        keeps HIGH and MEDIUM

        min_severity = LOW
        keeps HIGH, MEDIUM, and LOW
    """

    severity_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
    }

    minimum_rank = severity_rank.get(min_severity, 1)

    filtered_findings = []

    for finding in findings:
        finding_severity = finding.get("severity", "MEDIUM")
        finding_rank = severity_rank.get(finding_severity, 2)

        if finding_rank >= minimum_rank:
            filtered_findings.append(finding)

    return filtered_findings


def parse_arguments():
    """
    Handles command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description="AI Code Safety Reviewer - scan Python projects for risky code patterns."
    )

    parser.add_argument(
        "folder_path",
        help="Path to the project folder you want to scan."
    )

    ai_group = parser.add_mutually_exclusive_group()

    ai_group.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI Fix Coach using OpenAI API."
    )

    ai_group.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI Fix Coach and use manual suggestions only."
    )

    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH"],
        default="LOW",
        help="Minimum severity to include in reports. Default is LOW."
    )

    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Do not save this scan into scan history."
    )

    parser.add_argument(
        "--open-dashboard",
        action="store_true",
        help="Open the generated HTML dashboard automatically after scanning."
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    project_path = args.folder_path
    use_ai = args.ai

    print(f"Scanning folder: {project_path}")

    if use_ai:
        print("AI Fix Coach: enabled")
    else:
        print("AI Fix Coach: manual fallback mode")

    print(f"Minimum severity: {args.min_severity}")

    if args.no_history:
        print("Scan history: disabled for this run")
    else:
        print("Scan history: enabled")

    files = find_files_to_scan(project_path)

    all_findings = []

    for file_path in files:
        code_text = read_file(file_path)
        findings = scan_code(file_path, code_text)
        all_findings.extend(findings)

    all_findings = filter_findings_by_min_severity(
        findings=all_findings,
        min_severity=args.min_severity
    )

    all_findings = enrich_findings_with_ai(
        findings=all_findings,
        use_ai=use_ai
    )

    severity_summary = create_severity_summary(all_findings)
    risk_score = calculate_risk_score(severity_summary)
    risk_level = get_risk_level(risk_score)

    report_path = generate_report(all_findings)

    if args.no_history:
        scan_history = load_scan_history()

        latest_dashboard_path = generate_html_dashboard(
            findings=all_findings,
            output_path="reports/dashboard.html",
            scan_history=scan_history,
        )

        saved_scan_snapshot_path = None

    else:
        scan_history, scan_snapshot_path = add_scan_record(
            project_path=project_path,
            files_scanned=len(files),
            findings=all_findings,
            severity_summary=severity_summary,
            risk_score=risk_score,
            risk_level=risk_level,
        )

        latest_dashboard_path = generate_html_dashboard(
            findings=all_findings,
            output_path="reports/dashboard.html",
            scan_history=scan_history,
        )

        saved_scan_snapshot_path = generate_html_dashboard(
            findings=all_findings,
            output_path=scan_snapshot_path,
            scan_history=scan_history,
        )

    print("\nScan completed.")
    print(f"Files scanned: {len(files)}")
    print(f"Issues found after filtering: {len(all_findings)}")
    print(f"Risk Score: {risk_score}/10")
    print(f"Risk Level: {risk_level}")
    print(f"Text report saved at: {report_path}")
    print(f"Latest HTML dashboard saved at: {latest_dashboard_path}")

    if saved_scan_snapshot_path:
        print(f"Saved scan snapshot at: {saved_scan_snapshot_path}")

    if not args.no_history:
        print("Scan history updated at: scan_history/history.json")

    if args.open_dashboard:
        dashboard_absolute_path = os.path.abspath(latest_dashboard_path)
        webbrowser.open(f"file:///{dashboard_absolute_path}")


if __name__ == "__main__":
    main()