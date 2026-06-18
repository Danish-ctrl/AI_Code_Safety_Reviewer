# report_generator.py

import os
import html


def ensure_output_folder(output_path):
    """
    Creates output folder if the path contains a folder.
    Example:
        reports/report.txt -> creates reports/
    """

    folder = os.path.dirname(output_path)

    if folder:
        os.makedirs(folder, exist_ok=True)


def create_severity_summary(findings):
    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "MEDIUM")

        if severity in summary:
            summary[severity] += 1

    return summary


def create_confidence_summary(findings):
    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        confidence = finding.get("confidence", "MEDIUM")

        if confidence in summary:
            summary[confidence] += 1

    return summary


def create_file_summary(findings):
    file_summary = {}

    for finding in findings:
        file_path = finding.get("file", "Unknown file")

        if file_path not in file_summary:
            file_summary[file_path] = 0

        file_summary[file_path] += 1

    return file_summary


def calculate_risk_score(severity_summary):
    high_score = severity_summary["HIGH"] * 3
    medium_score = severity_summary["MEDIUM"] * 2
    low_score = severity_summary["LOW"] * 1

    total_score = high_score + medium_score + low_score

    if total_score > 10:
        return 10

    return total_score


def get_risk_level(risk_score):
    if risk_score >= 8:
        return "HIGH"
    elif risk_score >= 4:
        return "MEDIUM"
    elif risk_score > 0:
        return "LOW"
    else:
        return "NONE"


def build_relative_link(target_path, current_output_path):
    """
    Builds a relative link from the current HTML file to another HTML file.

    This allows links to work from:
        reports/dashboard.html
        reports/scans/scan_xxx.html
    """

    current_folder = os.path.dirname(current_output_path)

    if not current_folder:
        current_folder = "."

    relative_path = os.path.relpath(target_path, start=current_folder)

    return relative_path.replace("\\", "/")


def generate_report(findings, output_path="reports/report.txt"):
    ensure_output_folder(output_path)

    severity_summary = create_severity_summary(findings)
    confidence_summary = create_confidence_summary(findings)
    file_summary = create_file_summary(findings)
    risk_score = calculate_risk_score(severity_summary)
    risk_level = get_risk_level(risk_score)

    severity_order = {
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    findings.sort(
        key=lambda finding: severity_order.get(
            finding.get("severity", "MEDIUM"),
            99
        )
    )

    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.write("AI Code Safety Reviewer Report\n")
        report_file.write("=" * 40 + "\n\n")

        report_file.write(f"Total issues found: {len(findings)}\n")
        report_file.write(f"Project Risk Score: {risk_score}/10\n")
        report_file.write(f"Risk Level: {risk_level}\n\n")

        report_file.write("Severity Summary:\n")
        report_file.write("-" * 20 + "\n")
        for severity, count in severity_summary.items():
            report_file.write(f"{severity}: {count}\n")
        report_file.write("\n")

        report_file.write("Confidence Summary:\n")
        report_file.write("-" * 20 + "\n")
        for confidence, count in confidence_summary.items():
            report_file.write(f"{confidence}: {count}\n")
        report_file.write("\n")

        report_file.write("File Summary:\n")
        report_file.write("-" * 20 + "\n")

        if file_summary:
            for file_path, count in file_summary.items():
                report_file.write(f"{file_path}: {count} issue(s)\n")
        else:
            report_file.write("No file issues found.\n")

        report_file.write("\n")

        if not findings:
            report_file.write("No risky patterns found.\n")
            return output_path

        grouped = {
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }

        for finding in findings:
            severity = finding.get("severity", "MEDIUM")

            if severity not in grouped:
                severity = "MEDIUM"

            grouped[severity].append(finding)

        for severity in ["HIGH", "MEDIUM", "LOW"]:
            if not grouped[severity]:
                continue

            report_file.write(f"{severity} Issues\n")
            report_file.write("=" * 20 + "\n\n")

            for index, finding in enumerate(grouped[severity], start=1):
                ai_fix = finding.get("ai_fix", {})

                report_file.write(f"Issue #{index}\n")
                report_file.write("-" * 20 + "\n")
                report_file.write(f"Rule ID: {finding.get('rule_id', 'UNKNOWN-RULE')}\n")
                report_file.write(f"File: {finding.get('file', 'Unknown file')}\n")
                report_file.write(f"Line: {finding.get('line', 'Unknown line')}\n")
                report_file.write(f"Severity: {finding.get('severity', 'MEDIUM')}\n")
                report_file.write(f"Confidence: {finding.get('confidence', 'MEDIUM')}\n")
                report_file.write(f"Rule: {finding.get('rule', 'Unknown rule')}\n")
                report_file.write(f"Message: {finding.get('message', '')}\n")
                report_file.write(f"Why Risky: {finding.get('why_risky', '')}\n")
                report_file.write(f"Attack Example: {finding.get('attack_example', '')}\n")
                report_file.write(f"Suggestion: {finding.get('suggestion', '')}\n")
                report_file.write(f"Detected Code: {finding.get('code', '')}\n\n")

                report_file.write("AI Fix Coach\n")
                report_file.write("-" * 12 + "\n")
                report_file.write(f"Summary: {ai_fix.get('ai_summary', '')}\n")
                report_file.write(f"Explanation: {ai_fix.get('ai_explanation', '')}\n")
                report_file.write(f"Fix Steps: {ai_fix.get('ai_fix_steps', '')}\n")
                report_file.write(f"Before Code: {ai_fix.get('before_code', finding.get('code', ''))}\n")
                report_file.write(f"Safer Code: {ai_fix.get('after_code', finding.get('safe_example', ''))}\n\n")

    return output_path


def generate_html_dashboard(findings, output_path="reports/dashboard.html", scan_history=None):
    ensure_output_folder(output_path)

    if scan_history is None:
        scan_history = []

    severity_summary = create_severity_summary(findings)
    confidence_summary = create_confidence_summary(findings)
    file_summary = create_file_summary(findings)
    risk_score = calculate_risk_score(severity_summary)
    risk_level = get_risk_level(risk_score)

    severity_order = {
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    findings.sort(
        key=lambda finding: severity_order.get(
            finding.get("severity", "MEDIUM"),
            99
        )
    )

    risk_color = {
        "HIGH": "#dc2626",
        "MEDIUM": "#d97706",
        "LOW": "#16a34a",
        "NONE": "#6b7280",
    }.get(risk_level, "#6b7280")

    if risk_level == "NONE":
        risk_note = "No immediate action required"
    elif risk_level == "LOW":
        risk_note = "Review when possible"
    elif risk_level == "MEDIUM":
        risk_note = "Review soon"
    else:
        risk_note = "Immediate attention recommended"

    risk_percent = risk_score * 10

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AI Code Safety Reviewer Dashboard</title>
    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            font-family: Arial, sans-serif;
            background: radial-gradient(circle at top left, #e0e7ff, transparent 30%),
                        radial-gradient(circle at top right, #fee2e2, transparent 25%),
                        #f8fafc;
            margin: 0;
            padding: 32px;
            color: #111827;
            transition: background 0.3s ease, color 0.3s ease;
        }}

        body.dark {{
            background: radial-gradient(circle at top left, #1e1b4b, transparent 30%),
                        radial-gradient(circle at top right, #7f1d1d, transparent 25%),
                        #020617;
            color: #e5e7eb;
        }}

        .container {{
            max-width: 1250px;
            margin: auto;
        }}

        .header {{
            background: linear-gradient(135deg, #111827, #312e81);
            color: white;
            padding: 34px;
            border-radius: 24px;
            margin-bottom: 28px;
            box-shadow: 0 18px 40px rgba(17,24,39,0.25);
            display: flex;
            justify-content: space-between;
            gap: 18px;
            align-items: center;
            flex-wrap: wrap;
        }}

        .header h1 {{
            margin: 0;
            font-size: 38px;
            letter-spacing: -1px;
        }}

        .header p {{
            margin-top: 10px;
            color: #d1d5db;
            font-size: 16px;
        }}

        .header-actions {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}

        .top-button {{
            border: none;
            background: rgba(255,255,255,0.14);
            color: white;
            padding: 10px 14px;
            border-radius: 999px;
            cursor: pointer;
            font-weight: bold;
        }}

        .top-button:hover {{
            background: rgba(255,255,255,0.24);
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 20px;
            margin-bottom: 28px;
        }}

        .card {{
            background: rgba(255,255,255,0.88);
            backdrop-filter: blur(12px);
            padding: 24px;
            border-radius: 24px;
            box-shadow: 0 12px 30px rgba(15,23,42,0.10);
            border: 1px solid rgba(255,255,255,0.8);
            transition: transform 0.2s ease, background 0.3s ease;
        }}

        .card:hover {{
            transform: translateY(-3px);
        }}

        body.dark .card,
        body.dark .section {{
            background: rgba(15,23,42,0.88);
            border-color: rgba(148,163,184,0.2);
        }}

        .card h3 {{
            margin-top: 0;
            color: #374151;
            font-size: 16px;
        }}

        body.dark .card h3,
        body.dark .section h2 {{
            color: #e5e7eb;
        }}

        .score {{
            font-size: 46px;
            font-weight: 900;
            letter-spacing: -1px;
        }}

        .risk-card {{
            position: relative;
            overflow: hidden;
            background: linear-gradient(135deg, #ffffff, #fff1f2);
            border: 1px solid #fecaca;
        }}

        body.dark .risk-card {{
            background: linear-gradient(135deg, #1e293b, #450a0a);
        }}

        .risk-card::before {{
            content: "";
            position: absolute;
            width: 210px;
            height: 210px;
            background: rgba(220, 38, 38, 0.13);
            border-radius: 50%;
            top: -75px;
            right: -75px;
            animation: pulseGlow 2.6s infinite ease-in-out;
        }}

        .risk-card::after {{
            content: "";
            position: absolute;
            width: 90px;
            height: 90px;
            background: rgba(220, 38, 38, 0.10);
            border-radius: 50%;
            bottom: -35px;
            left: -25px;
        }}

        .risk-score {{
            color: {risk_color};
            animation: popIn 0.75s ease-out;
            position: relative;
            z-index: 2;
        }}

        .risk-badge {{
            display: inline-block;
            background: linear-gradient(135deg, {risk_color}, #7f1d1d);
            color: white;
            padding: 8px 16px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: bold;
            box-shadow: 0 8px 18px rgba(220, 38, 38, 0.35);
            position: relative;
            z-index: 2;
        }}

        .risk-bar {{
            width: 100%;
            height: 18px;
            background: #fee2e2;
            border-radius: 999px;
            margin-top: 18px;
            overflow: hidden;
            position: relative;
            z-index: 2;
        }}

        .risk-fill {{
            width: 0;
            height: 100%;
            background: linear-gradient(90deg, #f87171, {risk_color}, #7f1d1d);
            border-radius: 999px;
            animation: fillRiskBar 1.4s ease-out forwards;
            box-shadow: 0 0 16px rgba(220, 38, 38, 0.65);
        }}

        .risk-note {{
            margin-top: 14px;
            color: #7f1d1d;
            font-weight: 700;
            position: relative;
            z-index: 2;
        }}

        body.dark .risk-note {{
            color: #fecaca;
        }}

        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-top: 14px;
        }}

        .severity-box {{
            padding: 14px;
            border-radius: 18px;
            text-align: center;
            font-weight: bold;
        }}

        .severity-box span {{
            display: block;
            font-size: 30px;
            margin-top: 6px;
        }}

        .severity-high {{
            background: #fee2e2;
            color: #991b1b;
        }}

        .severity-medium {{
            background: #fef3c7;
            color: #92400e;
        }}

        .severity-low {{
            background: #dcfce7;
            color: #166534;
        }}

        .confidence-high {{
            background: #dbeafe;
            color: #1e40af;
        }}

        .confidence-medium {{
            background: #ede9fe;
            color: #5b21b6;
        }}

        .confidence-low {{
            background: #f3f4f6;
            color: #374151;
        }}

        .section {{
            background: rgba(255,255,255,0.92);
            padding: 26px;
            border-radius: 24px;
            margin-bottom: 28px;
            box-shadow: 0 12px 30px rgba(15,23,42,0.10);
        }}

        .section h2 {{
            margin-top: 0;
            color: #111827;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            overflow: hidden;
            border-radius: 16px;
        }}

        th {{
            background: #111827;
            color: white;
            padding: 14px;
            text-align: left;
        }}

        td {{
            padding: 14px;
            border-bottom: 1px solid #e5e7eb;
        }}

        tr:hover {{
            background: #f9fafb;
        }}

        body.dark tr:hover {{
            background: #1e293b;
        }}

        .history-link {{
            display: inline-block;
            background: #312e81;
            color: white;
            text-decoration: none;
            padding: 7px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
        }}

        .history-link:hover {{
            background: #4338ca;
        }}

        .trend-row {{
            margin-bottom: 14px;
        }}

        .trend-meta {{
            display: flex;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 6px;
            font-size: 14px;
        }}

        .trend-bar {{
            width: 100%;
            height: 14px;
            background: #e5e7eb;
            border-radius: 999px;
            overflow: hidden;
        }}

        .trend-fill {{
            height: 100%;
            border-radius: 999px;
            background: linear-gradient(90deg, #818cf8, #dc2626);
        }}

        .filters {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 14px;
            margin-bottom: 18px;
        }}

        .search-input {{
            width: 100%;
            padding: 14px 16px;
            border: 1px solid #d1d5db;
            border-radius: 16px;
            font-size: 15px;
        }}

        body.dark .search-input {{
            background: #020617;
            color: #e5e7eb;
            border-color: #334155;
        }}

        .filter-row {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }}

        .filter-label {{
            font-weight: bold;
            margin-right: 4px;
        }}

        .filter-button {{
            border: none;
            padding: 8px 13px;
            border-radius: 999px;
            background: #e5e7eb;
            cursor: pointer;
            font-weight: bold;
            color: #111827;
        }}

        .filter-button.active {{
            background: #312e81;
            color: white;
        }}

        .utility-button {{
            border: none;
            padding: 8px 13px;
            border-radius: 999px;
            background: #111827;
            color: white;
            cursor: pointer;
            font-weight: bold;
        }}

        .issue {{
            padding: 20px;
            margin-bottom: 22px;
            border-radius: 22px;
            background: #f9fafb;
            border-left: 8px solid #9ca3af;
            box-shadow: 0 8px 20px rgba(15,23,42,0.06);
            transition: transform 0.2s ease, opacity 0.2s ease;
        }}

        .issue:hover {{
            transform: translateY(-2px);
        }}

        body.dark .issue {{
            background: #0f172a;
        }}

        .issue.HIGH {{
            border-left-color: #dc2626;
            background: linear-gradient(135deg, #fff1f2, #ffffff);
        }}

        .issue.MEDIUM {{
            border-left-color: #d97706;
            background: linear-gradient(135deg, #fffbeb, #ffffff);
        }}

        .issue.LOW {{
            border-left-color: #16a34a;
            background: linear-gradient(135deg, #f0fdf4, #ffffff);
        }}

        body.dark .issue.HIGH {{
            background: linear-gradient(135deg, #450a0a, #0f172a);
        }}

        body.dark .issue.MEDIUM {{
            background: linear-gradient(135deg, #451a03, #0f172a);
        }}

        body.dark .issue.LOW {{
            background: linear-gradient(135deg, #052e16, #0f172a);
        }}

        .issue.reviewed {{
            opacity: 0.58;
        }}

        .issue-title {{
            display: flex;
            justify-content: space-between;
            gap: 12px;
            align-items: center;
            flex-wrap: wrap;
            cursor: pointer;
        }}

        .issue-title h3 {{
            margin: 0;
        }}

        .issue-body {{
            display: none;
            margin-top: 14px;
        }}

        .issue.open .issue-body {{
            display: block;
        }}

        .badge-group {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}

        .badge {{
            color: white;
            padding: 7px 14px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
        }}

        .badge.HIGH {{
            background: #dc2626;
        }}

        .badge.MEDIUM {{
            background: #d97706;
        }}

        .badge.LOW {{
            background: #16a34a;
        }}

        .confidence-badge {{
            padding: 7px 14px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
        }}

        .reviewed-badge {{
            display: none;
            background: #334155;
            color: white;
            padding: 7px 14px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
        }}

        .issue.reviewed .reviewed-badge {{
            display: inline-block;
        }}

        .meta {{
            color: #4b5563;
            margin-top: 12px;
        }}

        body.dark .meta {{
            color: #cbd5e1;
        }}

        .rule-id {{
            display: inline-block;
            background: #111827;
            color: white;
            padding: 5px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 8px;
        }}

        .coach-box {{
            background: #eef2ff;
            border-radius: 18px;
            padding: 18px;
            margin-top: 16px;
            border: 1px solid #c7d2fe;
        }}

        body.dark .coach-box {{
            background: #1e1b4b;
            border-color: #3730a3;
        }}

        .coach-box h4 {{
            margin-top: 0;
            color: #3730a3;
            font-size: 18px;
        }}

        body.dark .coach-box h4 {{
            color: #c4b5fd;
        }}

        .compare-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-top: 14px;
        }}

        .before-box {{
            background: #fff1f2;
            border: 1px solid #fecdd3;
            border-radius: 16px;
            padding: 14px;
        }}

        .after-box {{
            background: #ecfdf5;
            border: 1px solid #bbf7d0;
            border-radius: 16px;
            padding: 14px;
        }}

        body.dark .before-box {{
            background: #450a0a;
            border-color: #991b1b;
        }}

        body.dark .after-box {{
            background: #052e16;
            border-color: #166534;
        }}

        .before-box h5,
        .after-box h5 {{
            margin: 0 0 8px 0;
            font-size: 15px;
        }}

        .code-wrapper {{
            position: relative;
        }}

        .copy-button {{
            position: absolute;
            right: 10px;
            top: 10px;
            border: none;
            background: #4f46e5;
            color: white;
            padding: 5px 9px;
            border-radius: 999px;
            cursor: pointer;
            font-size: 11px;
            font-weight: bold;
        }}

        code {{
            display: block;
            background: #111827;
            color: #f9fafb;
            padding: 38px 13px 13px 13px;
            border-radius: 14px;
            margin-top: 8px;
            white-space: pre-wrap;
            font-family: Consolas, monospace;
            font-size: 14px;
            overflow-x: auto;
        }}

        .review-button {{
            border: none;
            background: #334155;
            color: white;
            padding: 8px 12px;
            border-radius: 999px;
            cursor: pointer;
            font-weight: bold;
            margin-top: 10px;
        }}

        .hidden {{
            display: none !important;
        }}

        .empty {{
            padding: 22px;
            background: #ecfdf5;
            border-radius: 18px;
            color: #166534;
            font-weight: bold;
        }}

        @keyframes fillRiskBar {{
            from {{
                width: 0;
            }}
            to {{
                width: {risk_percent}%;
            }}
        }}

        @keyframes pulseGlow {{
            0%, 100% {{
                transform: scale(1);
                opacity: 0.7;
            }}
            50% {{
                transform: scale(1.18);
                opacity: 1;
            }}
        }}

        @keyframes popIn {{
            from {{
                transform: scale(0.85);
                opacity: 0;
            }}
            to {{
                transform: scale(1);
                opacity: 1;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">

        <div class="header">
            <div>
                <h1>AI Code Safety Reviewer</h1>
                <p>Interactive security dashboard with filters, AI Fix Coach, scan history, and before/after safer code.</p>
            </div>

            <div class="header-actions">
                <button class="top-button" onclick="toggleDarkMode()">Dark Mode</button>
                <button class="top-button" onclick="expandAllIssues()">Expand All</button>
                <button class="top-button" onclick="collapseAllIssues()">Collapse All</button>
                <button class="top-button" onclick="clearReviewed()">Clear Reviewed</button>
            </div>
        </div>

        <div class="cards">
            <div class="card">
                <h3>Total Issues</h3>
                <div class="score">{len(findings)}</div>
            </div>

            <div class="card risk-card">
                <h3>Project Risk</h3>
                <div class="score risk-score">{risk_score}/10</div>
                <p><span class="risk-badge">{html.escape(risk_level)}</span></p>

                <div class="risk-bar">
                    <div class="risk-fill"></div>
                </div>

                <p class="risk-note">{html.escape(risk_note)}</p>
            </div>

            <div class="card">
                <h3>Severity Summary</h3>
                <div class="severity-grid">
                    <div class="severity-box severity-high">
                        HIGH
                        <span>{severity_summary["HIGH"]}</span>
                    </div>
                    <div class="severity-box severity-medium">
                        MEDIUM
                        <span>{severity_summary["MEDIUM"]}</span>
                    </div>
                    <div class="severity-box severity-low">
                        LOW
                        <span>{severity_summary["LOW"]}</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>Confidence Summary</h3>
                <div class="severity-grid">
                    <div class="severity-box confidence-high">
                        HIGH
                        <span>{confidence_summary["HIGH"]}</span>
                    </div>
                    <div class="severity-box confidence-medium">
                        MEDIUM
                        <span>{confidence_summary["MEDIUM"]}</span>
                    </div>
                    <div class="severity-box confidence-low">
                        LOW
                        <span>{confidence_summary["LOW"]}</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>File Summary</h2>
            <table>
                <tr>
                    <th>File</th>
                    <th>Issues</th>
                </tr>
"""

    if file_summary:
        sorted_file_summary = sorted(
            file_summary.items(),
            key=lambda item: item[1],
            reverse=True
        )

        for file_path, count in sorted_file_summary:
            html_content += f"""
                <tr>
                    <td>{html.escape(file_path)}</td>
                    <td>{count}</td>
                </tr>
"""
    else:
        html_content += """
                <tr>
                    <td colspan="2">No file issues found.</td>
                </tr>
"""

    html_content += """
            </table>
        </div>

        <div class="section">
            <h2>Risk Trend</h2>
"""

    if scan_history:
        for record in scan_history[-3:]:
            record_time = html.escape(record.get("timestamp", "Unknown time"))
            record_score = record.get("risk_score", 0)
            record_level = html.escape(record.get("risk_level", "UNKNOWN"))
            record_width = record_score * 10

            html_content += f"""
            <div class="trend-row">
                <div class="trend-meta">
                    <span>{record_time}</span>
                    <strong>{record_score}/10 - {record_level}</strong>
                </div>
                <div class="trend-bar">
                    <div class="trend-fill" style="width: {record_width}%;"></div>
                </div>
            </div>
"""
    else:
        html_content += """
            <div class="empty">
                No scan history available yet.
            </div>
"""

    html_content += """
        </div>

        <div class="section">
            <h2>Scan History</h2>
            <table>
                <tr>
                    <th>Time</th>
                    <th>Project</th>
                    <th>Files</th>
                    <th>Issues</th>
                    <th>Risk Score</th>
                    <th>Risk Level</th>
                    <th>Report</th>
                </tr>
"""

    if scan_history:
        for record in reversed(scan_history[-3:]):
            html_report_path = record.get("html_report_path", "")

            if html_report_path:
                relative_link = build_relative_link(html_report_path, output_path)
                safe_relative_link = html.escape(relative_link)
                report_link = f'<a class="history-link" href="{safe_relative_link}">Open scan</a>'
            else:
                report_link = "-"

            html_content += f"""
                <tr>
                    <td>{html.escape(record.get("timestamp", "Unknown time"))}</td>
                    <td>{html.escape(record.get("project_path", "Unknown project"))}</td>
                    <td>{record.get("files_scanned", 0)}</td>
                    <td>{record.get("total_issues", 0)}</td>
                    <td>{record.get("risk_score", 0)}/10</td>
                    <td>{html.escape(record.get("risk_level", "UNKNOWN"))}</td>
                    <td>{report_link}</td>
                </tr>
"""
    else:
        html_content += """
                <tr>
                    <td colspan="7">No previous scan history found.</td>
                </tr>
"""

    html_content += """
            </table>
        </div>

        <div class="section">
            <h2>Detailed Findings</h2>

            <div class="filters">
                <input
                    id="searchInput"
                    class="search-input"
                    type="text"
                    placeholder="Search by file, rule ID, rule name, message, or code..."
                    oninput="applyFilters()"
                >

                <div class="filter-row">
                    <span class="filter-label">Severity:</span>
                    <button class="filter-button active" data-severity="ALL" onclick="setSeverityFilter('ALL', this)">All</button>
                    <button class="filter-button" data-severity="HIGH" onclick="setSeverityFilter('HIGH', this)">High</button>
                    <button class="filter-button" data-severity="MEDIUM" onclick="setSeverityFilter('MEDIUM', this)">Medium</button>
                    <button class="filter-button" data-severity="LOW" onclick="setSeverityFilter('LOW', this)">Low</button>
                </div>

                <div class="filter-row">
                    <span class="filter-label">Confidence:</span>
                    <button class="filter-button active" data-confidence="ALL" onclick="setConfidenceFilter('ALL', this)">All</button>
                    <button class="filter-button" data-confidence="HIGH" onclick="setConfidenceFilter('HIGH', this)">High</button>
                    <button class="filter-button" data-confidence="MEDIUM" onclick="setConfidenceFilter('MEDIUM', this)">Medium</button>
                    <button class="filter-button" data-confidence="LOW" onclick="setConfidenceFilter('LOW', this)">Low</button>
                </div>
            </div>
"""

    if findings:
        for finding in findings:
            ai_fix = finding.get("ai_fix", {})

            severity = finding.get("severity", "MEDIUM")
            confidence = finding.get("confidence", "MEDIUM")
            rule_id = finding.get("rule_id", "UNKNOWN-RULE")
            rule = finding.get("rule", "Unknown rule")
            file_path = finding.get("file", "Unknown file")
            line = finding.get("line", "Unknown line")
            message = finding.get("message", "")
            why_risky = finding.get("why_risky", "")
            attack_example = finding.get("attack_example", "")
            suggestion = finding.get("suggestion", "")
            code = finding.get("code", "")

            issue_id = f"{file_path}::{line}::{rule_id}"
            search_text = " ".join([
                str(rule_id),
                str(rule),
                str(file_path),
                str(line),
                str(message),
                str(why_risky),
                str(suggestion),
                str(code),
            ]).lower()

            safe_issue_id = html.escape(issue_id, quote=True)
            safe_search_text = html.escape(search_text, quote=True)

            safe_severity = html.escape(severity)
            safe_confidence = html.escape(confidence)
            safe_rule_id = html.escape(rule_id)
            safe_rule = html.escape(rule)
            safe_file = html.escape(file_path)
            safe_line = html.escape(str(line))
            safe_message = html.escape(message)
            safe_why_risky = html.escape(why_risky)
            safe_attack_example = html.escape(attack_example)
            safe_suggestion = html.escape(suggestion)
            safe_code = html.escape(code)

            confidence_class = f"confidence-{confidence.lower()}"

            safe_ai_summary = html.escape(ai_fix.get("ai_summary", ""))
            safe_ai_explanation = html.escape(ai_fix.get("ai_explanation", ""))
            safe_ai_fix_steps = html.escape(ai_fix.get("ai_fix_steps", ""))
            safe_before_code = html.escape(ai_fix.get("before_code", code))
            safe_after_code = html.escape(ai_fix.get("after_code", finding.get("safe_example", "")))

            html_content += f"""
            <div
                class="issue {safe_severity}"
                data-severity="{safe_severity}"
                data-confidence="{safe_confidence}"
                data-search="{safe_search_text}"
                data-issue-id="{safe_issue_id}"
            >
                <div class="issue-title" onclick="toggleIssue(this)">
                    <h3><span class="rule-id">{safe_rule_id}</span>{safe_rule}</h3>
                    <div class="badge-group">
                        <span class="badge {safe_severity}">{safe_severity}</span>
                        <span class="confidence-badge {confidence_class}">Confidence: {safe_confidence}</span>
                        <span class="reviewed-badge">Reviewed</span>
                    </div>
                </div>

                <div class="issue-body">
                    <p class="meta"><strong>File:</strong> {safe_file} &nbsp; | &nbsp; <strong>Line:</strong> {safe_line}</p>
                    <p><strong>Message:</strong> {safe_message}</p>

                    <p><strong>Detected code:</strong></p>
                    <div class="code-wrapper">
                        <button class="copy-button" onclick="copyCode(this)">Copy</button>
                        <code>{safe_code}</code>
                    </div>

                    <div class="coach-box">
                        <h4>AI Security Fix Coach</h4>
                        <p><strong>AI Summary:</strong> {safe_ai_summary}</p>
                        <p><strong>Why this is risky:</strong> {safe_why_risky}</p>
                        <p><strong>AI Explanation:</strong> {safe_ai_explanation}</p>

                        <p><strong>Possible attack example:</strong></p>
                        <div class="code-wrapper">
                            <button class="copy-button" onclick="copyCode(this)">Copy</button>
                            <code>{safe_attack_example}</code>
                        </div>

                        <p><strong>Suggestion:</strong> {safe_suggestion}</p>
                        <p><strong>AI Fix Steps:</strong> {safe_ai_fix_steps}</p>

                        <div class="compare-grid">
                            <div class="before-box">
                                <h5>Before</h5>
                                <div class="code-wrapper">
                                    <button class="copy-button" onclick="copyCode(this)">Copy</button>
                                    <code>{safe_before_code}</code>
                                </div>
                            </div>

                            <div class="after-box">
                                <h5>Safer Version</h5>
                                <div class="code-wrapper">
                                    <button class="copy-button" onclick="copyCode(this)">Copy</button>
                                    <code>{safe_after_code}</code>
                                </div>
                            </div>
                        </div>
                    </div>

                    <button class="review-button" onclick="toggleReviewed(this)">Mark as Reviewed</button>
                </div>
            </div>
"""
    else:
        html_content += """
            <div class="empty">
                No risky patterns found. Nice work!
            </div>
"""

    html_content += """
        </div>
    </div>

    <script>
        let activeSeverity = "ALL";
        let activeConfidence = "ALL";

        function toggleDarkMode() {
            document.body.classList.toggle("dark");

            if (document.body.classList.contains("dark")) {
                localStorage.setItem("aiReviewerDarkMode", "true");
            } else {
                localStorage.setItem("aiReviewerDarkMode", "false");
            }
        }

        function loadDarkMode() {
            const darkMode = localStorage.getItem("aiReviewerDarkMode");

            if (darkMode === "true") {
                document.body.classList.add("dark");
            }
        }

        function setSeverityFilter(severity, button) {
            activeSeverity = severity;

            document.querySelectorAll("[data-severity].filter-button").forEach(function(btn) {
                btn.classList.remove("active");
            });

            button.classList.add("active");
            applyFilters();
        }

        function setConfidenceFilter(confidence, button) {
            activeConfidence = confidence;

            document.querySelectorAll("[data-confidence].filter-button").forEach(function(btn) {
                btn.classList.remove("active");
            });

            button.classList.add("active");
            applyFilters();
        }

        function applyFilters() {
            const searchValue = document.getElementById("searchInput").value.toLowerCase();
            const issues = document.querySelectorAll(".issue");

            issues.forEach(function(issue) {
                const severity = issue.getAttribute("data-severity");
                const confidence = issue.getAttribute("data-confidence");
                const searchText = issue.getAttribute("data-search");

                const severityMatches = activeSeverity === "ALL" || severity === activeSeverity;
                const confidenceMatches = activeConfidence === "ALL" || confidence === activeConfidence;
                const searchMatches = searchText.includes(searchValue);

                if (severityMatches && confidenceMatches && searchMatches) {
                    issue.classList.remove("hidden");
                } else {
                    issue.classList.add("hidden");
                }
            });
        }

        function toggleIssue(headerElement) {
            const issue = headerElement.closest(".issue");
            issue.classList.toggle("open");
        }

        function expandAllIssues() {
            document.querySelectorAll(".issue").forEach(function(issue) {
                issue.classList.add("open");
            });
        }

        function collapseAllIssues() {
            document.querySelectorAll(".issue").forEach(function(issue) {
                issue.classList.remove("open");
            });
        }

        function copyCode(button) {
            const codeBlock = button.nextElementSibling;
            const textToCopy = codeBlock.innerText;

            navigator.clipboard.writeText(textToCopy).then(function() {
                const originalText = button.innerText;
                button.innerText = "Copied";
                setTimeout(function() {
                    button.innerText = originalText;
                }, 1200);
            });
        }

        function toggleReviewed(button) {
            const issue = button.closest(".issue");
            const issueId = issue.getAttribute("data-issue-id");
            const reviewedKey = "aiReviewerReviewed:" + issueId;

            if (issue.classList.contains("reviewed")) {
                issue.classList.remove("reviewed");
                localStorage.removeItem(reviewedKey);
                button.innerText = "Mark as Reviewed";
            } else {
                issue.classList.add("reviewed");
                localStorage.setItem(reviewedKey, "true");
                button.innerText = "Unmark Reviewed";
            }
        }

        function loadReviewedIssues() {
            document.querySelectorAll(".issue").forEach(function(issue) {
                const issueId = issue.getAttribute("data-issue-id");
                const reviewedKey = "aiReviewerReviewed:" + issueId;
                const button = issue.querySelector(".review-button");

                if (localStorage.getItem(reviewedKey) === "true") {
                    issue.classList.add("reviewed");

                    if (button) {
                        button.innerText = "Unmark Reviewed";
                    }
                }
            });
        }

        function clearReviewed() {
            Object.keys(localStorage).forEach(function(key) {
                if (key.startsWith("aiReviewerReviewed:")) {
                    localStorage.removeItem(key);
                }
            });

            document.querySelectorAll(".issue").forEach(function(issue) {
                issue.classList.remove("reviewed");
                const button = issue.querySelector(".review-button");

                if (button) {
                    button.innerText = "Mark as Reviewed";
                }
            });
        }

        loadDarkMode();
        loadReviewedIssues();
    </script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as html_file:
        html_file.write(html_content)

    return output_path