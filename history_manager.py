# history_manager.py

import json
import os
from datetime import datetime


HISTORY_FILE = "scan_history/history.json"
SCAN_REPORTS_FOLDER = os.path.join("reports", "scans")
MAX_HISTORY_RECORDS = 3


def ensure_history_folders_exist():
    """
    Creates folders needed for scan history and scan snapshots.
    """

    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    os.makedirs(SCAN_REPORTS_FOLDER, exist_ok=True)


def load_scan_history():
    """
    Loads previous scan history.

    Output:
        list of previous scan records
    """

    ensure_history_folders_exist()

    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            history = json.load(file)

        if isinstance(history, list):
            return history

        return []

    except json.JSONDecodeError:
        return []


def save_scan_history(history):
    """
    Saves scan history list into history.json.
    """

    ensure_history_folders_exist()

    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=4)


def create_scan_id_and_timestamp():
    """
    Creates a unique scan ID and readable timestamp.
    """

    now = datetime.now()

    scan_id = now.strftime("%Y%m%d_%H%M%S_%f")
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    return scan_id, timestamp


def build_scan_html_path(scan_id):
    """
    Builds the HTML snapshot path for a scan.
    """

    return os.path.join(SCAN_REPORTS_FOLDER, f"scan_{scan_id}.html")


def cleanup_old_scan_html_files(history):
    """
    Keeps only HTML files that belong to the latest history records.
    Removes older scan snapshot files.
    """

    ensure_history_folders_exist()

    html_paths_to_keep = set()

    for record in history:
        html_report_path = record.get("html_report_path")

        if html_report_path:
            html_paths_to_keep.add(os.path.normpath(html_report_path))

    for file_name in os.listdir(SCAN_REPORTS_FOLDER):
        if not file_name.endswith(".html"):
            continue

        full_path = os.path.normpath(os.path.join(SCAN_REPORTS_FOLDER, file_name))

        if full_path not in html_paths_to_keep:
            try:
                os.remove(full_path)
            except OSError:
                pass


def add_scan_record(project_path, files_scanned, findings, severity_summary, risk_score, risk_level):
    """
    Adds one scan result into history.

    Input:
        project_path      -> scanned folder
        files_scanned     -> number of scanned files
        findings          -> detected issues
        severity_summary  -> HIGH/MEDIUM/LOW counts
        risk_score        -> project risk score
        risk_level        -> LOW/MEDIUM/HIGH/NONE

    Output:
        updated history list
        current scan HTML snapshot path
    """

    ensure_history_folders_exist()

    history = load_scan_history()

    scan_id, timestamp = create_scan_id_and_timestamp()
    html_report_path = build_scan_html_path(scan_id)

    scan_record = {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "project_path": project_path,
        "files_scanned": files_scanned,
        "total_issues": len(findings),
        "severity_summary": severity_summary,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "html_report_path": html_report_path,
    }

    history.append(scan_record)

    # Keep only latest 3 scans
    history = history[-MAX_HISTORY_RECORDS:]

    save_scan_history(history)
    cleanup_old_scan_html_files(history)

    return history, html_report_path