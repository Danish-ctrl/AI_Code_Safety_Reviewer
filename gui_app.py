# gui_app.py

import threading
import traceback
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

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


class AICodeReviewerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AI Code Safety Reviewer")
        self.root.geometry("980x680")
        self.root.minsize(900, 620)

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.selected_folder = tk.StringVar()
        self.use_ai = tk.BooleanVar(value=False)
        self.save_history = tk.BooleanVar(value=True)
        self.open_dashboard_after_scan = tk.BooleanVar(value=True)
        self.min_severity = tk.StringVar(value="LOW")

        self.latest_dashboard_path = None

        self.colors = {
            "primary": "#4f46e5",
            "success": "#16a34a",
            "warning": "#d97706",
            "danger": "#dc2626",
            "dark": "#111827",
        }

        self.create_widgets()

    def create_widgets(self):
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        self.main_frame = ctk.CTkFrame(
            self.root,
            corner_radius=0,
        )
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        self.create_header()
        self.create_top_content()
        self.create_log_section()

    def create_header(self):
        header = ctk.CTkFrame(
            self.main_frame,
            corner_radius=22,
            fg_color=("#ffffff", "#111827"),
        )
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(24, 16))
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header,
            text="AI Code Safety Reviewer",
            font=ctk.CTkFont(size=28, weight="bold"),
        )
        title.grid(row=0, column=0, sticky="w", padx=24, pady=(22, 4))

        subtitle = ctk.CTkLabel(
            header,
            text="Scan project folders, detect risky code, and generate an AI-powered dashboard.",
            font=ctk.CTkFont(size=14),
            text_color=("#6b7280", "#d1d5db"),
        )
        subtitle.grid(row=1, column=0, sticky="w", padx=24, pady=(0, 22))

        button_frame = ctk.CTkFrame(
            header,
            fg_color="transparent",
        )
        button_frame.grid(row=0, column=1, rowspan=2, padx=24, pady=22, sticky="e")

        self.theme_button = ctk.CTkButton(
            button_frame,
            text="Toggle Theme",
            command=self.toggle_theme,
            width=130,
        )
        self.theme_button.pack(side="top", pady=(0, 10))

        self.status_badge = ctk.CTkLabel(
            button_frame,
            text="Ready",
            fg_color=self.colors["success"],
            text_color="white",
            corner_radius=999,
            padx=14,
            pady=7,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self.status_badge.pack(side="top", fill="x")

    def create_top_content(self):
        content = ctk.CTkFrame(
            self.main_frame,
            fg_color="transparent",
        )
        content.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 16))
        content.grid_columnconfigure(0, weight=2)
        content.grid_columnconfigure(1, weight=1)

        self.create_scan_card(content)
        self.create_summary_card(content)

    def create_scan_card(self, parent):
        scan_card = ctk.CTkFrame(
            parent,
            corner_radius=22,
        )
        scan_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        scan_card.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            scan_card,
            text="Scan Setup",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        title.grid(row=0, column=0, sticky="w", padx=22, pady=(20, 4))

        subtitle = ctk.CTkLabel(
            scan_card,
            text="Choose the project folder you want to review.",
            text_color=("#6b7280", "#9ca3af"),
        )
        subtitle.grid(row=1, column=0, sticky="w", padx=22, pady=(0, 16))

        folder_label = ctk.CTkLabel(
            scan_card,
            text="Project Folder",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        folder_label.grid(row=2, column=0, sticky="w", padx=22, pady=(0, 6))

        folder_row = ctk.CTkFrame(
            scan_card,
            fg_color="transparent",
        )
        folder_row.grid(row=3, column=0, sticky="ew", padx=22, pady=(0, 16))
        folder_row.grid_columnconfigure(0, weight=1)

        self.folder_entry = ctk.CTkEntry(
            folder_row,
            textvariable=self.selected_folder,
            placeholder_text="Select a project folder...",
            height=38,
        )
        self.folder_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        browse_button = ctk.CTkButton(
            folder_row,
            text="Browse",
            command=self.browse_folder,
            width=110,
            height=38,
        )
        browse_button.grid(row=0, column=1)

        options = ctk.CTkFrame(
            scan_card,
            fg_color="transparent",
        )
        options.grid(row=4, column=0, sticky="ew", padx=22, pady=(0, 12))
        options.grid_columnconfigure((0, 1, 2), weight=1)

        self.ai_checkbox = ctk.CTkCheckBox(
            options,
            text="Enable AI Fix Coach",
            variable=self.use_ai,
        )
        self.ai_checkbox.grid(row=0, column=0, sticky="w", pady=6)

        self.history_checkbox = ctk.CTkCheckBox(
            options,
            text="Save scan history",
            variable=self.save_history,
        )
        self.history_checkbox.grid(row=0, column=1, sticky="w", pady=6)

        self.dashboard_checkbox = ctk.CTkCheckBox(
            options,
            text="Open dashboard",
            variable=self.open_dashboard_after_scan,
        )
        self.dashboard_checkbox.grid(row=0, column=2, sticky="w", pady=6)

        severity_row = ctk.CTkFrame(
            scan_card,
            fg_color="transparent",
        )
        severity_row.grid(row=5, column=0, sticky="ew", padx=22, pady=(0, 18))

        severity_label = ctk.CTkLabel(
            severity_row,
            text="Minimum Severity:",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        severity_label.pack(side="left", padx=(0, 12))

        severity_menu = ctk.CTkOptionMenu(
            severity_row,
            values=["LOW", "MEDIUM", "HIGH"],
            variable=self.min_severity,
            width=160,
        )
        severity_menu.pack(side="left")

        button_row = ctk.CTkFrame(
            scan_card,
            fg_color="transparent",
        )
        button_row.grid(row=6, column=0, sticky="ew", padx=22, pady=(0, 18))

        self.scan_button = ctk.CTkButton(
            button_row,
            text="Start Scan",
            command=self.start_scan_thread,
            height=42,
            width=140,
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.scan_button.pack(side="left")

        self.open_dashboard_button = ctk.CTkButton(
            button_row,
            text="Open Latest Dashboard",
            command=self.open_latest_dashboard,
            height=42,
            width=180,
            state="disabled",
            fg_color="#374151",
            hover_color="#1f2937",
        )
        self.open_dashboard_button.pack(side="left", padx=(10, 0))

        self.progress_bar = ctk.CTkProgressBar(scan_card)
        self.progress_bar.grid(row=7, column=0, sticky="ew", padx=22, pady=(0, 22))
        self.progress_bar.set(0)

    def create_summary_card(self, parent):
        summary_card = ctk.CTkFrame(
            parent,
            corner_radius=22,
        )
        summary_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        title = ctk.CTkLabel(
            summary_card,
            text="Latest Scan",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        title.pack(anchor="w", padx=22, pady=(20, 4))

        subtitle = ctk.CTkLabel(
            summary_card,
            text="Result overview will appear here.",
            text_color=("#6b7280", "#9ca3af"),
        )
        subtitle.pack(anchor="w", padx=22, pady=(0, 16))

        self.files_label = self.create_metric(summary_card, "Files scanned", "-")
        self.issues_label = self.create_metric(summary_card, "Issues found", "-")
        self.risk_score_label = self.create_metric(summary_card, "Risk score", "-")
        self.risk_level_label = self.create_metric(summary_card, "Risk level", "-")

    def create_metric(self, parent, label_text, value_text):
        metric = ctk.CTkFrame(
            parent,
            corner_radius=16,
            fg_color=("#f9fafb", "#1f2937"),
        )
        metric.pack(fill="x", padx=22, pady=(0, 10))

        label = ctk.CTkLabel(
            metric,
            text=label_text,
            text_color=("#6b7280", "#9ca3af"),
            font=ctk.CTkFont(size=12),
        )
        label.pack(anchor="w", padx=14, pady=(10, 0))

        value = ctk.CTkLabel(
            metric,
            text=value_text,
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        value.pack(anchor="w", padx=14, pady=(0, 10))

        return value

    def create_log_section(self):
        log_card = ctk.CTkFrame(
            self.main_frame,
            corner_radius=22,
        )
        log_card.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 24))
        log_card.grid_columnconfigure(0, weight=1)
        log_card.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(
            log_card,
            fg_color="transparent",
        )
        header.grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 10))
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header,
            text="Scan Log",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        title.grid(row=0, column=0, sticky="w")

        clear_button = ctk.CTkButton(
            header,
            text="Clear Log",
            command=self.clear_status,
            width=110,
            fg_color="#374151",
            hover_color="#1f2937",
        )
        clear_button.grid(row=0, column=1, sticky="e")

        self.status_text = ctk.CTkTextbox(
            log_card,
            height=220,
            corner_radius=16,
            font=("Consolas", 12),
        )
        self.status_text.grid(row=1, column=0, sticky="nsew", padx=22, pady=(0, 22))

        self.write_status("Ready.\n")
        self.write_status("Choose a folder and click Start Scan.\n")

    def toggle_theme(self):
        current_mode = ctk.get_appearance_mode()

        if current_mode == "Dark":
            ctk.set_appearance_mode("Light")
        else:
            ctk.set_appearance_mode("Dark")

    def browse_folder(self):
        folder_path = filedialog.askdirectory(title="Select project folder to scan")

        if folder_path:
            self.selected_folder.set(folder_path)

    def write_status(self, message):
        self.status_text.insert("end", message)
        self.status_text.see("end")
        self.root.update_idletasks()

    def safe_status(self, message):
        self.root.after(0, lambda: self.write_status(message))

    def clear_status(self):
        self.status_text.delete("1.0", "end")

    def start_scan_thread(self):
        folder_path = self.selected_folder.get().strip()

        if not folder_path:
            messagebox.showwarning(
                "No folder selected",
                "Please select a project folder first."
            )
            return

        project_path = Path(folder_path)

        if not project_path.exists() or not project_path.is_dir():
            messagebox.showerror(
                "Invalid folder",
                "The selected path is not a valid folder."
            )
            return

        self.set_scanning_state(is_scanning=True)

        scan_thread = threading.Thread(
            target=self.run_scan,
            args=(project_path,),
            daemon=True,
        )
        scan_thread.start()

    def set_scanning_state(self, is_scanning):
        if is_scanning:
            self.scan_button.configure(state="disabled")
            self.open_dashboard_button.configure(state="disabled")
            self.status_badge.configure(
                text="Scanning...",
                fg_color=self.colors["warning"],
            )
            self.progress_bar.start()
        else:
            self.scan_button.configure(state="normal")
            self.status_badge.configure(
                text="Ready",
                fg_color=self.colors["success"],
            )
            self.progress_bar.stop()
            self.progress_bar.set(0)

    def run_scan(self, project_path):
        try:
            self.root.after(0, self.clear_status)

            self.safe_status(f"Scanning folder:\n{project_path}\n\n")

            if self.use_ai.get():
                self.safe_status("AI Fix Coach: enabled\n")
            else:
                self.safe_status("AI Fix Coach: manual fallback mode\n")

            self.safe_status(f"Minimum severity: {self.min_severity.get()}\n")

            if self.save_history.get():
                self.safe_status("Scan history: enabled\n\n")
            else:
                self.safe_status("Scan history: disabled for this scan\n\n")

            files = find_files_to_scan(str(project_path))

            self.safe_status(f"Files found: {len(files)}\n\n")

            all_findings = []

            for file_path in files:
                self.safe_status(f"Scanning: {file_path}\n")

                code_text = self.read_file_safely(file_path)
                findings = scan_code(file_path, code_text)
                all_findings.extend(findings)

            all_findings = self.filter_findings_by_min_severity(
                findings=all_findings,
                min_severity=self.min_severity.get()
            )

            self.safe_status("\nApplying AI/manual fix coach...\n")

            all_findings = enrich_findings_with_ai(
                findings=all_findings,
                use_ai=self.use_ai.get()
            )

            severity_summary = create_severity_summary(all_findings)
            risk_score = calculate_risk_score(severity_summary)
            risk_level = get_risk_level(risk_score)

            report_path = generate_report(all_findings)

            if self.save_history.get():
                scan_history, scan_snapshot_path = add_scan_record(
                    project_path=str(project_path),
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

                generate_html_dashboard(
                    findings=all_findings,
                    output_path=scan_snapshot_path,
                    scan_history=scan_history,
                )

            else:
                scan_history = load_scan_history()

                latest_dashboard_path = generate_html_dashboard(
                    findings=all_findings,
                    output_path="reports/dashboard.html",
                    scan_history=scan_history,
                )

            self.root.after(
                0,
                lambda: self.handle_scan_success(
                    files_scanned=len(files),
                    issues_found=len(all_findings),
                    risk_score=risk_score,
                    risk_level=risk_level,
                    report_path=report_path,
                    dashboard_path=latest_dashboard_path,
                )
            )

        except Exception:
            error_details = traceback.format_exc()

            self.root.after(
                0,
                lambda: self.handle_scan_error(error_details)
            )

    def handle_scan_success(
        self,
        files_scanned,
        issues_found,
        risk_score,
        risk_level,
        report_path,
        dashboard_path,
    ):
        self.latest_dashboard_path = dashboard_path

        self.files_label.configure(text=str(files_scanned))
        self.issues_label.configure(text=str(issues_found))
        self.risk_score_label.configure(text=f"{risk_score}/10")
        self.risk_level_label.configure(text=risk_level)

        if risk_level == "HIGH":
            self.risk_level_label.configure(text_color=self.colors["danger"])
        elif risk_level == "MEDIUM":
            self.risk_level_label.configure(text_color=self.colors["warning"])
        elif risk_level == "LOW":
            self.risk_level_label.configure(text_color=self.colors["success"])
        else:
            self.risk_level_label.configure(text_color="#6b7280")

        self.write_status("\nScan completed successfully.\n")
        self.write_status(f"Files scanned: {files_scanned}\n")
        self.write_status(f"Issues found: {issues_found}\n")
        self.write_status(f"Risk Score: {risk_score}/10\n")
        self.write_status(f"Risk Level: {risk_level}\n")
        self.write_status(f"Text report: {report_path}\n")
        self.write_status(f"HTML dashboard: {dashboard_path}\n")

        self.set_scanning_state(is_scanning=False)
        self.open_dashboard_button.configure(state="normal")

        if self.open_dashboard_after_scan.get():
            self.open_latest_dashboard()

        messagebox.showinfo(
            "Scan completed",
            f"Scan completed successfully.\n\n"
            f"Issues found: {issues_found}\n"
            f"Risk Score: {risk_score}/10\n"
            f"Risk Level: {risk_level}"
        )

    def handle_scan_error(self, error_details):
        self.write_status("\nERROR:\n")
        self.write_status(error_details)

        self.set_scanning_state(is_scanning=False)

        messagebox.showerror(
            "Scan failed",
            "Something went wrong during the scan. Check the scan log for details."
        )

    def read_file_safely(self, file_path):
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            return file.read()

    def filter_findings_by_min_severity(self, findings, min_severity):
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

    def open_latest_dashboard(self):
        if not self.latest_dashboard_path:
            messagebox.showwarning(
                "No dashboard available",
                "Please run a scan first."
            )
            return

        dashboard_path = Path(self.latest_dashboard_path).resolve()

        if not dashboard_path.exists():
            messagebox.showerror(
                "Dashboard not found",
                "The dashboard file could not be found."
            )
            return

        webbrowser.open(dashboard_path.as_uri())


def main():
    root = ctk.CTk()
    AICodeReviewerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()