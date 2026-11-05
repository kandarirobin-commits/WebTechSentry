#!/usr/bin/env python3
"""
WebTechSentry - PySide6 graphical interface.

Runs the Phase 1 (passive) and Phase 2 (fingerprinting) modules from core.py
in a background thread and shows each module's results in its own tab.
"""

import sys
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QProgressBar,
    QPushButton, QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser,
    QVBoxLayout, QWidget,
)

import core

STYLE = """
* { font-family: 'Segoe UI', 'Inter', 'Noto Sans', sans-serif; font-size: 13px; }
QMainWindow, QWidget { background: #0f1420; color: #d7deee; }
QLabel#title { font-size: 22px; font-weight: 700; color: #ffffff; }
QLabel#subtitle { color: #7f8aa6; }
QGroupBox { border: 1px solid #263049; border-radius: 8px; margin-top: 12px; padding: 10px 8px 6px 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #5ec2ff; font-weight: 600; }
QLineEdit, QSpinBox, QComboBox { background: #171e30; border: 1px solid #2b3652; border-radius: 6px; padding: 6px 8px; }
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border-color: #5ec2ff; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #3a4768; background: #171e30; }
QCheckBox::indicator:checked { background: #5ec2ff; border-color: #5ec2ff; }
QPushButton { background: #1d2740; border: 1px solid #2f3c5e; border-radius: 6px; padding: 7px 14px; }
QPushButton:hover { background: #26335a; }
QPushButton:disabled { color: #5a6580; background: #151c2e; }
QPushButton#run { background: #1f8fff; border: none; color: white; font-weight: 700; padding: 9px 22px; }
QPushButton#run:hover { background: #3fa0ff; }
QPushButton#run:disabled { background: #223a5c; color: #7f8aa6; }
QTabWidget::pane { border: 1px solid #263049; border-radius: 8px; top: -1px; }
QTabBar::tab { background: #151c2e; padding: 8px 14px; margin-right: 2px; border-top-left-radius: 6px; border-top-right-radius: 6px; color: #8a95b3; }
QTabBar::tab:selected { background: #1d2740; color: #ffffff; }
QTableWidget { background: #121a2b; alternate-background-color: #151e33; gridline-color: #1d2740; border: none; }
QHeaderView::section { background: #1a2338; padding: 6px; border: none; color: #9fb0d4; font-weight: 600; }
QTextBrowser { background: #121a2b; border: none; padding: 10px; }
QProgressBar { background: #171e30; border: none; border-radius: 4px; height: 6px; }
QProgressBar::chunk { background: #5ec2ff; border-radius: 4px; }
"""

SEVERITY_COLORS = {
    "high": QColor("#ff6b6b"), "medium": QColor("#ffb347"), "low": QColor("#f1e05a"),
    "ok": QColor("#5fd38d"), "info": QColor("#d7deee"),
}


class ScanWorker(QThread):
    progress = Signal(str)
    finished_ok = Signal(dict)
    failed = Signal(str)

    def __init__(self, url, modules, aggression, timeout, out_dir, use_nmap):
        super().__init__()
        self.args = (url, modules, aggression, timeout, out_dir)
        self.use_nmap = use_nmap

    def run(self):
        try:
            url, modules, aggression, timeout, out_dir = self.args
            result = core.assess(url, modules, aggression, timeout, out_dir,
                                 use_nmap=self.use_nmap, progress=self.progress.emit)
            self.finished_ok.emit(result)
        except ValueError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(f"Unexpected error: {exc}")


def make_table(headers):
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setAlternatingRowColors(True)
    table.setEditTriggers(QTableWidget.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectRows)
    table.verticalHeader().setVisible(False)
    table.setWordWrap(True)
    header = table.horizontalHeader()
    header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
    header.setSectionResizeMode(1, QHeaderView.Interactive)
    header.setStretchLastSection(True)
    table.setColumnWidth(1, 420)
    return table


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WebTechSentry - Recon & Fingerprinting")
        self.resize(1100, 780)
        self.worker = None
        self.last_report_dir = None
        self.module_boxes = {}
        self.tables = {}
        self._build()
        self._update_run_state()

    # ----- layout -----
    def _build(self):
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(18, 14, 18, 12)
        outer.setSpacing(10)

        title = QLabel("WebTechSentry")
        title.setObjectName("title")
        sub = QLabel("Passive OSINT and technology fingerprinting - authorized targets only")
        sub.setObjectName("subtitle")
        outer.addWidget(title)
        outer.addWidget(sub)

        # target row
        row = QHBoxLayout()
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://your-authorized-site.example")
        self.url_edit.textChanged.connect(self._update_run_state)
        self.url_edit.returnPressed.connect(self._start)
        row.addWidget(QLabel("Target URL"))
        row.addWidget(self.url_edit, 1)
        outer.addLayout(row)

        # module groups
        groups = QHBoxLayout()
        for title_text, modules in (("Phase 1 - Passive recon (no direct probing)", core.PHASE1_MODULES),
                                    ("Phase 2 - Fingerprinting (contacts the target)", core.PHASE2_MODULES)):
            box = QGroupBox(title_text)
            lay = QVBoxLayout(box)
            for key, label in modules:
                cb = QCheckBox(label)
                cb.setChecked(key != "whatweb")
                cb.toggled.connect(self._update_run_state)
                self.module_boxes[key] = cb
                lay.addWidget(cb)
            groups.addWidget(box)

        opts = QGroupBox("Options")
        grid = QGridLayout(opts)
        self.nmap_cb = QCheckBox("Nmap -O for OS discovery (needs root)")
        grid.addWidget(self.nmap_cb, 0, 0, 1, 2)
        grid.addWidget(QLabel("WhatWeb aggression"), 1, 0)
        self.aggr = QComboBox()
        self.aggr.addItems(["1", "2", "3", "4"])
        grid.addWidget(self.aggr, 1, 1)
        grid.addWidget(QLabel("WhatWeb timeout (s)"), 2, 0)
        self.timeout = QSpinBox()
        self.timeout.setRange(10, 600)
        self.timeout.setValue(core.DEFAULT_TIMEOUT)
        grid.addWidget(self.timeout, 2, 1)
        grid.addWidget(QLabel("Report folder"), 3, 0)
        self.out_edit = QLineEdit("reports")
        grid.addWidget(self.out_edit, 3, 1)
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._browse)
        grid.addWidget(browse, 4, 1)
        groups.addWidget(opts)
        outer.addLayout(groups)

        # authorization + run
        self.auth_cb = QCheckBox("I own this target or have explicit written authorization to test it")
        self.auth_cb.toggled.connect(self._update_run_state)
        outer.addWidget(self.auth_cb)

        run_row = QHBoxLayout()
        self.run_btn = QPushButton("Run Assessment")
        self.run_btn.setObjectName("run")
        self.run_btn.clicked.connect(self._start)
        self.open_btn = QPushButton("Open report folder")
        self.open_btn.setEnabled(False)
        self.open_btn.clicked.connect(self._open_reports)
        self.status = QLabel("Idle.")
        self.status.setObjectName("subtitle")
        run_row.addWidget(self.run_btn)
        run_row.addWidget(self.open_btn)
        run_row.addWidget(self.status, 1)
        outer.addLayout(run_row)

        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 1)
        outer.addWidget(self.bar)

        # results
        self.tabs = QTabWidget()
        self.overview = QTextBrowser()
        self.overview.setHtml("<p style='color:#7f8aa6'>Results will appear here.</p>")
        self.tabs.addTab(self.overview, "Overview")
        for key in core.ALL_MODULES:
            table = make_table(["Item", "Value", "Detail"])
            self.tables[key] = table
            self.tabs.addTab(table, core.MODULE_LABELS[key].split(" (")[0])
        outer.addWidget(self.tabs, 1)

        self.footer = QLabel("")
        self.footer.setObjectName("subtitle")
        outer.addWidget(self.footer)

    # ----- behavior -----
    def _selected(self):
        return {k for k, cb in self.module_boxes.items() if cb.isChecked()}

    def _update_run_state(self):
        busy = self.worker is not None and self.worker.isRunning()
        ok = bool(self.url_edit.text().strip()) and self.auth_cb.isChecked() and bool(self._selected())
        self.run_btn.setEnabled(ok and not busy)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Report folder", self.out_edit.text() or ".")
        if d:
            self.out_edit.setText(d)

    def _open_reports(self):
        if self.last_report_dir:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_report_dir)))

    def _start(self):
        if not self.run_btn.isEnabled():
            return
        url = self.url_edit.text().strip()
        try:
            core.validate_url(url)
        except ValueError as exc:
            QMessageBox.critical(self, "Input error", str(exc))
            return
        for t in self.tables.values():
            t.setRowCount(0)
        self.overview.setHtml("<p style='color:#7f8aa6'>Scanning...</p>")
        self.footer.setText("")
        self.bar.setRange(0, 0)  # indeterminate
        self.worker = ScanWorker(url, self._selected(), int(self.aggr.currentText()),
                                 self.timeout.value(), self.out_edit.text() or "reports",
                                 self.nmap_cb.isChecked())
        self.worker.progress.connect(self.status.setText)
        self.worker.finished_ok.connect(self._done)
        self.worker.failed.connect(self._failed)
        self.worker.finished.connect(self._update_run_state)
        self.worker.start()
        self._update_run_state()

    def _failed(self, msg):
        self.bar.setRange(0, 1)
        self.status.setText("Failed.")
        QMessageBox.critical(self, "Scan failed", msg)

    def _done(self, result):
        self.bar.setRange(0, 1)
        self.status.setText(f"Done. {len(result['errors'])} module error(s)." if result["errors"] else "Done.")

        grouped = {}
        for module, item, value, detail, sev in core.flatten(result):
            grouped.setdefault(module, []).append((item, str(value), detail, sev))
        for key, table in self.tables.items():
            rows = grouped.get(key, [])
            table.setRowCount(len(rows))
            for r, (item, value, detail, sev) in enumerate(rows):
                for c, text in enumerate((item, value, detail)):
                    cell = QTableWidgetItem(text)
                    cell.setForeground(SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"]))
                    cell.setToolTip(text)
                    table.setItem(r, c, cell)
            table.resizeRowsToContents()
            idx = self.tabs.indexOf(table)
            label = core.MODULE_LABELS[key].split(" (")[0]
            self.tabs.setTabText(idx, f"{label} ({len(rows)})" if key in result["modules_run"] else label)

        lines = "".join(f"<li>{self._esc(x)}</li>" for x in core.summarize(result))
        self.overview.setHtml(
            f"<h3 style='color:#fff'>{self._esc(result['target'])}</h3>"
            f"<p style='color:#7f8aa6'>{result['timestamp_utc']} UTC</p><ul>{lines}</ul>"
            f"<p style='color:#7f8aa6'>{self._esc(result['note'])}</p>")
        self.tabs.setCurrentIndex(0)
        self.last_report_dir = Path(result["json_path"]).parent.resolve()
        self.open_btn.setEnabled(True)
        self.footer.setText(f"JSON: {result['json_path']}   |   CSV: {result['csv_path']}")

    @staticmethod
    def _esc(text):
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
