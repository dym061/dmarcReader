import sys
import logging
import xml.etree.ElementTree as ET
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QPushButton,
    QFileDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTextEdit,
    QTabWidget,
    QScrollArea,
    QFrame,
)
from PySide6.QtCore import Qt, Signal


class QtLogHandler(logging.Handler):
    """Logging handler that sends logs to a QTextEdit."""

    def __init__(self, widget: QTextEdit):
        super().__init__()
        self.widget = widget
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
        self.setFormatter(formatter)

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        # Append log message in GUI thread
        self.widget.append(msg)


class MainTab(QWidget):
    """Main tab that accepts drops and contains result area."""

    fileLoaded = Signal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)

        self.loadButton = QPushButton("Load XML")
        self.loadButton.clicked.connect(self.open_file)

        # Result area inside scroll
        self.resultWidget = QWidget()
        self.resultLayout = QVBoxLayout(self.resultWidget)
        self.resultLayout.addStretch()

        self.resultArea = QScrollArea()
        self.resultArea.setWidgetResizable(True)
        self.resultArea.setWidget(self.resultWidget)

        # Ensure dark background throughout the tab
        self.setStyleSheet("background-color: #000000;")
        self.resultWidget.setStyleSheet("background-color: #000000;")
        self.resultArea.setStyleSheet("background: #000000;")
        self.resultArea.viewport().setStyleSheet("background-color: #000000;")

        layout = QVBoxLayout(self)
        layout.addWidget(self.loadButton)
        layout.addWidget(self.resultArea)

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open DMARC Report", "", "XML Files (*.xml)")
        if path:
            self.fileLoaded.emit(path)

    # Drag and drop support
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            url = event.mimeData().urls()[0]
            self.fileLoaded.emit(url.toLocalFile())


class DmarcViewer(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DMARC Reader")
        self.resize(800, 600)

        # Tabs
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Main tab
        self.mainTab = MainTab()
        self.mainTab.fileLoaded.connect(self.load_file)
        self.tabs.addTab(self.mainTab, "Main")

        # Log tab
        self.logText = QTextEdit()
        self.logText.setReadOnly(True)
        self.tabs.addTab(self.logText, "Log")

        # Logging setup
        self.logger = logging.getLogger("dmarc")
        self.logger.setLevel(logging.INFO)
        handler = QtLogHandler(self.logText)
        self.logger.addHandler(handler)

        self.apply_style()

    # Styling to achieve dark theme
    def apply_style(self):
        dark_bg = "#2b2b2b"
        black = "#000000"
        green = "#008000"

        self.setStyleSheet(
            f"""
            QMainWindow {{ background-color: {dark_bg}; color: white; }}
            QPushButton {{ background-color: {green}; color: white; border: none; padding: 8px; }}
            QPushButton:hover {{ background-color: #00aa00; }}
            QTabWidget::pane {{ border: 0; background: {dark_bg}; }}
            QTabBar::tab {{ background: {black}; color: white; padding: 6px; }}
            QTabBar::tab:selected {{ background: #111111; }}
            QTextEdit {{ background: #1e1e1e; color: white; border: none; }}
            QLabel {{ color: white; }}
            """
        )

    def load_file(self, path: str) -> None:
        self.logger.info(f"Loading DMARC XML: {path}")
        try:
            data = parse_dmarc(path)
            self.display_results(data)
            self.logger.info("Loaded DMARC report successfully")
        except Exception as exc:
            self.logger.error(f"Failed to load DMARC report: {exc}")

    def display_results(self, data):
        layout = self.mainTab.resultLayout
        # Clear previous
        while layout.count() > 1:
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        # Helper to add colored label
        def add_label(text: str, color: str, parent_layout):
            lbl = QLabel(text)
            lbl.setStyleSheet(f"color: {color};")
            parent_layout.addWidget(lbl)

        # Metadata
        meta = data.get("report_metadata", {})
        add_label(f"Organization: {meta.get('org_name','')}", "white", layout)
        add_label(f"Email: {meta.get('email','')}", "grey", layout)
        add_label(f"Report ID: {meta.get('report_id','')}", "white", layout)

        dr = meta.get('date_range', {})
        add_label(
            f"Date Range: {dr.get('begin','')} - {dr.get('end','')}",
            "grey",
            layout,
        )

        # Policy
        policy = data.get("policy_published", {})
        add_label(f"Policy Domain: {policy.get('domain','')}", "white", layout)
        add_label(
            f"Alignment DKIM/SPF: {policy.get('adkim','')}/{policy.get('aspf','')}",
            "grey",
            layout,
        )
        add_label(f"Policy: {policy.get('p','')}", "white", layout)

        # Records
        for rec in data.get("records", []):
            frame = QFrame()
            frame.setFrameShape(QFrame.StyledPanel)
            frame.setStyleSheet("background: #1e1e1e; border: 1px solid #333333;")
            fl = QVBoxLayout(frame)
            add_label(f"Source IP: {rec['source_ip']}", "white", fl)
            add_label(f"Count: {rec['count']}", "grey", fl)
            disposition = rec['policy_evaluated']['disposition']
            add_label(f"Disposition: {disposition}", "grey", fl)

            dkim_color = "#90ee90" if rec['policy_evaluated']['dkim'] == 'pass' else "red"
            spf_color = "#228b22" if rec['policy_evaluated']['spf'] == 'pass' else "red"
            add_label(f"DKIM: {rec['policy_evaluated']['dkim']}", dkim_color, fl)
            add_label(f"SPF: {rec['policy_evaluated']['spf']}", spf_color, fl)
            layout.insertWidget(layout.count() - 1, frame)

        layout.addStretch()


def parse_dmarc(path: str):
    """Parse DMARC XML into a dictionary."""
    tree = ET.parse(path)
    root = tree.getroot()

    def text(element, tag):
        found = element.find(tag)
        return found.text if found is not None else ""

    data = {}
    rm = root.find('report_metadata')
    if rm is not None:
        begin = text(rm.find('date_range'), 'begin') if rm.find('date_range') is not None else ""
        end = text(rm.find('date_range'), 'end') if rm.find('date_range') is not None else ""
        data['report_metadata'] = {
            'org_name': text(rm, 'org_name'),
            'email': text(rm, 'email'),
            'report_id': text(rm, 'report_id'),
            'date_range': {'begin': begin, 'end': end},
        }

    pp = root.find('policy_published')
    if pp is not None:
        data['policy_published'] = {
            'domain': text(pp, 'domain'),
            'adkim': text(pp, 'adkim'),
            'aspf': text(pp, 'aspf'),
            'p': text(pp, 'p'),
            'pct': text(pp, 'pct'),
        }

    records = []
    for record in root.findall('record'):
        row = record.find('row')
        pe = row.find('policy_evaluated') if row is not None else None
        records.append(
            {
                'source_ip': text(row, 'source_ip'),
                'count': text(row, 'count'),
                'policy_evaluated': {
                    'disposition': text(pe, 'disposition'),
                    'dkim': text(pe, 'dkim'),
                    'spf': text(pe, 'spf'),
                },
            }
        )
    data['records'] = records
    return data


def main():
    app = QApplication(sys.argv)
    viewer = DmarcViewer()
    viewer.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
