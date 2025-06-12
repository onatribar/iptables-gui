import re
import subprocess
from PyQt5.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QCheckBox,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QHeaderView,
    QStyle,
    QApplication,
)
from utils import RuleValidator, IptablesInterface


class IptablesGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Iptables Interface")
        self.setMinimumSize(900, 600)

        # Central widget / layout
        self._central = QWidget()
        self.setCentralWidget(self._central)
        self.layout = QVBoxLayout()
        self._central.setLayout(self.layout)
        self.setWindowIcon(QApplication.style().standardIcon(QStyle.SP_DesktopIcon))

        self._build_form()
        self._build_table()
        self._build_buttons()

        # Populate table on launch
        self.refresh_table()

    # ------------------------------------------------------------------
    #  UI builders
    # ------------------------------------------------------------------
    def _build_form(self):
        form = QHBoxLayout()

        # Protocol selector
        self.proto_box = QComboBox()
        self.proto_box.addItems(["tcp", "udp"])
        self.proto_box.currentTextChanged.connect(self._toggle_tcp_flags)
        form.addWidget(QLabel("Protocol:"))
        form.addWidget(self.proto_box)

        # IP fields
        self.src_ip = QLineEdit()
        form.addWidget(QLabel("Source IP:"))
        form.addWidget(self.src_ip)

        self.dst_ip = QLineEdit()
        form.addWidget(QLabel("Destination IP:"))
        form.addWidget(self.dst_ip)

        # Ports
        self.src_port = QLineEdit()
        self.src_port.setPlaceholderText("1‑65535")
        form.addWidget(QLabel("Source Port:"))
        form.addWidget(self.src_port)

        self.dst_port = QLineEdit()
        self.dst_port.setPlaceholderText("1‑65535")
        form.addWidget(QLabel("Destination Port:"))
        form.addWidget(self.dst_port)

        # Action
        self.action_box = QComboBox()
        self.action_box.addItems(["ACCEPT", "DROP"])
        form.addWidget(QLabel("Action:"))
        form.addWidget(self.action_box)

        self.layout.addLayout(form)

        # TCP Flags row
        self.flags_row = QHBoxLayout()
        self.flags_label = QLabel("TCP Flags:")
        self.flags_row.addWidget(self.flags_label)
        self.flag_boxes = []
        for f in ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]:
            cb = QCheckBox(f)
            self.flags_row.addWidget(cb)
            self.flag_boxes.append(cb)
        self.layout.addLayout(self.flags_row)
        self._toggle_tcp_flags("tcp")  # default

    def _build_buttons(self):
        row = QHBoxLayout()

        self.add_btn = QPushButton("Add Rule")
        self.add_btn.clicked.connect(self.add_rule)
        row.addWidget(self.add_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_table)
        row.addWidget(self.refresh_btn)

        self.disable_btn = QPushButton("Disable Selected Rule")
        self.disable_btn.clicked.connect(self.disable_rule)
        row.addWidget(self.disable_btn)

        self.layout.addLayout(row)

    def _build_table(self):
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["Line", "Protocol", "Source", "Destination", "Ports", "Packets"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.layout.addWidget(self.table)

    # ------------------------------------------------------------------
    #  Helpers
    # ------------------------------------------------------------------
    def _toggle_tcp_flags(self, proto: str):
        is_tcp = proto == "tcp"
        self.flags_label.setEnabled(is_tcp)
        for cb in self.flag_boxes:
            cb.setEnabled(is_tcp)
            cb.setVisible(is_tcp)

    # ------------------------------------------------------------------
    #  Core interactions
    # ------------------------------------------------------------------
    def add_rule(self):
        proto = self.proto_box.currentText()
        src_ip = self.src_ip.text().strip()
        dst_ip = self.dst_ip.text().strip()
        src_port = self.src_port.text().strip()
        dst_port = self.dst_port.text().strip()
        action = self.action_box.currentText()
        flags = [cb.text() for cb in self.flag_boxes if cb.isChecked()] if proto == "tcp" else None

        # Validation ----------------------------------------------------
        if not RuleValidator.validate_ip(src_ip):
            QMessageBox.warning(self, "Invalid IP", "Invalid source IPv4/CIDR.")
            return
        if not RuleValidator.validate_ip(dst_ip):
            QMessageBox.warning(self, "Invalid IP", "Invalid destination IPv4/CIDR.")
            return
        if not RuleValidator.validate_port(src_port):
            QMessageBox.warning(self, "Invalid Port", "Source port must be 1‑65535.")
            return
        if not RuleValidator.validate_port(dst_port):
            QMessageBox.warning(self, "Invalid Port", "Destination port must be 1‑65535.")
            return
        if not RuleValidator.validate_flags(proto, flags):
            QMessageBox.warning(self, "Invalid Flags", "TCP flags can only be used with proto=TCP.")
            return

        # Apply ---------------------------------------------------------
        try:
            IptablesInterface.add_rule(proto, src_ip, dst_ip, src_port, dst_port, action, flags)
            self.refresh_table()
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "iptables error", e.stderr or str(e))
        except Exception as e:
            QMessageBox.critical(self, "error", str(e))

    def refresh_table(self):
        try:
            out = IptablesInterface.list_rules()
            self.table.setRowCount(0)
            for ln in out.splitlines():
                if not re.match(r"^\s*\d+", ln):
                    continue
                parts = ln.split()
                if len(parts) < 9:
                    continue  # malformed
                line_no, pkts, proto, src, dst = parts[0], parts[1], parts[4], parts[7], parts[8]
                # Extract ports if present
                ports = "-"
                dpt = re.search(r"dpt:(\d+)", ln)
                spt = re.search(r"spt:(\d+)", ln)
                if spt and dpt:
                    ports = f"{spt.group(1)}→{dpt.group(1)}"
                elif dpt:
                    ports = dpt.group(1)
                elif spt:
                    ports = spt.group(1)

                row = self.table.rowCount()
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(line_no))
                self.table.setItem(row, 1, QTableWidgetItem(proto))
                self.table.setItem(row, 2, QTableWidgetItem(src))
                self.table.setItem(row, 3, QTableWidgetItem(dst))
                self.table.setItem(row, 4, QTableWidgetItem(ports))
                self.table.setItem(row, 5, QTableWidgetItem(pkts))
        except Exception as e:
            QMessageBox.critical(self, "Refresh failed", str(e))

    def disable_rule(self):
        idx = self.table.currentRow()
        if idx == -1:
            QMessageBox.warning(self, "No selection", "Select a rule to disable.")
            return
        line_item = self.table.item(idx, 0)
        if not line_item:
            QMessageBox.warning(self, "No line", "Couldn't obtain line number.")
            return
        try:
            IptablesInterface.delete_rule(line_item.text())
            self.refresh_table()
        except Exception as e:
            QMessageBox.critical(self, "Disable failed", str(e))
