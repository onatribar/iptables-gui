import subprocess
from typing import List

from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from utils import RuleValidator, IptablesInterface


class IptablesGUI(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Iptables Interface")
        self.resize(1200, 680)

        central = QWidget()
        self.setCentralWidget(central)
        self.layout = QVBoxLayout(central)

        self._build_form()
        self._build_table()
        self._build_buttons()
        self.refresh_table()

    # UI builders
    def _build_form(self) -> None:
        row = QHBoxLayout()

        # Protocol
        self.proto_box = QComboBox()
        self.proto_box.addItems(["tcp", "udp"])
        self.proto_box.currentTextChanged.connect(self._toggle_flags)
        row.addWidget(QLabel("Protocol:"))
        row.addWidget(self.proto_box)

        # Source/Destination IP
        self.src_ip = QLineEdit()
        row.addWidget(QLabel("Source IP:"))
        row.addWidget(self.src_ip)

        self.dst_ip = QLineEdit()
        row.addWidget(QLabel("Destination IP:"))
        row.addWidget(self.dst_ip)

        # Ports
        self.src_port = QLineEdit()
        self.src_port.setPlaceholderText("1-65535")
        row.addWidget(QLabel("Source Port:"))
        row.addWidget(self.src_port)

        self.dst_port = QLineEdit()
        self.dst_port.setPlaceholderText("1-65535")
        row.addWidget(QLabel("Destination Port:"))
        row.addWidget(self.dst_port)

        # Action
        self.action_box = QComboBox()
        self.action_box.addItems(["ACCEPT", "DROP"])
        row.addWidget(QLabel("Action:"))
        row.addWidget(self.action_box)

        self.layout.addLayout(row)

        # Bulk boxes
        bulk = QHBoxLayout()
        self.whitelist_box = QTextEdit()
        self.whitelist_box.setPlaceholderText("One IP/CIDR per line to ACCEPT…")
        bulk.addWidget(QLabel("Whitelist:"))
        bulk.addWidget(self.whitelist_box)

        self.blacklist_box = QTextEdit()
        self.blacklist_box.setPlaceholderText("One IP/CIDR per line to DROP…")
        bulk.addWidget(QLabel("Blacklist:"))
        bulk.addWidget(self.blacklist_box)

        self.layout.addLayout(bulk)

        # TCP flags
        self.flags_row = QHBoxLayout()
        self.flags_row.addWidget(QLabel("TCP Flags:"))
        self.flag_boxes: List[QCheckBox] = []
        for f in ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]:
            cb = QCheckBox(f)
            self.flags_row.addWidget(cb)
            self.flag_boxes.append(cb)
        self.layout.addLayout(self.flags_row)
        self._toggle_flags("tcp")

    def _build_table(self) -> None:
        self.table = QTableWidget()
        self.table.setColumnCount(8)   # was 7
        self.table.setHorizontalHeaderLabels(
            ["Line", "Proto", "Source", "Destination",
             "Ports", "Flags", "Action", "Packets"]  # added “Action”
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.layout.addWidget(self.table)


    def _build_buttons(self) -> None:
        row = QHBoxLayout()

        self.add_btn = QPushButton("Add Rule(s)")
        self.add_btn.clicked.connect(self.add_rule)
        row.addWidget(self.add_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_table)
        row.addWidget(self.refresh_btn)

        self.disable_btn = QPushButton("Toggle Disable Selected")
        self.disable_btn.clicked.connect(self.disable_rule)
        row.addWidget(self.disable_btn)

        self.delete_btn = QPushButton("Delete Selected")
        self.delete_btn.clicked.connect(self.delete_rule)
        row.addWidget(self.delete_btn)

        self.reorder_btn = QPushButton("Reorder by Usage")
        self.reorder_btn.clicked.connect(self.reorder_rules)
        row.addWidget(self.reorder_btn)

        self.layout.addLayout(row)

    def _toggle_flags(self, proto: str) -> None:
        visible = proto == "tcp"
        for cb in self.flag_boxes:
            cb.setEnabled(visible)
            cb.setVisible(visible)

    def _parse_bulk(self, txt: str) -> List[str]:
        return [ln.strip() for ln in txt.strip().splitlines() if ln.strip()]

    def add_rule(self) -> None:
        proto = self.proto_box.currentText()
        flags = [cb.text() for cb in self.flag_boxes if cb.isChecked()] if proto == "tcp" else None

        # Bulk mode
        wlist = self._parse_bulk(self.whitelist_box.toPlainText())
        blist = self._parse_bulk(self.blacklist_box.toPlainText())
        if wlist or blist:
            try:
                for ip in wlist:
                    if not RuleValidator.validate_ip(ip):
                        raise ValueError(f"Invalid IP in whitelist: {ip}")
                    IptablesInterface.add_rule(proto, ip, "", "", "", "ACCEPT", flags)
                for ip in blist:
                    if not RuleValidator.validate_ip(ip):
                        raise ValueError(f"Invalid IP in blacklist: {ip}")
                    IptablesInterface.add_rule(proto, ip, "", "", "", "DROP", flags)
                self.whitelist_box.clear(); self.blacklist_box.clear()
            except Exception as err:
                QMessageBox.critical(self, "Bulk add failed", str(err))
            finally:
                self.refresh_table()
            return

        # Single rule mode
        src_ip, dst_ip = self.src_ip.text().strip(), self.dst_ip.text().strip()
        src_port, dst_port = self.src_port.text().strip(), self.dst_port.text().strip()
        action = self.action_box.currentText()

        if src_ip in blist:
            action = "DROP"
        elif src_ip in wlist:
            action = "ACCEPT"

        # Validation
        if not RuleValidator.validate_ip(src_ip):
            QMessageBox.warning(self, "Invalid IP", "Invalid source IPv4/CIDR."); return
        if not RuleValidator.validate_ip(dst_ip):
            QMessageBox.warning(self, "Invalid IP", "Invalid destination IPv4/CIDR."); return
        if not RuleValidator.validate_port(src_port):
            QMessageBox.warning(self, "Invalid Port", "Source port must be 1-65535."); return
        if not RuleValidator.validate_port(dst_port):
            QMessageBox.warning(self, "Invalid Port", "Destination port must be 1-65535."); return
        if not RuleValidator.validate_flags(proto, flags):
            QMessageBox.warning(self, "Invalid Flags", "TCP flags only valid for protocol TCP."); return

        try:
            IptablesInterface.add_rule(proto, src_ip, dst_ip, src_port, dst_port, action, flags)
            self.refresh_table()
        except Exception as err:
            QMessageBox.critical(self, "Add failed", str(err))

    def refresh_table(self) -> None:
        try:
            rules = IptablesInterface.list_rules_detailed()
            self.table.setRowCount(0)
            for r in rules:
                row = self.table.rowCount()
                self.table.insertRow(row)

                self.table.setItem(row, 0, QTableWidgetItem(r["line"]))
                self.table.setItem(row, 1, QTableWidgetItem(r["proto"]))
                self.table.setItem(row, 2, QTableWidgetItem(r["src"]))
                self.table.setItem(row, 3, QTableWidgetItem(r["dst"]))
                self.table.setItem(row, 4, QTableWidgetItem(r["ports"]))

                flag_txt = r["flags"] + (" (DIS)" if r["disabled"] else "")
                self.table.setItem(row, 5, QTableWidgetItem(flag_txt))

                self.table.setItem(row, 6, QTableWidgetItem(r["action"]))  # new column
                self.table.setItem(row, 7, QTableWidgetItem(r["pkts"]))    # shifted
        except Exception as err:
            QMessageBox.critical(self, "Refresh failed", str(err))

    def disable_rule(self) -> None:
        idx = self.table.currentRow()
        if idx == -1:
            QMessageBox.warning(self, "Select a rule", "No row selected."); return
        line = self.table.item(idx, 0).text()
        try:
            IptablesInterface.toggle_rule_state(line)
            self.refresh_table()
        except Exception as err:
            QMessageBox.critical(self, "Disable failed", str(err))

    def delete_rule(self) -> None:
        idx = self.table.currentRow()
        if idx == -1:
            QMessageBox.warning(self, "Select a rule", "No row selected."); return
        line = self.table.item(idx, 0).text()
        try:
            IptablesInterface.delete_rule(line)
            self.refresh_table()
        except Exception as err:
            QMessageBox.critical(self, "Delete failed", str(err))

    def reorder_rules(self) -> None:
        try:
            IptablesInterface.reorder_by_packets()
            self.refresh_table()
        except Exception as err:
            QMessageBox.critical(self, "Reorder failed", str(err))
