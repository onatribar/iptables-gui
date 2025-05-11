from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QComboBox, QCheckBox, QTableWidget, QTableWidgetItem,
    QMessageBox, QHeaderView,
    QStyle, QApplication
)
import re
from utils import RuleValidator, IptablesInterface

class IptablesGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Iptables Interface")
        self.setMinimumSize(900, 600)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        self.setWindowIcon(QApplication.style().standardIcon(QStyle.SP_DesktopIcon))

        self.disabled_rules = []

        self.build_form()
        self.build_table()
        self.build_buttons()

    def build_form(self):
        form_layout = QHBoxLayout()

        self.proto_box = QComboBox()
        self.proto_box.addItems(["tcp", "udp"])
        self.proto_box.currentTextChanged.connect(self.toggle_tcp_flags)
        form_layout.addWidget(QLabel("Protocol:"))
        form_layout.addWidget(self.proto_box)

        self.src_ip = QLineEdit()
        form_layout.addWidget(QLabel("Source IP:"))
        form_layout.addWidget(self.src_ip)

        self.dst_ip = QLineEdit()
        form_layout.addWidget(QLabel("Destination IP:"))
        form_layout.addWidget(self.dst_ip)

        self.src_port = QLineEdit()
        self.src_port.setPlaceholderText("1-65535")
        form_layout.addWidget(QLabel("Source Port:"))
        form_layout.addWidget(self.src_port)

        self.dst_port = QLineEdit()
        self.dst_port.setPlaceholderText("1-65535")
        form_layout.addWidget(QLabel("Destination Port:"))
        form_layout.addWidget(self.dst_port)

        self.action_box = QComboBox()
        self.action_box.addItems(["ACCEPT", "DROP"])
        form_layout.addWidget(QLabel("Action:"))
        form_layout.addWidget(self.action_box)

        self.layout.addLayout(form_layout)

        self.flags_layout = QHBoxLayout()
        self.flags_label = QLabel("TCP Flags:")
        self.flags_layout.addWidget(self.flags_label)
        self.flag_checkboxes = []
        for flag in ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]:
            cb = QCheckBox(flag)
            self.flags_layout.addWidget(cb)
            self.flag_checkboxes.append(cb)
        self.layout.addLayout(self.flags_layout)
        self.toggle_tcp_flags("tcp")

    def build_buttons(self):
        btn_layout = QHBoxLayout()
        self.add_rule_btn = QPushButton("Add Rule")
        self.add_rule_btn.clicked.connect(self.add_rule)
        btn_layout.addWidget(self.add_rule_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_table)
        btn_layout.addWidget(self.refresh_btn)

        self.disable_rule_btn = QPushButton("Disable Selected Rule")
        self.disable_rule_btn.clicked.connect(self.disable_rule)
        btn_layout.addWidget(self.disable_rule_btn)

        self.layout.addLayout(btn_layout)

    def build_table(self):
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Line", "Protocol", "Source", "Destination", "Ports", "Packets"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.layout.addWidget(self.table)

    def toggle_tcp_flags(self, proto):
        is_tcp = proto == "tcp"
        self.flags_label.setVisible(is_tcp)
        for cb in self.flag_checkboxes:
            cb.setVisible(is_tcp)

    def add_rule(self):
        proto = self.proto_box.currentText()
        src_ip = self.src_ip.text()
        dst_ip = self.dst_ip.text()
        dst_port = self.dst_port.text()
        action = self.action_box.currentText()

        if not RuleValidator.validate_ip(src_ip):
            QMessageBox.warning(self, "Invalid IP", "Please enter a valid Source IPv4 or CIDR address.")
            return
        if not RuleValidator.validate_ip(dst_ip):
            QMessageBox.warning(self, "Invalid IP", "Please enter a valid Destination IPv4 or CIDR address.")
            return
        
        flags = [cb.text() for cb in self.flag_checkboxes if cb.isChecked()] if proto == "tcp" else None

        try:
            IptablesInterface.add_rule(proto, src_ip, dst_ip, dst_port, action, flags)
            self.refresh_table()
        except Exception:
            QMessageBox.critical(self, "Error", "Failed to add rule. Make sure you approved the pkexec dialog.")

    def refresh_table(self):
        try:
            output = IptablesInterface.list_rules()
            print("DEBUG raw iptables output:\\n", output)
            self.table.setRowCount(0)
            lines = output.splitlines()
            for line in lines:
                if re.match(r"^\s*\d+", line):
                    parts = line.split()

                    try:
                        line_num = parts[0]
                        pkts = parts[1]
                        proto = parts[4]
                        src = parts[7]
                        dst = parts[8]

                        port = "-"
                        if "dpt:" in line:
                            port_match = re.search(r"dpt:(\d+)", line)
                            if port_match:
                                port = port_match.group(1)

                        row = self.table.rowCount()
                        self.table.insertRow(row)
                        self.table.setItem(row, 0, QTableWidgetItem(line_num))
                        self.table.setItem(row, 1, QTableWidgetItem(proto))
                        self.table.setItem(row, 2, QTableWidgetItem(src))
                        self.table.setItem(row, 3, QTableWidgetItem(dst))
                        self.table.setItem(row, 4, QTableWidgetItem(port))
                        self.table.setItem(row, 5, QTableWidgetItem(pkts))
                    except IndexError:
                        print("WARNING: Malformed line skipped:", line)

        except Exception:
            QMessageBox.critical(self, "Error", "Failed to refresh rules. Please approve the pkexec dialog.")

    def disable_rule(self):
        selected_row = self.table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "No Selection", "Please select a rule to disable.")
            return
        line_item = self.table.item(selected_row, 0)
        if line_item is None:
            QMessageBox.warning(self, "Invalid Selection", "Could not find line number.")
            return

        line_number = line_item.text()
        try:
            IptablesInterface.delete_rule(line_number)
            QMessageBox.information(self, "Disabled", f"Rule at line {line_number} disabled.")
            self.refresh_table()
        except Exception:
            QMessageBox.critical(self, "Error", f"Failed to disable rule at line {line_number}.")
