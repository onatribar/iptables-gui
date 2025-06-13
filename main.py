import sys
from PyQt5.QtWidgets import QApplication
from gui import IptablesGUI


def main() -> None:
    app = QApplication(sys.argv)
    win = IptablesGUI()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()