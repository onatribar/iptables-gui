import sys
from PyQt5.QtWidgets import QApplication
from gui import IptablesGUI

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = IptablesGUI()
    window.show()
    sys.exit(app.exec_())