from PyQt5 import uic
from PyQt5.QtWidgets import QMainWindow, QApplication, Qsci
from pathlib import Path
from constants import UI_FILE
import sys


class GzillaUi(QMainWindow):  # type: ignore
    """Import UI spec from designer UI file."""

    def __init__(self) -> None:
        """Set up and load UI spec."""
        super(GzillaUi, self).__init__()
        uic.loadUi(Path(__file__).parents[0] / UI_FILE, self)
        self.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GzillaUi()
    app.exec_()
