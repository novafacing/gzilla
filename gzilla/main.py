from ui.ui import GzillaUi
from compiletools import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.Qsci import *
from PyQt5.Qt import QStandardItemModel, QStandardItem
import sys

app = QApplication(sys.argv)
# console = PythonConsole()
window = GzillaUi()
window.show()
# console.show()
# console.push_local_ns("window", window)
# console.eval_queued()
sys.exit(app.exec_())
