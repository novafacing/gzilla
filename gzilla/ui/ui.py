from PyQt5 import uic
from enum import Enum
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.Qsci import *
from PyQt5.Qt import QStandardItemModel, QStandardItem
from pathlib import Path
from constants import UI_FILE
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import Ether
import sys

from gz_ui import Ui_MainWindow

class FieldType(Enum):
    STRING = 0
    INT = 1
    FUNCTION = 2
    ARRAY = 3
    INVALID = -1

class Field:
    def __init__(self, name="", type: FieldType = FieldType.INVALID) -> None:
        self.name = name
        self.type = type


class Sniff:
    fields_desc = [Field(name="interface", type=FieldType.STRING), Field(name="filter", type=FieldType.STRING), Field(name="count", type=FieldType.INT),Field(name="prn", type=FieldType.FUNCTION)]

class Spoof:
    fields_desc = [Field(name="packets", type=FieldType.ARRAY), Field(name="iface", type=FieldType.STRING)] 

class TextNode(QStandardItem):
    def __init__(self, txt="") -> None:
        super().__init__()
        self.setText(txt)

class KeyValueNode(QStandardItem):
    def __init__(self, txt=''):
        super().__init__()
        self.appendColumn([TextNode(txt), QStandardItem()])

class GzillaCallbacks(object):
    def tree_depth(self):
        return self.yaml_data_root.rowCount()

    def get_selected(self):
        idx = self.yaml_builder.selectedIndexes()[0]
        selected = idx.model().itemFromIndex(idx)
        print(selected)

    def editor_sync(self):  
        print("Editor sync.")

    def tree_sync(self):
        print("Tree sync.")

    def new_sniff(self):
        print("New sniff.")
        if self.tree_depth() == 0:
            # New toplevel
            e = Sniff()
            fields = tuple(map(lambda f: f.name, e.fields_desc))
            sniff_node = TextNode("sniff")
            for f in fields:
                sniff_node.appendRow(KeyValueNode(f))
            self.yaml_data_root.appendRow(sniff_node)
            self.yaml_builder.expandAll()
            pass

    def new_spoof(self):
        print("New spoof")
        if self.tree_depth() == 0:
            # New toplevel
            e = Spoof()
            fields = tuple(map(lambda f: f.name, e.fields_desc))
            spoof_node = TextNode("spoof")
            for f in fields:
                spoof_node.appendRow(KeyValueNode(f))
            self.yaml_data_root.appendRow(spoof_node)
            self.yaml_builder.expandAll()
            pass

    def new_ethernet(self):
        print("New ethernet")
        if self.tree_depth() == 0:
            # ERR
            return

        e = Ether()
        fields = tuple(map(lambda f: f.name, e.fields_desc))
        ether_node = TextNode("Ether")
        for f in fields:
            ether_node.appendRow(KeyValueNode(f))
        self.current_selection.appendRow(ether_node)
        self.yaml_builder.expandAll()



    def new_ip(self):
        print("New ip")
        if self.tree_depth() == 0:
            # ERR
            return

        e = IP()
        fields = tuple(map(lambda f: f.name, e.fields_desc))
        ip_node = TextNode("IP")
        for f in fields:
            ip_node.appendRow(KeyValueNode(f))
        self.current_selection.appendRow(ip_node)
        self.yaml_builder.expandAll()

    def new_udp(self):
        print("New udp")
        if self.tree_depth() == 0:
            # ERR
            return

        e = UDP()
        fields = tuple(map(lambda f: f.name, e.fields_desc))
        udp_node = TextNode("UDP")
        for f in fields:
            udp_node.appendRow(KeyValueNode(f))
        self.current_selection.appendRow(udp_node)
        self.yaml_builder.expandAll()

    def new_tcp(self):
        print("New tcp")
        if self.tree_depth() == 0:
            # ERR
            return

        e = TCP()
        fields = tuple(map(lambda f: f.name, e.fields_desc))
        tcp_node = TextNode("TCP")
        for f in fields:
            tcp_node.appendRow(KeyValueNode(f))
        self.current_selection.appendRow(tcp_node)
        self.yaml_builder.expandAll()

    def new_icmp(self):
        print("New icmp")
        if self.tree_depth() == 0:
            # ERR
            return

        e = ICMP()
        fields = tuple(map(lambda f: f.name, e.fields_desc))
        icmp_node = TextNode("ICMP")
        for f in fields:
            icmp_node.appendRow(KeyValueNode(f))
        self.current_selection.appendRow(icmp_node)
        self.yaml_builder.expandAll()

    def new_dns(self):
        print("New dns")
        if self.tree_depth() == 0:
            # ERR
            return

        e = DNS()
        fields = tuple(map(lambda f: f.name, e.fields_desc))
        dns_node = TextNode("DNS")
        for f in fields:
            dns_node.appendRow(KeyValueNode(f))
        self.current_selection.appendRow(dns_node)
        self.yaml_builder.expandAll()

    def init_buttons(self):
        self.editor_sync_button.clicked.connect(self.editor_sync)
        self.tree_sync_button.clicked.connect(self.tree_sync)
        self.new_sniff_button.clicked.connect(self.new_sniff)
        self.new_spoof_button.clicked.connect(self.new_spoof)
        self.new_ethernet_button.clicked.connect(self.new_ethernet)
        self.new_ip_button.clicked.connect(self.new_ip)
        self.new_udp_button.clicked.connect(self.new_udp)
        self.new_tcp_button.clicked.connect(self.new_tcp)
        self.new_icmp_button.clicked.connect(self.new_icmp)
        self.new_dns_button.clicked.connect(self.new_dns)

class GzillaUi(QMainWindow, Ui_MainWindow, GzillaCallbacks):  # type: ignore
    """Import UI spec from designer UI file."""

    def __init__(self, parent=None) -> None:
        """Set up and load UI spec."""
        super().__init__(parent)
        self.setupUi(self)
        self.connectSignalsSlots()

        self.editor = self.textEdit
        self.lexer = QsciLexerYAML(self.editor)
        self.editor.setLexer(self.lexer)
        self.yaml_builder = self.treeView
        self.yaml_data = QStandardItemModel()
        self.yaml_builder.setModel(self.yaml_data)
        self.yaml_data_root = self.yaml_data.invisibleRootItem()
        self.yaml_builder.clicked.connect(self.set_current_builder_item)
        self.current_selection = None
        self.init_buttons()

    def set_current_builder_item(self, val):
        print("ROW: ", val.row(), "COL: ", val.column())
        self.current_selection = self.yaml_data.itemFromIndex(val)

    def connectSignalsSlots(self):
        pass


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GzillaUi()
    window.show()
    sys.exit(app.exec_())
