from PyQt5 import uic
from enum import Enum
from collections import OrderedDict
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.Qsci import *
from PyQt5.Qt import QStandardItemModel, QStandardItem
from pyqtconsole.console import PythonConsole
from pathlib import Path
from constants import UI_FILE
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import Ether
import sys
from typing import Optional
from pprint import pprint
import yaml
from json import loads, dumps
from nested_lookup import nested_lookup, nested_update

from gz_ui import Ui_MainWindow


class FieldType(Enum):
    STRING = 0
    INT = 1
    FUNCTION = 2
    ARRAY = 3
    INVALID = -1


class Field:
    def __init__(
        self,
        name="",
        type: FieldType = FieldType.INVALID,
        default: Optional[str] = None,
    ) -> None:
        self.name = name
        self.type = type
        self.default = None


class Sniff:
    fields_desc = [
        Field(name="interface: ", type=FieldType.STRING, default="eth0"),
        Field(name="filter: ", type=FieldType.STRING, default="ip"),
        Field(name="count: ", type=FieldType.INT, default="1"),
        Field(name="prn: ", type=FieldType.FUNCTION),
    ]


class Spoof:
    fields_desc = [
        Field(name="packets", type=FieldType.ARRAY),
        Field(name="iface: ", type=FieldType.STRING, default="eth0"),
    ]


class TextNode(QStandardItem):
    def __init__(self, txt="") -> None:
        super().__init__()
        self.setText(txt)
        self.rows = []
        self.parent = None

    def appendRow(self, node) -> None:
        self.rows.append(node)
        node.parent = self
        if self.text() == "packets: ":
            node.setText(node.text())
        super().appendRow(node)


class GzillaCallbacks(object):
    def tree_depth(self):
        return self.yaml_data_root.rowCount()

    def get_selected(self):
        idx = self.yaml_builder.selectedIndexes()[0]
        selected = idx.model().itemFromIndex(idx)
        print(selected)

    def fill_model_from_json(self, parent, d):
        if isinstance(d, dict):
            for k, v in d.items():
                child = TextNode(str(k))
                parent.appendRow(child)
                self.fill_model_from_json(child, v)
        elif isinstance(d, list):
            for v in d:
                self.fill_model_from_json(parent, v)
        else:
            parent.appendRow(TextNode(str(d)))

    def tree_sync(self):
        print("Tree sync.")
        self.ymlfile = self.dump_tree()
        self.editor.setText(self.ymlfile)

    def new_sniff(self):
        print("New sniff.")
        if self.tree_depth() == 0:
            # New toplevel
            e = Sniff()
            fields = tuple(map(lambda f: f.name, e.fields_desc))
            sniff_node = TextNode("sniff: ")
            self.root = sniff_node
            for f in fields:
                sniff_node.appendRow(TextNode(f))
            self.yaml_data_root.appendRow(sniff_node)
            self.yaml_builder.expandAll()
            pass

    def to_dict(self, input_ordered_dict):
        return loads(dumps(input_ordered_dict))

    def dump_tree(self):
        data = self.model_to_dict(self.yaml_data)
        pprint(data)
        ddata = self.to_dict(data)
        tdata = ddata.copy()
        packets = nested_lookup("packets", tdata)
        ntdata = nested_update(tdata, key="packets", value=packets)
        ydata = yaml.dump(ntdata)
        print(ydata)
        return ydata
        # print(ydata)

    def fill_dict_from_model(self, parent_index, d) -> None:
        v = OrderedDict()
        if self.yaml_data.rowCount(parent_index):
            for i in range(self.yaml_data.rowCount(parent_index)):
                ix = self.yaml_data.index(i, 0, parent_index)
                self.fill_dict_from_model(ix, v)

            d[parent_index.data()] = v
        else:
            dt = parent_index.data().split(":")
            dd = dt[1].lstrip().rstrip()
            try:
                dp = int(dd, 10)
            except:
                dp = dd
            print(dt)
            if (type(dp) == str and dp) or type(dp) != str:
                d[dt[0]] = dp

    def model_to_dict(self, model) -> OrderedDict:
        d = OrderedDict()
        for i in range(model.rowCount()):
            ix = self.yaml_data.index(i, 0)
            self.fill_dict_from_model(ix, d)
        return d

    def new_spoof(self) -> None:
        print("New spoof")
        if self.tree_depth() == 0:
            # New toplevel
            e = Spoof()
            fields = tuple(map(lambda f: f.name, e.fields_desc))
            spoof_node = TextNode("spoof")
            self.root = spoof_node
            for f in fields:
                spoof_node.appendRow(TextNode(f))
            self.yaml_data_root.appendRow(spoof_node)
            self.yaml_builder.expandAll()
            pass

    def new_ethernet(self) -> None:
        print("New ethernet")
        if self.tree_depth() == 0:
            # ERR
            return

        e = Ether()
        fields = tuple(
            map(
                lambda f: (f.name, str(f.default) if f.default is not None else ""),
                e.fields_desc,
            )
        )
        ether_node = TextNode("Ether")
        for f in fields:
            ether_node.appendRow(TextNode(f[0] + ": " + f[1]))
        self.current_selection.appendRow(ether_node)
        self.yaml_builder.expandAll()

    def new_ip(self) -> None:
        print("New ip")
        if self.tree_depth() == 0:
            # ERR
            return

        e = IP()
        fields = tuple(
            map(
                lambda f: (f.name, str(f.default) if f.default is not None else ""),
                e.fields_desc,
            )
        )
        ip_node = TextNode("IP")
        for f in fields:
            ip_node.appendRow(TextNode(f[0] + ": " + f[1]))
        self.current_selection.appendRow(ip_node)
        self.yaml_builder.expandAll()

    def new_udp(self) -> None:
        print("New udp")
        if self.tree_depth() == 0:
            # ERR
            return

        e = UDP()
        fields = tuple(
            map(
                lambda f: (f.name, str(f.default) if f.default is not None else ""),
                e.fields_desc,
            )
        )
        udp_node = TextNode("UDP")
        for f in fields:
            udp_node.appendRow(TextNode(f[0] + ": " + f[1]))
        self.current_selection.appendRow(udp_node)
        self.yaml_builder.expandAll()

    def new_tcp(self) -> None:
        print("New tcp")
        if self.tree_depth() == 0:
            # ERR
            return

        e = TCP()
        fields = tuple(
            map(
                lambda f: (f.name, str(f.default) if f.default is not None else ""),
                e.fields_desc,
            )
        )
        tcp_node = TextNode("TCP")
        for f in fields:
            tcp_node.appendRow(TextNode(f[0] + ": " + f[1]))
        self.current_selection.appendRow(tcp_node)
        self.yaml_builder.expandAll()

    def new_icmp(self) -> None:
        print("New icmp")
        if self.tree_depth() == 0:
            # ERR
            return

        e = ICMP()
        fields = tuple(
            map(
                lambda f: (f.name, str(f.default) if f.default is not None else ""),
                e.fields_desc,
            )
        )
        icmp_node = TextNode("ICMP")
        for f in fields:
            icmp_node.appendRow(TextNode(f[0] + ": " + f[1]))
        self.current_selection.appendRow(icmp_node)
        self.yaml_builder.expandAll()

    def new_dns(self) -> None:
        print("New dns")
        if self.tree_depth() == 0:
            # ERR
            return

        e = DNS()
        fields = tuple(
            map(
                lambda f: (f.name, str(f.default) if f.default is not None else ""),
                e.fields_desc,
            )
        )
        dns_node = TextNode("DNS")
        for f in fields:
            dns_node.appendRow(TextNode(f[0] + ": " + f[1]))
        self.current_selection.appendRow(dns_node)
        self.yaml_builder.expandAll()

    def save_and_run(self) -> None:
        with open("file.yml", "w") as savefile:
            savefile.write(self.ymlfile)
        print("Saved!")
        print(self.ymlfile)

    def init_buttons(self):
        self.run_button.clicked.connect(self.save_and_run)
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
    # console = PythonConsole()
    window = GzillaUi()
    window.show()
    # console.show()
    # console.push_local_ns("window", window)
    # console.eval_queued()
    sys.exit(app.exec_())
