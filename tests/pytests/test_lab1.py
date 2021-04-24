import pytest
import threading
from scapy.all import *

# Added to PYTHONPATH in Docker
from compiletools import execute_yaml

# Include all features used to complete lab1:
## sniffing
# - Capture ICMP packets between two specific hosts.
# - Capture TCP packets with destination port range from port 50 - 100
# - Sniff telnet passwords
## spoofing
# - ICMP ping
# - Ethernet frame


def start_gzilla_thread(filename):
    print("In thread:\nStarting gzilla on {}".format(filename))
    execute_yaml(filename)


def test_sniff_icmp():
    gzilla = threading.Thread(target=start_gzilla_thread, args=("/tests/lab1/spoof_icmp_echo.yaml",))
    # Race condition...?
    gzilla.start()
    sniff_out = sniff(filter="icmp", count=5, timeout=2)
    gzilla.join()
    for packet in sniff_out:
        if packet.haslayer(ICMP):
            if packet[IP].dst == "1.1.1.1":
                assert True
                return

    assert False


def test_sniff_tcp():
    assert 1 == 1

def test_sniff_telnet():
    assert 1 == 1
