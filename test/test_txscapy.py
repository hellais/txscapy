import sys
from twisted.trial import unittest
from twisted.python import log

from txscapy import txsr, txsend

class TXScapyTest(unittest.TestCase):

    def test_txsr(self):
        from scapy.all import IP, RandShort, TCP
        def done(a):
            pass
        packets = IP(dst='8.8.8.8', ttl=20,id=RandShort())/TCP(flags='S',
            window=200, sport=8088, dport=53)
        d = txsr(packets)
        return d

    def test_txsend(self):
        from scapy.all import IP, RandShort, TCP
        def done(a):
            pass
        packets = IP(dst='8.8.8.8', ttl=20,id=RandShort())/TCP(flags='S',
            window=200, sport=8088, dport=53)
        d = txsend(packets)
        return d

    def test_txsr_write(self):
        from scapy.all import IP, RandShort, TCP
        def done(a):
            pass
        packets = IP(dst='8.8.8.8', ttl=20,id=RandShort())/TCP(flags='S',
            window=200, sport=8088, dport=53)
        d = txsend(packets, pcapfile='test.pcap')
        return d

