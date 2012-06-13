import struct
import socket
import os

from twisted.internet import protocol, base, fdesc, error, defer
from twisted.internet import reactor, threads
from twisted.pair import raw, ip
from zope.interface import implements

from scapy.all import Gen
from scapy.all import SetGen

class ScapyProtocol(protocol.AbstractDatagramProtocol):
    implements(raw.IRawPacketProtocol)

    def datagramReceived(self, data, partial, dest,
                         source, protocol):
        print data

from pcapy import open_live
# pcap settings
DEV          = 'lo0'  # interface to listen on
MAX_LEN      = 1514    # max size of packet to capture
PROMISCUOUS  = 1       # promiscuous mode?
READ_TIMEOUT = 100     # in milliseconds
PCAP_FILTER  = ''      # empty => get everything (or we could use a BPF filter)
MAX_PKTS     = -1      # number of packets to capture; -1 => no limit



class ScapySRProtocol(object):
    """
    This is the scapy sendrecv protocol.
    """
    min = 2
    max = 6
    def __init__(self, pkts, maxPacketSize=8192, reactor=None, filter=None,
            iface=None, nofilter=None):
        self.maxPacketSize = maxPacketSize
        if not reactor:
            from twisted.internet import reactor

        self._reactor = reactor
        if not isinstance(pkts, Gen):
            self.pkts = SetGen(pkts)

        self.outqueue = [p for p in pkts]
        self.total_count = len(self.outqueue)
        self.in_count = 0
        self.out_count = 0
        self.cthreads = 0
        self.mthreads = 80
        self.running = False
        self.done = False
        self.finished = False

        import thread
        from twisted.python import threadpool
        self.threadID = thread.get_ident
        self.threadpool = threadpool.ThreadPool(self.min, self.max)
        self.startID = self._reactor.callWhenRunning(self._start)

        def run_pcap(f):
            # the method which will be called when a packet is captured
            def ph(hdr, data):
                f(data)

            # start the packet capture
            p = open_live(DEV, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
            p.setfilter(PCAP_FILTER)
            print "Listening on %s: net=%s, mask=%s" % (DEV, p.getnet(), p.getmask())
            p.loop(MAX_PKTS, ph)

        #self.deferred = threads.deferToThreadPool(reactor, self.threadpool, run_pcap, self.pcapDataReceived)
        self.deferred = defer.Deferred()

        from scapy.all import conf
        self.supersocket = conf.L3socket(filter=filter, iface=iface, nofilter=nofilter)

    def pcapDataReceived(self, data):
        print "got %s" % data
        print "count %d" % self.in_count
        self.in_count += 1
        if self.in_count >= self.total_count and not self.finished:
            print "FINISHED!!!"
            self.finished = True
            self.deferred.callback(None)
            return

    def logPrefix(self):
        return "ScapySR"

    def _start(self):
        self.startID = None
        return self.start()

    def start(self):
        if not self.running:
            self.threadpool.start()
            self.shutdownID = self._reactor.addSystemEventTrigger(
                    'during', 'shutdown', self.finalClose)
            self.running = True

    def sendPkt(self, pkt):
        self.supersocket.send(pkt)

    def startSend(self):
        pkt = self.outqueue.pop()
        def sent(cb):
            print "Sent!"
            if self.cthreads < self.mthreads and not self.done:
                pkt = None
                try:
                    pkt = self.outqueue.pop()
                except:
                    self.done = True
                    self.deferred.callback(None)
                    print "Done!"
                    return
                d = threads.deferToThreadPool(reactor, self.threadpool,
                                    self.sendPkt, pkt)
                d.addCallback(sent)
                return d

        if self.cthreads < self.mthreads and not self.done:
            print "Sending"
            d = threads.deferToThreadPool(reactor, self.threadpool,
                                self.sendPkt, pkt)
            d.addCallback(sent)
            return d

    def finalClose(self):
        self.shutdownID = None
        self.threadpool.stop()
        self.running = False

def txsr(arg):
    tr = ScapySRProtocol(arg)
    tr.startSend()
    return tr.deferred

import time
global start_time

def finished(a):
    print "Time:", float(time.time()) - float(start_time)
    print "Finish done."
    reactor.stop()
    packets = []
    start_b = time.time()
    for x in range(1,1000):
        packets.append(IP(src='0.1.1.0', dst='127.0.0.1', ttl=20,id=RandShort())/TCP(flags='S', window=200, sport=255, dport=255))
    send(packets)
    print "Time:", float(time.time()) - float(start_b)

from scapy.all import IP, RandShort, TCP, send
packets = []
for x in range(1,1000):
    packets.append(IP(src='0.1.1.2', dst='127.0.0.1', ttl=20,id=RandShort())/TCP(flags='S', window=200, sport=255, dport=255))

#packets = IP(src='0.1.1.0', dst='127.0.0.1', ttl=(4,2000),id=RandShort())/TCP(flags='S', window=200, sport=255, dport=255 )

start_time = time.time()
d = txsr(packets)

#pkt = IP(dst='127.0.0.1', ttl=(4,25),id=RandShort())/TCP(flags=0x2)
#dst = (pkt.dst, 0)
#spkt = str(pkt)
#outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
# Do not include IP headers in the out socket.
#outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
#outs.sendto(spkt, dst)

d.addCallback(finished)
reactor.run()

