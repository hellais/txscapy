import struct
import socket
import os

from twisted.internet import protocol, base, fdesc, error, defer
from twisted.internet import reactor
from twisted.pair import raw, ip
from zope.interface import implements

from scapy.all import Gen
from scapy.all import SetGen

class ScapyProtocol(protocol.AbstractDatagramProtocol):
    implements(raw.IRawPacketProtocol)

    def datagramReceived(self, data, partial, dest,
                         source, protocol):
        print data

class ScapySRProtocol(object):
    """
    This is the scapy sendrecv protocol.
    """

    maxThroughput = 256 * 1024 # max bytes we read in one eventloop iteration

    def __init__(self, pkts, maxPacketSize=8192, reactor=None):
        self.maxPacketSize = maxPacketSize
        if not reactor:
            from twisted.internet import reactor
        if not isinstance(pkts, Gen):
            pkts = SetGen(pkts)

        self.outqueue = [p for p in pkts]
        self.total_count = len(self.outqueue)
        self.in_count = 0
        self.out_count = 0

        reactor.addWriter(self)
        reactor.addReader(self)

        self.deferred = defer.Deferred()

        self.ins = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # Do not include IP headers in the out socket.
        self.outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

        #fdesc.setNonBlocking(self.ins)
        #fdesc.setNonBlocking(self.outs)

    def logPrefix(self):
        return "ScapySR"

    def fileno(self):
        return self.outs.fileno()

    def doRead(self):
        if 1:
            return
        read = 0
        while read < self.maxThroughput:
            try:
                data = os.read(self.ins, self.maxPacketSize)
                read += len(data)
            except OSError, e:
                if e.errno in (errno.EWOULDBLOCK,):
                    return
                else:
                    raise e
            except IOError, e:
                if e.errno in (errno.EAGAIN, errno.EINTR):
                    return
                else:
                    raise e
            except:
                raise e
        print "Received %d/%d" % (self.in_count, self.total_count)
        self.in_count += 1

    def doWrite(self):
        pkt = self.outqueue.pop()

        from scapy.all import hexdump,wrpcap
        wrpcap('txscapy.pcap', [pkt])
        print hexdump(pkt)
        for p in pkt:
            self.outs.sendto(str(p), (p.dst, 0))

        self.out_count += 1

    def connectionLost(self, why):
        print why


def txsr(arg):
    tr = ScapySRProtocol(arg)
    return tr.deferred

def finished(a):
    print "Done!!"

from scapy.all import IP, RandShort, TCP
d = txsr(IP(src='0.0.0.0', dst='127.0.0.1', ttl=(4,25),id=RandShort())/TCP(flags='S', window=200, sport=255, dport=255 ))

#pkt = IP(dst='127.0.0.1', ttl=(4,25),id=RandShort())/TCP(flags=0x2)
#dst = (pkt.dst, 0)
#spkt = str(pkt)
#outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
# Do not include IP headers in the out socket.
#outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
#outs.sendto(spkt, dst)

d.addCallback(finished)
reactor.run()

