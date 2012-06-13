# -*- coding:utf8 -*-
"""
    txscapy
    ******
    (c) 2012 Arturo Filastò
    a twisted wrapper for scapys send and receive functions.

    This software has been written to be part of OONI, the Open Observatory of
    Network Interference. More information on that here: http://ooni.nu/

"""

import struct
import socket
import os
import sys

from twisted.internet import protocol, base, fdesc, error, defer
from twisted.internet import reactor, threads
from twisted.pair import raw, ip
from twisted.python import log
from zope.interface import implements

from scapy.all import Gen
from scapy.all import SetGen

LINUX=sys.platform.startswith("linux")
OPENBSD=sys.platform.startswith("openbsd")
FREEBSD=sys.platform.startswith("freebsd")
NETBSD=sys.platform.startswith("netbsd")
DARWIN=sys.platform.startswith("darwin")
SOLARIS=sys.platform.startswith("sunos")
WINDOWS=sys.platform.startswith("win32")

class ScapySocket(object):
    MTU = 1500
    def __init__(self, filter=None, iface=None, nofilter=None):
        from scapy.all import conf
        self.ssocket = conf.L3socket(filter=filter, iface=iface, nofilter=nofilter)

    def fileno(self):
        return self.ssocket.ins.fileno()

    def send(self, data):
        return self.ssocket.send(data)

    def recv(self):
        if FREEBSD or DARWIN:
            return self.ssocket.nonblock_recv()
        else:
            return self.ssocket.recv(self.MTU)

class Scapy(object):
    """
    A twisted based wrapper for scapy send and receive functionality.

    It sends packets inside of a threadpool and receives packets using the
    libdnet receive non blocking file descriptor.
    """
    min = 2
    max = 6
    debug = True

    def __init__(self, pkts=None, maxPacketSize=8192, reactor=None, filter=None,
            iface=None, nofilter=None):

        if self.debug:
            log.startLogging(sys.stdout)

        self.maxPacketSize = maxPacketSize
        if not reactor:
            from twisted.internet import reactor

        self._reactor = reactor

        if pkts:
            self._buildPacketQueues(pkts)
            self._buildSocket()

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

        self.deferred = defer.Deferred()
        self.recv = False

    def _buildSocket(self, filter=None, iface=None, nofilter=None):
        self.socket = ScapySocket(filter, iface, nofilter)
        if self.recv:
            self._reactor.addReader(self)

    def _buildPacketQueues(self, pkts):
        """
        Converts the list of packets to a Scapy generator and sets up all the
        necessary attributes for understanding if all the needed responses have
        been received.
        """
        if not isinstance(pkts, Gen):
            self.pkts = SetGen(pkts)

        self.outqueue = [p for p in pkts]

        self.total_count = len(self.outqueue)
        self.answer_count = 0
        self.out_count = 0

        self.hsent = {}
        for p in self.outqueue:
            h = p.hashret()
            if h in self.hsent:
                self.hsent[h].append(p)
            else:
                self.hsent[h] = [p]


    def gotAnswer(self, answer, question):
        """
        Got a packet that has been identified as an answer to one of the sent
        out packets.

        If the answer count matches the sent count the finish callback is
        fired.

        @param answer: the packet received on the wire.

        @param question: the sent packet that matches that response.

        """
        self.answer_count += 1
        if self.answer_count >= self.total_count:
            print "Got all the answers I need"
            self.deferred.callback(None)

    def processAnswer(self, pkt, hlst):
        """
        Checks if the potential answer is in fact an answer to one of the
        matched sent packets. Uses the scapy .answers() function to verify
        this.

        @param pkt: The packet to be tested if is the answer to a sent packet.

        @param hlst: a list of packets that match the hash for an answer to
                     pkt.
        """
        for i in range(len(hlst)):
            if pkt.answers(hlst[i]):
                self.gotAnswer(pkt, hlst[i])

    def fileno(self):
        """
        Returns a fileno for use by twisteds Reader.
        """
        return self.socket.fileno()

    def processPacket(self, pkt):
        """
        Override this method to process your packets.

        @param pkt: the packet that has been received.
        """
        #pkt.show()


    def doRead(self):
        """
        There is something to be read on the wire. Do all the processing on the
        received packet.
        """
        pkt = self.socket.recv()
        self.processPacket(pkt)

        h = pkt.hashret()
        if h in self.hsent:
            hlst = self.hsent[h]
            self.processAnswer(pkt, hlst)

    def logPrefix(self):
        """
        The prefix to be prepended in logging.
        """
        return "txScapy"

    def _start(self):
        """
        Start the twisted thread pool.
        """
        self.startID = None
        return self.start()

    def start(self):
        """
        Actually start the thread pool.
        """
        if not self.running:
            self.threadpool.start()
            self.shutdownID = self._reactor.addSystemEventTrigger(
                    'during', 'shutdown', self.finalClose)
            self.running = True

    def sendPkt(self, pkt):
        """
        Send a packet to the wire.

        @param pkt: The packet to be sent.
        """
        self.socket.send(pkt)

    def sr(self, pkts, filter=None, iface=None, nofilter=0):
        """
        Wraps the scapy sr function.

        @param nofilter: put 1 to avoid use of bpf filters

        @param retry:    if positive, how many times to resend unanswered packets
                         if negative, how many times to retry when no more packets are
                         answered (XXX to be implemented)

        @param timeout:  how much time to wait after the last packet has
                         been sent (XXX to be implemented)

        @param multi:    whether to accept multiple answers for the same
                         stimulus (XXX to be implemented)

        @param filter:   provide a BPF filter
        @param iface:    listen answers only on the given interface
        """
        self.recv = True
        self._sendrcv(pkts, filter=filter, iface=iface, nofilter=nofilter)

    def send(self, pkts, filter=None, iface=None, nofilter=0):
        """
        Wraps the scapy send function. Its the same as send and receive, except
        it does not receive. Who would have ever guessed? ;)

        @param nofilter: put 1 to avoid use of bpf filters

        @param retry:    if positive, how many times to resend unanswered packets
                         if negative, how many times to retry when no more packets are
                         answered (XXX to be implemented)

        @param timeout:  how much time to wait after the last packet has
                         been sent (XXX to be implemented)

        @param multi:    whether to accept multiple answers for the same
                         stimulus (XXX to be implemented)

        @param filter:   provide a BPF filter
        @param iface:    listen answers only on the given interface
        """
        self.recv = False
        self._sendrcv(pkts, filter=filter, iface=iface, nofilter=nofilter)

    def _sendrcv(self, pkts, filter=None, iface=None, nofilter=0):
        self._buildSocket(filter, iface, nofilter)
        self._buildPacketQueues(pkts)
        def sent(cb):
            if self.cthreads < self.mthreads and not self.done:
                pkt = None
                try:
                    pkt = self.outqueue.pop()
                except:
                    self.done = True
                    if not self.recv:
                        self.deferred.callback(None)
                    return
                d = threads.deferToThreadPool(reactor, self.threadpool,
                                    self.sendPkt, pkt)
                d.addCallback(sent)
                return d

        for x in range(self.mthreads):
            try:
                pkt = self.outqueue.pop()
            except:
                self.done = True
                return
            if self.cthreads >= self.mthreads and self.done:
                return
            d = threads.deferToThreadPool(reactor, self.threadpool,
                                self.sendPkt, pkt)
            d.addCallback(sent)
            return d

    def connectionLost(self, why):
        pass

    def finalClose(self):
        """
        Clean all the thread related stuff up.
        """
        self.shutdownID = None
        self.threadpool.stop()
        self.running = False

def txsr(arg):
    tr = Scapy()
    tr.sr(arg)
    return tr.deferred

def txsend(arg):
    tr = Scapy()
    tr.send(arg)
    return tr.deferred
