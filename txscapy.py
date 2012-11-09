import time

from twisted.internet import reactor
from twisted.internet import abstract, defer, threads

try:
    from scapy.all import conf, Gen, SetGen
except:
    print "txscapy required scapy, obviously :P"

class ScapyProtocol(abstract.FileDescriptor):
    def __init__(self, super_socket=None, 
            reactor=None, timeout=None):
        abstract.FileDescriptor.__init__(self, reactor)
        # By default we use the conf.L3socket
        if not super_socket:
            super_socket = conf.L3socket()
        self.super_socket = super_socket
        
        self.timeout = timeout

        # This dict is used to store the unique hashes that allow scapy to
        # match up request with answer
        self.hr_sent_packets = {}

        # These are the packets we have received as answer to the ones we sent
        self.answered_packets = []
        
        # These are the packets we send
        self.sent_packets = []

        # This deferred will fire when we have finished sending a receiving packets.
        self.d = defer.Deferred()
        self.debug = True
        self.multi = False

    def fileno(self):
        return self.super_socket.ins.fileno()

    def processPacket(self, packet):
        """
        Hook useful for processing packets as they come in.
        """

    def processAnswer(self, packet, answer_hr):
        for i in range(len(answer_hr)):
            if packet.answers(answer_hr[i]):
                self.answered_packets.append((answer_hr[i], packet))
                if self.debug:
                    print packet.src, packet.ttl
                    #answer.show()

                if not self.multi:
                    del(answer_hr[i])
                break
        if len(self.answered_packets) == len(self.sent_packets):
            # All of our questions have been answered.
            self.stopSending()

    def doRead(self):
        if self.timeout and time.time() - self._start_time > self.timeout:
            self.stopSending()
        packet = self.super_socket.recv()
        if packet:
            self.processPacket(packet)
            # A string that has the same value for the request than for the
            # response.
            hr = packet.hashret()
            if hr in self.hr_sent_packets:
                answer_hr = self.hr_sent_packets[hr]
                self.processAnswer(packet, answer_hr)

    def stopSending(self):
        self.stopReading()
        self.super_socket.close()
        if hasattr(self, "d"):
            result = (self.answered_packets, self.sent_packets)
            self.d.callback(result)
            del self.d

    def write(self, packet):
        """
        Write a scapy packet to the wire
        """
        hashret = packet.hashret()
        if hashret in self.hr_sent_packets:
            self.hr_sent_packets[hashret].append(packet)
        else:
            self.hr_sent_packets[hashret] = [packet]
        self.sent_packets.append(packet)
        return self.super_socket.send(packet)

    def sendPackets(self, packets):
        if not isinstance(packets, Gen):
            packets = SetGen(packets)
        for packet in packets:
            self.write(packet)

    def startSending(self, packets):
        self._start_time = time.time()
        self.startReading()
        self.sendPackets(packets)
        return self.d

def sr(x, filter=None, iface=None, nofilter=0, timeout=None):
    super_socket = conf.L3socket(filter=filter, iface=iface, nofilter=nofilter)
    sp = ScapyProtocol(super_socket=super_socket, timeout=timeout)
    return sp.startSending(x)

def send(x, filter=None, iface=None, nofilter=0, timeout=None):
    super_socket = conf.L3socket(filter=filter, iface=iface, nofilter=nofilter)
    sp = ScapyProtocol(super_socket=super_socket, timeout=timeout)
    return sp.startSending(x)

def finished(result):
    answered, unanswered = result
    for snd, rcv in answered:
        print snd.ttl, rcv.src, isinstance(rcv.payload, TCP)
    reactor.stop()

from scapy.all import *
scapyProtocol = ScapyProtocol()
target = "8.8.8.8"

packets = IP(dst=target, ttl=(0,47),id=RandShort())/TCP(flags=0x2)

d = scapyProtocol.startSending(packets)
d.addCallback(finished)
reactor.run()

