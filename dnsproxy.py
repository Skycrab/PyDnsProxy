# -*- coding=utf-8 -*-
import struct
from cStringIO import StringIO
from collections import namedtuple
from gevent import socket
from gevent.server import DatagramServer

Hex = lambda x : '0x{0:04x}'.format(x) # Hex(256) => "0x0100"

QueryResult = namedtuple("DnsQuery",
                 "transactionID,flags,questions,answerRrs \
                 authorityRrs,additionalRrs,qname,qtype,qclass"
)

LOCALDNS = ("114.114.114.114",53)

Hosts = {
    "*.ttt.com":"173.194.127.144", # google ip
}

def preg_match(preg,real):
    """
    only support '*'
    >>>preg_match("www.*.test*.com","www.python.test.com")
    True
    >>>preg_match("www.*.test*.com","www.python.tes.com")
    False
    """
    pre = 0
    for s in preg.split('*'):
        now = real.find(s)
        if now < pre:
            return False
        prev = now +len(s)
    return True

def udp_send(address,data):
    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.connect(address)
    sock.send(data)
    response, address = sock.recvfrom(8192*4)
    return response,address

class DnsParser:
    
    @classmethod
    def parseQuery(self,query):
        """
               6a 02 01 00 00 01                         j.....
        00 00 00 00 00 00 03 77 77 77 03 61 61 61 03 63  .......www.aaa.c
        6f 6d 00 00 01 00 01                             om.....

        dns query package like above
        03 77 77 77 : three www

        """
        transactionID,flags,questions,answerRrs,authorityRrs,additionalRrs = map(Hex,struct.unpack("!6H",query[:12]))
        quries = StringIO(query[12:])
        c = struct.unpack("!c",quries.read(1))[0]
        domain = []
        while  c != '\x00':
            n = ord(c)
            domain.append(''.join(struct.unpack("!%sc" % n,quries.read(ord(c)))))
            c = struct.unpack("!c",quries.read(1))[0]
        domain = '.'.join(domain)
        qtype,qclass = map(Hex,struct.unpack("!2H",quries.read()))
        return QueryResult(transactionID,flags,questions,answerRrs,
                            authorityRrs,additionalRrs,domain,qtype,qclass)

    @classmethod
    def generateReqponse(self,queryData,ip):
        """
        only support ipv4
        """
        return ''.join([queryData[:2],"\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00",
          queryData[12:],"\xc0\x0c","\x00\x01","\x00\x01","\x00\x00\x00\x1e","\x00\x04",
          struct.pack('BBBB',*map(int,ip.split('.')))
          ])

class DnsServer(DatagramServer):
    def handle(self,data,address):
        query = DnsParser.parseQuery(data)
        print "get dns query from %s,query:%s" %(str(address),str(query))
        find = False
        for preg,ip in Hosts.iteritems():
            if preg_match(preg,query.qname):
                find = True
                break
        if find and query.qtype == "0x0001": #only handle A record
            print 'domain:%s in hosts' % query.qname
            response = DnsParser.generateReqponse(data,ip)
            self.socket.sendto(response,address)
        else:
            print 'transfer for %s' % query.qname
            response,serveraddress = udp_send(LOCALDNS,data)
            self.socket.sendto(response,address)


if __name__ == "__main__":
    DnsServer("192.168.9.178:53").serve_forever()
