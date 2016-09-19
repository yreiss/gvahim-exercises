#! /usr/bin/env python

import hashlib
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
from struct import *


class filter_spec():
    def __init__(self):
        self.excluded_extensions = []

    def add_excluded_extention(self, ext):
        self.excluded_extensions.append(ext)

    def is_excluded(self, ext):
        return ext in self.excluded_extensions


def print_hexview(_str):
    print(":".join("{:02x}".format(ord(c)) for c in _str))


def prety_print_fingerprint(fp):
    
    pass

def md5_fingerprint(fp):
    m = hashlib.md5()
    m.update(fp)
    return m.hexdigest()    


def create_fingerprint(record, filter_spec=None):
    ''' receives a client_hello string
    '''

    excluded_extensions=[0x23, 0x15]  # 0x23 is token. 0x15 is padding

    ch=record[TLSClientHello]

    fp=''
    fp += str(record)[1:3]  # record version position
    fp += str(ch)[:2]  # client hello version
    fp += pack('>H', len(ch.cipher_suites)*2)
    for i in ch.cipher_suites:
        fp += pack('>H', i)

    fp += pack('>B', ch.compression_methods_length)
    for i in ch.compression_methods:
        fp += pack('B', i)

    for e in ch.extensions:
        if e.type == 0:  # server name. We do not want to digest the server name.
            fp += pack('L', 0)
        elif e.type not in excluded_extensions:
            fp += str(e)
        
    return fp
    
pkts = rdpcap("stuff.pcap")
for pkt in pkts:
    if 'TLSClientHello' in pkt and 'TLSClientHello' in pkt.records[0]:
        fp = create_fingerprint(pkt.records[0])
#        print_hexview(fp)
        print md5_fingerprint(fp)




