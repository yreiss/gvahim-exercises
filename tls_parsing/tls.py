#! /usr/bin/env python

import argparse
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
    fp_dict = decode_fingerprint(fp)
    print "record version: ", "0x%x" % fp_dict['record_version']
    print "client hello version: ", "0x%x" % fp_dict['ch_version']
    print "cipher suite: ", str(fp_dict['cipher_suites'] )
    print "compression methods: ", str(fp_dict['compression_methods'])


def decode_fingerprint(fp):
    fp_dict = {}
    fp_dict['cipher_suites']=[]
    fp_dict['compression_methods']=[]

    fp_dict['record_version'], fp_dict['ch_version'], fp_dict['cipher_suites_len'] = unpack('>HHH', fp[0:6])

    for i in range(6,fp_dict['cipher_suites_len']+6,2):
        fp_dict['cipher_suites'].append(unpack('>H', fp[i:i+2])[0])

    pos=fp_dict['cipher_suites_len']+6
    fp_dict['compression_method_len'] = unpack('B', fp[pos:pos+1])[0]
    pos+=1
    for pos in range(pos,pos+fp_dict['compression_method_len']):
        fp_dict['compression_methods'].append(unpack('B', fp[pos:pos+1])[0])
    pos += 1

    
    
    return fp_dict

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


def parse_args():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("pcaps", metavar='P', nargs='+', help="pcap(s) to parse")
    argument_parser.add_argument("-d,", "--display-client-hello", dest='disp', action='store_true', help="display content of client hello") 
    argument_parser.set_defaults(disp=False)

    return argument_parser.parse_args()

def main():
    args = parse_args()
    for pcap in args.pcaps:
        pkts = rdpcap(pcap)
        for pkt in pkts:
            if 'TLSClientHello' in pkt and 'TLSClientHello' in pkt.records[0]:
                fp = create_fingerprint(pkt.records[0])
                #        print_hexview(fp)
                print pkt.time, ", ", pkt[IP].src, ", ", pkt[IP].dst, ", ", md5_fingerprint(fp)
                if args.disp:
                    prety_print_fingerprint(fp)

if __name__ == "__main__":
    main()





