#! /usr/bin/env python

import argparse
import hashlib
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
from struct import *
from sets import Set
import json
from os import listdir
from os import path

class filter_spec():
    def __init__(self):
        self.excluded_extensions = []

    def add_excluded_extention(self, ext):
        self.excluded_extensions.append(ext)

    def is_excluded(self, ext):
        return ext in self.excluded_extensions


class client_hello():

    def __init__(self, record):
        self._record = record
        self._fp = ''   # fingerprint - a string containing the parts of the record that do not inherently change between client hellos (e.g. host)
        self._md5 = ''  # md5 hash of fingerprint
        self._descr = {} # dict describing the packet
        self._md5hasher = hashlib.md5()
        self.__prepare_record()

    # does most of the work. The rest is just getters.
    def __prepare_record(self):

        # by default, all extensions will be included by type only. excluded extensions will not be entered into the digest. explicit extensions will be entered with their data.
        excluded_extensions=[0x23, 0x15]  # 0x23 is token. 0x15 is padding
        explicit_extensions=[0xa, 0xb, 0xd]

        r = self._record
        ch=self._record[TLSClientHello]

        self._descr['session_exists'] = True if ch.session_id_length > 0 else False

        tmp = str(r)[1:3] # record version
        self._fp += tmp
        self._descr['r_version'] = unpack('>H', tmp)

        tmp = str(ch)[:2]  # client hello version
        self._fp += tmp
        self._descr['ch_version'] = unpack('>H', tmp)       

        self._fp += pack('>H', len(ch.cipher_suites)*2)
        for i in ch.cipher_suites:
            self._fp += pack('>H', i)
            
        self._descr['cipher_suites'] = ch.cipher_suites

        self._fp += pack('>B', ch.compression_methods_length)
        for i in ch.compression_methods:
            self._fp += pack('B', i)
        
        self._descr['compression_methods'] = ch.compression_methods

        self._descr['extensions'] = {}

        self._hosts=[]
        for e in ch.extensions:
            if e.type not in excluded_extensions:
                self._fp += pack('>H', e.type)
                if e.type not in explicit_extensions:
                    self._fp += pack('>H', 0)
                    self._descr['extensions'][e.type] = '...'
                else:
                    self._fp += str(e)[4:]
                    self._descr['extensions'][e.type] = get_extension_content(e)
            if e.type == 0:
                for n in e.server_names:
                    self._hosts += [n.data]


            #     if e.type == 0:  # server name. We do not want to digest the server name.
            #         self._fp += pack('L', 0)
            # elif e.type not in excluded_extensions:
            #     self._fp += str(e)

        # do not remove the server name. We can remove it later in the relevant getter.
        #self._descr['extensions'] = ch.extensions

        self._md5hasher.update(self._fp)
        self._md5 = self._md5hasher.hexdigest()    

    def get_finger_print(self):
        return self._fp
 
    def get_md5_hash(self):
        return self._md5

    # returns a json representing the record
    def get_description(self):
        return self._descr

    def get_hosts(self):
        return self._hosts

    def display(self):
        pass

    # not sure if this is required
    @staticmethod
    def parse_finger_print(self):
        pass


def get_extension_content(e):
    ret=[]
    st=str(e)[4:]
    if e.type == 0xa or e.type == 0xd:
        return [unpack('>H', st[i:i+2])[0] for i in range(0,len(st),2)]
    elif e.type == 0xb:
        return [unpack('>B', st[i:i+1])[0] for i in range(0,len(st))]
    else:
        return None
    

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



def hash_by_ip(di, src_ip, md5):
    if src_ip not in di:
        di[src_ip] =  {md5:1}
    else:
        if md5 not in di[src_ip]:
            di[src_ip][md5] = 1
        else:
            di[src_ip][md5] += 1

def hash_by_hash(di, src_ip, md5):
    if md5 not in di:        
        di[md5] = Set()
    di[md5].add(src_ip)


# def get_hosts_from_desc(desc):
#     hosts=[]
#     for e in desc['extensions']:
#         if e.type == 0:
#             for n in e.server_names:
#                 hosts += [n.data]
#             break
#     return hosts

def add_hash_description(di, md5, desc, hosts):
    if md5 not in di:
        di[md5] = desc
    if not 'hosts' in di[md5]:
        di[md5]['hosts'] = Set()

    for host in hosts:
        if (len(di[md5]['hosts']) < 200):
            di[md5]['hosts'].add(host)
        else:
            di[md5]['hosts'].add('and more...')
            break

def analyze_pcaps(pcaps, ignore_existing, hash_description, hashes_by_ip, hashes_by_hash):
    for pcap in pcaps:
        try:
            pkts = rdpcap(pcap)
        except Scapy_Exception:
            print "Error: Cannot read ", pcap
            exit(1)
        for pkt in pkts:
            if 'TLSClientHello' in pkt and 'TLSClientHello' in pkt.records[0]:
                c = client_hello(pkt.records[0])
                md5=c.get_md5_hash()
                descr=c.get_description()
                if ignore_existing and descr['session_exists']:
                    continue
                hash_by_ip(hashes_by_ip, pkt[Ether].src, md5)
                hash_by_hash(hashes_by_hash, pkt[Ether].src, md5)
                add_hash_description(hash_description, md5, descr, c.get_hosts())
                            

def parse_args():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("pcaps", metavar='P', nargs='+', help="pcap(s) to parse")
    argument_parser.add_argument("-d,", "--display-client-hello", dest='disp', action='store_true', help="display content of client hello") 
    argument_parser.add_argument("-j,", "--dump-to-json", dest='json_file', help="json file name") 
    argument_parser.add_argument("-i,", "--ignore-existing-sessions", dest='ignore_existing', action='store_true', help="ignore client hello with existing session") 
    argument_parser.add_argument("-a,", "--analyze_all", dest='analyze_all', action='store_true', help="treats the pcaps variable as a directory and analyzes all pcaps in the directory. In case of subdirs, treat every subdir as a subnet (removing the _field_try part)")
    argument_parser.set_defaults(disp=False)
    argument_parser.set_defaults(ignore_existing=False)
    argument_parser.set_defaults(analyze_all=False)

    return argument_parser.parse_args()

def main():
    args = parse_args()

    hash_description={}
    hashes_by_ip={}  # dict with source ip as key, containing for each IP a dict by hashes + their counter.
    hashes_by_hash={}  # dict by hash, containing for each hash a set of IPs on which it was seen


    if args.analyze_all:
        if (len(args.pcaps) != 1) or not os.path.isdir(args.pcaps[0]):
            raise Exception
        dirs=os.listdir(args.pcaps[0])
        for d in dirs:
            gw=d.replace('_field_trial', '').replace('_field_trail', '').replace('_field_try', '').replace('_FT_gateway', '')
            fp=os.path.join(args.pcaps[0], d)
            pcaps=[os.path.join(fp, f) for f in os.listdir(fp)]
            analyze_pcaps(pcaps, args.ignore_existing, hash_description, hashes_by_ip, hashes_by_hash)
    else:
        analyze_pcaps(args.pcaps, args.ignore_existing, hash_description, hashes_by_ip, hashes_by_hash)


    print "hashes by ip:"
    print
    for k in hashes_by_ip:
        print k, "(%d)" % len(hashes_by_ip[k]), hashes_by_ip[k]

    
    
    print 
    print
    print "hashes_by_hash:"
    print
    for k in hashes_by_hash:
        print k, hashes_by_hash[k]


    print "all hash descriptions: "
    print
    for k in hash_description:
        print k
        print "hosts: ", hash_description[k]['hosts']
        print "cipher suites: ", hash_description[k]['cipher_suites']
        print "extensions: ", 
        print hash_description[k]['extensions']
        print


    if args.disp:
        prety_print_fingerprint(fp)

if __name__ == "__main__":
    main()





