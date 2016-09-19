#! /usr/bin/env python

import sys
import optparse
import socket
import select
import errno
import pytun
from scapy.all import *
import time
from struct import *

def hexprint(str):
    print(":".join("{:02x}".format(ord(c)) for c in str))


    

def read_name(dns_pkt, pos):    
    name=''
    pointed=False
    end_pos=pos

    while True:
        b=unpack('B', dns_pkt[pos:pos+1])[0]
        if not b:
            pos += 1
            break
    
   
        if (b & 0xc0) == 0xc0: # pointer
            h=unpack('>H', dns_pkt[pos:pos+2])[0]
            if not pointed:
                end_pos = pos + 2
            pointed=True           
            pos = h & 0x3FFF
            continue
        else:
            if name:  # not first label. add a '.'
                name+='.'
            pos += 1

        name += dns_pkt[pos:pos+b]
        pos += b

    if not pointed:
        end_pos=pos

    return name,end_pos




# receive a pointer to the question section (RFC1035 section 4.1.2) and the number of questions
# returns an array of tuples of (name, qtype, qclass)
def read_questions(dns_pkt, pos, qnum):
    questions=[]
    for i in range (0,qnum):
        qsection=dns_pkt[pos:]
        name, pos=read_name(dns_pkt, pos)
        questions.append((name, 
                          unpack('>H', dns_pkt[pos:pos+2])[0], 
                          unpack('>H', dns_pkt[pos+2:pos+4])[0]))
        pos += 4
        i += 1

    return questions, pos

    
def read_rrs(dns_pkt, pos, rnum):
    rrs=[]
    addr_types=[1]
    data=''
    
    
    for i in range (0,rnum):
        name,pos=read_name(dns_pkt, pos)
        (tp,cl,ttl,dlen)=unpack('>HHLH', dns_pkt[pos:pos+10])
        pos += 10
        if tp in addr_types:
            for i in range(0,4):
                b=unpack('B', dns_pkt[pos+i:pos+i+1])[0]
                data += str(b) #str(unpack('B', dns_pkt[pos+i:pos+i+1])[0] + ord('0'))
                data += '.' if i < 3 else ''
            pos += 4
        else:
            data, pos =read_name(dns_pkt, pos)

        rrs.append((name, tp, cl, ttl, data))

    return rrs

def pretty_records(li):
    for i in li:
        print "\tName: ", i[0]
        print "\tType: ", i[1]
        print "\tClass: ", i[2]
        print "\tTime to live: ", i[3]
        print "\tAddress: ", i[4]
        print

def pretty_print(dns_dict):
    print "===== begin display DNS packet 0x%x =====" % dns_dict['tid']
    #print "Transaction ID: ", "0x%x" % dns_dict['tid']
    print
    print "Flags: ", "0x%x" % dns_dict['flags']
    print "Questions: ", "%d" % dns_dict['q_num']
    print "Answer RRs: ", "%d" % dns_dict['ans_num']
    print "Authority RRs: ", "%d" % dns_dict['auth_num'] 
    print "Additional RRs: ", "%d" % dns_dict['add_num']   
    print
    print "Queries:"
    for i in dns_dict['Queries']:
        print "\tName: ", i[0]
        print "\tType: ", i[1]
        print "\tClass: ", i[2]
        print
    print "Answers:"
    pretty_records(dns_dict['Answers'])
          
    print "===== end display DNS packet 0x%x =====" % dns_dict['tid']
    print
    print

def read_dns_packet(dns_pkt):
    dns_dict = {}
    d=dns_dict
    
    # hexprint(str(dns_pkt))

    (d['tid'],d['flags'],d['q_num'],d['ans_num'], d['auth_num'],d['add_num'])=unpack('>HHHHHH', dns_pkt[:12])
    d['Queries'], pos = read_questions(dns_pkt, 12, d['q_num'])
    d['Answers'] = read_rrs(dns_pkt, pos, d['ans_num'])
    #d['Auth'] = read_rrs(dns_pkt, pos, d['auth_num'])
    #d['Add'] = read_rrs(dns_pkt, pos, d['add_num'])

    pretty_print(dns_dict)

            
def main():
    parser = optparse.OptionParser()
    parser.add_option('--pcap', dest='pcap', help='name of pcap file')

    opt, args = parser.parse_args()
    pkts = rdpcap(opt.pcap)
    for pkt in pkts:
        if 'DNS' in pkt:
            raw=str(pkt['DNS'])
            read_dns_packet(raw)


if __name__ == '__main__':
    sys.exit(main())

