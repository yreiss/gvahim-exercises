#! /usr/bin/env python

import sys
import argparse
from scapy.all import *
from struct import *
from scapy.utils import PcapWriter

# not used but left here for debug aid
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
# returns an array of tuples of (name, qtype, qclass) and the new position
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
   
    
    for i in range (0,rnum):
        data=''
        name,pos=read_name(dns_pkt, pos)
        (tp,cl,ttl,dlen)=unpack('>HHLH', dns_pkt[pos:pos+10])
        pos += 10
        if tp == 1:
            for i in range(0,4):
                b=unpack('B', dns_pkt[pos+i:pos+i+1])[0]
                data += str(b) #str(unpack('B', dns_pkt[pos+i:pos+i+1])[0] + ord('0'))
                data += '.' if i < 3 else ''
            pos += 4
        elif tp == 5:
            data, pos =read_name(dns_pkt, pos)
        else:
            pos += dlen

        if tp == 1 or tp == 5:
            rrs.append((name, tp, cl, ttl, data))

    return rrs

def pretty_records(li):
    for i in li:
        print "    Name: ", i[0]
        print "    Type: ", i[1]
        print "    Class: ", i[2]
        print "    Time to live: ", i[3]
        print "    Address: ", i[4]
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
    print
    for i in dns_dict['Queries']:
        print "    Name: ", i[0]
        print "    Type: ", i[1]
        print "    Class: ", i[2]
        print
    print "Answers:"
    print
    pretty_records(dns_dict['Answers'])
         
    print "===== end display DNS packet 0x%x =====" % dns_dict['tid']
    print
    print

def read_dns_packet(raw_pkt, pkt, domain=None):
    dns_dict = {}
    d=dns_dict
    
    (d['tid'],d['flags'],d['q_num'],d['ans_num'], d['auth_num'],d['add_num'])=unpack('>HHHHHH', raw_pkt[:12])
    d['Queries'], pos = read_questions(raw_pkt, 12, d['q_num'])
    d['Answers'] = read_rrs(raw_pkt, pos, d['ans_num'])
    d['packet'] = pkt

    return d if not domain or domain == dns_dict['Queries'][0][0] else None


def parse_args():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("pcap", help="pcap to parse")
    argument_parser.add_argument("--domain", help="specify single domain") 
    argument_parser.add_argument("--action", default='display', choices=['display', 'filter'], help="define the action - either display DNS entries, or filter by specific domain. Defaults to display") 

    return argument_parser.parse_args()

def main():
    args = parse_args()

    all_packet_dic = []

    pkts = rdpcap(args.pcap)           
    for pkt in pkts:
        if 'DNS' in pkt:
            raw=str(pkt['DNS'])
            d=read_dns_packet(raw, pkt, args.domain)
            if d:
                all_packet_dic.append(d)

    if args.action == 'display':
        for p in all_packet_dic:
            pretty_print(p)
    else:
        n=args.pcap
        ind=n.rfind('.')
        new_pcap = n[:ind] + '.' + args.domain + '.' + n[ind+1:]
        pktdump = PcapWriter(new_pcap, append=True, sync=True)
        addresses=[]
        for p in all_packet_dic:
            pktdump.write(p['packet'])
            if p['Answers']:
                for a in p['Answers']:
                    if a[1] == 1:
                        addresses.append(a[4])
        for pkt in pkts:
            try:           
                if 'IP' in pkt and pkt[IP].src in addresses or pkt[IP].dst in addresses:
                    pktdump.write(pkt)
            except:
                IndexError

                


if __name__ == '__main__':
    sys.exit(main())

