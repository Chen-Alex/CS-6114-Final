#!/usr/bin/env python
# cd Desktop/CS6114/homework03
import argparse
import sys
import socket
import random
import struct
import argparse
import time

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, hexdump
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
# from tunnel import Tunnel
from Instruction import Instr
from Query import Query

import os
import inspect

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    parser.add_argument('message', type=str, help="The message to include in packet")
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    iface = get_if()

    print "sending on interface {} to IP addr {}".format(iface, str(addr))

    dic = {'add':0,'sub':1,'mul':2,'div':3,'lshift':4,'rshift':5,'and':7,'or':8,'xor':9,'addi':10,'subi':11,
    'muli':12,'divi':13, 'read':14,'write':15,'readm':16,'writem':17,'beq':18,'bneq':19,'bgt':20,'bgeq':21,'jump':22,'noop':31}

    # This will put the sum of the numbers 1 to 100 in r3
    h = ["write 100 r2 0", "addi r1 1 r1", "add r1 r3 r3", "bgt r2 1 r1"]
    g= []
    count = 0
    while len(h) >=5:
        g.append(h[0:5])
        h = h[5:]
    if len(h) > 0:
        i = 5-len(h)
        t = h
        for j in range(i):
            t.append('noop')
        g.append(t)
    for f in g:
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        for line in f:
            words = line.split(" ")
            words = [word.strip() for word in words]
            opcode = dic[words[0]]

            if opcode == 31:
                pkt = pkt / Instr(a=248)
            # for non immediate operation
            elif opcode < 10:
                s = ''
                s += "{0:05b}".format(opcode)
                r1 = (int) (words[1][1:])
                s += "{0:05b}".format(r1)
                r2 = (int) (words[2][1:])
                s += "{0:05b}".format(r2)
                s += '0'*11
                rd = (int) (words[3][1:])
                s += "{0:05b}".format(rd)
                s += "0"
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))
            elif (opcode >= 10 and opcode <14) or (opcode >= 18 and opcode <= 22):
                s = ''
                s += "{0:05b}".format(opcode)
                r1 = (int) (words[1][1:])
                s += "{0:05b}".format(r1)
                imm = (int) (words[2])
                s += "{0:016b}".format(imm)
                rd = (int) (words[3][1:])
                s += "{0:05b}".format(rd)
                s += "0"
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))
            elif opcode == 14: # read from register
                s = "{0:05b}".format(opcode)
                r1 = (int) (words[1][1:])
                s += "{0:05b}".format(r1)
                s += '0'*22
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))
            elif opcode == 15: #write to register
                s = "{0:05b}".format(opcode)
                s += '0'*5
                imm = (int) (words[1])
                s += "{0:016b}".format(imm)
                rd = (int) (words[2][1:])
                s += "{0:05b}".format(rd)
                flag = words[3]
                s += words[3]
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))
            elif opcode == 16: # load from memeory to register
                s = "{0:05b}".format(opcode)
                s += '0'*5
                imm = (int) (words[1])
                s += "{0:016b}".format(imm)
                rd = (int) (words[2][1:])
                s += "{0:05b}".format(rd)
                s += '0'
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))
            elif opcode == 17: # write from register to memeory
                s = "{0:05b}".format(opcode)
                r1 = (int) (words[1][1:])
                s += "{0:05b}".format(r1)
                imm = (int) (words[2])
                s += "{0:016b}".format(imm)
                s += '0'*6
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))

        # the below Instr header is for output header
        pkt = pkt / Instr(d=count)/IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message
        count += 1
        sendp(pkt, iface=iface, verbose=False)
        # sendp(pkt2, iface=iface, verbose=False)
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x6666)
    sendp(pkt, iface=iface, verbose=False)
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x6115)
    pkt = pkt / Query(is_memory = 0, index1 = 0, index2 = 3) / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message
    time.sleep(1)
    sendp(pkt, iface=iface, verbose=False)



if __name__ == '__main__':
    main()
