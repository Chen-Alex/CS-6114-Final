#!/usr/bin/env python
# cd Desktop/CS6114/homework03
import argparse
import sys
import socket
import random
import struct
import argparse

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, hexdump
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
# from tunnel import Tunnel
from Instruction import Instr

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
    # dir_path = os.path.dirname(os.path.realpath(__file__))
    # dir_path2 = os.path.dirname(os.path.abspath(__file__))
    # cwd = os.getcwd()
    # print dir_path2
    # print dir_path
    # print cwd
    #print os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    # os.chdir("~/Desktop/CS6114/CS-6114-Final/")
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    parser.add_argument('message', type=str, help="The message to include in packet")
    # parser.add_argument('--tunnel_id', type=int, default=None, help='The tunnel id to use, if unspecified then the tunnel header will not be included in packet')
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    # tunnel_id = args.tunnel_id
    iface = get_if()

    # if (tunnel_id is not None):
    #     print "sending on interface {} to tunnel_id {}".format(iface, str(tunnel_id))
    #     pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    #     pkt = pkt / Tunnel(tunnel_id=tunnel_id) / IP(dst=addr) / args.message
    # else:
    print "sending on interface {} to IP addr {}".format(iface, str(addr))

    # pkt = pkt / Instr()/IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message
    # pkt2 = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    # pkt2 = pkt2 /IP(dst=addr) /Instr() /TCP(dport=1234, sport=random.randint(49152,65535)) / 'I love Qiqi'
    # read the instructions file
    dic = {'add':0,'sub':1,'mul':2,'div':3,'lshift':4,'rshift':5,'and':7,'or':8,'xor':9,'addi':10,'subi':11,
    'muli':12,'divi':13, 'read':14,'write':15,'readm':16,'writem':17,'noop':31}
    # with open('instructions.txt') as f:
    # h is the total set of instructions
    # h = ['write 15 r1 0', 'write 30 r2 0',  'add r1 r2 r3', 'writem r3 1', 'readm 1 r4']
    h = ["write 1 r0 0",
    "write 2 r1 0",
    "write 3 r2 0",
    "write 4 r3 0",
    "write 5 r4 0",
    "write 6 r5 0",
    "write 7 r6 0",
    "write 8 r7 0",
    "write 9 r8 0",
    "write 10 r9 0",
    "add r0 r1 r1",
    "add r2 r3 r3",
    "add r4 r5 r5",
    "add r6 r7 r7",
    "add r8 r9 r9",
    "add r1 r3 r3",
    "add r5 r7 r7",
    "add r3 r7 r7",
    "add r7 r9 r9"]
    g= []
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
            print "opcode is " + str(opcode)

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
                print s
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))
            elif opcode >= 10 and opcode <14:
                s = ''
                s += "{0:05b}".format(opcode)
                r1 = (int) (words[1][1:])
                s += "{0:05b}".format(r1)
                imm = (int) (words[2])
                s += "{0:016b}".format(imm)
                rd = (int) (words[3][1:])
                s += "{0:05b}".format(rd)
                s += "0"
                print s
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))
            elif opcode == 14: # read from register
                s = "{0:05b}".format(opcode)
                r1 = (int) (words[1][1:])
                s += "{0:05b}".format(r1)
                s += '0'*22
                print s
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
                print s
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))
            elif opcode == 16: # load from memeory to register
                s = "{0:05b}".format(opcode)
                s += '0'*5
                imm = (int) (words[1])
                s += "{0:016b}".format(imm)
                rd = (int) (words[2][1:])
                s += "{0:05b}".format(rd)
                s += '0'
                print s
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))
            elif opcode == 17: # write from register to memeory
                s = "{0:05b}".format(opcode)
                r1 = (int) (words[1][1:])
                s += "{0:05b}".format(r1)
                imm = (int) (words[2])
                s += "{0:016b}".format(imm)
                s += '0'*6
                print s
                pkt = pkt / Instr(a=int(s[0:8],2),b=int(s[8:16],2),c=int(s[16:24],2),d=int(s[24:32],2))
        # the below Instr header is for output header
        pkt = pkt / Instr()/IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message
        pkt.show2()
        # pkt2.show2()
    #    hexdump(pkt)
    #    print "len(pkt) = ", len(pkt)
        sendp(pkt, iface=iface, verbose=False)
        # sendp(pkt2, iface=iface, verbose=False)



if __name__ == '__main__':
    main()
