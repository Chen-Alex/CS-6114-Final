
from scapy.all import *
import sys, os

TYPE_INSTR = 0x6114
TYPE_IPV4 = 0x0800

class Instr(Packet):
    name = "MyTunnel"
    fields_desc = [
        XByteField("pre", 0),
        XByteField("tunnel_id", 2),
        XByteField("post", 0),
        XByteField("post", 4)

    ]
    # def mysummary(self):
    #     return self.sprintf("pre=%pre%, tunnel_id=%tunnel_id%, post=%post%")

bind_layers(Ether, Instr, type=TYPE_INSTR)
bind_layers(Instr, IP, pid=TYPE_IPV4)
