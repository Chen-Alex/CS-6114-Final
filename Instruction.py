
from scapy.all import *
from scapy.fields import *

import sys, os

TYPE_INSTR = 0x6114
TYPE_IPV4 = 0x0800

class Instr(Packet):
    name = "MyInstruction"

    fields_desc = [
        XByteField("a", 0),
        XByteField("b", 0),
        XByteField("c", 0),
        XByteField("d", 0)
    ]
    

bind_layers(Ether, Instr, type=TYPE_INSTR)
bind_layers(Ether, IP, type=TYPE_IPV4)
