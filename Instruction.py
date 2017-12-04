
from scapy.all import *
from scapy.fields import *

import sys, os

TYPE_INSTR = 0x6114
TYPE_IPV4 = 0x0800

# class Wrap(FlagsField):
#     name = '5 bit field'
#     def __init__(self, name):
#         # note "a" is the least significant bit
#         FlagsField.__init__(self, name, 0, 5, ["a", "b", "c", "d","e"])
class Instr(Packet):
    name = "MyInstruction"

    fields_desc = [
        XByteField("a", 0),
        XByteField("b", 0),
        XByteField("c", 0),
        XByteField("d", 0)

    ]
    # def mysummary(self):
    #     return self.sprintf("pre=%pre%, tunnel_id=%tunnel_id%, post=%post%")
    

bind_layers(Ether, Instr, type=TYPE_INSTR)
bind_layers(Ether, IP, type=TYPE_IPV4)
# bind_layers(Instr, IP, pid=TYPE_IPV4)
