
from scapy.all import *
from scapy.fields import *

import sys, os

TYPE_QUERY = 0x6115
TYPE_IPV4 = 0x0800

class Query(Packet):
    name = "Query"

    fields_desc = [
        XByteField("is_memory", 0),
        XByteField("index1", 0),
        XByteField("index2", 0),
        XByteField("out1", 0),
        XByteField("out2", 0),
        XByteField("out3", 0),
        XByteField("out4", 0),
        XByteField("success", 0)
    ]
    

bind_layers(Ether, Query, type=TYPE_QUERY)
bind_layers(Ether, IP, type=TYPE_IPV4)
