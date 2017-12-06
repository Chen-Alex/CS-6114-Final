parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            16w0x6114: parse_instrs;
            16w0x6115: parse_query;
            default: accept;
        }
    }
    @name("parse_instrs") state parse_instrs {
        packet.extract(hdr.instrs.next);
        packet.extract(hdr.instrs.next);
        packet.extract(hdr.instrs.next);
        packet.extract(hdr.instrs.next);
        packet.extract(hdr.instrs.next);
        transition parse_identifier;
    }
    @name("parse_query") state parse_query {
        packet.extract(hdr.query);
        transition parse_ipv4;
    }
    @name("parse_identifier") state parse_identifier {
        packet.extract(hdr.identifier);
        transition parse_ipv4;
    }
    @name("parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
    @name("start") state start {
        transition parse_ethernet;
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.instrs);
        packet.emit(hdr.identifier);
	packet.emit(hdr.query);
        packet.emit(hdr.ipv4);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
                hdr.ipv4.isValid(),
                { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.totalLen, hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
                hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16);
    }
}
