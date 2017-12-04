#include <core.p4>
#include <v1model.p4>

#include "header.p4"
#include "parser.p4"

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("_drop") action _drop() {
        mark_to_drop();
    }
    @name("send_frame") table send_frame {
        actions = {
            rewrite_mac;
            _drop;
            NoAction;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
        default_action = NoAction();
    }
    apply {
        if (hdr.ipv4.isValid()) {
          send_frame.apply();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    
    register<bit<32>>(32) register_file;
    bit<5> reg_a;
    bit<5> reg_b;
    bit<5> reg_d;
    bit<16> imm;
    
    @name("_drop") action _drop() {
        mark_to_drop();
    }
    @name("set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.ingress_metadata.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
    @name("set_dmac") action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    @name("extract_bits") action extract_bits(bit<27> data) {
        reg_a = data[0:4];
        reg_b = data[5:9];
        reg_d = data[21:25];
        imm = data[5:20];
    }
    @name("add") action add() {
        extract_bits(hdr.instrs[0]);
        bit<32> tmp1;
        bit<32> tmp2; 
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 + tmp2);
    }
    @name("sub") action sub() {
        extract_bits(hdr.instrs[0]);
        bit<32> tmp1;
        bit<32> tmp2; 
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 - tmp2);
    }
    @name("mul") action mul() {
        extract_bits(hdr.instrs[0]);
        bit<32> tmp1;
        bit<32> tmp2; 
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 * tmp2);
    }
    @name("lshft") action lshft() {
        extract_bits(hdr.instrs[0]);
        bit<32> tmp; 
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.write((bit<32>) reg_d, tmp1 << reg_b);
    }
    @name("rshft") action shft() {
        extract_bits(hdr.instrs[0]);
        bit<32> tmp; 
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.write((bit<32>) reg_d, tmp1 >> reg_b);
    }
    @name("op_and") action op_and() {
        extract_bits(hdr.instrs[0]);
        bit<32> tmp1;
        bit<32> tmp2; 
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 & tmp2);
    }
    @name("op_or") action op_or() {
        extract_bits(hdr.instrs[0]);
        bit<32> tmp1;
        bit<32> tmp2; 
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 | tmp2);
    }
    @name("op_xor") action op_xor() {
        extract_bits(hdr.instrs[0]);
        bit<32> tmp1;
        bit<32> tmp2; 
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 ^ tmp2);
    }
    @name("pop_instr") action pop_instr() {
        hdr.instrs.pop_front(1);
    }
    @name("ipv4_lpm") table ipv4_lpm {
        actions = {
            _drop;
            set_nhop;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
        default_action = NoAction();
    }
    @name("forward") table forward {
        actions = {
            set_dmac;
            _drop;
            NoAction;
        }
        key = {
            meta.ingress_metadata.nhop_ipv4: exact;
        }
        size = 512;
        default_action = NoAction();
    }
    apply {
        if (hdr.ipv4.isValid()) {
          ipv4_lpm.apply();
          forward.apply();
        }
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
