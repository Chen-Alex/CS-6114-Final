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
    register<bit<32>>(65536) big_register_file;
    bit<5> reg_a;
    bit<5> reg_b;
    bit<5> reg_d;
    bit<16> imm;
    bit upper;

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
        reg_a = data[26:22];
        reg_b = data[21:17];
        reg_d = data[5:1];
        imm = data[21:6];
        upper = data[0:0];
    }
    @name("add") action add() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 + tmp2);
    }
    @name("sub") action sub() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 - tmp2);
    }
    @name("mul") action mul() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 * tmp2);
    }
    @name("lshft") action lshft() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) reg_a);
        register_file.write((bit<32>) reg_d, tmp << reg_b);
    }
    @name("rshft") action rshft() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) reg_a);
        register_file.write((bit<32>) reg_d, tmp >> reg_b);
    }
    @name("op_and") action op_and() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 & tmp2);
    }
    @name("op_or") action op_or() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 | tmp2);
    }
    @name("op_xor") action op_xor() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) reg_a);
        register_file.read(tmp2, (bit<32>) reg_b);
        register_file.write((bit<32>) reg_d, tmp1 ^ tmp2);
    }
    @name("addi") action addi() {
        extract_bits(hdr.instr[0].data); 
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) reg_a);
        register_file.write((bit<32>) reg_d, tmp + (bit<32>) imm);
    }
    @name("addi") action subi() {
        extract_bits(hdr.instr[0].data); 
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) reg_a);
        register_file.write((bit<32>) reg_d, tmp - (bit<32>) imm);
    }
    @name("addi") action muli() {
        extract_bits(hdr.instr[0].data); 
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) reg_a);
        register_file.write((bit<32>) reg_d, tmp * (bit<32>) imm);
    }
    @name("read") action read() {
        extract_bits(hdr.instr[0].data);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) reg_a);
        hdr.output.data = tmp;
    }
    @name("write") action write() {
        extract_bits(hdr.instr[0].data); 
        bit<32> data = (bit<32>) imm;
        if (upper) {
          imm <<= 16;
        }
        register_file.write((bit<32>) reg_d, data);
    }
    @name("readm") action readm() {
        extract_bits(hdr.instr[0].data);
        bit<32> data;
        big_register_file.read(data, (bit<32>) imm);
        register_file.write((bit<32>) reg_d, data);
    }
    @name("writem") action writem() {
        extract_bits(hdr.instr[0].data);
        bit<32> data;
        register_file.read(data, (bit<32>) reg_a);
        big_register_file.write((bit<32>) imm, data);
    }
    @name("noop") action noop() {
        // Do nothing, but record the fact that a noop action was triggered
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
    @name("opcode") table opcode {
      actions = {
        _drop;
        NoAction;
        add;
        sub;
        mul;
        lshft;
        rshft;
        op_and;
        op_or;
        op_xor;
        addi;
        subi;
        muli;
        read;
        write;
        readm;
        writem;
        noop; // Stronger version of noop that halts computation on this packet
      }
      key = {
        hdr.instrs[0].opcode: exact;
      }
      size = 32;
      default_action = _drop;
    }
    @name("opcode2") table opcode2 {
      actions = {
        _drop;
        NoAction;
        add;
        sub;
        mul;
        lshft;
        rshft;
        op_and;
        op_or;
        op_xor;
        addi;
        subi;
        muli;
        read;
        write;
        readm;
        writem;
        noop; // Stronger version of noop that halts computation on this packet
      }
      key = {
        hdr.instrs[0].opcode: exact;
      }
      size = 32;
      default_action = _drop;
    }
    @name("opcode3") table opcode3 {
      actions = {
        _drop;
        NoAction;
        add;
        sub;
        mul;
        lshft;
        rshft;
        op_and;
        op_or;
        op_xor;
        addi;
        subi;
        muli;
        read;
        write;
        readm;
        writem;
        noop; // Stronger version of noop that halts computation on this packet
      }
      key = {
        hdr.instrs[0].opcode: exact;
      }
      size = 32;
      default_action = _drop;
    }
    @name("opcode4") table opcode4 {
      actions = {
        _drop;
        NoAction;
        add;
        sub;
        mul;
        lshft;
        rshft;
        op_and;
        op_or;
        op_xor;
        addi;
        subi;
        muli;
        read;
        write;
        readm;
        writem;
        noop; // Stronger version of noop that halts computation on this packet
      }
      key = {
        hdr.instrs[0].opcode: exact;
      }
      size = 32;
      default_action = _drop;
    }
    @name("opcode5") table opcode5 {
      actions = {
        _drop;
        NoAction;
        add;
        sub;
        mul;
        lshft;
        rshft;
        op_and;
        op_or;
        op_xor;
        addi;
        subi;
        muli;
        read;
        write;
        readm;
        writem;
        noop; // Stronger version of noop that halts computation on this packet
      }
      key = {
        hdr.instrs[0].opcode: exact;
      }
      size = 32;
      default_action = _drop;
    }
    apply {
        if (hdr.instrs[0].isValid() && hdr.instrs[1].isValid() && hdr.instrs[2].isValid() && hdr.instrs[3].isValid() && hdr.instrs[4].isValid() &&hdr.output.isValid()) {
            if (opcode.apply().action_run != noop) {
                pop_instr();
                if (opcode2.apply().action_run != noop) {
                    pop_instr();
                    if (opcode3.apply().action_run != noop) {
                        pop_instr();
                        if (opcode4.apply().action_run != noop) {
                            pop_instr();
                            opcode5.apply();
                        }
                    }
                }
            }
        }
        if (hdr.ipv4.isValid()) {
          ipv4_lpm.apply();
          forward.apply();
        }
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
