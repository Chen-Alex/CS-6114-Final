#include <core.p4>
#include <v1model.p4>

#include "headerv2.p4"
#include "parserv2.p4"

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
    register<bit<32>>(65536) memory;
    register<bit<32>>(65536) instr_memory;
    register<bit<16>>(1) program_counter;
    register<bit<16>>(1) program_length;
    register<bit>(1) is_running;
    bit<32> current_instr;

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
    @name("extract_bits") action extract_bits(bit<32> instr) {
        meta.ingress_metadata.reg_a = instr[26:22];
        meta.ingress_metadata.reg_b = instr[21:17];
        meta.ingress_metadata.reg_d = instr[5:1];
        meta.ingress_metadata.imm = instr[21:6];
        meta.ingress_metadata.write_upper = instr[0:0];
    }
    @name("add") action add() {
        extract_bits(current_instr);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.read(tmp2, (bit<32>) meta.ingress_metadata.reg_b);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp1 + tmp2);
    }
    @name("sub") action sub() {
        extract_bits(current_instr);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.read(tmp2, (bit<32>) meta.ingress_metadata.reg_b);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp1 - tmp2);
    }
    @name("mul") action mul() {
        extract_bits(current_instr);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.read(tmp2, (bit<32>) meta.ingress_metadata.reg_b);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp1 * tmp2);
    }
    @name("lshft") action lshft() {
        extract_bits(current_instr);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp << meta.ingress_metadata.reg_b);
    }
    @name("rshft") action rshft() {
        extract_bits(current_instr);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp >> meta.ingress_metadata.reg_b);
    }
    @name("op_and") action op_and() {
        extract_bits(current_instr);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.read(tmp2, (bit<32>) meta.ingress_metadata.reg_b);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp1 & tmp2);
    }
    @name("op_or") action op_or() {
        extract_bits(current_instr);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.read(tmp2, (bit<32>) meta.ingress_metadata.reg_b);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp1 | tmp2);
    }
    @name("op_xor") action op_xor() {
        extract_bits(current_instr);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.read(tmp2, (bit<32>) meta.ingress_metadata.reg_b);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp1 ^ tmp2);
    }
    @name("addi") action addi() {
        extract_bits(current_instr);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp + (bit<32>) meta.ingress_metadata.imm);
    }
    @name("subi") action subi() {
        extract_bits(current_instr);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp - (bit<32>) meta.ingress_metadata.imm);
    }
    @name("muli") action muli() {
        extract_bits(current_instr);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, tmp * (bit<32>) meta.ingress_metadata.imm);
    }
    @name("write") action write() {
        extract_bits(current_instr);
        bit<32> data = (bit<32>) meta.ingress_metadata.imm;
        if (meta.ingress_metadata.write_upper == 1) {
          data = data <<16;
        }
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, data);
    }
    @name("readm") action readm() {
        extract_bits(current_instr);
        bit<32> data;
        memory.read(data, (bit<32>) meta.ingress_metadata.imm);
        register_file.write((bit<32>) meta.ingress_metadata.reg_d, data);
    }
    @name("writem") action writem() {
        extract_bits(current_instr);
        bit<32> data;
        register_file.read(data, (bit<32>) meta.ingress_metadata.reg_a);
        memory.write((bit<32>) meta.ingress_metadata.imm, data);
    }
    @name("beq") action beq() {
        extract_bits(current_instr);
        bit<32> tmp1;
        bit<32> tmp2;
        bit<16> tgt;
        register_file.read(tmp1, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.read(tmp2, (bit<32>) meta.ingress_metadata.reg_d);
        program_counter.read(tgt, 0);
        if (tmp1 == tmp2) {
            tgt = meta.ingress_metadata.imm - 1;
        } 
        program_counter.write(0, tgt);
    }
    @name("bneq") action bneq() {
        extract_bits(current_instr);
        bit<32> tmp1;
        bit<32> tmp2;
        bit<16> tgt;
        register_file.read(tmp1, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.read(tmp2, (bit<32>) meta.ingress_metadata.reg_d);
        program_counter.read(tgt, 0);
        if (tmp1 != tmp2) {
            tgt = meta.ingress_metadata.imm - 1;
        } 
        program_counter.write(0, tgt);
    }
    @name("bgt") action bgt() {
        extract_bits(current_instr);
        bit<32> tmp1;
        bit<32> tmp2;
        bit<16> tgt;
        register_file.read(tmp1, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.read(tmp2, (bit<32>) meta.ingress_metadata.reg_d);
        program_counter.read(tgt, 0);
        if (tmp1 > tmp2) {
            tgt = meta.ingress_metadata.imm - 1;
        } 
        program_counter.write(0, tgt);    
    }
    @name("bgeq") action bgeq() {
        extract_bits(current_instr);
        bit<32> tmp1;
        bit<32> tmp2;
        bit<16> tgt;
        register_file.read(tmp1, (bit<32>) meta.ingress_metadata.reg_a);
        register_file.read(tmp2, (bit<32>) meta.ingress_metadata.reg_d);
        program_counter.read(tgt, 0);
        if (tmp1 >= tmp2) {
            tgt = meta.ingress_metadata.imm - 1;
        } 
        program_counter.write(0, tgt);    
    }
    @name("jump") action jump() {
        extract_bits(current_instr);
        program_counter.write(0, meta.ingress_metadata.imm - 1);    
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
        write;
        readm;
        writem;
        beq;
        bneq;
        bgt;
        bgeq;
        jump;
        noop;
      }
      key = {
        meta.ingress_metadata.current_opcode : exact;
      }
      size = 32;
      default_action = _drop;
    }
    apply {
        if (hdr.instrs[0].isValid() && hdr.instrs[1].isValid() && hdr.instrs[2].isValid() && hdr.instrs[3].isValid() && hdr.instrs[4].isValid()) {
            bit ir;
            is_running.read(ir, 0);
            if (ir == 0) {
                bit<16> start = 5 * ((bit<16>) hdr.identifier.location);
                instr_memory.write((bit<32>) start, hdr.instrs[0].instr);
                instr_memory.write((bit<32>) start + 1, hdr.instrs[1].instr);
                instr_memory.write((bit<32>) start + 2, hdr.instrs[2].instr);
                instr_memory.write((bit<32>) start + 3, hdr.instrs[3].instr);
                instr_memory.write((bit<32>) start + 4, hdr.instrs[4].instr);
                bit<16> pl;
                program_length.read(pl, 0);
                if (pl < start + 4) {
                    program_length.write(0, start + 4);
                }
            }
        }
        @atomic {
            if (hdr.ethernet.etherType == 0x6666) {
                is_running.write(0, 1);
                bit<16> pc;
                bit<16> pl;
                program_counter.read(pc, 0);
                program_length.read(pl, 0);
                if (pc > pl) {
                    program_counter.write(0, 0);
                    program_length.write(0, 0);
                    is_running.write(0, 0);
                } else {
                    instr_memory.read(current_instr, (bit<32>) pc);
                    meta.ingress_metadata.current_opcode = current_instr[31:27];
                    opcode.apply();
                    program_counter.read(pc, 0);
                    program_counter.write(0, pc + 1);
                    recirculate<bit>(0);
                    resubmit<bit>(0);
                }
            }
        }
        if (hdr.query.isValid()) {
            bit ir;
            is_running.read(ir, 0);
            if (ir == 1) {
                hdr.query.success = 0;
            } else {
                hdr.query.success = 1;
                if (hdr.query.is_memory == 1) {
                    memory.read(hdr.query.output, (bit<32>) hdr.query.index);
                } else { 
                    register_file.read(hdr.query.output, (bit<32>) hdr.query.index);
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
