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
    register<bit<32>>(65536) memory;
    register<bit<32>>(65536) instr_memory;
    bit<16> program_counter = 0;
    bit<16> program_length = 0;
    bit<32> current_instr;
    bit is_running = 0;

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
        meta.reg_a = data[26:22];
        meta.reg_b = data[21:17];
        meta.reg_d = data[5:1];
        meta.imm = data[21:6];
        meta.write_upper = data[0:0];
    }
    @name("add") action add() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.reg_a);
        register_file.read(tmp2, (bit<32>) meta.reg_b);
        register_file.write((bit<32>) meta.reg_d, tmp1 + tmp2);
    }
    @name("sub") action sub() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.reg_a);
        register_file.read(tmp2, (bit<32>) meta.reg_b);
        register_file.write((bit<32>) meta.reg_d, tmp1 - tmp2);
    }
    @name("mul") action mul() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.reg_a);
        register_file.read(tmp2, (bit<32>) meta.reg_b);
        register_file.write((bit<32>) meta.reg_d, tmp1 * tmp2);
    }
    @name("lshft") action lshft() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.reg_a);
        register_file.write((bit<32>) meta.reg_d, tmp << meta.reg_b);
    }
    @name("rshft") action rshft() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.reg_a);
        register_file.write((bit<32>) meta.reg_d, tmp >> meta.reg_b);
    }
    @name("op_and") action op_and() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.reg_a);
        register_file.read(tmp2, (bit<32>) meta.reg_b);
        register_file.write((bit<32>) meta.reg_d, tmp1 & tmp2);
    }
    @name("op_or") action op_or() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.reg_a);
        register_file.read(tmp2, (bit<32>) meta.reg_b);
        register_file.write((bit<32>) meta.reg_d, tmp1 | tmp2);
    }
    @name("op_xor") action op_xor() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp1;
        bit<32> tmp2;
        register_file.read(tmp1, (bit<32>) meta.reg_a);
        register_file.read(tmp2, (bit<32>) meta.reg_b);
        register_file.write((bit<32>) meta.reg_d, tmp1 ^ tmp2);
    }
    @name("addi") action addi() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.reg_a);
        register_file.write((bit<32>) meta.reg_d, tmp + (bit<32>) meta.imm);
    }
    @name("subi") action subi() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.reg_a);
        register_file.write((bit<32>) meta.reg_d, tmp - (bit<32>) meta.imm);
    }
    @name("muli") action muli() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.reg_a);
        register_file.write((bit<32>) meta.reg_d, tmp * (bit<32>) meta.imm);
    }
    @name("read") action read() {
        extract_bits(hdr.instrs[0].data);
        bit<32> tmp;
        register_file.read(tmp, (bit<32>) meta.reg_a);
        hdr.output.data = tmp;
    }
    @name("write") action write() {
        extract_bits(hdr.instrs[0].data);
        bit<32> data = (bit<32>) meta.imm;
        if (meta.write_upper == 1) {
          data = data <<16;
        }
        register_file.write((bit<32>) meta.reg_d, data);
    }
    @name("readm") action readm() {
        extract_bits(hdr.instrs[0].data);
        bit<32> data;
        big_register_file.read(data, (bit<32>) meta.imm);
        register_file.write((bit<32>) meta.reg_d, data);
    }
    @name("writem") action writem() {
        extract_bits(hdr.instrs[0].data);
        bit<32> data;
        register_file.read(data, (bit<32>) meta.reg_a);
        big_register_file.write((bit<32>) meta.imm, data);
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
        noop;
      }
      key = {
        current_instr[31:27] : exact;
      }
      size = 32;
      default_action = _drop;
    }
    apply {
        @atomic {
            if (hdr.instrs[0].isValid() && hdr.instrs[1].isValid() && hdr.instrs[2].isValid() && hdr.instrs[3].isValid() && hdr.instrs[4].isValid() && hdr.output.isValid()) {
                if (is_running) {
                    resubmit();
                }
                bit<16> start = 5 * ((bit<16>) hdr.identifier.id);
                instr_memory.write((bit<32> start), hdr.instrs[0].opcode ++ hdr.instrs[0].data);
                instr_memory.write((bit<32> start) + 1, hdr.instrs[1].opcode ++ hdr.instrs[1].data);
                instr_memory.write((bit<32> start) + 2, hdr.instrs[2].opcode ++ hdr.instrs[2].data);
                instr_memory.write((bit<32> start) + 3, hdr.instrs[3].opcode ++ hdr.instrs[3].data);
                instr_memory.write((bit<32> start) + 4, hdr.instrs[4].opcode ++ hdr.instrs[4].data);
                if (program_length < start + 4) {
                    program_length = start + 4;
                }
            }
            if (hdr.identifier.is_last == 1) {
                is_running = 1;
                instr_memory.read(current_instr, (bit<32>) program_counter);
                opcode.apply();
                program_counter = program_counter + 1;
                if (program_counter < program_length) {
                    resubmit();
                } else {
                    program_counter = 0;
                    program_length = 0;
                    is_running = 0;
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
