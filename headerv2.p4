#ifndef __HEADER_H__
#define __HEADER_H__ 1
#define N_INSTR 5

struct ingress_metadata_t {
    bit<32> nhop_ipv4;
    bit<5> reg_a;
    bit<5> reg_b;
    bit<5> reg_d;
    bit<16> imm;
    bit write_upper;
    bit<5> current_opcode;
}

struct intrinsic_metadata_t {
    bit<48> ingress_global_timestamp;
    bit<32> lf_field_list;
    bit<16> mcast_grp;
    bit<16> egress_rid;
    bit<8> resubmit_flag;
    bit<8> recirculate_flag;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header instr_t {
    bit<32> instr;
}

header identifier_t {
    bit<32> location;
}

header query_t {
    bit<8> is_memory;
    bit<16> index;
    bit<32> output;
    bit<8> success;
}

struct metadata {
    @name("ingress_metadata")
    ingress_metadata_t   ingress_metadata;
    @name("intrinsic_metadata")
    intrinsic_metadata_t intrinsic_metadata;
}

struct headers {
    @name("ethernet")
    ethernet_t ethernet;
    @name("instructions")
    instr_t[N_INSTR] instrs;
    @name("identifier")
    identifier_t identifier;
    @name("query")
    query_t query;
    @name("ipv4")
    ipv4_t     ipv4;
}

#endif // __HEADER_H__
