/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

#define BLOOM_FILTER_ENTRIES 4096

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;

}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* add parser logic */
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            default: accept;
        }
    }

    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    // counter for tcp packets
    counter(3, CounterType.packets) ctr;
    
    // BLOOM_FILTER_BIT_WIDTH = 1
    register<bit<1>>(BLOOM_FILTER_ENTRIES) bloom_filter;
    
    bit<32> reg_one = 0;
    bit<1> reg_val = 0;



    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* fill out code in action body */
        standard_metadata.egress_spec = port;
        // source gets switch address 
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        // dest gets dest address
        hdr.ethernet.dstAddr = dstAddr;
        // decrement ttl
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    /*
     *   0    1      2
     * [SYN, ACK, SYN-ACK]
     *
     */
    action count_p(bit<32> i) {
        ctr.count(i);
    }

    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2){
       //Get register position
       hash(reg_one, HashAlgorithm.crc16, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        if (hdr.tcp.isValid()) {
            compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort);
          
            //    ############### ############ ###############
            //    ############### filter works ############### 

            if(hdr.tcp.syn == 1 && hdr.tcp.ack != 1) {
                count_p(0);
                //drop();
            } else if (hdr.tcp.ack == 1 && hdr.tcp.syn != 1) {
                count_p(1);
                bloom_filter.write(reg_one, 1);
                //ipv4_lpm.apply();
            } else if (hdr.tcp.ack == 1 && hdr.tcp.syn == 1) {
                count_p(3);
                //drop();
            }
            //    ############### filter works ############### 
            //    ############### ############ ###############
    
            /*
            if (hdr.tcp.ack == 1 && hdr.tcp.syn != 1) {
                count_p(1);
                bloom_filter.write(reg_one, 1);
                ipv4_lpm.apply();
            }
            else {
                bloom_filter.read(reg_val, reg_one);
                
                if(hdr.tcp.syn == 1 && hdr.tcp.ack != 1) {
                    count_p(0);
                    drop();

                }

                else if (hdr.tcp.ack == 1 && hdr.tcp.syn == 1) {
                    count_p(3);
                    drop();

                }
                
                if (reg_val == 0) {
                    drop();
                } else {
                    ipv4_lpm.apply();
                }
                
            }
            */
            if (hdr.tcp.ack == 1 && hdr.tcp.syn != 1) {
                bloom_filter.write(reg_one, 1);
            }
            else {
                bloom_filter.read(reg_val, reg_one);
                
                if (reg_val == 0) {
                    drop();
                } else {
                    ipv4_lpm.apply();
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* add deparser logic */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);

    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
