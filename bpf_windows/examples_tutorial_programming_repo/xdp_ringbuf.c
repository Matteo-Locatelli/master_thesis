// cdp_ringbuf.c


#include "bpf_helpers.h"
#include "stdint.h"
#include "bpf_endian.h" // correct for network byte order
#include "net\if_ether.h"
#include "..\include\packets.h"


SEC("maps")
ebpf_map_definition_in_file_t xdp_map = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = sizeof(FiveTuple) * 1024,
};


// Returns true on successful parse of an ethernet packet, else false
// If parsing was a success, all the fields of the tuple are filled.
bool parse_ethernet_packet(uint8_t* start, uint8_t* end, FiveTuple* tuple){
    bool is_parse_success = false;
    ETHERNET_HEADER* ethernet_header = (ETHERNET_HEADER*)start;

    //Bounds check on ethernet header
    if ((uint8_t*)(ethernet_header + 1) > end) {
        goto ipv4_udp_parse_done;
    }

    //Skip if packet is not ipv4
    if (!(ethernet_header->Type == bpf_ntohs(ETHERNET_TYPE_IPV4))) {
        goto ipv4_udp_parse_done;
    }

    //Move sizeof(ETHERNET_HEADER) bytes ahead to the next header
    IPV4_HEADER* ipv4_header = (IPV4_HEADER*)(ethernet_header + 1);

    //*Bounds check on ipv4 header
    if ((uint8_t*)(ipv4_header + 1) > end) {
        goto ipv4_udp_parse_done;
    }    

    tuple->proto = ipv4_header->protocol;
    tuple->src_address = ipv4_header->SourceAddress;
    tuple->dst_address = ipv4_header->DestinationAddress;

    // Skip if packet is not UDP
    if (tuple->proto == IPPROTO_UDP) {
        UDP_HEADER* udp_header = (UDP_HEADER*)(ipv4_header + 1);
        //*Bounds check on udp header
        if ((uint8_t*)(udp_header + 1) > end) {
            goto ipv4_udp_parse_done;
        }    
        tuple->src_port = udp_header->srcPort;
        tuple->dst_port = udp_header->destPort;
    }
    else {
        goto ipv4_udp_parse_done;
    }

    is_parse_success = true;
    ipv4_udp_parse_done:
    return is_parse_success;
}


SEC("xdp")
int packet_parse(xdp_md_t* ctx){
    FiveTuple tuple = {0};
    bool is_parse_success = parse_ethernet_packet(ctx->data, ctx->data_end, &tuple);
    if (!is_parse_success) {
        goto done;
    }
    bpf_ringbuf_output(&xdp_map, &tuple, sizeof(FiveTuple), 0);
    bpf_printk("Aggiunto pacchetto");

done:
      return XDP_PASS;

}