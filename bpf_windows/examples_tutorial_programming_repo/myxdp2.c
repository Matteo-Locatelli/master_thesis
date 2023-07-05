// myxdp2.c


#include "bpf_helpers.h"
#include "stdint.h"
#include "bpf_endian.h" // correct for network byte order
#include "net\if_ether.h"


SEC("xdp")         
int32_t packet_parse(xdp_md_t *ctx) {

    uint8_t* data = ctx->data;
    uint8_t* data_end = ctx->data_end;

    ETHERNET_HEADER *eth_hdr =(ETHERNET_HEADER*)data;
    
    //* Bounds check on the ethernet header
    if ((uint8_t*)(eth_hdr + 1) > data_end) {
        goto done;
    }            
    
    // NOTE: above check same as (uint_8*)eth_hdr + sizeof(ETHERNET_HEADER) > data_end

    bpf_printk("Ciao! %x", bpf_ntohs(eth_hdr->Type));

done: 
      return XDP_DROP;
}