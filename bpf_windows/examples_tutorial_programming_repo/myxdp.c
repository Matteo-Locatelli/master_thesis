//myxdp.c


#include "bpf_helpers.h"
#include "stdint.h"


SEC("xdp")
int32_t our_program() {
    return 2;
}