#include "C:\eBPF-for-Windows.0.9.0\build\native\include\bpf_helpers.h"
#include "C:\eBPF-for-Windows.0.9.0\build\native\include\ebpf_nethooks.h"

// Put "xdp" in the section name to specify XDP as the hook.
// The SEC macro below has the same effect as the
// clang pragma used in section 2 of this tutorial.
SEC("xdp")
int my_xdp_parser(xdp_md_t* ctx)
{
    int length = (char *)ctx->data_end - (char *)ctx->data;

    if (length > 1) {
        return XDP_PASS;
    }
    return XDP_DROP;
}