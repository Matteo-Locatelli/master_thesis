// lin_helloworld.c -> example_helloworld.bpf.c from Linux examples


#include "bpf_helpers.h"
#include "bpf_helper_defs.h"


// tracepoint/syscalls/_execve
SEC("xdp")
int bpf_prog(void *ctx) 
{
    char msg[] = "Hello, World!";

    // bpf_printk only prints numeric arguments -> minimum 0 & maximum 3 -> varargs

    bpf_printk("invoke bpf_prog: %s.\n", msg);
    
    return 0;
}