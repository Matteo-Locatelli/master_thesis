// lin_simple.c -> simple.bpf.c from Linux examples


#include "bpf_helpers.h"
#include "stdint.h"
#include "ebpf_nethooks.h"
#include "bpf_helper_defs.h"


// Set the event
struct event {
    uint32_t pid;
    uint64_t time_stamp;
};


SEC("xdp")
int print_pid(xdp_md_t* ctx)
{
    bpf_printk("### SIMPLE EXAMPLE WORKING ###");

    uint32_t pid;
    uint64_t time_stamp;
    struct event *e;
    uint32_t number;
    
    number = bpf_get_prandom_u32();

    pid = bpf_get_current_pid_tgid() >> 32;
    time_stamp = bpf_ktime_get_boot_ns();    // from system boot
    
	bpf_printk("BPF triggered from PID %d at time %d (number = %d).\n", pid, time_stamp, number);

	return 0;
}