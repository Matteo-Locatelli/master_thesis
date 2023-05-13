
// example_simple.bpf.c


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// Set the license of the code
char LICENSE[] SEC("license") = "Dual BSD/GPL";


// Set the event
struct event {
    pid_t pid;
    u64 time_stamp;
};


// Set a random number to print
int number = 0;


SEC("kprobe/tcp_v4_connect")
int print_pid(tcp_v4_connect)
{
    bpf_printk("### SIMPLE EXAMPLE WORKING ###");

    pid_t pid;
    u64 time_stamp;
    struct event *e;
    
    pid = bpf_get_current_pid_tgid() >> 32;
    time_stamp = bpf_ktime_get_ns();    // from system boot

	bpf_printk("BPF triggered from PID %d at time %d (number = %d).\n", pid, time_stamp, number);

    number ++;

/*  ERROR  
    e->pid = pid;
    e->time_stamp = time_stamp;
*/

	return 0;
}