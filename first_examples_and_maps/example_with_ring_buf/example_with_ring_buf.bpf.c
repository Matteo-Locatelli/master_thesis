
// example_with_ring_buf.bpf.c

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

// Definition of global maps for kernel and user space
struct {
    __uint(max_entries, 256 * 1024);    // 256 kb
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} ring_buf SEC(".maps");


// In ring buffer: before reserve the space -> then set the event -> then submit
void ring_buf_use(struct event* e, pid_t pid, u64 time_stamp) 
{ 
    bpf_printk("### BEGIN RING BUFFER ###");

    // Reserve a spot in the ringbuffer for the event
    e = bpf_ringbuf_reserve(&ring_buf, sizeof(*e), 0);
    if (!e) {
        bpf_printk("Unable to reserve space to ring buffer.\n");
        return;
    } else {
        bpf_printk("Reserved space for event in ring buffer.");
    }

    // Set the event
    e->pid = pid;
    e->time_stamp = time_stamp;

    bpf_printk("Update fields in event.");

    // Submit the event
    bpf_ringbuf_submit(e, 0);

    bpf_printk("Submitted event in ring buffer.");

    bpf_printk("### END RING BUFFER ###\n\n");
}


SEC("kprobe/tcp_v4_connect")
int print_pid_ring_buf(tcp_v4_connect)
{
    pid_t pid;
    u64 time_stamp;
    struct event *e;
    
    pid = bpf_get_current_pid_tgid() >> 32;
    time_stamp = bpf_ktime_get_ns();    // from system boot

	bpf_printk("BPF triggered from PID %d at time %d.\n", pid, time_stamp);

    ring_buf_use(e, pid, time_stamp);

	return 0;
}
