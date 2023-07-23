// lin_ring_buf_use.c -> example_with_ring_buf.bpf.c from Linux examples


#include "stdint.h"
#include "bpf_helpers.h"
#include "bpf_helper_defs.h"
#include "ebpf_structs.h"
#include "bpf_helpers_platform.h"
#include "libbpf\src\bpf_helper_defs.h"
#include "libbpf\src\bpf_helpers.h"


// Set the event
struct event {
    uint32_t pid;
    uint64_t time_stamp;
};

// Definition of global maps for kernel and user space
SEC("maps")
ebpf_map_definition_in_file_t ring_buf = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = sizeof(struct event) * 1024,
};


// In ring buffer: before reserve the space -> then set the event -> then submit
static void ring_buf_use(struct event* e, uint32_t pid, uint64_t time_stamp) 
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

    bpf_printk("Query the ring buffer.");

    bpf_printk("Avaiable data: %d.", bpf_ringbuf_query(&ring_buf, BPF_RB_AVAIL_DATA));
    bpf_printk("Ring buffer size: %d.", bpf_ringbuf_query(&ring_buf, BPF_RB_RING_SIZE));
    bpf_printk("Consumer position: %d.", bpf_ringbuf_query(&ring_buf, BPF_RB_CONS_POS));
    bpf_printk("Producer position: %d.", bpf_ringbuf_query(&ring_buf, BPF_RB_PROD_POS));

    bpf_printk("### END RING BUFFER ###\n\n");
}


SEC("xdp")
int print_pid_ring_buf(xdp_md_t* ctx)
{
    uint32_t pid;
    uint64_t time_stamp;
    struct event *e;
    
    pid = bpf_get_current_pid_tgid() >> 32;
    time_stamp = bpf_ktime_get_ns();    // from system boot

	bpf_printk("BPF triggered from PID %d at time %ld.\n", pid, time_stamp);

    ring_buf_use(e, pid, time_stamp);

	return 0;
}
