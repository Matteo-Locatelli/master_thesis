#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "solo_types.h"

// 1. Change the license if necessary 
char __license[] SEC("license") = "Dual MIT/GPL";

// This struct represents the data we will gather from the tracepoint to send to our ring buffer map
// The 'bee' runner will watch for entries to our ring buffer and print them out for us
struct event {
	// In this example, we have a single field, the filename being opened
	char fname[255];
};

// This is the definition for the global map which both our
// bpf program and user space program can access.
// More info and map types can be found here: https://www.man7.org/linux/man-pages/man2/bpf.2.html
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	// Define the type of struct that will be submitted to the ringbuf
	// This allows the bee runner to dynamically read and output the data from the ringbuf
	__type(value, struct event);
} events SEC(".maps.print");

// Attach our bpf program to the tracepoint for the openat() syscall
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
	// initialize the event struct which we will send the the ring buffer
	struct event event = {};

	// use a bpf helper function to read a string containing the filename 
	// the filename comes from the tracepoint we are attaching to
	bpf_probe_read_user_str(&event.fname, sizeof(event.fname), ctx->args[1]);

	// create a pointer which will be used to access memory in the ring buffer
	struct event *ring_val;

	// use another bpf helper to reserve memory for our event in the ring buffer
	// our pointer will now point to the correct location we should write our event to
	ring_val = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!ring_val) {
		return 0;
	}
	
	// copy our event into the ring buffer
	memcpy(ring_val, &event, sizeof(struct event));

	// submit the event to the ring buffer
	bpf_ringbuf_submit(ring_val, 0);

	return 0;
}
