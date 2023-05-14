
// example_simple_map.bpf.c


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// Set the license of the code
char LICENSE[] SEC("license") = "Dual BSD/GPL";


// Set a random number to print
int number = 0;


// Define the array map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256 * 1024);
    __type(key, u32);
    __type(value, int);
} array_map SEC(".maps");


void array_map_use(u32 key, int n){
    bpf_printk("### BEGIN ARRAY MAP ###");

    u64 update;

    void *found;

    update = bpf_map_update_elem(&array_map, &key, &n, BPF_ANY);

    bpf_printk("UPDATE %d (update %d).", key, update);

    bpf_printk("key pid %d - ts %d - &pid %d - update %d.", key, n, &key, update);

    found = bpf_map_lookup_elem(&array_map, &key);

    if (found) {
        bpf_printk("FOUND IN ARRAY (found %d).", found);
    } else {
        bpf_printk("NOT FOUND IN ARRAY (found %d).", found);
    }

    bpf_printk("### END ARRAY MAP ###\n\n");
}


SEC("kprobe/tcp_v4_connect")
int print_pid(tcp_v4_connect)
{
    bpf_printk("### SIMPLE EXAMPLE WORKING %d ###", number);

    number ++;

    u32 r1 = bpf_get_prandom_u32();
    //array_map_use(r1, 1);

    bpf_printk("### BEGIN ARRAY MAP ###");

    u64 update;

    void *found;

    update = bpf_map_update_elem(&array_map, &r1, &number, BPF_ANY);

    bpf_printk("UPDATE %d (update %d).", r1, update);

    bpf_printk("key pid %d - ts %d - &pid %d - update %d.", r1, number, &r1, update);

    found = bpf_map_lookup_elem(&array_map, &r1);

    if (found) {
        bpf_printk("FOUND IN ARRAY (found %d).", found);
    } else {
        bpf_printk("NOT FOUND IN ARRAY (found %d).", found);
    }

    bpf_printk("### END ARRAY MAP ###\n\n");


	return 0;
}