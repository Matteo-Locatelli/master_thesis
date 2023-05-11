
// example_with_array_map.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// Set the license of the code
char LICENSE[] SEC("license") = "Dual BSD/GPL";


// Set the event
struct event {
    pid_t pid;      // int
    u64 time_stamp; // unsigned long
};


// Define the array map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256 * 1024);
    __type(key, pid_t);
    __type(value, u64);
} array_map SEC(".maps");


void array_map_use(pid_t pid, u64 time_stamp){
    bpf_printk("### BEGIN ARRAY MAP ###");

    u64 update, delete;

    void *found, *deleted;

    bpf_printk("Found = %d - Deleted = %d.", found, deleted);

    update = bpf_map_update_elem(&array_map, &pid, &time_stamp, BPF_ANY);

    bpf_printk("UPDATE %d (update %d).", pid, update);

    bpf_printk("key pid %d - ts %d - &pid %d - update %d.", pid, time_stamp, &pid, update);

    found = bpf_map_lookup_elem(&array_map, &pid);

    if (found) {
        bpf_printk("FOUND IN ARRAY (found %d).", found);
    } else {
        bpf_printk("NOT FOUND IN ARRAY (found %d).", found);
    }

/*
    delete = bpf_map_delete_elem(&array_map, &pid);

    if(delete){
        bpf_printk("DELETED %d (delete %d).", pid, delete);
    } else {
        bpf_printk("UNABLE TO DELETE %d (delete %d).", pid, delete);
    }
*/
    //bpf_printk("delete -> %d", bpf_map_delete_elem(&array_map, &pid));
/* 
    Can't do like this -> error code -22 (element not found in map)
    
    deleted = bpf_map_lookup_elem(&array_map, &pid);    -> ERROR

    if (deleted) {
        bpf_printk("DELETED FROM ARRAY (deleted %d).", deleted);
    } else {
        bpf_printk("NOT DELETED FROM ARRAY (deleted %d).", deleted);
    }
*/

    bpf_printk("### END ARRAY MAP ###\n\n");
}


SEC("kprobe/tcp_v4_connect")
int print_pid(tcp_v4_connect)
{
    pid_t pid;
    u64 time_stamp;
    //struct event *e;
    
    pid = bpf_get_current_pid_tgid() >> 32;
    time_stamp = bpf_ktime_get_ns();    // from system boot

	bpf_printk("BPF triggered from PID %d at time %d.\n", pid, time_stamp);

    array_map_use(pid, time_stamp);

	return 0;
}
