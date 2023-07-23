
// example_with_hash_map.bpf.c


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


// Define the hash map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, pid_t);
    __type(value, u64);
} hash_map SEC(".maps");


static void hash_map_use(pid_t pid, u64 time_stamp){
    bpf_printk("### BEGIN HASH MAP WORK ###");

    u64 update;
    u64 delete;

    u64 *found;
    u64 *deleted;

    update = bpf_map_update_elem(&hash_map, &pid, &time_stamp, BPF_ANY);

    bpf_printk("UPDATE %d (update %d).", pid, update);

    bpf_printk("key pid %d - ts %llu - &pid %d - update %d.", pid, time_stamp, &pid, update);

    found = (u64 *)bpf_map_lookup_elem(&hash_map, &pid);

    if (found) {
        bpf_printk("FOUND IN HASH MAP (found %llu).", *found);
    } else {
        bpf_printk("NOT FOUND IN HASH MAP");
    }

    delete = bpf_map_delete_elem(&hash_map, &pid);

    bpf_printk("DELETE %d (delete %lld).", pid, delete);

    deleted = (u64 *)bpf_map_lookup_elem(&hash_map, &pid);

    if (!deleted) {
        bpf_printk("DELETED IN HASH MAP (*deleted %llu & deleted %p).", *deleted, deleted);
    } else {
        bpf_printk("NOT POSSIBLE TO DELETE IN HASH MAP");
    }

    bpf_printk("### END HASH MAP WORK ###\n\n");

}


/*
3 ways to write code:
- inside the function in SEC
- in a function that return int & return 0 at the end
- in a function declared static 
*/


SEC("kprobe/tcp_v4_connect")
int print_pid(tcp_v4_connect)   
{
    pid_t pid;
    u64 time_stamp;
    //struct event *e;
    
    pid = bpf_get_current_pid_tgid() >> 32;
    time_stamp = bpf_ktime_get_ns();    // from system boot

	bpf_printk("BPF triggered from PID %d at time %d.\n", pid, time_stamp);

    hash_map_use(pid, time_stamp);

	return 0;
}
