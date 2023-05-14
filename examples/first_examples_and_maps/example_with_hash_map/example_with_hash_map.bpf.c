
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


// Define the array map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, pid_t);
    __type(value, u64);
} hash_map SEC(".maps");


void hash_map_use_not_working(pid_t pid, u64 time_stamp){
    bpf_printk("### BEGIN HASH MAP NOT WORKING ###");

    u64 update = 0;
    u64 delete = 0;

    void *found;
    void *deleted;

/*  ERROR even if update and delete are initialized
    bpf_printk("Update = %d - Delete = %d - Found = %d - Deleted = %d.", update, delete, found, deleted); 
*/
    bpf_printk("Found = %d - Deleted = %d.", found, deleted);   // -> 0 both

    update = bpf_map_update_elem(&hash_map, &pid, &time_stamp, BPF_ANY);

    bpf_printk("UPDATE %d (update %d).", pid, update);

    bpf_printk("key pid %d - ts %d - &pid %d - update %d.", pid, time_stamp, &pid, update);

    found = bpf_map_lookup_elem(&hash_map, &pid);

    if (found) {
        bpf_printk("FOUND IN HASH MAP (found %d).", found);
    } else {
        bpf_printk("NOT FOUND IN HASH MAP (found %d).", found);
    }

//  bpf_printk("delete %d -> result %d", pid, bpf_map_delete_elem(&hash_map, &pid));  

/*  Can't do like this -> error code -22 (element not found in map)
    
    deleted = bpf_map_lookup_elem(&hash_map, &pid);    -> ERROR

    if (deleted) {
        bpf_printk("DELETED FROM ARRAY (deleted %d).", deleted);
    } else {
        bpf_printk("NOT DELETED FROM ARRAY (deleted %d).", deleted);
    }
*/

    bpf_printk("### END HASH MAP NOT WORKING ###\n\n");
}


void hash_map_use_working(pid_t pid, u64 time_stamp){
    bpf_printk("### BEGIN HASH MAP WORKING ###");

    u64 update;
//  u64 delete;

    void *found;

    update = bpf_map_update_elem(&hash_map, &pid, &time_stamp, BPF_ANY);

    bpf_printk("UPDATE %d (update %d).", pid, update);

    bpf_printk("key pid %d - ts %d - &pid %d - update %d.", pid, time_stamp, &pid, update);

    found = bpf_map_lookup_elem(&hash_map, &pid);

    if (found) {
        bpf_printk("FOUND IN HASH MAP (found %d).", found);
    } else {
        bpf_printk("NOT FOUND IN HASH MAP (found %d).", found);
    }

//  works (alone)
//  bpf_map_delete_elem(&hash_map, &pid);
    
//  does not work (alone)
//  bpf_printk("DELETED FROM ARRAY (deleted %d).", bpf_map_delete_elem(&hash_map, &pid));

//  works (alone)
//  delete = bpf_map_delete_elem(&hash_map, &pid);

//  does not work (combo with previous instruction and with definition of delete variable)
//  bpf_printk("DELETE %d (delete %d).", pid, delete);

    bpf_printk("### END HASH MAP WORKING ###\n\n");
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

//  Execute only one of the 2 functions

//  hash_map_use_not_working(pid, time_stamp);

    hash_map_use_working(pid, time_stamp);

	return 0;
}
