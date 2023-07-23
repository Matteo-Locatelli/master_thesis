// lin_hash_map_use.c -> example_with_hash_map.bpf.c from Linux examples


#include "stdint.h"
#include "bpf_helpers.h"
#include "bpf_helper_defs.h"
#include "ebpf_structs.h"


SEC("maps")
ebpf_map_definition_in_file_t hash_map = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 256 * 1024,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
};


static void hash_map_use(uint32_t pid, uint64_t time_stamp){
    bpf_printk("### BEGIN HASH MAP USE ###");

    uint64_t update;
    uint64_t delete;

    uint64_t *found;
    uint64_t *deleted;

    update = bpf_map_update_elem(&hash_map, &pid, &time_stamp, EBPF_ANY);

    bpf_printk("UPDATE %d (update %d).", pid, update);

    bpf_printk("key pid %d - ts %llu - update %d.", pid, time_stamp, update);

    found = (uint64_t *) bpf_map_lookup_elem(&hash_map, &pid);

    if (found) {
        bpf_printk("FOUND IN HASH MAP (*found %llu).", *found);
    } else {
        bpf_printk("NOT FOUND IN HASH MAP");
    }

    delete = bpf_map_delete_elem(&hash_map, &pid);

    bpf_printk("DELETE %d (delete %lld).", pid, delete);

    deleted = (uint64_t *)bpf_map_lookup_elem(&hash_map, &pid);

    if (!deleted) {
        bpf_printk("DELETED IN HASH MAP (*deleted %llu).", *deleted);
    } else {
        bpf_printk("NOT DELETED IN HASH MAP.");
    }

    bpf_printk("### END HASH MAP USE ###\n\n");
}


SEC("xdp")
int print_pid_hash_map(xdp_md_t* ctx)
{
    uint32_t pid;
    uint64_t time_stamp;
    
    pid = bpf_get_current_pid_tgid() >> 32;
    time_stamp = bpf_ktime_get_ns();    // from system boot

	bpf_printk("BPF triggered from PID %d at time %llu.\n", pid, time_stamp);

    hash_map_use(pid, time_stamp);

	return 0;
}
