// lin_array_map_use.c -> example_with_array_map.bpf.c from Linux examples


#include "stdint.h"
#include "bpf_helpers.h"
#include "bpf_helper_defs.h"
#include "ebpf_structs.h"


SEC("maps")
ebpf_map_definition_in_file_t array_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .max_entries = 256 * 1024,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
};


static void array_map_use(uint32_t pid, uint64_t time_stamp){
    bpf_printk("### BEGIN ARRAY MAP USE ###");

    uint64_t update;
    uint64_t delete;

    uint64_t *found;
    uint64_t *deleted;

    update = bpf_map_update_elem(&array_map, &pid, &time_stamp, EBPF_ANY);

    bpf_printk("UPDATE %d (update %d).", pid, update);

    bpf_printk("key pid %d - ts %llu - update %d.", pid, time_stamp, update);

    found = (uint64_t *) bpf_map_lookup_elem(&array_map, &pid);

    if (found) {
        bpf_printk("FOUND IN ARRAY (*found %llu).", *found);
    } else {
        bpf_printk("NOT FOUND IN ARRAY");
    }

    delete = bpf_map_delete_elem(&array_map, &pid);

    bpf_printk("DELETE %d (delete %lld).", pid, delete);

    deleted = (uint64_t *)bpf_map_lookup_elem(&array_map, &pid);

    if (!deleted) {
        bpf_printk("DELETED IN ARRAY (*deleted %llu).", *deleted);
    } else {
        bpf_printk("NOT POSSIBLE TO DELETE IN ARRAY");
    }

    bpf_printk("### END ARRAY MAP USE ###\n\n");
}


SEC("xdp")
int print_pid_array_map(xdp_md_t* ctx)
{
    uint32_t pid;
    uint64_t time_stamp;
    
    pid = bpf_get_current_pid_tgid() >> 32;
    time_stamp = bpf_ktime_get_ns();    // from system boot

	bpf_printk("BPF triggered from PID %d at time %llu.\n", pid, time_stamp);

    array_map_use(pid, time_stamp);

	return 0;
}
