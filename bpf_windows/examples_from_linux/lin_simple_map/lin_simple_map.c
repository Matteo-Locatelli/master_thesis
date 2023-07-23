// lin_simple_map.c -> example_simple_map.bpf.c from Linux examples


#include "stdint.h"
#include "bpf_helpers.h"
#include "bpf_helper_defs.h"
#include "ebpf_structs.h"


SEC("maps")
ebpf_map_definition_in_file_t array_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .max_entries = 256 * 1024,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(int),
};


static void array_map_use(uint32_t key, int n){
    bpf_printk("### BEGIN ARRAY MAP ###");

    uint64_t update;

    uint64_t *found;

    update = bpf_map_update_elem(&array_map, &key, &n, EBPF_ANY);

    bpf_printk("UPDATE %d (update %d).", key, update);

    bpf_printk("key pid %d - n %d - update %d.", key, n, update);

    found = (uint64_t *) bpf_map_lookup_elem(&array_map, &key);

    if (found) {
        bpf_printk("FOUND IN ARRAY (found %llu).", *found);
    } else {
        bpf_printk("NOT FOUND IN ARRAY (found %llu).", *found);
    }

    bpf_printk("### END ARRAY MAP ###\n\n");
}


SEC("xdp")
int print_pid(xdp_md_t* ctx)
{
    int number = bpf_get_prandom_u32();

    bpf_printk("### SIMPLE EXAMPLE WORKING %d ###", number);

    uint32_t r1 = bpf_get_prandom_u32();
    array_map_use(r1, number);

	return 0;
}
