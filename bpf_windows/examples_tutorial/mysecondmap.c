#include "C:\eBPF-for-Windows.0.9.0\build\native\include\bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, uint16_t);
    __type(value, uint32_t);
    __uint(max_entries, 512);
} map SEC(".maps");

SEC("myprog")
int func1()
{
    int fd;
    fd = BPF_ARRAY(name=map, leaf_type=uint16_t, size=512);
    uint32_t key = 0;
    uint32_t value = 42;
    int result = bpf_map_update_elem(&fd, &key, &value, 0);
    return result;
}

/*
mysecondmap.c:15:38: error: incompatible pointer types passing 
'struct (anonymous struct at mysecondmap.c:3:1) *' 
to parameter of type 
'struct _ebpf_map_definition_in_file *' 
[-Werror,-Wincompatible-pointer-types]
int result = bpf_map_update_elem(&map, &key, &value, 0);
*/