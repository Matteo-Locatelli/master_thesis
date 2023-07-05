#include "C:\eBPF-for-Windows.0.9.0\build\native\include\bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __uint(max_entries, 512);
} map SEC(".maps");

SEC("myprog")
int func1()
{
    uint32_t key = 0;
    uint32_t value = 42;
    int result = bpf_map_update_elem((struct bpf_map*)&map, &key, &value, 0);
    return result;
}
