#include "C:\eBPF-for-Windows.0.9.0\build\native\include\bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, uint16_t);
    __type(value, uint32_t);
    __uint(max_entries, 512);
} map SEC(".maps");

SEC("myprog")
int func()
{
    return 0;
}
