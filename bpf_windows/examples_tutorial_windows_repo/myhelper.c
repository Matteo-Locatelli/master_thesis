/* Specify the complete path
 * Or specify in compilation: clang -I .\eBPF-for-Windows.X.Y.Z\build\native\include\ ...
 */ 

#include "C:\eBPF-for-Windows.0.9.0\build\native\include\bpf_helpers.h"

int func()
{
    int result = bpf_map_update_elem((struct bpf_map*)0, (uint32_t*)0, (uint32_t*)0, 0);
    return result;
}