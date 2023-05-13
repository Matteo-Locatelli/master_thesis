// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

// helloworld.bpf.c 


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
  char msg[] = "Hello, World!";
  bpf_printk("invoke bpf_prog: %s\n", msg);
  return 0;
}
