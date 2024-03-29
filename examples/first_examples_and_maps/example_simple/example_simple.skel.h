/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __EXAMPLE_SIMPLE_BPF_SKEL_H__
#define __EXAMPLE_SIMPLE_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct example_simple_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *bss;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *print_pid;
	} progs;
	struct {
		struct bpf_link *print_pid;
	} links;
	struct example_simple_bpf__bss {
		int number;
	} *bss;

#ifdef __cplusplus
	static inline struct example_simple_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct example_simple_bpf *open_and_load();
	static inline int load(struct example_simple_bpf *skel);
	static inline int attach(struct example_simple_bpf *skel);
	static inline void detach(struct example_simple_bpf *skel);
	static inline void destroy(struct example_simple_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
example_simple_bpf__destroy(struct example_simple_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
example_simple_bpf__create_skeleton(struct example_simple_bpf *obj);

static inline struct example_simple_bpf *
example_simple_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct example_simple_bpf *obj;
	int err;

	obj = (struct example_simple_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = example_simple_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	example_simple_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct example_simple_bpf *
example_simple_bpf__open(void)
{
	return example_simple_bpf__open_opts(NULL);
}

static inline int
example_simple_bpf__load(struct example_simple_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct example_simple_bpf *
example_simple_bpf__open_and_load(void)
{
	struct example_simple_bpf *obj;
	int err;

	obj = example_simple_bpf__open();
	if (!obj)
		return NULL;
	err = example_simple_bpf__load(obj);
	if (err) {
		example_simple_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
example_simple_bpf__attach(struct example_simple_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
example_simple_bpf__detach(struct example_simple_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *example_simple_bpf__elf_bytes(size_t *sz);

static inline int
example_simple_bpf__create_skeleton(struct example_simple_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "example_simple_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "example_.bss";
	s->maps[0].map = &obj->maps.bss;
	s->maps[0].mmaped = (void **)&obj->bss;

	s->maps[1].name = "example_.rodata";
	s->maps[1].map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "print_pid";
	s->progs[0].prog = &obj->progs.print_pid;
	s->progs[0].link = &obj->links.print_pid;

	s->data = (void *)example_simple_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *example_simple_bpf__elf_bytes(size_t *sz)
{
	*sz = 6504;
	return (const void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x68\x12\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1c\0\
\x01\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x1f\0\0\0\x85\0\0\0\x06\
\0\0\0\x85\0\0\0\x0e\0\0\0\xbf\x06\0\0\0\0\0\0\x85\0\0\0\x05\0\0\0\x18\x07\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x61\x75\0\0\0\0\0\0\x77\x06\0\0\x20\0\0\0\x18\x01\0\0\
\x1f\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x35\0\0\0\xbf\x63\0\0\0\0\0\0\xbf\x04\0\
\0\0\0\0\0\x85\0\0\0\x06\0\0\0\x61\x71\0\0\0\0\0\0\x07\x01\0\0\x01\0\0\0\x63\
\x17\0\0\0\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x44\x75\x61\x6c\x20\x42\
\x53\x44\x2f\x47\x50\x4c\0\0\0\0\x23\x23\x23\x20\x53\x49\x4d\x50\x4c\x45\x20\
\x45\x58\x41\x4d\x50\x4c\x45\x20\x57\x4f\x52\x4b\x49\x4e\x47\x20\x23\x23\x23\0\
\x42\x50\x46\x20\x74\x72\x69\x67\x67\x65\x72\x65\x64\x20\x66\x72\x6f\x6d\x20\
\x50\x49\x44\x20\x25\x64\x20\x61\x74\x20\x74\x69\x6d\x65\x20\x25\x64\x20\x28\
\x6e\x75\x6d\x62\x65\x72\x20\x3d\x20\x25\x64\x29\x2e\x0a\0\x1d\0\0\0\x05\0\x08\
\0\x02\0\0\0\x08\0\0\0\x0e\0\0\0\x04\x30\x58\x01\x56\0\x04\x38\x88\x01\x01\x50\
\0\x01\x11\x01\x25\x25\x13\x05\x03\x25\x72\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\
\x73\x17\x8c\x01\x17\0\0\x02\x34\0\x03\x25\x49\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\
\x18\0\0\x03\x01\x01\x49\x13\0\0\x04\x21\0\x49\x13\x37\x0b\0\0\x05\x24\0\x03\
\x25\x3e\x0b\x0b\x0b\0\0\x06\x24\0\x03\x25\x0b\x0b\x3e\x0b\0\0\x07\x2e\x01\x11\
\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x49\x13\x3f\x19\0\0\x08\
\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x02\x18\0\0\x09\x05\0\x03\x25\x3a\x0b\
\x3b\x0b\x49\x13\0\0\x0a\x34\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x0b\
\x34\0\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x0c\x26\0\x49\x13\0\0\x0d\x34\0\x03\
\x25\x49\x13\x3a\x0b\x3b\x0b\0\0\x0e\x0f\0\x49\x13\0\0\x0f\x15\x01\x49\x13\x27\
\x19\0\0\x10\x05\0\x49\x13\0\0\x11\x18\0\0\0\x12\x16\0\x49\x13\x03\x25\x3a\x0b\
\x3b\x0b\0\0\x13\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x05\0\0\x14\x15\0\x49\x13\
\x27\x19\0\0\x15\x13\x01\x03\x25\x0b\x0b\x3a\x0b\x3b\x0b\0\0\x16\x0d\0\x03\x25\
\x49\x13\x3a\x0b\x3b\x0b\x38\x0b\0\0\0\x46\x01\0\0\x05\0\x01\x08\0\0\0\0\x01\0\
\x0c\0\x01\x08\0\0\0\0\0\0\0\x02\x04\xb0\0\0\0\x08\0\0\0\x0c\0\0\0\x02\x03\x32\
\0\0\0\x01\x0c\x02\xa1\0\x03\x3e\0\0\0\x04\x42\0\0\0\x0d\0\x05\x04\x06\x01\x06\
\x05\x08\x07\x02\x06\x51\0\0\0\x01\x17\x02\xa1\x01\x05\x07\x05\x04\x07\x04\xb0\
\0\0\0\x01\x5a\x11\x01\x1b\x51\0\0\0\x08\x08\x9d\0\0\0\x01\x1d\x02\xa1\x02\x08\
\x08\xae\0\0\0\x01\x26\x02\xa1\x03\x09\x17\x01\x1b\x51\0\0\0\x0a\0\x12\x01\x1f\
\x14\x01\0\0\x0a\x01\x15\x01\x20\x24\x01\0\0\x0b\x18\x01\x21\x2c\x01\0\0\0\x03\
\xa9\0\0\0\x04\x42\0\0\0\x1f\0\x0c\x3e\0\0\0\x03\xa9\0\0\0\x04\x42\0\0\0\x35\0\
\x0d\x09\xc2\0\0\0\x03\xb1\x0e\xc7\0\0\0\x0f\xd8\0\0\0\x10\xdc\0\0\0\x10\xe1\0\
\0\0\x11\0\x05\x0a\x05\x08\x0e\xa9\0\0\0\x12\xe9\0\0\0\x0c\x02\x12\x05\x0b\x07\
\x04\x13\x0d\xf6\0\0\0\x03\x70\x01\x0e\xfb\0\0\0\x14\0\x01\0\0\x12\x08\x01\0\0\
\x0f\x02\x16\x05\x0e\x07\x08\x0d\x10\xf6\0\0\0\x03\x72\x12\x1c\x01\0\0\x14\x02\
\x4d\x12\x51\0\0\0\x13\x02\x31\x12\0\x01\0\0\x16\x02\x26\x0e\x31\x01\0\0\x15\
\x19\x10\x01\x10\x16\x12\x14\x01\0\0\x01\x11\0\x16\x15\x24\x01\0\0\x01\x12\x08\
\0\0\x6c\0\0\0\x05\0\0\0\0\0\0\0\x25\0\0\0\x63\0\0\0\x87\0\0\0\x8f\0\0\0\x94\0\
\0\0\xa8\0\0\0\xaf\0\0\0\xb3\0\0\0\xbb\0\0\0\xcc\0\0\0\xd1\0\0\0\xde\0\0\0\xe4\
\0\0\0\xfd\0\0\0\x10\x01\0\0\x16\x01\0\0\x27\x01\0\0\x31\x01\0\0\x35\x01\0\0\
\x44\x01\0\0\x4a\x01\0\0\x55\x01\0\0\x59\x01\0\0\x68\x01\0\0\x6a\x01\0\0\x55\
\x62\x75\x6e\x74\x75\x20\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\
\x20\x31\x34\x2e\x30\x2e\x30\x2d\x31\x75\x62\x75\x6e\x74\x75\x31\0\x2f\x68\x6f\
\x6d\x65\x2f\x6d\x61\x74\x74\x65\x6f\x2f\x6c\x69\x62\x62\x70\x66\x2d\x62\x6f\
\x6f\x74\x73\x74\x72\x61\x70\x2f\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\x2f\
\x65\x78\x61\x6d\x70\x6c\x65\x5f\x73\x69\x6d\x70\x6c\x65\x2e\x62\x70\x66\x2e\
\x63\0\x2f\x68\x6f\x6d\x65\x2f\x6d\x61\x74\x74\x65\x6f\x2f\x6c\x69\x62\x62\x70\
\x66\x2d\x62\x6f\x6f\x74\x73\x74\x72\x61\x70\x2f\x62\x75\x69\x6c\x64\0\x4c\x49\
\x43\x45\x4e\x53\x45\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\
\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x6e\x75\x6d\x62\x65\x72\0\x69\x6e\
\x74\0\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\
\x70\x72\x69\x6e\x74\x6b\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\x67\x6e\x65\x64\
\x20\x69\x6e\x74\0\x5f\x5f\x75\x33\x32\0\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\
\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\x64\0\x75\x6e\x73\x69\
\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x5f\x5f\x75\x36\x34\
\0\x62\x70\x66\x5f\x6b\x74\x69\x6d\x65\x5f\x67\x65\x74\x5f\x6e\x73\0\x70\x72\
\x69\x6e\x74\x5f\x70\x69\x64\0\x70\x69\x64\0\x5f\x5f\x6b\x65\x72\x6e\x65\x6c\
\x5f\x70\x69\x64\x5f\x74\0\x70\x69\x64\x5f\x74\0\x74\x69\x6d\x65\x5f\x73\x74\
\x61\x6d\x70\0\x75\x36\x34\0\x74\x63\x70\x5f\x76\x34\x5f\x63\x6f\x6e\x6e\x65\
\x63\x74\0\x65\0\x65\x76\x65\x6e\x74\0\x2c\0\0\0\x05\0\x08\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\
\0\x18\0\0\0\0\0\0\0\x38\x01\0\0\x38\x01\0\0\xe8\x01\0\0\x01\0\0\0\0\0\0\x01\
\x04\0\0\0\x20\0\0\x01\0\0\0\0\x01\0\0\x0d\x01\0\0\0\x05\0\0\0\x01\0\0\0\x14\0\
\0\0\x01\0\0\x0c\x02\0\0\0\x85\x01\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\
\0\0\0\x03\0\0\0\0\x04\0\0\0\x06\0\0\0\x0d\0\0\0\x8a\x01\0\0\0\0\0\x01\x04\0\0\
\0\x20\0\0\0\x9e\x01\0\0\0\0\0\x0e\x05\0\0\0\x01\0\0\0\xa6\x01\0\0\0\0\0\x0e\
\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x0a\x04\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x09\
\0\0\0\x06\0\0\0\x1f\0\0\0\xad\x01\0\0\0\0\0\x0e\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x03\0\0\0\0\x09\0\0\0\x06\0\0\0\x35\0\0\0\xbf\x01\0\0\0\0\0\x0e\x0c\0\0\0\0\
\0\0\0\xd3\x01\0\0\x01\0\0\x0f\0\0\0\0\x08\0\0\0\0\0\0\0\x04\0\0\0\xd8\x01\0\0\
\x02\0\0\x0f\0\0\0\0\x0b\0\0\0\0\0\0\0\x1f\0\0\0\x0d\0\0\0\x1f\0\0\0\x35\0\0\0\
\xe0\x01\0\0\x01\0\0\x0f\0\0\0\0\x07\0\0\0\0\0\0\0\x0d\0\0\0\0\x69\x6e\x74\0\
\x74\x63\x70\x5f\x76\x34\x5f\x63\x6f\x6e\x6e\x65\x63\x74\0\x70\x72\x69\x6e\x74\
\x5f\x70\x69\x64\0\x6b\x70\x72\x6f\x62\x65\x2f\x74\x63\x70\x5f\x76\x34\x5f\x63\
\x6f\x6e\x6e\x65\x63\x74\0\x2f\x68\x6f\x6d\x65\x2f\x6d\x61\x74\x74\x65\x6f\x2f\
\x6c\x69\x62\x62\x70\x66\x2d\x62\x6f\x6f\x74\x73\x74\x72\x61\x70\x2f\x65\x78\
\x61\x6d\x70\x6c\x65\x73\x2f\x63\x2f\x65\x78\x61\x6d\x70\x6c\x65\x5f\x73\x69\
\x6d\x70\x6c\x65\x2e\x62\x70\x66\x2e\x63\0\x20\x20\x20\x20\x62\x70\x66\x5f\x70\
\x72\x69\x6e\x74\x6b\x28\x22\x23\x23\x23\x20\x53\x49\x4d\x50\x4c\x45\x20\x45\
\x58\x41\x4d\x50\x4c\x45\x20\x57\x4f\x52\x4b\x49\x4e\x47\x20\x23\x23\x23\x22\
\x29\x3b\0\x20\x20\x20\x20\x70\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\x74\
\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\x64\x28\x29\
\x20\x3e\x3e\x20\x33\x32\x3b\0\x20\x20\x20\x20\x74\x69\x6d\x65\x5f\x73\x74\x61\
\x6d\x70\x20\x3d\x20\x62\x70\x66\x5f\x6b\x74\x69\x6d\x65\x5f\x67\x65\x74\x5f\
\x6e\x73\x28\x29\x3b\x20\x20\x20\x20\x2f\x2f\x20\x66\x72\x6f\x6d\x20\x73\x79\
\x73\x74\x65\x6d\x20\x62\x6f\x6f\x74\0\x09\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\
\x6b\x28\x22\x42\x50\x46\x20\x74\x72\x69\x67\x67\x65\x72\x65\x64\x20\x66\x72\
\x6f\x6d\x20\x50\x49\x44\x20\x25\x64\x20\x61\x74\x20\x74\x69\x6d\x65\x20\x25\
\x64\x20\x28\x6e\x75\x6d\x62\x65\x72\x20\x3d\x20\x25\x64\x29\x2e\x5c\x6e\x22\
\x2c\x20\x70\x69\x64\x2c\x20\x74\x69\x6d\x65\x5f\x73\x74\x61\x6d\x70\x2c\x20\
\x6e\x75\x6d\x62\x65\x72\x29\x3b\0\x20\x20\x20\x20\x6e\x75\x6d\x62\x65\x72\x20\
\x2b\x2b\x3b\0\x09\x72\x65\x74\x75\x72\x6e\x20\x30\x3b\0\x63\x68\x61\x72\0\x5f\
\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x4c\
\x49\x43\x45\x4e\x53\x45\0\x6e\x75\x6d\x62\x65\x72\0\x70\x72\x69\x6e\x74\x5f\
\x70\x69\x64\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x70\x72\x69\x6e\x74\x5f\x70\x69\
\x64\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\x2e\x31\0\x2e\x62\x73\x73\0\x2e\x72\x6f\
\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\
\0\x14\0\0\0\x14\0\0\0\x8c\0\0\0\xa0\0\0\0\0\0\0\0\x08\0\0\0\x1e\0\0\0\x01\0\0\
\0\0\0\0\0\x03\0\0\0\x10\0\0\0\x1e\0\0\0\x08\0\0\0\0\0\0\0\x34\0\0\0\x72\0\0\0\
\x05\x74\0\0\x20\0\0\0\x34\0\0\0\xa4\0\0\0\x0b\x8c\0\0\x30\0\0\0\x34\0\0\0\xd0\
\0\0\0\x12\x90\0\0\x38\0\0\0\x34\0\0\0\x0c\x01\0\0\x02\x98\0\0\x50\0\0\0\x34\0\
\0\0\xa4\0\0\0\x26\x8c\0\0\x58\0\0\0\x34\0\0\0\x0c\x01\0\0\x02\x98\0\0\x88\0\0\
\0\x34\0\0\0\x6b\x01\0\0\x0c\xa0\0\0\xa0\0\0\0\x34\0\0\0\x7a\x01\0\0\x02\xbc\0\
\0\x0c\0\0\0\xff\xff\xff\xff\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xb0\0\0\0\0\0\0\0\xb2\0\0\0\x05\0\x08\0\x7e\0\0\0\x08\x01\x01\xfb\
\x0e\x0d\0\x01\x01\x01\x01\0\0\0\x01\0\0\x01\x01\x01\x1f\x03\0\0\0\0\x24\0\0\0\
\x42\0\0\0\x03\x01\x1f\x02\x0f\x05\x1e\x04\x4d\0\0\0\0\xc6\xb4\x21\x8c\x5a\x8e\
\xac\x61\xef\xe1\x3a\x65\xcb\xb2\xd9\x73\x8b\0\0\0\x01\xc6\xb4\x21\x8c\x5a\x8e\
\xac\x61\xef\xe1\x3a\x65\xcb\xb2\xd9\x73\xab\0\0\0\x01\xb6\x2e\x98\x47\x48\x43\
\x74\x33\xe3\x5d\x4d\x64\x9e\xea\xde\xec\xce\0\0\0\x02\xb2\xcd\x23\x82\xf6\x75\
\x90\x99\xa0\x49\xf8\x37\x5a\xd4\x99\x87\0\x09\x02\0\0\0\0\0\0\0\0\x03\x1b\x01\
\x05\x05\x0a\x13\x05\x0b\x50\x05\x12\x2f\x05\x02\x22\x05\x26\x39\x05\x02\x23\
\x05\x0c\x68\x05\x02\x43\x02\x02\0\x01\x01\x2f\x68\x6f\x6d\x65\x2f\x6d\x61\x74\
\x74\x65\x6f\x2f\x6c\x69\x62\x62\x70\x66\x2d\x62\x6f\x6f\x74\x73\x74\x72\x61\
\x70\x2f\x62\x75\x69\x6c\x64\0\x2f\x68\x6f\x6d\x65\x2f\x6d\x61\x74\x74\x65\x6f\
\x2f\x6c\x69\x62\x62\x70\x66\x2d\x62\x6f\x6f\x74\x73\x74\x72\x61\x70\0\x6c\x69\
\x62\x62\x70\x66\x2f\x62\x70\x66\0\x2f\x68\x6f\x6d\x65\x2f\x6d\x61\x74\x74\x65\
\x6f\x2f\x6c\x69\x62\x62\x70\x66\x2d\x62\x6f\x6f\x74\x73\x74\x72\x61\x70\x2f\
\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\x2f\x65\x78\x61\x6d\x70\x6c\x65\x5f\
\x73\x69\x6d\x70\x6c\x65\x2e\x62\x70\x66\x2e\x63\0\x65\x78\x61\x6d\x70\x6c\x65\
\x73\x2f\x63\x2f\x65\x78\x61\x6d\x70\x6c\x65\x5f\x73\x69\x6d\x70\x6c\x65\x2e\
\x62\x70\x66\x2e\x63\0\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\x2f\x2e\x2e\x2f\
\x2e\x2e\x2f\x76\x6d\x6c\x69\x6e\x75\x78\x2f\x76\x6d\x6c\x69\x6e\x75\x78\x2e\
\x68\0\x62\x70\x66\x5f\x68\x65\x6c\x70\x65\x72\x5f\x64\x65\x66\x73\x2e\x68\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfd\0\0\0\x04\0\xf1\xff\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x22\0\0\0\x01\0\x07\0\0\0\0\0\0\0\0\0\x1f\0\0\0\0\0\0\0\x3b\x01\0\0\x01\0\
\x07\0\x1f\0\0\0\0\0\0\0\x35\0\0\0\0\0\0\0\0\0\0\0\x03\0\x07\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0c\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x15\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x17\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x19\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf3\0\0\0\x12\0\x03\0\0\0\0\0\0\0\
\0\0\xb0\0\0\0\0\0\0\0\x95\0\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\
\x33\x01\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\
\0\0\0\x05\0\0\0\x38\0\0\0\0\0\0\0\x01\0\0\0\x0f\0\0\0\x58\0\0\0\0\0\0\0\x01\0\
\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x11\0\0\0\0\0\0\0\x03\0\0\
\0\x08\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\x0c\0\0\0\x1f\0\0\0\0\0\0\0\x03\0\0\0\
\x0a\0\0\0\x23\0\0\0\0\0\0\0\x03\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x0c\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x1c\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x24\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x2c\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x34\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x38\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x3c\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x44\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x48\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x4c\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x50\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x54\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x58\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x5c\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x64\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x68\0\0\0\0\0\0\0\x03\0\0\0\
\x09\0\0\0\x6c\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\
\x10\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\x0f\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\
\x05\0\0\0\x20\0\0\0\0\0\0\0\x02\0\0\0\x05\0\0\0\x28\0\0\0\0\0\0\0\x02\0\0\0\
\x02\0\0\0\x0c\x01\0\0\0\0\0\0\x04\0\0\0\x0f\0\0\0\x24\x01\0\0\0\0\0\0\x03\0\0\
\0\x05\0\0\0\x30\x01\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\x48\x01\0\0\0\0\0\0\x04\0\
\0\0\x10\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\
\0\x02\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\
\x02\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\
\x02\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xa0\0\0\0\0\0\0\0\x04\0\0\0\
\x02\0\0\0\xb0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\
\x0b\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\
\x0d\0\0\0\x26\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x2a\0\0\0\0\0\0\0\x03\0\0\0\
\x0d\0\0\0\x36\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x4b\0\0\0\0\0\0\0\x03\0\0\0\
\x0d\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x75\0\0\0\0\0\0\0\x03\0\0\0\
\x0d\0\0\0\x8d\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x0e\x10\x03\x04\0\x2e\x64\x65\
\x62\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\
\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x70\x72\x69\x6e\x74\x5f\x70\x69\x64\x2e\
\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x72\x65\x6c\x6b\x70\x72\x6f\x62\x65\x2f\x74\
\x63\x70\x5f\x76\x34\x5f\x63\x6f\x6e\x6e\x65\x63\x74\0\x2e\x64\x65\x62\x75\x67\
\x5f\x6c\x6f\x63\x6c\x69\x73\x74\x73\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\
\x5f\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\x74\x73\0\x2e\x62\x73\x73\0\x2e\x64\
\x65\x62\x75\x67\x5f\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\
\x5f\x73\x74\x72\0\x6e\x75\x6d\x62\x65\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\
\x75\x67\x5f\x61\x64\x64\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\
\x6e\x66\x6f\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x6c\x69\
\x63\x65\x6e\x73\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\
\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x70\
\x72\x69\x6e\x74\x5f\x70\x69\x64\0\x65\x78\x61\x6d\x70\x6c\x65\x5f\x73\x69\x6d\
\x70\x6c\x65\x2e\x62\x70\x66\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\
\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\x6c\x2e\x42\
\x54\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\x70\x72\x69\x6e\x74\x5f\x70\x69\x64\
\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\x2e\x31\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x12\x01\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x14\x11\0\0\0\0\0\0\x4f\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\0\
\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\xb0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x34\0\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\x0d\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x1b\0\
\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xca\0\0\0\x01\0\0\0\x03\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x75\0\0\0\x08\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x22\x01\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\x54\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x4e\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x54\x01\0\0\0\0\0\0\
\x21\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x75\x01\0\0\0\0\0\0\x10\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\x02\0\0\0\0\0\0\x4a\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xac\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x60\x0d\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x1b\0\0\0\x0a\0\0\0\x08\
\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x62\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xcf\x03\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x5e\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\x0d\
\0\0\0\0\0\0\xa0\x01\0\0\0\0\0\0\x1b\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\
\0\0\0\0\0\x7a\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3f\x04\0\0\0\
\0\0\0\x70\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\xa0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xaf\x05\0\0\0\0\0\0\x30\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9c\0\0\0\x09\0\
\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\x0f\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\
\x1b\0\0\0\x0f\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x2e\x01\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe0\x05\0\0\0\0\0\0\x38\x03\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2a\x01\0\0\x09\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xa0\x0f\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x1b\0\0\0\x11\0\0\
\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x18\x09\0\0\0\0\0\0\xc0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xe0\x0f\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\x1b\0\0\0\x13\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\xe6\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd8\x09\
\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xe2\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\x10\0\0\0\0\0\0\
\x20\0\0\0\0\0\0\0\x1b\0\0\0\x15\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xd6\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0a\0\0\0\0\0\0\xb6\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd2\0\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x10\0\0\0\0\0\0\x80\0\0\0\0\0\0\0\x1b\0\
\0\0\x17\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x30\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xb6\x0a\0\0\0\0\0\0\xe0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xbc\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\
\0\0\0\0\0\0\0\0\0\0\x10\x11\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x1b\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1a\x01\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x98\x0b\0\0\0\0\0\0\x98\x01\0\0\0\0\0\0\x01\0\0\0\x0e\0\0\0\x08\0\0\
\0\0\0\0\0\x18\0\0\0\0\0\0\0";
}

#ifdef __cplusplus
struct example_simple_bpf *example_simple_bpf::open(const struct bpf_object_open_opts *opts) { return example_simple_bpf__open_opts(opts); }
struct example_simple_bpf *example_simple_bpf::open_and_load() { return example_simple_bpf__open_and_load(); }
int example_simple_bpf::load(struct example_simple_bpf *skel) { return example_simple_bpf__load(skel); }
int example_simple_bpf::attach(struct example_simple_bpf *skel) { return example_simple_bpf__attach(skel); }
void example_simple_bpf::detach(struct example_simple_bpf *skel) { example_simple_bpf__detach(skel); }
void example_simple_bpf::destroy(struct example_simple_bpf *skel) { example_simple_bpf__destroy(skel); }
const void *example_simple_bpf::elf_bytes(size_t *sz) { return example_simple_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
example_simple_bpf__assert(struct example_simple_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->bss->number) == 4, "unexpected size of 'number'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __EXAMPLE_SIMPLE_BPF_SKEL_H__ */
