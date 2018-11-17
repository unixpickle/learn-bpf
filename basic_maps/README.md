# Overview

This barebones example shows how to communicate from an eBPF program to a userspace program using eBPF maps.

In this case, the information transmitted from the kernel to userspace is random. A map of 13 elements is used, and every packet increments element ((random()&0xf) % 13). Because of the prime radix, the first three elements of the map are incremented much more than the final 11. The output ends up looking something like this:

```
0=7746 1=7749 2=7632 3=3834 4=3976 5=3973 6=3777 7=3812 8=3754 9=3884 10=3862 11=3844 12=3839
0=7746 1=7749 2=7633 3=3835 4=3976 5=3973 6=3778 7=3812 8=3754 9=3884 10=3863 11=3845 12=3839
0=7746 1=7749 2=7634 3=3835 4=3976 5=3973 6=3778 7=3812 8=3754 9=3884 10=3863 11=3845 12=3839
```

# Steps to using eBPF maps

In userspace, you create a map like so:

```c
union bpf_attr bpf_args;
bzero(&bpf_args, sizeof(bpf_args));
bpf_args.map_type = BPF_MAP_TYPE_HASH;
bpf_args.key_size = 1;
bpf_args.value_size = 4;
bpf_args.max_entries = 13;
int mapFd = syscall(__NR_bpf, BPF_MAP_CREATE, &bpf_args, sizeof(bpf_args));
```

To pass the map to a BPF program, you use a special 64-bit load instruction:

```c
{BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, mapFd},
{0, 0, 0, 0, 0},
```

To access the map from the BPF program, you can invoke helpers like so:

```c
{BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem},
```

Finally, you can read the map in userspace like so:

```c
union bpf_attr bpf_args;
uint8_t key = 11;
uint32_t value = 0;
bpf_args.map_fd = mapFd;
bpf_args.key = (uint64_t)&key;
bpf_args.value = (uint64_t)&value;
syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &bpf_args, sizeof(bpf_args));
```
