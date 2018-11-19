# Overview

This is a helper command to count how many times a kernel function is called. You run it like so:

```
$ ./build/probe_count sys_write
func=sys_write count=5
func=sys_write count=10
func=sys_write count=12
...
```

where you can replace `sys_write` with any function defined in the kernel.

# How it works

This tool uses kprobes to attach a BPF program to a kernel function. The BPF program is simple: it just counts the number of times it is called.