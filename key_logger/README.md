# Overview

This is a Linux keylogger that uses BPF and kprobes.

# How it works

The kprobes mechanism allows us to attach breakpoints to any spot in the kernel. After creating a kprobe, we can supply a eBPF program to run every time the kprobe is hit. The eBPF code has access to the registers before the kprobe, allowing it to inspect function arguments.

In this case, I put a kprobe at [input_event](https://elixir.bootlin.com/linux/v4.6/source/drivers/input/input.c#L429) in the kernel. This is called for keyboard and mouse events, as well as events for other devices. The signature looks like so:

```c
void input_event(struct input_dev* dev,
                 unsigned int type,
                 unsigned int code,
                 int value);
```

The eBPF program is run for every `input_event()` call. It first checks that `type` is 1, which excludes everything but key events. It then pushes the type, code, and value to a ring buffer for the userspace program to read. The ring buffer is implemented using BPF maps in a fairly hacky way.
