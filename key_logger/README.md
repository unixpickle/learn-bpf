# Overview

This is a Linux keylogger that uses BPF and kprobes.

# How it works

The kprobes facility effectively allows us to attach breakpoints to any spot in the kernel. We can then supply eBPF code to run every time the kprobe is hit. The eBPF code gets access to the registers before the kprobe, allowing it to inspect function arguments.

In this case, I put a kprobe at [input_event](https://elixir.bootlin.com/linux/v4.6/source/drivers/input/input.c#L429) in the kernel. This seems to be called whenever a key is pressed (it may also be called when the mouse is moved). The eBPF program pushes the arguments to a ring buffer. The userspace program reads from the ring buffer in a loop.
