# learn-bpf

In this repository, I'm going to learn about the [Berkeley packet filter](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) and eBPF.

BPF is much more than just a packet filter. It is a powerful byte-code that can be used for various purposes. For example, you can attach a BPF filter to a kprobe, effectively allowing you to write a custom checkpoint that you load dynamically into the kernel.
