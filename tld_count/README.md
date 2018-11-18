# Overview

This program monitors outgoing DNS requests and logs the TLD frequency. The output looks something like this:

```
TLD freqs: com=1 
TLD freqs: com=1 net=1 
TLD freqs: edu=1 com=1 net=1 
TLD freqs: edu=1 com=2 net=1
...
```

# How it works

To capture DNS requests, the program captures all packets, and performs some filtering. First, it filters for UDP packets, then for outgoing port 53. Next, it scans the packet to find the last domain name label, and copies this onto the stack. Finally, it increments a counter in a BPF map using the label as a key.