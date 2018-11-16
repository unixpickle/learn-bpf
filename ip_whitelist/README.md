# Overview

This is a TCP socket server that only accepts connections from a particular set of IPv4 addresses. We're not talking "accept all connections, then close the non-whitelisted ones". We're talking "non-whitelisted hosts simply cannot get any TCP responses". Non-whitelisted hosts will be stuck in the "connecting" phase forever, as if the port weren't open at all.

# How it works

It's possible to use `SO_ATTACH_FILTER` on a `SOCK_STREAM` socket in order to filter packets processed for a socket. We then construct a BPF program that drops packets that aren't from whitelisted hosts. For one host, the program looks like this:

```
(000) ld       [-0x100000 + 12]
(001) jeq      #0x1020304       jt 2	jf 3
(002) ret      #262144
(003) ret      #0
```

Line (000) loads the source IP address from the IP header, which is accessed via the magical -0x100000 offset. Line (001) compares it against an IP, in this case 1.2.3.4. Line (002) is the "accept" return, and line (003) is the "reject" return.