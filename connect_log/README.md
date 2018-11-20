# Overview

This program logs every socket connection that is established, and the PID that made the connection. Here is what the output looks like while I run `curl http://google.com` on my home network:

```
PID 23157: connect: 127.0.0.53:53
PID 16746: connect: 192.168.1.1:53
PID 16746: connect: 192.168.1.1:53
PID 23157: connect: 172.217.10.78:80
```

PID 23157 is `curl`, and PID 16746 is `systemd-resolved`. As we can see, first curl asks `systemd-resolved` for the address, and then `systemd-resolved` asks my router for the address in turn. Finally, `curl` makes a connection to Google's server.

# How it works

This program attaches a kprobe to the `sys_connect` kernel function, and simply logs the arguments.