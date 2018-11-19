# Overview

This program tallies network reads per user ID. The output looks like this:

```
UID amount read: 122=27007 0=180 
UID amount read: 122=27007 0=274 
UID amount read: 122=28152 0=1170 
UID amount read: 122=28152 0=1265 
UID amount read: 122=28704 0=1415
```

# How it works

Instead of using a packet filter, I chose to use kprobes for the coolness factor. I attached a kprobe at the return of `sock_read_iter`, which has the following definition:

```c
static ssize_t sock_read_iter(struct kiocb *iocb, struct iov_iter *to)
```

I sum up the return values per UID, which I get using the `get_current_uid_gid()` BPF helper function. I store these sums in a BPF map.