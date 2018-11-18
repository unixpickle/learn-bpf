#ifndef __KPROBES_UTIL_H__
#define __KPROBES_UTIL_H__

#include <linux/bpf.h>

//
// Utilities for creating and using kprobe perf events.
//

// Create a kprobe, open it, and return the file descriptor.
// Returns a negative value in the case of failure.
int create_open_kprobe(const char* name, const char* cmd);

// Create a kprobe using the name and creation command.
// A command looks like "p:kprobes/my_app sys_write".
// Returns a negative value on failure.
int create_kprobe(const char* name, const char* cmd);

// Open an existing kprobe given it's name.
// Returns a negative value on failure.
int open_kprobe(const char* name);

// Attach a BPF program to an open kprobe.
// Returns 0 on success, -1 on failure.
int attach_program(int progFd, int perfFd);

// Load a kprobe BPF program.
// Dies on failure, with a verbose error message.
int load_kprobe_bpf(struct bpf_insn* program, int numInsns);

#endif