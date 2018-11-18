#include "kprobes.h"
#include <inttypes.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <syscall.h>
#include <unistd.h>

int create_open_kprobe(const char* name, const char* cmd) {
  int res = open_kprobe(name);
  if (res >= 0) {
    return res;
  }

  res = create_kprobe(name, cmd);
  if (res < 0) {
    return res;
  }

  return open_kprobe(name);
}

int create_kprobe(const char* name, const char* cmd) {
  FILE* fp = fopen("/sys/kernel/debug/tracing/kprobe_events", "wab");
  if (!fp) {
    perror("fopen");
    exit(1);
  }
  if (fprintf(fp, "%s", cmd) < 0) {
    goto fail;
  }
  if (fflush(fp)) {
    goto fail;
  }
  fclose(fp);

  return 0;

fail:
  fclose(fp);
  return -1;
}

int open_kprobe(const char* name) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/kprobes/%s/id",
           name);
  FILE* fp = fopen(path, "rb");
  if (!fp) {
    return -1;
  }
  char config[512];
  fread(config, sizeof(config), 1, fp);
  fclose(fp);

  struct perf_event_attr attr;
  bzero(&attr, sizeof(attr));
  attr.config = strtol(config, NULL, 0);
  attr.type = PERF_TYPE_TRACEPOINT;
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  return syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
}

int attach_program(int progFd, int perfFd) {
  if (ioctl(perfFd, PERF_EVENT_IOC_SET_BPF, progFd) < 0) {
    return -1;
  }
  if (ioctl(perfFd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    return -1;
  }
  return 0;
}

int load_kprobe_bpf(struct bpf_insn* program, int numInsns) {
  char* logBuffer = (char*)malloc(0x10000);
  bzero(logBuffer, 0x10000);
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  bpf_args.prog_type = BPF_PROG_TYPE_KPROBE;
  bpf_args.insns = (uint64_t)program;
  bpf_args.insn_cnt = (uint64_t)numInsns;
  bpf_args.license = (uint64_t) "GPL";
  bpf_args.log_level = 1;
  bpf_args.log_size = 0x10000;
  bpf_args.log_buf = (uint64_t)logBuffer;
  bpf_args.kern_version = LINUX_VERSION_CODE;

  int filter = syscall(__NR_bpf, BPF_PROG_LOAD, &bpf_args, sizeof(bpf_args));
  if (filter >= 0) {
    return filter;
  }

  // Brute force the kernel version number.
  for (int i = 0; i < 255; ++i) {
    for (int j = 0; j < 255; ++j) {
      bpf_args.kern_version = KERNEL_VERSION(LINUX_VERSION_CODE >> 16, i, j);
      int filter =
          syscall(__NR_bpf, BPF_PROG_LOAD, &bpf_args, sizeof(bpf_args));
      if (filter >= 0) {
        return filter;
      }
    }
  }

  perror("load program");
  fprintf(stderr, "%s\n", logBuffer);
  exit(1);
}