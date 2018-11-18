#include "kprobes.h"
#include <linux/limits.h>
#include <linux/perf_event.h>
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