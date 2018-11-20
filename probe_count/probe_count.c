#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include "kprobes.h"
#include "map_util.h"

int create_map();
int create_program();
int create_perf_event(const char* functionName);
uint32_t get_count(int mapFd);

int main(int argc, const char** argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <kernel_func>\n", argv[0]);
    return 1;
  }
  int mapFd = create_map();
  int progFd = create_program(mapFd);
  int perfFd = create_perf_event(argv[1]);
  if (attach_program(progFd, perfFd)) {
    perror("attach_program");
    return 1;
  }
  uint32_t oldCount = 0;
  while (1) {
    uint32_t count = get_count(mapFd);
    if (count != oldCount) {
      printf("func=%s count=%u\n", argv[1], count);
      oldCount = count;
    }
    usleep(100000);
  }
  return 0;
}

int create_map() {
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  bpf_args.map_type = BPF_MAP_TYPE_HASH;
  bpf_args.key_size = 1;
  bpf_args.value_size = 4;
  bpf_args.max_entries = 1;

  int mapFd = syscall(__NR_bpf, BPF_MAP_CREATE, &bpf_args, sizeof(bpf_args));
  if (mapFd < 0) {
    perror("create map");
    exit(1);
  }

  return mapFd;
}

int create_program(int mapFd) {
  struct bpf_insn program[] = {
      // Put the key into FP[-4].
      {BPF_ST | BPF_B | BPF_MEM, 10, 0, -4, 0},

      INC_BPF_MAP(mapFd, -4, -8)

      // Terminate the program.
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0},
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},
  };
  return load_kprobe_bpf(program, sizeof(program) / sizeof(struct bpf_insn));
}

int create_perf_event(const char* functionName) {
  delete_kprobe("probe_count");
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "p:kprobes/probe_count %s", functionName);
  int fd = create_open_kprobe("probe_count", cmd);
  if (fd < 0) {
    perror("create_open_kprobe");
    exit(1);
  }
  return fd;
}

uint32_t get_count(int mapFd) {
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));

  uint8_t key = 0;
  uint32_t value = 0;

  bpf_args.map_fd = mapFd;
  bpf_args.key = (uint64_t)&key;
  bpf_args.value = (uint64_t)&value;

  syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &bpf_args, sizeof(bpf_args));

  return value;
}
