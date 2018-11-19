#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include "kprobes.h"

int create_map();
int create_program();
int create_perf_event();
void print_map(int mapFd);

int main() {
  int mapFd = create_map();
  int progFd = create_program(mapFd);
  int perfFd = create_perf_event();
  if (attach_program(progFd, perfFd)) {
    perror("attach_program");
    return 1;
  }
  while (1) {
    sleep(1);
    print_map(mapFd);
  }
  return 0;
}

int create_map() {
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  bpf_args.map_type = BPF_MAP_TYPE_HASH;
  bpf_args.key_size = 4;
  bpf_args.value_size = 4;
  bpf_args.max_entries = 32;

  int mapFd = syscall(__NR_bpf, BPF_MAP_CREATE, &bpf_args, sizeof(bpf_args));
  if (mapFd < 0) {
    perror("create map");
    exit(1);
  }

  return mapFd;
}

int create_program(int mapFd) {
  struct bpf_insn program[] = {
      // R7 = function return value (bytes written).
      {BPF_LDX | BPF_MEM | BPF_W, 7, 1, 10 * 8, 0},

      // Put the UID into FP[-4].
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_current_uid_gid},
      {BPF_STX | BPF_W | BPF_MEM, 10, 0, -4, 0},

      // Load the map file descriptor into R1.
      {BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, mapFd},
      {0, 0, 0, 0, 0},
      // Load FP[-4] into R2.
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},
      {BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, -4},
      // Lookup the key.
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem},

      // Check if the map value is NULL.
      {BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1, 0},
      // R0 = *(u32*)R0
      {BPF_LDX | BPF_MEM | BPF_W, 0, 0, 0, 0},
      // R0 += R7
      {BPF_ALU | BPF_ADD | BPF_X, 0, 7, 0, 0},
      // FP[-8] = R0
      {BPF_STX | BPF_MEM | BPF_W, 10, 0, -8, 0},

      // Load the map file descriptor into R1.
      {BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, mapFd},
      {0, 0, 0, 0, 0},
      // Set R2 to &FP[-4].
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},
      {BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, -4},
      // Set R3 to &FP[-8].
      {BPF_ALU64 | BPF_MOV | BPF_X, 3, 10, 0, 0},
      {BPF_ALU64 | BPF_ADD | BPF_K, 3, 0, 0, -8},
      // R4 = BPF_ANY
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
  int fd = create_open_kprobe("sock_read_iter_ret",
                              "r:kprobes/sock_read_iter_ret "
                              "sock_read_iter");
  if (fd < 0) {
    perror("create_open_kprobe");
    exit(1);
  }
  return fd;
}

void print_map(int mapFd) {
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));

  uint32_t key = 0xffffffff;
  uint32_t next_key = 0;
  uint32_t value = 0;

  bpf_args.map_fd = mapFd;
  bpf_args.key = (uint64_t)&key;
  bpf_args.next_key = (uint64_t)&next_key;

  printf("UID amount read: ");
  while (
      !syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &bpf_args, sizeof(bpf_args))) {
    key = next_key;

    bzero(&bpf_args, sizeof(bpf_args));
    bpf_args.map_fd = mapFd;
    bpf_args.key = (uint64_t)&key;
    bpf_args.value = (uint64_t)&value;
    syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &bpf_args, sizeof(bpf_args));

    bzero(&bpf_args, sizeof(bpf_args));
    bpf_args.map_fd = mapFd;
    bpf_args.key = (uint64_t)&key;
    bpf_args.next_key = (uint64_t)&next_key;

    printf("%u=%u ", key, value);
  }
  printf("\n");
}
