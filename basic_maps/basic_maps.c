#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syscall.h>
#include <unistd.h>

int main(int argc, const char** argv) {
  int socket = create_socket();
  int mapFd = create_map();
  attach_filter(fd, mapFd);
  read_loop(fd);
  close(fd);
  close(mapFd);
  return 0;
}

int create_socket() {
  int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    perror("open socket");
    exit(1);
  }
}

int create_map() {
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  bpf_args.map_type = BPF_MAP_TYPE_HASH;
  bpf_args.key_size = 1;
  bpf_args.value_size = 4;
  bpf_args.max_entries = 13;

  int mapFd = syscall(__NR_bpf, BPF_MAP_CREATE, &bpf_args, sizeof(bpf_args));
  if (mapFd < 0) {
    perror("create map");
    exit(1);
  }
  return mapFd;
}

void attach_filter(int fd, int mapFd) {
  struct bpf_insn program[] = {
      // Get a random 32-bit value in R0.
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_prandom_u32},
      // Turn into a random 4-bit value.
      {BPF_ALU | BPF_AND | BPF_K, 0, 0, 0, 0xf},
      // Turn into a value between 0 and 13.
      {BPF_ALU | BPF_MOD | BPF_K, 0, 0, 0, 13},
      // Store the value into FP[-4].
      {BPF_STX | BPF_MEM | BPF_B, 10, 0, -4, 0},

      // Load the map file descriptor into R1.
      {BPF_ALU | BPF_MOV | BPF_K, 1, 0, 0, (sint32_t)mapFd},
      // Load FP into R2.
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},
      // Put FP[-4] in R2.
      {BPF_ALU64 | BPF_SUB | BPF_K, 2, 0, 0, -4},
      // Lookup the current map value.
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem},

      // Check if the map value is NULL.
      {BPF_JMP | BPF_JE | BPF_K, 0, 0, 1, 0},
      // Load the value out of (u32*)R0 into R0.
      {BPF_LD | BPF_MEM | BPF_W, 0, 0, 0, 0},
      // Increment the value in the map.
      {BPF_ALU | BPF_ADD | BPF_K, 0, 0, 0, 1},
      // Store the value into FP[-8].
      {BPF_STX | BPF_MEM | BPF_W, 10, 0, -8, 0},

      // Load the map file descriptor into R1.
      {BPF_ALU | BPF_MOV | BPF_K, 1, 0, 0, (sint32_t)mapFd},
      // Load FP into R2.
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},
      // Put FP[-4] in R2.
      {BPF_ALU64 | BPF_SUB | BPF_K, 2, 0, 0, -4},
      // Load FP into R3.
      {BPF_ALU64 | BPF_MOV | BPF_X, 3, 10, 0, 0},
      // Put FP[-8] in R3.
      {BPF_ALU64 | BPF_SUB | BPF_K, 3, 0, 0, -8},
      // Set the BPF_ANY flag.
      {BPF_ALU | BPF_MOV | BPF_K, 4, 0, 0, 0, BPF_ANY},
      // Set the current map value.
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem},

      // Accept the packet.
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0x4000},
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},
  };

  char* logBuffer = (char*)malloc(0x10000);
  bzero(logBuffer, 0x10000);
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  bpf_args.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  bpf_args.insns = (uint64_t)program;
  bpf_args.insn_cnt = sizeof(program) / sizeof(struct bpf_insn);
  bpf_args.license = (uint64_t) "GPL";
  bpf_args.log_level = 1;
  bpf_args.log_size = 0x10000;
  bpf_args.log_buf = (uint64_t)logBuffer;
  bpf_args.kern_version = 0;

  int filter = syscall(__NR_bpf, BPF_PROG_LOAD, &bpf_args, sizeof(bpf_args));
  if (filter < 0) {
    perror("load program");
    fprintf(stderr, "%s\n", logBuffer);
    exit(1);
  }

  int res = setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF, &filter, sizeof(filter));
  if (res < 0) {
    perror("set BPF program");
    exit(1);
  }
}

void read_loop(int fd) {
  char* buf = malloc(0x10000);
  while (1) {
    if (recv(fd, buf, 0x10000, 0) < 0) {
      perror("recv");
      return 1;
    }
  }
}
