#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syscall.h>
#include <unistd.h>
#include "map_util.h"

int create_socket();
int create_map();
void attach_filter(int fd, int mapFd);
void read_loop(int fd, int mapFd);
void print_map(int mapFd);

int main(int argc, const char** argv) {
  int fd = create_socket();
  int mapFd = create_map();
  attach_filter(fd, mapFd);
  read_loop(fd, mapFd);
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
  bpf_args.key_size = 16;
  bpf_args.value_size = 4;
  bpf_args.max_entries = 32;

  int mapFd = syscall(__NR_bpf, BPF_MAP_CREATE, &bpf_args, sizeof(bpf_args));
  if (mapFd < 0) {
    perror("create map");
    exit(1);
  }
  return mapFd;
}

void attach_filter(int fd, int mapFd) {
  struct bpf_insn program[] = {
      // Set R6 = R1 for BPF_LD|BPF_ABS insns.
      {BPF_ALU64 | BPF_MOV | BPF_X, 6, 1, 0, 0},
      // Get the protocol field from the IPv4 header.
      {BPF_LD | BPF_B | BPF_ABS, 0, 0, 0, -0x100000 + 9},
      // Check if protocol == UDP.
      {BPF_JMP | BPF_JEQ, 0, 0, 2, 0x11},
      // Drop packet.
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0},
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},

      // Get the IPv4 header length into R0.
      {BPF_LD | BPF_B | BPF_ABS, 0, 0, 0, -0x100000},
      {BPF_ALU | BPF_AND | BPF_K, 0, 0, 0, 0xf},
      {BPF_ALU | BPF_MUL | BPF_K, 0, 0, 0, 4},
      // Move IPv4 header length into R7.
      {BPF_ALU | BPF_MOV | BPF_X, 7, 0, 0, 0},

      // Read the destination port into R0.
      {BPF_LD | BPF_H | BPF_IND, 0, 7, 0, -0x100000 + 2},
      // Check if port is 53 (DNS).
      {BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, 53},
      // Drop packet.
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0},
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},

      // R7 points to the current name label.
      {BPF_ALU | BPF_ADD | BPF_K, 7, 0, 0, -0x100000 + 20},
      // R8 points to the previous name label.
      {BPF_ALU | BPF_MOV | BPF_X, 8, 7, 0, 0},

#define LABEL_LOOP_CONTENTS                    \
  {BPF_LD | BPF_B | BPF_IND, 0, 7, 0, 0},      \
      {BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3, 0}, \
      {BPF_ALU | BPF_MOV | BPF_X, 8, 7, 0, 0}, \
      {BPF_ALU | BPF_ADD | BPF_X, 7, 0, 0, 0}, \
      {BPF_ALU | BPF_ADD | BPF_K, 7, 0, 0, 1},
#define LABEL_LOOP_2 LABEL_LOOP_CONTENTS LABEL_LOOP_CONTENTS
#define LABEL_LOOP_4 LABEL_LOOP_2 LABEL_LOOP_2
#define LABEL_LOOP_8 LABEL_LOOP_4 LABEL_LOOP_4
#define LABEL_LOOP_16 LABEL_LOOP_8 LABEL_LOOP_8
#define LABEL_LOOP_32 LABEL_LOOP_16 LABEL_LOOP_16
#define LABEL_LOOP_64 LABEL_LOOP_32 LABEL_LOOP_32
#define LABEL_LOOP_128 LABEL_LOOP_64 LABEL_LOOP_64
      LABEL_LOOP_128 LABEL_LOOP_128

      // R8 now points to the size field for the final label.

      // R7 = *(u8*)R8 (size field).
      {BPF_LD | BPF_B | BPF_IND, 0, 8, 0, 0},
      {BPF_ALU | BPF_MOV | BPF_X, 7, 0, 0, 0},

// Copy the label into FP[-32], writing zeros once
// we pass the label length.
#define COPY_LOOP_CONTENTS(offset)                                             \
  {BPF_ALU | BPF_MOV | BPF_X, 0, 7, 0, 0},                                     \
      {BPF_JMP | BPF_JGT | BPF_K, 0, 0, 3, 0x100},                             \
      {BPF_LD | BPF_B | BPF_IND, 0, 8, 0, offset + 1},                         \
      {BPF_ALU | BPF_SUB | BPF_K, 7, 0, 0, 1}, {BPF_JMP | BPF_JA, 0, 0, 1, 0}, \
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0},                                 \
      {BPF_STX | BPF_B | BPF_MEM, 10, 0, -32 + offset, 0},
#define COPY_LOOP_2(x) COPY_LOOP_CONTENTS(x) COPY_LOOP_CONTENTS(x + 1)
#define COPY_LOOP_4(x) COPY_LOOP_2(x) COPY_LOOP_2(x + 2)
#define COPY_LOOP_8(x) COPY_LOOP_4(x) COPY_LOOP_4(x + 4)
#define COPY_LOOP_16(x) COPY_LOOP_8(x) COPY_LOOP_8(x + 8)
      COPY_LOOP_16(0) COPY_LOOP_16(16)

      // Increment the TLD's count in the map.
      INC_BPF_MAP(mapFd, -32, -36)

      // Accept the packet.
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0x4000},
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},
  };

  char* logBuffer = (char*)malloc(0x100000);
  bzero(logBuffer, 0x100000);
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  bpf_args.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  bpf_args.insns = (uint64_t)program;
  bpf_args.insn_cnt = sizeof(program) / sizeof(struct bpf_insn);
  bpf_args.license = (uint64_t) "GPL";
  bpf_args.log_level = 1;
  bpf_args.log_size = 0x100000;
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

void read_loop(int fd, int mapFd) {
  unsigned char* buf = malloc(0x10000);
  while (1) {
    if (recv(fd, buf, 0x10000, 0) < 0) {
      perror("recv");
      return;
    }
    print_map(mapFd);
  }
}

void print_map(int mapFd) {
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  unsigned char key[33];
  unsigned char next_key[33];
  bzero(key, sizeof(key));
  bzero(next_key, sizeof(next_key));

  uint32_t value = 0;
  bpf_args.map_fd = mapFd;
  bpf_args.key = (uint64_t)&key;
  bpf_args.next_key = (uint64_t)&next_key;

  printf("TLD freqs: ");
  while (
      !syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &bpf_args, sizeof(bpf_args))) {
    memcpy(key, next_key, sizeof(key));

    bzero(&bpf_args, sizeof(bpf_args));
    bpf_args.map_fd = mapFd;
    bpf_args.key = (uint64_t)&key;
    bpf_args.value = (uint64_t)&value;
    syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &bpf_args, sizeof(bpf_args));

    bzero(&bpf_args, sizeof(bpf_args));
    bpf_args.map_fd = mapFd;
    bpf_args.key = (uint64_t)&key;
    bpf_args.next_key = (uint64_t)&next_key;

    printf("%s=%u ", key, value);
  }
  printf("\n");
}
