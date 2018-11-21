#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "kprobes.h"
#include "ring_queue.h"

#define MAX_ADDR_SIZE (int)sizeof(struct sockaddr_un)

int create_program();
int create_perf_event();

int main() {
  ring_queue_t* queue = ring_queue_create(31, MAX_ADDR_SIZE + 8);
  if (!queue) {
    perror("ring_queue_create");
    return 1;
  }
  int progFd = create_program(queue);
  int perfFd = create_perf_event();
  if (attach_program(progFd, perfFd)) {
    perror("attach_program");
    return 1;
  }
  int value[MAX_ADDR_SIZE + 8];
  while (1) {
    while (ring_queue_pop(queue, &value)) {
      int addrSize = value[1];
      printf("PID %d: connect:", value[0]);
      if (addrSize == sizeof(struct sockaddr_in)) {
        struct sockaddr_in* addr = (struct sockaddr_in*)&value[2];
        addr->sin_addr.s_addr = ntohl(addr->sin_addr.s_addr);
        addr->sin_port = ntohs(addr->sin_port);
        printf(" %d.%d.%d.%d:%d", addr->sin_addr.s_addr >> 24,
               (addr->sin_addr.s_addr >> 16) & 0xff,
               (addr->sin_addr.s_addr >> 8) & 0xff,
               addr->sin_addr.s_addr & 0xff, addr->sin_port);
      } else if (addrSize == sizeof(struct sockaddr_un)) {
        struct sockaddr_un* addr = (struct sockaddr_un*)&value[2];
        printf(" UNIX(%s)", addr->sun_path);
      } else if (addrSize <= MAX_ADDR_SIZE) {
        unsigned char* addr = (char*)&value[2];
        for (int i = 0; i < addrSize; ++i) {
          printf(" %02x", addr[i]);
        }
      }
      printf("\n");
    }
    usleep(100000);
  }
  return 0;
}

int create_program(ring_queue_t* queue) {
  struct bpf_insn program[] = {
      // R6 = R1.
      {BPF_ALU64 | BPF_MOV | BPF_X, 6, 1, 0, 0},

#define ZERO_OFFSET(x) {BPF_ST | BPF_MEM | BPF_W, 10, 0, -(4 + x * 4), 0},
#define ZERO_2(x) ZERO_OFFSET(x) ZERO_OFFSET(x + 1)
#define ZERO_4(x) ZERO_2(x) ZERO_2(x + 2)
#define ZERO_8(x) ZERO_4(x) ZERO_4(x + 4)
#define ZERO_16(x) ZERO_8(x) ZERO_8(x + 8)
      // Zero out a large part of the stack.
      ZERO_16(0) ZERO_16(16) ZERO_16(24) ZERO_16(32) ZERO_16(48) ZERO_16(64)

      // FP[-(8 + MAX_ADDR_SIZE)] = PID.
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_current_pid_tgid},
      {BPF_STX | BPF_W | BPF_MEM, 10, 0, -(8 + MAX_ADDR_SIZE), 0},

      // R3 = RSI (pointer).
      {BPF_LDX | BPF_MEM | BPF_DW, 3, 6, 13 * 8, 0},
      // R2 = RDX (length).
      {BPF_LDX | BPF_MEM | BPF_W, 2, 6, 12 * 8, 0},

      // FP[-(4 + MAX_ADDR_SIZE)] = R2.
      {BPF_STX | BPF_MEM | BPF_W, 10, 2, -(4 + MAX_ADDR_SIZE)},
      // R1 = &FP[-MAX_ADDR_SIZE].
      {BPF_ALU64 | BPF_MOV | BPF_X, 1, 10, 0, 0},
      {BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, -MAX_ADDR_SIZE},
      // Check if R2 <= MAX_ADDR_SIZE
      {BPF_JMP | BPF_JGT | BPF_K, 2, 0, 1, MAX_ADDR_SIZE},
      // memcpy(FP[-MAX_ADDR_SIZE], address)
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_probe_read},

      PUSH_QUEUE(queue, -(8 + MAX_ADDR_SIZE), -(8 + MAX_ADDR_SIZE) * 2,
                 -(8 + MAX_ADDR_SIZE) * 2 - 4)

      // Terminate the program.
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0},
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},
  };
  return load_kprobe_bpf(program, sizeof(program) / sizeof(struct bpf_insn));
}

int create_perf_event() {
  int fd =
      create_open_kprobe("connect_log", "p:kprobes/connect_log sys_connect");
  if (fd < 0) {
    perror("create_open_kprobe");
    exit(1);
  }
  return fd;
}
