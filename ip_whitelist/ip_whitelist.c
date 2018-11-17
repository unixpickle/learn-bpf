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

const int PORT = 1337;
const int USE_EBPF = 0;

void attach_whitelist(int fd, int count, const char** ips);
void attach_whitelist_ebpf(int fd, int count, const char** ips);
uint32_t parse_ip(const char* ip);

int main(int argc, const char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: ip_whitelist <source_ip> [source_ip ...]\n");
    return 1;
  }

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("open socket");
    return 1;
  }

  int option = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option,
                 sizeof(option)) < 0) {
    perror("set listen flags");
    return 1;
  }

  if (USE_EBPF) {
    attach_whitelist_ebpf(fd, argc - 1, argv + 1);
  } else {
    attach_whitelist(fd, argc - 1, argv + 1);
  }

  struct sockaddr_in bind_address;
  bind_address.sin_family = AF_INET;
  bind_address.sin_addr.s_addr = INADDR_ANY;
  bind_address.sin_port = htons(PORT);
  if (bind(fd, (struct sockaddr*)&bind_address, sizeof(bind_address)) < 0) {
    perror("bind");
    return 1;
  }

  if (listen(fd, 5) < 0) {
    perror("listen");
    return 1;
  }

  while (1) {
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    int client_socket =
        accept(fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (client_socket < 0) {
      perror("accept");
      return 1;
    }
    printf("Got connection from %08x\n", address.sin_addr.s_addr);
    close(client_socket);
  }

  return 0;
}

void attach_whitelist(int fd, int count, const char** ips) {
  int lastIdx = count * 2 + 1;
  struct sock_filter* instructions =
      (struct sock_filter*)malloc(sizeof(struct sock_filter) * (lastIdx + 1));
  struct sock_filter load_op = {0x20, 0, 0, ((uint32_t)-0x100000) + 12};
  struct sock_filter drop_op = {0x6, 0, 0, 0x00000000};
  struct sock_filter jump_op = {0x15, 0, 1, 0};
  struct sock_filter accept_op = {0x6, 0, 0, 0x00040000};
  memcpy(&instructions[0], &load_op, sizeof(load_op));
  memcpy(&instructions[lastIdx], &drop_op, sizeof(drop_op));
  for (int i = 0; i < count; ++i) {
    uint32_t ip = parse_ip(ips[i]);
    jump_op.k = ip;
    memcpy(&instructions[1 + i * 2], &jump_op, sizeof(jump_op));
    memcpy(&instructions[2 + i * 2], &accept_op, sizeof(accept_op));
  }

  struct sock_fprog prog = {
      lastIdx + 1,
      instructions,
  };

  int res = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
  free(instructions);
  if (res < 0) {
    perror("set BPF program");
    exit(1);
  }
}

void attach_whitelist_ebpf(int fd, int count, const char** ips) {
  int numInsns = count * 6 + 3;
  struct bpf_insn* instructions =
      (struct bpf_insn*)malloc(sizeof(struct bpf_insn) * numInsns);
  bzero(instructions, sizeof(struct bpf_insn) * numInsns);
  struct bpf_insn mov_to_r6 = {BPF_MOV | BPF_X | BPF_ALU64, 6, 1, 0, 0};
  struct bpf_insn load_first_op = {BPF_ABS | BPF_H | BPF_LD, 0, 0, 0,
                                   -0x100000 + 12};
  struct bpf_insn load_second_op = {BPF_ABS | BPF_H | BPF_LD, 0, 0, 0,
                                    -0x100000 + 14};
  struct bpf_insn exit_op = {BPF_JMP | BPF_EXIT, 0, 0, 0, 0};
  struct bpf_insn accept_op = {BPF_MOV | BPF_ALU64, 0, 0, 0, 0x40000};
  struct bpf_insn reject_op = {BPF_MOV | BPF_ALU64, 0, 0, 0, 0};
  struct bpf_insn jump_op = {BPF_JNE | BPF_K | BPF_JMP, 0, 0, 2, 0};
  memcpy(&instructions[0], &mov_to_r6, sizeof(mov_to_r6));
  memcpy(&instructions[numInsns - 2], &reject_op, sizeof(reject_op));
  memcpy(&instructions[numInsns - 1], &exit_op, sizeof(exit_op));
  for (int i = 0; i < count; ++i) {
    uint32_t ip = parse_ip(ips[i]);
    memcpy(&instructions[1 + i * 6], &load_first_op, sizeof(load_first_op));
    jump_op.imm = ip >> 16;
    jump_op.off = 4;
    memcpy(&instructions[2 + i * 6], &jump_op, sizeof(jump_op));
    memcpy(&instructions[3 + i * 6], &load_second_op, sizeof(load_second_op));
    jump_op.imm = ip & 0xffff;
    jump_op.off = 2;
    memcpy(&instructions[4 + i * 6], &jump_op, sizeof(jump_op));
    memcpy(&instructions[5 + i * 6], &accept_op, sizeof(accept_op));
    memcpy(&instructions[6 + i * 6], &exit_op, sizeof(exit_op));
  }

  char* logBuffer = (char*)malloc(0x10000);
  bzero(logBuffer, 0x10000);
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  bpf_args.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  bpf_args.insns = (uint64_t)instructions;
  bpf_args.insn_cnt = numInsns, bpf_args.license = (uint64_t) "BSD";
  bpf_args.log_level = 1;
  bpf_args.log_size = 0x10000;
  bpf_args.log_buf = (uint64_t)logBuffer;
  bpf_args.kern_version = 0;

  int filter = syscall(__NR_bpf, BPF_PROG_LOAD, &bpf_args, sizeof(bpf_args));
  free(instructions);
  if (filter < 0) {
    perror("bpf");
    fprintf(stderr, "%s\n", logBuffer);
    exit(1);
  }

  int res = setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF, &filter, sizeof(filter));
  if (res < 0) {
    perror("set BPF program");
    exit(1);
  }
}

uint32_t parse_ip(const char* ip) {
  int numDots = 0;
  int length = strlen(ip);
  for (int i = 0; i < length; ++i) {
    if (ip[i] == '.') {
      ++numDots;
    } else if (ip[i] < '0' || ip[i] > '9') {
      goto bad;
    }
  }
  if (numDots != 3) {
    goto bad;
  }
  char* part = malloc(length);
  int partLen = 0;
  int partIdx = 0;
  uint32_t result = 0;
  for (int i = 0; i < length; ++i) {
    if (ip[i] != '.') {
      part[partLen++] = ip[i];
      continue;
    }
    if (partLen == 0) {
      goto bad;
    }
    part[partLen] = 0;
    uint32_t partValue = (uint32_t)atoi(part);
    if (partValue > 255) {
      goto bad;
    }
    result |= (partValue << (24 - 8 * partIdx));
    partLen = 0;
    ++partIdx;
  }
  uint32_t partValue = (uint32_t)atoi(part);
  if (partValue > 255) {
    goto bad;
  }
  result |= partValue;
  return result;

bad:
  fprintf(stderr, "invalid IP: %s\n", ip);
  exit(1);
}
