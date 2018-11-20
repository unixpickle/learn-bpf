#include "ring_queue.h"
#include <assert.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <strings.h>
#include <syscall.h>
#include <unistd.h>

static void _read_map(ring_queue_t* queue, int idx, void* value);
static void _write_map(ring_queue_t* queue, int idx, void* value);

ring_queue_t* ring_queue_create(int capacity, int valueSize) {
  assert(valueSize >= 8);
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  bpf_args.map_type = BPF_MAP_TYPE_HASH;
  bpf_args.key_size = 4;
  bpf_args.value_size = valueSize;
  bpf_args.max_entries = capacity + 1;

  int mapFd = syscall(__NR_bpf, BPF_MAP_CREATE, &bpf_args, sizeof(bpf_args));
  if (mapFd < 0) {
    return NULL;
  }

  ring_queue_t* result = malloc(sizeof(ring_queue_t));
  result->fd = mapFd;
  result->capacity = capacity;
  result->value_size = valueSize;

  // Zero out the start/end pointer.
  void* zeros = malloc(valueSize);
  bzero(zeros, valueSize);
  _write_map(result, capacity, zeros);
  free(zeros);

  return result;
}

void ring_queue_destroy(ring_queue_t* queue) {
  close(queue->fd);
  free(queue);
}

int ring_queue_pop(ring_queue_t* queue, void* output) {
  int* startEnd = malloc(queue->value_size);
  _read_map(queue, queue->capacity, startEnd);
  if (startEnd[0] == startEnd[1]) {
    free(startEnd);
    return 0;
  }
  _read_map(queue, startEnd[0], output);
  startEnd[0] = (startEnd[0] + 1) % queue->capacity;
  _write_map(queue, queue->capacity, startEnd);
  free(startEnd);
  return 1;
}

static void _read_map(ring_queue_t* queue, int idx, void* value) {
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  uint32_t key = idx;
  bpf_args.map_fd = queue->fd;
  bpf_args.key = (uint64_t)&key;
  bpf_args.value = (uint64_t)value;
  syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &bpf_args, sizeof(bpf_args));
}

static void _write_map(ring_queue_t* queue, int idx, void* value) {
  union bpf_attr bpf_args;
  bzero(&bpf_args, sizeof(bpf_args));
  uint32_t key = idx;
  bpf_args.map_fd = queue->fd;
  bpf_args.key = (uint64_t)&key;
  bpf_args.value = (uint64_t)value;
  syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &bpf_args, sizeof(bpf_args));
}