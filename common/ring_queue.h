//
// Functions for queues between userspace and BPF programs.
//

#ifndef __RING_QUEUE_H__
#define __RING_QUEUE_H__

#include "map_util.h"

typedef struct {
  int fd;
  int capacity;
  int value_size;
} ring_queue_t;

// Create a ring buffer BPF map.
//
// The capacity specifies how many elements can be pushed
// before old elements are removed.
// The valueSize must be at least 8.
//
// Returns NULL on failure.
ring_queue_t* ring_queue_create(int capacity, int valueSize);

// Dispose of the ring queue.
void ring_queue_destroy(ring_queue_t* queue);

// Pop the next element from a ring buffer.
// Returns 1 if an element is popped, 0 otherwise.
int ring_queue_pop(ring_queue_t* queue, void* output);

#define PUSH_QUEUE(queue, valOffset, scratchOffset, keyOffset)               \
  {BPF_ST | BPF_MEM | BPF_W, 10, 0, keyOffset, queue->capacity},             \
      READ_BPF_MAP(queue->fd, keyOffset){BPF_JMP | BPF_JNE | BPF_K, 0, 0, 2, \
                                         0},                                 \
      {BPF_ALU | BPF_MOV | BPF_K, 0, 0, 0, 0},                               \
      {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},                                      \
      {BPF_LDX | BPF_MEM | BPF_W, 1, 0, 0, 0},                               \
      {BPF_STX | BPF_MEM | BPF_W, 10, 1, scratchOffset, 0},                  \
      {BPF_LDX | BPF_MEM | BPF_W, 1, 0, 4, 0},                               \
      {BPF_STX | BPF_MEM | BPF_W, 10, 1, scratchOffset + 4, 0},              \
      WRITE_BPF_MAP(queue->fd, scratchOffset + 4, valOffset){                \
          BPF_LDX | BPF_MEM | BPF_W, 1, 10, scratchOffset + 4, 0},           \
      {BPF_ALU | BPF_ADD | BPF_K, 1, 0, 0, 1},                               \
      {BPF_ALU | BPF_MOD | BPF_K, 1, 0, 0, queue->capacity},                 \
      {BPF_STX | BPF_MEM | BPF_W, 10, 1, scratchOffset + 4, 0},              \
      {BPF_ST | BPF_MEM | BPF_W, 10, 0, keyOffset, queue->capacity},         \
      WRITE_BPF_MAP(queue->fd, keyOffset, scratchOffset)

#endif