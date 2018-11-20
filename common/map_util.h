// Read a value for the key FP[keyOffset] from the map
// specified by fd. The value pointer is put into R0.
#define READ_BPF_MAP(fd, keyOffset)                                          \
  {BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, fd}, {0, 0, 0, 0, 0}, \
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},                            \
      {BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, keyOffset},                     \
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem},

// Read a u32 for the key FP[keyOffset] from the map
// specified by fd. The value is loaded into R0.
#define READ_BPF_MAP_32(fd, keyOffset)                                       \
  {BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, fd}, {0, 0, 0, 0, 0}, \
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},                            \
      {BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, keyOffset},                     \
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem},               \
      {BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1, 0},                               \
      {BPF_LDX | BPF_MEM | BPF_W, 0, 0, 0, 0},

// Write a key stored in FP[keyOffset] with the value
// stored at FP[valOffset] in the map specified by fd.
#define WRITE_BPF_MAP(fd, keyOffset, valOffset)                              \
  {BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, fd}, {0, 0, 0, 0, 0}, \
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},                            \
      {BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, keyOffset},                     \
      {BPF_ALU64 | BPF_MOV | BPF_X, 3, 10, 0, 0},                            \
      {BPF_ALU64 | BPF_ADD | BPF_K, 3, 0, 0, valOffset},                     \
      {BPF_ALU | BPF_MOV | BPF_K, 4, 0, 0, BPF_ANY},                         \
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem},

// INC_BPF_MAP increments the 32-bit value for a given key
// and stores the resulting value in FP[valOffset].
#define INC_BPF_MAP(fd, keyOffset, valOffset)                                \
  {BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, fd}, {0, 0, 0, 0, 0}, \
      {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},                            \
      {BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, keyOffset},                     \
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem},               \
      {BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1, 0},                               \
      {BPF_LDX | BPF_MEM | BPF_W, 0, 0, 0, 0},                               \
      {BPF_ALU | BPF_ADD | BPF_K, 0, 0, 0, 1},                               \
      {BPF_STX | BPF_MEM | BPF_W, 10, 0, valOffset, 0},                      \
      {BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, fd},              \
      {0, 0, 0, 0, 0}, {BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0},           \
      {BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, keyOffset},                     \
      {BPF_ALU64 | BPF_MOV | BPF_X, 3, 10, 0, 0},                            \
      {BPF_ALU64 | BPF_ADD | BPF_K, 3, 0, 0, valOffset},                     \
      {BPF_ALU | BPF_MOV | BPF_K, 4, 0, 0, BPF_ANY},                         \
      {BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem},
