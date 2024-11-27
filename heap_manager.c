#include "heap_manager.h"

#define MIN_BLOCK_SIZE 4  

// define memory block size and adr
typedef struct {
  size_t size;  // size of the block
  char* addr;  // address of the block
} heap_block;

// Min-heap 
static heap_block* free_blocks_heap;

// initialize heap
void init_heap(size_t size) {
  free_blocks_heap = malloc(size);

  // first block == entire heap
  free_blocks_heap[0].size = size;
  free_blocks_heap[0].addr = (char*) free_blocks_heap;
}

// malloc
void* malloc(size_t size) {
  if (size < MIN_BLOCK_SIZE) size = MIN_BLOCK_SIZE;

  int i = 0;
  while (i < free_blocks_heap->size && free_blocks_heap[i].size < size) {
    i++;
  }

  
  if (i == free_blocks_heap->size) return NULL; // if no block


  heap_block* block = &free_blocks_heap[i];


  if (block->size > size + MIN_BLOCK_SIZE) {

    heap_block* new_block = (heap_block*) (block->addr + size);
    new_block->size = block->size - size;
    new_block->addr = (char*) new_block;

    block->size = size;
  }

  return block->addr;
}

void free(void* addr) {
  // search address with block
  int i = 0;
  while (i < free_blocks_heap->size && free_blocks_heap[i].addr != addr) {
    i++;
// free memory 
void free(void* addr) {

  int i = 0;
  while (i < free_blocks_heap->size && free_blocks_heap[i].addr != addr) {
    i++;
  }


  if (i == free_blocks_heap->size) return;

  heap_block* block = &free_blocks_heap[i];


  block->size = 0;
  block->addr = NULL;

}
