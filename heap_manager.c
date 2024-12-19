#include "heap_manager.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN_BLOCK_SIZE 4

// define memory block size and adr
typedef struct {
  size_t size;
  char *addr;
} heap_block;

// track free blocks aka metadata
typedef struct {
  heap_block *blocks;

  size_t count;
  size_t capacity;
} heap_metadata;

static heap_metadata free_blocks_heap; // global heap metadata
static pthread_mutex_t heap_lock =
    PTHREAD_MUTEX_INITIALIZER; // add mutex for thread locking

// min heap
void init_heap(size_t size) {
  free_blocks_heap.blocks =
      malloc(sizeof(heap_block) * size); // heap memory allocation
  free_blocks_heap.count = 1;            // intialize with a large block
  free_blocks_heap.capacity = size;

  // initialize the first block
  free_blocks_heap.blocks[0].size = size;
  free_blocks_heap.blocks[0].addr = (char *)free_blocks_heap.blocks;
}

// malloc
void *malloc(size_t size) {
  pthread_mutex_lock(&heap_lock);

  if (size < MIN_BLOCK_SIZE)
    size = MIN_BLOCK_SIZE;

  // for i in free blocks
  for (size_t i = 0; i < free_blocks_heap.count; i++) {
    heap_block *block = &free_blocks_heap.blocks[i];

    // if block large enough
    if (block->size >= size) {

      // split if size too large
      if (block->size > size + MIN_BLOCK_SIZE) {
        heap_block new_block;
        new_block.size = block->size - size; // adjust size of remianing block
        new_block.addr = block->addr + size; // address

        // reduce size
        block->size = size;

        if (free_blocks_heap.count >= free_blocks_heap.capacity) {
          // double capcaity
          free_blocks_heap.capacity *= 2;
          free_blocks_heap.blocks =
              realloc(free_blocks_heap.blocks,
                      sizeof(heap_block) * free_blocks_heap.capacity);
        }

        // add new block to list
        free_blocks_heap.blocks[free_blocks_heap.count++] = new_block;
      }

      void *addr = block->addr;

      // remove allocated block from list
      memmove(&free_blocks_heap.blocks[i], &free_blocks_heap.blocks[i + 1],
              sizeof(heap_block) * (free_blocks_heap.count - i - 1));
      free_blocks_heap.count--;

      // unlockign mutex
      pthread_mutex_unlock(&heap_lock);
      return addr;
    }
  }

  fprintf(stderr, "Error: No suitable memory block found for size %zu.\n",
          size);
  pthread_mutex_unlock(&heap_lock);
  return NULL;
}

void free(void *addr) {
  if (addr == NULL) // ignore null pointers
    return;

  pthread_mutex_lock(&heap_lock);

  // double free detection
  for (size_t i = 0; i < free_blocks_heap.count; i++) {
    // if address is already on list
    if (free_blocks_heap.blocks[i].addr == addr) {
      fprintf(stderr, "Error: Double free detected at %p\n", addr);

      pthread_mutex_unlock(&heap_lock);
      return;
    }
  }

  // new block for freed memory
  heap_block freed_block;
  freed_block.size = ((heap_block *)addr - 1)->size; // metadata size
  freed_block.addr = addr;

  // add block to list
  if (free_blocks_heap.count >= free_blocks_heap.capacity) {

    free_blocks_heap.capacity *= 2;
    free_blocks_heap.blocks =
        realloc(free_blocks_heap.blocks,
                sizeof(heap_block) * free_blocks_heap.capacity);
  }
  free_blocks_heap.blocks[free_blocks_heap.count++] = freed_block;

  // sort free list
  for (size_t i = 0; i < free_blocks_heap.count - 1; i++) {
    for (size_t j = i + 1; j < free_blocks_heap.count; j++) {

      if (free_blocks_heap.blocks[i].addr > free_blocks_heap.blocks[j].addr) {
        heap_block temp = free_blocks_heap.blocks[i];

        free_blocks_heap.blocks[i] = free_blocks_heap.blocks[j];
        free_blocks_heap.blocks[j] = temp;
      }
    }
  }

  // merdge for fragmentation errors
  for (size_t i = 0; i < free_blocks_heap.count - 1; i++) {
    heap_block *current = &free_blocks_heap.blocks[i];
    heap_block *next = &free_blocks_heap.blocks[i + 1];

    // if curr and next adjacent
    if (current->addr + current->size == next->addr) {
      // merdge
      current->size += next->size;
      memmove(&free_blocks_heap.blocks[i + 1], &free_blocks_heap.blocks[i + 2],
              sizeof(heap_block) * (free_blocks_heap.count - i - 2));
      free_blocks_heap.count--;
      i--;
    }
  }

  pthread_mutex_unlock(&heap_lock);
}

// realloc
void *realloc(void *addr, size_t size) {

  // if address == null, realloc acts as malloc
  if (addr == NULL) {
    return malloc(size);
  }

  // if size == 0, realloc acts as free
  if (size == 0) {
    free(addr);
    return NULL;
  }

  pthread_mutex_lock(&heap_lock);

  // locate the current block
  heap_block *current_block = (heap_block *)addr - 1;

  if (current_block->size >= size) {
    pthread_mutex_unlock(&heap_lock);
    return addr;
  }

  void *new_addr = malloc(size);
  if (new_addr == NULL) {
    pthread_mutex_unlock(&heap_lock);
    return NULL;
  }

  // copy old data to  new block
  memcpy(new_addr, addr, current_block->size);

  // free old block
  free(addr);

  pthread_mutex_unlock(&heap_lock);

  return new_addr;
}
