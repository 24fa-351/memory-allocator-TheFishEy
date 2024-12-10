
#ifndef HEAP_MANAGER_H
#define HEAP_MANAGER_H

#include <stdlib.h>

// malloc
void* malloc(size_t size);

// free
void free(void* addr);

// realloc
void* realloc(void* addr, size_t size);


#endif // HEAP_MANAGER_H
