#ifndef MEMDOM_COMMON_H
#define MEMDOM_COMMON_H



/* Maximum heap size a memdom can use: 1GB */
//#define MEMDOM_HEAP_SIZE 0x40000000
#define MEMDOM_HEAP_SIZE 0x400000

#define MAX_MEMDOM 16

/* Minimum size of bytes to allocate in one chunk */
#define CHUNK_SIZE 64

/* MMAP flag for udom protected area */
#define MAP_MEMDOM	0x00800000	

/* Maximum heap size a udom can use: 4MB */
//#define MEMDOM_HEAP_SIZE 0x400000

/* Every allocated chunk of memory has this block header to record the required
 * metadata for the allocator to free memory
 */
struct block_header_struct {
    void *addr;
    int memdom_id;
    unsigned long size;    
};


/* Free list structure
 * A free list struct records a block of memory available for allocation.
 * memdom_alloc() allocates memory from the tail of the free list (usually the largest available block).
 * memdom_free() inserts free list to the head of the free list
 */
struct free_list_struct {
    void *addr;
    unsigned long size;
    struct free_list_struct *next;
};

#endif