#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/mman.h>
#include "mem_common.h"

//#include "memdom_lib.h"




/* Memory domain metadata structure
 * A memory domain is an anonymously mmap-ed memory area.
 * mmap() is called when udom_alloc is called the first time for a given udom 
 * Subsequent allocation does not invoke mmap(), instead, it allocates memory from the mmaped
 * area and update related metadata fields. 
 */
struct udom_metadata_struct {
    int udom_id;
    void *start;    // start of this udom's addr (inclusive)
    unsigned long total_size; // the total memory size of this udom
    struct free_list_struct *free_list_head;
    struct free_list_struct *free_list_tail;
    pthread_mutex_t mlock;  // protects this udom in sn SMP environment
};
extern int cnt;
void* mem_start[3];
pthread_mutex_t mprotect_mutex[3];
extern struct udom_metadata_struct *udom[MAX_MEMDOM];


//#define UDOM_INTERCEPT_MALLOC
#ifdef UDOM_INTERCEPT_MALLOC
#define malloc(sz) udom_alloc(udom_private_id(), sz)
#define calloc(a,b) udom_alloc(udom_private_id(), a*b)
#define free(addr) udom_free(addr)
#endif


/* Create a memory domain and return it to user */
int udom_create(void);

/* Remove a udom from kernel */
int udom_kill(int udom);

/* Allocate memory region in memory domain */
void *udom_mmap(int udom_id, 
                  void * addr, unsigned long len, 
                  unsigned long prot, unsigned long flags, 
                  unsigned long fd, unsigned long pgoff);

/* Allocate npages pages in memory domain udom */
void *udom_alloc(int udom_id, unsigned long nbytes);
void *udom_malloc(unsigned long nbytes);

/* Deallocate npages pages in memory domain udom */
void udom_free(void* data);

/* Get the calling thread's defualt udom id */
int udom_private_id(void);

/*Set protection on a udom */
int udom_mprotect(unsigned long udom_id, void *addr, unsigned long len, unsigned long orig_prot);

void ufree_list_init(int udom_id);

