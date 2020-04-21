//#include <mutex>
//#include <thread>
#include "difc_mem.h"
#include "difc_api.h"

#define UDOM_ALIGN_MASK 0xF00000


#define LOGGING 0
#define __SOURCEFILE__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

FILE* fp;

struct udom_metadata_struct *udom[MAX_MEMDOM];
int cnt = 0;
//std::mutex so_mutex;

pthread_mutex_t so_mutex; 

    
static int mid;
static int central_udom;




/* Get calling thread's defualt udom id */
int udom_private_id(void){
    int rv = 4;
    char buf[1024];

    rlog("private udom id: %d\n", rv);    
    return rv;
}

void udom_dumpFreeListHead(int udom_id){
    struct free_list_struct *walk = udom[udom_id]->free_list_head;
    while ( walk ) {
        rlog("[%s] udom %d free_list addr: %p, sz: 0x%lx\n", 
                __func__, udom_id, walk->addr, walk->size);
        walk = walk->next;
    }

}

/* Insert a free list struct to the head of udom free list 
 * Reclaimed chunks are inserted to head
 */
void udom_free_list_insert_to_head(int udom_id, struct free_list_struct *new_free_list){
    int rv;
    struct free_list_struct *head = udom[udom_id]->free_list_head;
    if( head ) {
        new_free_list->next = head;
    }
    udom[udom_id]->free_list_head = new_free_list;
    rlog("[%s] udom %d inserted free list addr: %p, size: 0x%lx\n", __func__, udom_id, new_free_list->addr, new_free_list->size);
}

/* Initialize free list */
void udom_free_list_init(int udom_id){
    struct free_list_struct *new_free_list;

    /* The first free list should be the entire mmap region */
#ifdef UDOM_INTERCEPT_MALLOC
#undef malloc
#endif
    new_free_list = (struct free_list_struct*) malloc (sizeof(struct free_list_struct));
#ifdef UDOM_INTERCEPT_MALLOC
#define malloc(sz) udom_alloc(udom_private_id(), sz)
#endif
    new_free_list->addr = udom[udom_id]->start;
    new_free_list->size = udom[udom_id]->total_size;   
    new_free_list->next = NULL;
    udom[udom_id]->free_list_head = NULL;   // reclaimed chunk are inserted to head   
    udom[udom_id]->free_list_tail = new_free_list; 
    rlog("[%s] udom %d: free_list addr: %p, size: 0x%lx bytes\n", __func__, udom_id, new_free_list->addr, new_free_list->size);
}


/* Round up the number to the nearest multiple */
unsigned long udom_round_up(unsigned long numToRound, int multiple){
    int remainder = 0;
    if( multiple == 0 ) {
        return 0;
    }
    remainder = numToRound % multiple;
    if( remainder == 0 ) {
        return numToRound;
    }
    return numToRound + multiple - remainder;
}


/* Create memory domain and return it to user */
int udom_create(void){
    int udom_id;
    /*
    srand(time(0));
    std::unique_lock<std::mutex> lock(so_mutex);
    if (cnt < MAX_MEMDOM)
      udom_id = ++cnt;
    else
      udom_id = rand() % MAX_MEMDOM;
    lock.unlock();
    */
     //  pthread_mutex_lock(&so_mutex); 

    central_udom = sys_udom_alloc(0, 1);
    udom_id = central_udom;
    rlog("central_udom : %d\n", central_udom);

      //  pthread_mutex_unlock(&so_mutex); 

    // Allocate metadata to hold udom info 
#ifdef UDOM_INTERCEPT_MALLOC
#undef malloc
#endif
    udom[udom_id] = (struct udom_metadata_struct*) malloc(sizeof(struct udom_metadata_struct));
#ifdef UDOM_INTERCEPT_MALLOC
#define malloc(sz) udom_alloc(udom_private_id(), sz)
#endif
    udom[udom_id]->udom_id = udom_id;
    udom[udom_id]->start = NULL; // udom_alloc will do the actual mmap
    udom[udom_id]->total_size = 0;
    udom[udom_id]->free_list_head = NULL;
    udom[udom_id]->free_list_tail = NULL;
  // pthread_mutex_init(&udom[udom_id]->mlock, NULL);
    mid = udom_id;
    return udom_id;

}

/* Remove memory domain udom from kernel */
int udom_kill(int udom_id){
    int rv = 0;
    char buf[50];
    struct free_list_struct *free_list;

    /* Bound checking */
    if( udom_id > MAX_MEMDOM ) {
		fprintf(stderr, "udom_kill(%d) failed\n", udom_id);
        return -1;
    }

    /* Free mmap */
    if( udom[udom_id]->start ) {
        rv = munmap(udom[udom_id]->start, udom[udom_id]->total_size);
        if( rv != 0 ) {
            fprintf(stderr, "udom munmap failed, start: %p, sz: 0x%lx bytes\n", udom[udom_id]->start, udom[udom_id]->total_size);
        }
    }

    /* Free all free_list_struct in this udom */
    free_list = udom[udom_id]->free_list_head;
    while( free_list ) {
        struct free_list_struct *tmp = free_list;
        free_list = free_list->next;
      //  rlog("freeing free_list addr: %p, size: 0x%lx bytes\n", tmp->addr, tmp->size);
#ifdef UDOM_INTERCEPT_MALLOC
#undef free
#endif
        free(tmp);
#ifdef UDOM_INTERCEPT_MALLOC
#define free(addr) udom_free(addr)
#endif
    }

        /* Free udom metadata */
#ifdef UDOM_INTERCEPT_MALLOC
#undef free
#endif
    free(udom[udom_id]);
#ifdef UDOM_INTERCEPT_MALLOC
#define free(addr) udom_free(addr)
#endif
    
    return rv;
}


/* mmap memory in udom 
 * Caller should hold udom lock
 */
void *udom_mmap(int udom_id,
                  void* addr, unsigned long len, 
                  unsigned long prot, unsigned long flags, 
                  unsigned long fd, unsigned long pgoff){
    void *base = NULL;
    int rv = 0;
    char buf[50];
    size_t alignment = 1024 * 1024;
    unsigned long addr_temp=(unsigned long) addr;


    //addr &= UDOM_ALIGN_MASK;
    //len &= UDOM_ALIGN_MASK;
    if(addr ==NULL)
    {
       addr= (void*)0x100000;
    }

     if (((unsigned long)addr % alignment) != 0)
        { 
         addr_temp &= UDOM_ALIGN_MASK;
         addr=(void*) addr_temp;
          printf("[udom_mmap] the addr %p, is not aligned\n", addr);

          }

      if ((len % alignment) != 0)
        {    len &= UDOM_ALIGN_MASK;
          printf("[udom_mmap] the len %ld, is aligned\n", len); 
          
          }  

    /* Call the actual mmap with udom flag */
    //fp = fopen("/home/zt/log/log", "a+");

    //base = (void*) mmap(addr, len, prot, flags , fd, pgoff);
    addr_temp = sys_udom_mmap(udom_id,(unsigned long)addr, len, prot, flags , fd);

    base=(void *)addr_temp;
    printf("[udom_mmap] base is %p\n", base);   

    //pthread_mutex_lock(&so_mutex); 
   // udom_mprotect(base, len, prot, central_udom); 
   // lock.unlock();
    if( base == MAP_FAILED ) {
        perror("udom_mmap: ");
        return NULL;
    }
    udom[udom_id]->start = base;
    udom[udom_id]->total_size = len;
    printf("Memdom ID %d mmaped at %p\n", udom_id, base);

    printf("[%s] udom %d mmaped 0x%lx bytes at %p\n", __func__, udom_id, len, base);
    return base;
}


/*
    PROT_NONE  The memory cannot be accessed at all.
    PROT_READ  The memory can be read.
    PROT_WRITE The memory can be modified.
    PROT_EXEC  The memory can be executed.
*/
int udom_mprotect(unsigned long udom_id, void *addr, unsigned long len, unsigned long orig_prot)
{

    size_t alignment = 1024 * 1024;
    unsigned long addr_temp=(unsigned long) addr;
    char *memblock = NULL;

    if(udom_id == 0){
        printf("[udom_mprotect] Not valid udom_id, create a udom first\n");
        return -1;
    }

    if (((unsigned long)addr % alignment) != 0)
        { 
         addr_temp &= UDOM_ALIGN_MASK;
         addr=(void*) addr_temp;
          printf("[udom_mprotect] the addr %p, is not aligned\n", addr);
          return -1;

          }

    if ((len % alignment) != 0)
        {    len &= UDOM_ALIGN_MASK;
             printf("[udom_mprotect] the len %ld, is not aligned\n", len); 
             return -1;
          
          } 

    if( udom[udom_id] == NULL || !udom[udom_id]->start ) {
        /* Call mmap to set up initial memory region */
        memblock = (char*) udom_mmap(udom_id, addr, MEMDOM_HEAP_SIZE, 
                                       orig_prot , MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if( memblock == MAP_FAILED ) 
        {
            fprintf(stderr, "Failed to udom_alloc using mmap for udom %ld\n", udom_id);
            memblock = NULL;
            return -1; 
        }
      mem_start[udom_id] = memblock;  

    }

    if(orig_prot==PROT_NONE)
        {

        sys_udom_set(udom_id,DOMAIN_NOACCESS);
        //int udom_cntrl= sys_udom_get(udom_id);
	   // printf("client udom acc:%d\n",udom_cntrl);
        return 0;

        }
    else if(orig_prot==(PROT_READ | PROT_WRITE))
        {

        sys_udom_set(udom_id,DOMAIN_MANAGER);
       // int udom_cntrl= sys_udom_get(udom_id);
	    //printf("client udom acc:%d\n",udom_cntrl);
        return 0;

        } 
     else 
        {
            return sys_udom_mprotect(addr,len,orig_prot,udom_id);
            
        }        



return 0;


}


//allocate a memory inside a uTile only
void *udom_alloc(int udom_id, unsigned long sz) {

    char *memblock = NULL;
    struct free_list_struct *free_list = NULL;
    struct free_list_struct *prev = NULL;
    
    /* Memdom 0 is in global udom, Memdom -1 when defined THREAD_PRIVATE_STACK, use malloc */
    if(udom_id == 0){

#ifdef UDOM_INTERCEPT_MALLOC
#undef malloc
#endif
        sz = udom_round_up ( sz + sizeof(struct block_header_struct), CHUNK_SIZE);
        memblock = (char*) malloc(sz);   

#ifdef UDOM_INTERCEPT_MALLOC
#define malloc(sz) mpk_alloc(mpk_private_id(), sz)
#endif
        goto out;
    }



    /* First time this udom allocates memory */
    if( udom[udom_id] == NULL || !udom[udom_id]->start ) {
        /* Call mmap to set up initial memory region */
        memblock = (char*) udom_mmap(udom_id, 0, MEMDOM_HEAP_SIZE, 
                                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if( memblock == MAP_FAILED ) {
            fprintf(stderr, "Failed to udom_alloc using mmap for udom %d\n", udom_id);
            memblock = NULL;
            goto out;
        }
      mem_start[udom_id] = memblock;
     // pthread_mutex_lock(&udom[udom_id]->mlock);
        /* Initialize free list */
        udom_free_list_init(udom_id);
    }

    else {
     // pthread_mutex_lock(&udom[udom_id]->mlock);
    }
 //printf("[%s] udom %d allocating sz 0x%lx bytes\n", __func__, udom_id, sz);
    //do not need to set the udom permissions here. the defult is client that is set in mmap time
   // pkey_set_real(make_pkru(udom_id, PKEY_ENABLE_ALL), udom_id);

    /* Round up size to multiple of cache line size: 64B 
     * Note that the size of should block_header + the actual data
     * --------------------------------------
     * | block header |      your data       |
     * --------------------------------------
     */
    sz = udom_round_up ( sz + sizeof(struct block_header_struct), CHUNK_SIZE);
   // printf("[%s] request rounded to 0x%lx bytes\n", __func__, sz);

    /* Get memory from the tail of free list, if the last free list is not available for allocation,
     * start searching the free list from the head until first fit is found.
     */
    free_list = udom[udom_id]->free_list_tail;

    /* Allocate from tail: 
     * check if the last element in free list is available, 
     * allocate memory from it */
   // printf("[%s] udom %d search from tail for 0x%lx bytes, free_list->size %ld \n", __func__, udom_id, sz,free_list->size );     
    if ( free_list && sz <= free_list->size ) {
        memblock = (char*)free_list->addr;

        /* Adjust the last free list addr and size*/
        free_list->addr = (char*)free_list->addr + sz;
        free_list->size = free_list->size - sz;

       // printf("[%s] udom %d last free list available, free_list addr: %p, remaining sz: 0x%lx bytes\n", __func__, udom_id, free_list->addr, free_list->size);
        /* Last chunk is now allocated, tail is not available from now */
        if( free_list->size == 0 ) {

 #ifdef UDOM_INTERCEPT_MALLOC
#undef free
#endif
            free(free_list);

#ifdef UDOM_INTERCEPT_MALLOC
#define free(addr) udom_free(addr)
#endif

            udom[udom_id]->free_list_tail = NULL;
            //printf("[%s] free_list size is 0, freed this free_list_struct, the next allocate should request from free_list_head\n", __func__);
        }
        goto out;
    }

    /* Allocate from head: 
     * ok the last free list is not available, 
     * let's start searching from the head for the first fit */
   // printf("[%s] udom %d search from head for 0x%lx bytes\n", __func__, udom_id, sz);     
    udom_dumpFreeListHead(udom_id);
    free_list = udom[udom_id]->free_list_head;
    while (free_list) {
        if( prev ) {
            //rlog("[%s] udom %d prev->addr %p, prev->size 0x%lx bytes\n", __func__, udom_id, prev->addr, prev->size);
        }
        if( free_list ) {
           // rlog("[%s] udom %d free_list->addr %p, free_list->size 0x%lx bytes\n", __func__, udom_id, free_list->addr, free_list->size);
        }
        
        /* Found free list! */
        if( sz <= free_list->size ) {

            /* Get memory address */
            memblock = (char*)free_list->addr;

            /* Adjust free list:
             * if the remaining chunk size if greater then CHUNK_SIZE
             */
            if( free_list->size - sz >= CHUNK_SIZE ) {
                char *ptr = (char*)free_list->addr;
                ptr = ptr + sz;
                free_list->addr = (void*)ptr;
                free_list->size = free_list->size - sz;
               // printf("[%s] Adjust free list to addr %p, sz 0x%lx\n", __func__, free_list->addr, free_list->size);
            }
            /* Remove this free list struct: 
             * since there's no memory to allcoate from here anymore 
             */
            else{                
                if ( free_list == udom[udom_id]->free_list_head ) {
                    udom[udom_id]->free_list_head = udom[udom_id]->free_list_head->next;
                    //printf("[%s] udom %d set free_list_head to free_list_head->next\n", __func__, udom_id);
                }
                else {
                    prev->next = free_list->next;
                   // printf("[%s] udom %d set prev->next to free_list->next\n", __func__, udom_id);
                }

          #ifdef UDOM_INTERCEPT_MALLOC
#undef free
#endif
                free(free_list);
#ifdef UDOM_INTERCEPT_MALLOC
#define free(addr) udom_free(addr)
#endif


               // rlog("[%s] udom %d removed free list\n", __func__, udom_id);
            }
            goto out;
        }

        /* Move pointer forward */
        prev = free_list;
        free_list = free_list->next;
    }   
   
out:   
    if( !memblock ) {
        fprintf(stderr, "udom_alloc failed: no memory can be allocated in udom %d\n", udom_id);
    }
    else{    
        /* Record allocated memory in the block header for free to use later */
        struct block_header_struct header;
        header.addr = (void*)memblock;
        header.memdom_id = udom_id;
        header.size = sz;
        //rlog("[%s] pkru : %p\n", __func__, rdpkru());
        memcpy(memblock, &header, sizeof(struct block_header_struct));
        memblock = memblock + sizeof(struct block_header_struct);
        rlog("[%s] header: addr %p, allocated 0x%lx bytes and returning data addr %p\n", __func__, header.addr, sz, memblock);
    }
  //  pthread_mutex_init(&mprotect_mutex[udom_id], NULL);
   // pkey_set_real(make_pkru(udom_id, PKEY_DISABLE_ACCESS), udom_id);
  //  pthread_mutex_unlock(&udom[udom_id]->mlock);
    return (void*)memblock;
}


/* Deallocate data in memory domain udom */
void udom_free(void* data){
    struct block_header_struct header;
    char *memblock = NULL;
    int udom_id = -1;

    /* Read the header stored ahead of the actual data */
    memblock = (char*) data - sizeof(struct block_header_struct);
    memcpy(&header, memblock, sizeof(struct block_header_struct));
    udom_id = header.memdom_id;
  //  printf("[%s] block addr: %p, header addr: %p, freeing 0x%lx bytes in udom %d \n", __func__, memblock, header.addr, header.size, header.memdom_id);
    if(udom_id == 0) {

#ifdef UDOM_INTERCEPT_MALLOC
#undef free
#endif
      free(memblock);

#ifdef UDOM_INTERCEPT_MALLOC
#define free(addr) udom_free(addr)
#endif

      return;
    }
    if(udom_id < 0 || udom_id > MAX_MEMDOM)
      assert(!udom_id);

  //  pthread_mutex_lock(&udom[udom_id]->mlock);
 
    /* Free the memory */
    memset(memblock, 0, header.size);

    /* Create a new free list node */
#ifdef UDOM_INTERCEPT_MALLOC
#undef malloc
#endif
    struct free_list_struct *free_list = (struct free_list_struct *) malloc(sizeof(struct free_list_struct));
#ifdef UDOM_INTERCEPT_MALLOC
#define malloc(sz) udom_alloc(udom_private_id(), sz)
#endif
    free_list->addr = memblock;
    free_list->size = header.size;
    free_list->next = NULL;

    /* Insert the block into free list head */
    udom_free_list_insert_to_head(header.memdom_id, free_list);   

   // pthread_mutex_unlock(&udom[udom_id]->mlock);
}

