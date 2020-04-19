#include <linux/smv.h>
#include <linux/memdom.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>

#include <azure-sphere/difc.h>


/* SLAB cache for smv_struct structure  */
static struct kmem_cache *memdom_cachep;

/** void memdom_init(void)
 *  Create slab cache for future memdom_struct allocation This
 *  is called by start_kernel in main.c 
 */
void memdom_init(void){
    memdom_cachep = kmem_cache_create("memdom_struct",
                                      sizeof(struct memdom_struct), 0,
                                      SLAB_HWCACHE_ALIGN, NULL);
    if( !memdom_cachep ) {
       difc_lsm_debug("[%s] memdom slabs initialization failed...\n", __func__);
    } else{
       difc_lsm_debug("[%s] memdom slabs initialized\n", __func__);
    }
}

/* Create a memdom and update metadata */
int memdom_create(void){
    int memdom_id = -1;
    struct mm_struct *mm = current->mm;
    struct memdom_struct *memdom = NULL;

    /* SMP: protect shared memdom bitmap */
    mutex_lock(&mm->smv_metadataMutex);

    /* Are we having too many memdoms? */
    if( atomic_read(&mm->num_memdoms) == SMV_ARRAY_SIZE ) {
        goto err;
    }

    /* Find available slot in the bitmap for the new smv */
    memdom_id = find_first_zero_bit(mm->memdom_bitmapInUse, SMV_ARRAY_SIZE);
    if( memdom_id == SMV_ARRAY_SIZE ) {
        goto err;        
    }

    /* Create the actual memdom struct */
    memdom = allocate_memdom();
    memdom->memdom_id = memdom_id;
    bitmap_zero(memdom->smv_bitmapRead, SMV_ARRAY_SIZE);    
    bitmap_zero(memdom->smv_bitmapWrite, SMV_ARRAY_SIZE);    
    bitmap_zero(memdom->smv_bitmapExecute, SMV_ARRAY_SIZE);    
    bitmap_zero(memdom->smv_bitmapAllocate, SMV_ARRAY_SIZE);    
    mutex_init(&memdom->memdom_mutex);

    /* Record this new memdom to mm */
    mm->memdom_metadata[memdom_id] = memdom;

    /* Set bit in memdom bitmap */
    set_bit(memdom_id, mm->memdom_bitmapInUse);

    /* Increase total number of memdom count in mm_struct */
    atomic_inc(&mm->num_memdoms);

   difc_lsm_debug("Created new memdom with ID %d, #memdom: %d / %d\n", 
            memdom_id, atomic_read(&mm->num_memdoms), SMV_ARRAY_SIZE);
    goto out;

err:
    difc_lsm_debug("Too many memdoms, cannot create more.\n");
    memdom_id = -1;
out:
    mutex_unlock(&mm->smv_metadataMutex);
    return memdom_id;
}
EXPORT_SYMBOL(memdom_create);

/* Find the first (in bit order) smv in the memdom. Called by memdom_kill */
int find_first_smv(struct memdom_struct *memdom){
    int smv_id = 0;

    mutex_lock(&memdom->memdom_mutex);

    /* Check read permission */
    smv_id = find_first_bit(memdom->smv_bitmapRead, SMV_ARRAY_SIZE);
    if( smv_id != SMV_ARRAY_SIZE ) {
        goto out;
    }

    /* Check write permission */
    smv_id = find_first_bit(memdom->smv_bitmapWrite, SMV_ARRAY_SIZE);
    if( smv_id != SMV_ARRAY_SIZE ) {
        goto out;
    }

    /* Check allocate permission */
    smv_id = find_first_bit(memdom->smv_bitmapAllocate, SMV_ARRAY_SIZE);
    if( smv_id != SMV_ARRAY_SIZE ) {
        goto out;
    }

    /* Check execute permission */
    smv_id = find_first_bit(memdom->smv_bitmapExecute, SMV_ARRAY_SIZE);

out:
    mutex_unlock(&memdom->memdom_mutex);
    return smv_id;
}

/* Free a memory domain metadata and remove it from mm_struct */
int memdom_kill(int memdom_id, struct mm_struct *mm){
    struct memdom_struct *memdom = NULL;
    int smv_id = 0;

    if( memdom_id > LAST_MEMDOM_INDEX ) {
        difc_lsm_debug("[%s] Error, out of bound: memdom %d\n", __func__, memdom_id);
        return -1;
    }

    /* When user space program calls memdom_kill, mm_struct is NULL
     * If free_all_memdoms calls this function, it passes the about-to-destroy mm_struct, not current->mm */
    if( !mm ) {
        mm = current->mm;
    }
    
    /* SMP: protect shared memdom bitmap */
    mutex_lock(&mm->smv_metadataMutex);
    memdom = mm->memdom_metadata[memdom_id];

    /* TODO: check if current task has the permission to delete the memdom, only master thread can do this */
    
    /* Clear memdom_id-th bit in memdom_bitmapInUse */
    if( test_bit(memdom_id, mm->memdom_bitmapInUse) ) {
        clear_bit(memdom_id, mm->memdom_bitmapInUse);  
        mutex_unlock(&mm->smv_metadataMutex);
    } else {
        difc_lsm_debug("Error, trying to delete a memdom that does not exist: memdom %d, #memdoms: %d\n", memdom_id, atomic_read(&mm->num_memdoms));
        mutex_unlock(&mm->smv_metadataMutex);
        return -1;
    }

    /* Clear all smv_bitmapR/W/E/A bits for this memdom in all smvs */    
    do {
        smv_id = find_first_smv(memdom);
        if( smv_id != SMV_ARRAY_SIZE ) {
            smv_leave_memdom(memdom_id, smv_id, mm);             
        }
    } while( smv_id != SMV_ARRAY_SIZE );
    
    /* Free the actual memdom struct */
    free_memdom(memdom);
    mm->memdom_metadata[memdom_id] = NULL;

    /* Decrement memdom count */
    mutex_lock(&mm->smv_metadataMutex);
    atomic_dec(&mm->num_memdoms);
    mutex_unlock(&mm->smv_metadataMutex);

    slog(KERN_INFO "[%s] Deleted memdom with ID %d, #memdoms: %d / %d\n", 
            __func__, memdom_id, atomic_read(&mm->num_memdoms), SMV_ARRAY_SIZE);

    return 0;
}
EXPORT_SYMBOL(memdom_kill);

/* Free all the memdoms in this mm_struct */
void free_all_memdoms(struct mm_struct *mm){
    int index = 0;
    while( atomic_read(&mm->num_memdoms) > 0 ){
        index = find_first_bit(mm->memdom_bitmapInUse, SMV_ARRAY_SIZE);
        slog(KERN_INFO "[%s] killing memdom %d, remaining #memdom: %d\n", __func__, index, atomic_read(&mm->num_memdoms));
        memdom_kill(index, mm);
    }
}

/* Set bit in memdom->smv_bitmapR/W/E/A */
int memdom_priv_add(int memdom_id, int smv_id, int privs){
    struct smv_struct *smv; 
    struct memdom_struct *memdom; 
    struct mm_struct *mm = current->mm;

    if( smv_id > LAST_RIBBON_INDEX || memdom_id > LAST_MEMDOM_INDEX ) {
        difc_lsm_debug("[%s] Error, out of bound: smv %d / memdom %d\n", __func__, smv_id, memdom_id);
        return -1;
    }

    mutex_lock(&mm->smv_metadataMutex);
    smv = current->mm->smv_metadata[smv_id];
    memdom = current->mm->memdom_metadata[memdom_id];
    mutex_unlock(&mm->smv_metadataMutex);

    if( !memdom || !smv ) {
        difc_lsm_debug("[%s] memdom %p || smv %p not found\n", __func__, memdom, smv);
        return -1;
    }       
    if( !smv_is_in_memdom(memdom_id, smv->smv_id) ) {
        difc_lsm_debug("[%s] smv %d is not in memdom %d, please make smv join memdom first.\n", __func__, smv_id, memdom_id);
        return -1;  
    }
    
    /* TODO: Add privilege check to see if current thread can change the privilege */

    /* Set privileges in memdom's bitmap */   
    mutex_lock(&memdom->memdom_mutex);
    if( privs & MEMDOM_READ ) {
        set_bit(smv_id, memdom->smv_bitmapRead);
        slog(KERN_INFO "[%s] Added read privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_WRITE ) {
        set_bit(smv_id, memdom->smv_bitmapWrite);
        slog(KERN_INFO "[%s] Added write privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_EXECUTE ) {
        set_bit(smv_id, memdom->smv_bitmapExecute);
        slog(KERN_INFO "[%s] Added execute privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_ALLOCATE ) {
        set_bit(smv_id, memdom->smv_bitmapAllocate);
        slog(KERN_INFO "[%s] Added allocate privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }    
    mutex_unlock(&memdom->memdom_mutex);     
     
    return 0;
}
EXPORT_SYMBOL(memdom_priv_add);

/* Clear bit in memdom->smv_bitmapR/W/E/A */
int memdom_priv_del(int memdom_id, int smv_id, int privs){
    struct smv_struct *smv = NULL;
    struct memdom_struct *memdom = NULL;
    struct mm_struct *mm = current->mm;

    if( smv_id > LAST_RIBBON_INDEX || memdom_id > LAST_MEMDOM_INDEX ) {
        difc_lsm_debug("[%s] Error, out of bound: smv %d / memdom %d\n", __func__, smv_id, memdom_id);
        return -1;
    }

    mutex_lock(&mm->smv_metadataMutex);
    smv = current->mm->smv_metadata[smv_id];
    memdom = current->mm->memdom_metadata[memdom_id];
    mutex_unlock(&mm->smv_metadataMutex);

    if( !memdom || !smv ) {
        difc_lsm_debug("[%s] memdom %p || smv %p not found\n", __func__, memdom, smv);
        return -1;
    }       
    if( !smv_is_in_memdom(memdom_id, smv->smv_id) ) {
        difc_lsm_debug("[%s] smv %d is not in memdom %d, please make smv join memdom first.\n", __func__, smv_id, memdom_id);
        return -1;  
    }
    
    /* TODO: Add privilege check to see if current thread can change the privilege */

    /* Clear privileges in memdom's bitmap */   
    mutex_lock(&memdom->memdom_mutex);
    if( privs & MEMDOM_READ ) {
        clear_bit(smv_id, memdom->smv_bitmapRead);
        slog(KERN_INFO "[%s] Revoked read privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_WRITE ) {
        clear_bit(smv_id, memdom->smv_bitmapWrite);
        slog(KERN_INFO "[%s] Revoked write privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_EXECUTE ) {
        clear_bit(smv_id, memdom->smv_bitmapExecute);
        slog(KERN_INFO "[%s] Revoked execute privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }
    if( privs & MEMDOM_ALLOCATE ) {
        clear_bit(smv_id, memdom->smv_bitmapAllocate);
        slog(KERN_INFO "[%s] Revoked allocate privilege for smv %d in memdmo %d\n", __func__, smv_id, memdom_id);
    }            
    mutex_unlock(&memdom->memdom_mutex);

    return 0;
}
EXPORT_SYMBOL(memdom_priv_del);

/* Return smv's privileges in a given memdom and return to caller */
int memdom_priv_get(int memdom_id, int smv_id){
    struct smv_struct *smv = NULL;
    struct memdom_struct *memdom = NULL;
    struct mm_struct *mm = current->mm;
    int privs = 0;

    if( smv_id > LAST_RIBBON_INDEX || memdom_id > LAST_MEMDOM_INDEX ) {
        difc_lsm_debug("[%s] Error, out of bound: smv %d / memdom %d\n", __func__, smv_id, memdom_id);
        return -1;
    }

    mutex_lock(&mm->smv_metadataMutex);
    smv = current->mm->smv_metadata[smv_id];
    memdom = current->mm->memdom_metadata[memdom_id];
    mutex_unlock(&mm->smv_metadataMutex);

    if( !memdom || !smv ) {
        difc_lsm_debug("[%s] memdom %p || smv %p not found\n", __func__, memdom, smv);
        return -1;
    }       
    if( !smv_is_in_memdom(memdom_id, smv->smv_id) ) {
        difc_lsm_debug("[%s] smv %d is not in memdom %d, please make smv join memdom first.\n", __func__, smv_id, memdom_id);
        return -1;  
    }
    
    /* TODO: Add privilege check to see if current thread can change the privilege */

    /* Get privilege info */
    mutex_lock(&memdom->memdom_mutex);
    if( test_bit(smv_id, memdom->smv_bitmapRead) ) {
        privs = privs | MEMDOM_READ;
    }
    if( test_bit(smv_id, memdom->smv_bitmapWrite) ) {
        privs = privs | MEMDOM_WRITE;
    }
    if( test_bit(smv_id, memdom->smv_bitmapExecute) ) {
        privs = privs | MEMDOM_EXECUTE;
    }
    if( test_bit(smv_id, memdom->smv_bitmapAllocate) ) {
        privs = privs | MEMDOM_ALLOCATE;
    }
    mutex_unlock(&memdom->memdom_mutex);

    slog(KERN_INFO "[%s] smv %d has privs %x in memdom %d\n", __func__, smv_id, privs, memdom_id);
    return privs;
}
EXPORT_SYMBOL(memdom_priv_get);

/* User space signals the kernel what memdom a mmap call is for */
int memdom_mmap_register(int memdom_id){    
    struct memdom_struct *memdom; 
    struct mm_struct *mm = current->mm;

    if( memdom_id > LAST_MEMDOM_INDEX ) {
        difc_lsm_debug("[%s] Error, out of bound: memdom %d\n", __func__, memdom_id);
        return -1;
    }

    mutex_lock(&mm->smv_metadataMutex);
    memdom = current->mm->memdom_metadata[memdom_id];
    mutex_unlock(&mm->smv_metadataMutex);

    if( !memdom ) {
        difc_lsm_debug("[%s] memdom %p not found\n", __func__, memdom);
        return -1;
    }       
    
    /* TODO: privilege checks */

    /* Record memdom_id for mmap to use */
    current->mmap_memdom_id = memdom_id;

    return 0;
}
EXPORT_SYMBOL(memdom_mmap_register);

unsigned long memdom_munmap(unsigned long addr){

    return 0;
}
EXPORT_SYMBOL(memdom_munmap);

/* Return the memdom id used by the master thread (global memdom) */
int memdom_main_id(void){
    return MAIN_THREAD;
}
EXPORT_SYMBOL(memdom_main_id);

/* Initialize vma's owner to the main thread, only called by the main thread */
int memdom_claim_all_vmas(int memdom_id){
    struct vm_area_struct *vma;
    struct mm_struct *mm = current->mm;
    int vma_count = 0;

    if( memdom_id > LAST_MEMDOM_INDEX ) {
        difc_lsm_debug("[%s] Error, out of bound: memdom %d\n", __func__, memdom_id);
        return -1;
    }
    
   	down_write(&mm->mmap_sem);
  	for (vma = mm->mmap; vma; vma = vma->vm_next) {
        vma->memdom_id = MAIN_THREAD;
        vma_count++;
    }
   	up_write(&mm->mmap_sem);

    slog(KERN_INFO "[%s] Initialized %d vmas to be in memdom %d\n", __func__, vma_count, memdom_id);
    return 0;
}

/* Query the memdom id of an address, return -1 if not memdom not found */
int memdom_query_id(unsigned long addr){
    int memdom_id = 0;
    int smv_id = 0;
    struct vm_area_struct *vma = NULL;

    /* Look for vma covering the address */
    vma = find_vma(current->mm, addr);
    if( !vma ) {
        /* Debugging info, should remove printk to avoid information leakage and just go to out label. */
       difc_lsm_debug("[%s] addr 0x%16lx is not in any memdom\n", __func__, addr);
        goto out;    
    }

    /* Privilege check, only member smv can query */
    smv_id = current->smv_id;
    memdom_id = vma->memdom_id;
    if( smv_is_in_memdom(memdom_id, smv_id) ) {
       difc_lsm_debug("[%s] addr 0x%16lx is in memdom %d\n", __func__, addr, memdom_id);        
    } else {
        /* Debugging info, should remove to avoid information leakage, just set memdom_id to 0 (lying to the caller)*/
        difc_lsm_debug("[%s] hey you don't have the privilege to query this address (smv %d, memdom %d)\n", 
               __func__, smv_id, memdom_id);
        memdom_id = 0;        
    }
out:
    return memdom_id;
}
EXPORT_SYMBOL(memdom_query_id);

/* Get the calling thread's defualt memdom id */
int memdom_private_id(void){
    return current->mmap_memdom_id;
}
EXPORT_SYMBOL(memdom_private_id);

