#ifndef DIFC_LSM_ENABLED
#define DIFC_LSM_ENABLED // ZTODO: move it to makefile

// all difc usespace api is implemented here, we follow the flume difc labeling model

#include "difc_api.h"

/* difc syscalls */

static inline int linux_is_error_result(uint32_t result) {
  /*
   * -0x1000 is the highest address that mmap() can return as a result.
   * Linux errno values are less than 0x1000.
   */
  return result > (uint32_t) -0x1000;
}

static uint32_t irt_return_call(uintptr_t result) {
  if (linux_is_error_result(result))
    return -result;
  return 0;
}

// used to ask difc-lsm for allocating a label with proper capability type (T+ or T- or both by
// defult)
// mode: explicit label of floating
static inline int alloc_label(int type, enum label_types mode)
{
    int rv = syscall(__NR_alloc_label, type, mode);
    return rv ? rv : -errno;
}

// set a label for current task
static inline int set_task_label(unsigned long label, enum label_types ops, int label_type,
                                 struct label_struct *user_label)
{
    int rv = syscall(__NR_set_task_label, label, ops, label_type, user_label);
    return rv ? -errno : 0;
}

// create a labeled a directory
static inline int mkdir_labeled(const char *pathname, mode_t mode, struct label_struct *label)
{
    int rv = syscall(__NR_mkdir_labeled, pathname, mode, label);
    return rv ? -errno : 0;
}

// create a labeld file
static inline int sys_create_labeled_file(const char *pathname, int flags,mode_t mode,
                                          struct label_struct *label)
{
    int rv = syscall(__NR_create_labeled, pathname, flags, mode, label);
    return rv ? -errno : 0;
}

// label an existing file
static inline int set_labeled_file(const char *pathname, struct label_struct *label)
{
    int rv = syscall(__NR_set_labeled_file, pathname, label);
    return rv ? -errno : 0;
}

// drop a capability for declassification permanently
static inline int sys_permanent_declassify(unsigned long long *cap_list, unsigned int len,
                                           int cap_type, int label_type)
{
    int rv = syscall(__NR_permanent_declassify, cap_list, len, cap_type, label_type);
    return rv ? -errno : 0;
}

// drop capabilities temporarly for fast copy of a task label to its children
static inline int sys_temporarily_declassify(unsigned long long *cap_list, unsigned int len,
                                             int cap_type, int label_type)
{
    int rv = syscall(__NR_temporarily_declassify, cap_list, len, cap_type, label_type);
    return rv ? -errno : 0;
}
// restore only temporarly droped capabilities
static inline int sys_restore_suspended_capabilities(unsigned long long *cap_list, unsigned int len,
                                                     int cap_type, int label_type)
{
    int rv = syscall(__NR_restore_suspended_capabilities, cap_list, len, cap_type, label_type);
    return rv ? -errno : 0;
}

// allocate a domain for current task,if the task is not labeld the domain access is in
// CLIENT(DACR:01) mode if the task is labeld the domain access by default is NO Access(DACR:00)
static inline int set_task_domain(unsigned long addr, unsigned long counts, int domain)

{
    int rv = syscall(__NR_set_task_domain, addr, counts, domain);
    return rv ? -errno : 0;
}

int 
sys_udom_alloc(int flag, int permit) 
{ 
return syscall(__NR_udom_alloc, flag, permit); 
}


int sys_udom_free(unsigned long udom)
{
	int ret = syscall(__NR_udom_free, udom);
	return ret;
}

unsigned long sys_udom_mmap(unsigned long udom_id, unsigned long addr, unsigned long len,
			      unsigned long prot, unsigned long flags,
			      unsigned long fd)

{
    unsigned long ret = syscall(__NR_udom_mmap, udom_id,addr, len,prot,flags,fd);
	return ret;

}                  


int  sys_udom_mprotect(void *ptr, size_t size, unsigned long orig_prot, 
unsigned long udom_id) 
{ 
return syscall(__NR_udom_mprotect, ptr, size, orig_prot, udom_id); 
}

int sys_udom_get(int udom_id)
{
    return syscall(__NR_udom_get, udom_id); 

}

int sys_udom_set(int udom_id, unsigned val)
{

    return syscall(__NR_udom_set, udom_id, val); 

}

int sys_udom_ops(enum smv_ops smv_op, long smv_id, enum smv_udom_ops smv_domain_op,
                                          long memdom_id1)
{
        return syscall(__NR_udom_ops, smv_op, smv_id,smv_domain_op,memdom_id1); 


}
int sys_udom_mem_ops(enum udom_ops memdom_op, long memdom_id1,long smv_id,
                                         enum udom_priv_ops memdom_priv_op, long memdom_priv_value)

{ 
            return syscall(__NR_udom_mem_ops, memdom_op, memdom_id1,smv_id,memdom_priv_op,memdom_priv_value); 
    
}                                         


int thread_create(void (*start_func)(void), void *stack) {
  

  return 0;//irt_return_call(result);
}

/*
SYSCALL_DEFINE6(udom_clone, const char __user *, label, unsigned long, clone_flags, unsigned long, newsp,
		 int __user *, parent_tidptr,
		 int __user *, child_tidptr,
		 unsigned long, tls)
*/

int udom_thread_create(void (*start_func)(void), void *stack, struct label_struct *label)
 {
  /*
   * The prototype of clone(2) is
   *
   * clone(int flags, void *stack, pid_t *ptid, void *tls, pid_t *ctid);
   *
   * See linux_syscall_wrappers.h for syscalls' calling conventions.
   */
  /*
   * We do not use CLONE_CHILD_CLEARTID as we do not want any
   * non-private futex signaling. Also, NaCl ABI does not require us
   * to signal the futex on stack_flag.
   */
  int flags = (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
               CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS);
  /*
   * Make sure we can access stack[0] and align the stack address to a
   * 16-byte boundary.
   */
  static const int kStackAlignmentMask = ~15;
  stack = (void *) (((uintptr_t) stack - sizeof(uintptr_t)) &
                    kStackAlignmentMask);


  /* We pass start_func using the stack top. */
  ((uintptr_t *) stack)[0] = (uintptr_t) start_func;



 int rv = syscall(__NR_udom_clone, flags, (uint32_t) stack, 0,0,0,label);
    return rv ? -errno : 0;
/*
  register uint32_t result __asm__("r0");
  register uint32_t sysno __asm__("r7") = __NR_udom_clone;
  register uint32_t a1 __asm__("r0") = flags;
  register uint32_t a2 __asm__("r1") = (uint32_t) stack;
  register uint32_t a3 __asm__("r2") = 0; 
  register uint32_t a4 __asm__("r3") = 0;  
  register uint32_t a5 __asm__("r4") = 0;
    register uint32_t a6 __asm__("r5") = (uintptr_t)(label);


  __asm__ __volatile__("svc #0\n"
                     
                       "cmp r0, #0\n"
                       "bne 0f\n"
                    
                       "mov fp, #0\n"
                       "ldr r0, [sp]\n"
                       "blx r0\n"

                       "bkpt #0\n"
                       "0:\n"
                       : "=r"(result)
                       : "r"(sysno),
                         "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
                       : "memory");

  return 0;//irt_return_call(result);

  */
}



/* wrappers for easy use of difc syscalls*/

// creating and adding labels
int difc_create_label(int type, enum label_types mode)
{
    if (type == 0)
        return (int)alloc_label(PLUS_CAPABILITY, mode);
    else if (type == 1)
        return (int)alloc_label(MINUS_CAPABILITY, mode);

    return (int)alloc_label(PLUS_CAPABILITY | MINUS_CAPABILITY,
                            mode); // default is to give both t+ and t- capabilities
}

/*set secerecy and integrity labels of the current process*/
int difc_replace_labels(long secrecySet[], int sec_len, long integritySet[], int int_len)
{
    int i;
    struct label_struct cur_label;

    cur_label.sList[0] = (label_t)sec_len;

    for (i = 0; i < sec_len; i++) {
        cur_label.sList[i + 1] = (label_t)secrecySet[i];
        printf("[difc_replace_labels] cur_label.sList[%d]: %lld \n", (i + 1),
               cur_label.sList[i + 1]);
    }

    cur_label.iList[0] = (label_t)int_len;

    for (i = 0; i < int_len; i++) {
        cur_label.iList[i + 1] = (label_t)integritySet[i];
        printf("[difc_replace_labels] cur_label.iList[%d]: %lld \n", (i + 1),
               cur_label.iList[i + 1]);
    }
    return set_task_label(0, OWNERSHIP_ADD, 0, &cur_label);
}

int difc_add_label(unsigned long label, int label_type)
{

    return set_task_label(label, OWNERSHIP_ADD, label_type, NULL);
}


int difc_remove_label(unsigned long label, int label_type)
{

    return set_task_label(label, OWNERSHIP_DROP, label_type, NULL);
}


int difc_set_label(unsigned long label, enum label_types ops)
{

    return set_task_label(label, ops, 0, NULL);
}


int difc_create_add_label(unsigned long label, int label_type)
{

    return set_task_label(label, OWNERSHIP_ADD, label_type, NULL);
}



int create_labeled_dir(char *pathname, int mode,unsigned long secrecySet[], int sec_len,
                      unsigned long integritySet[], int int_len)
{
    int i;
    struct label_struct dir_label;
    (*dir_label.sList) = sec_len;
    for (i = 0; i < sec_len; i++)
        dir_label.sList[i + 1] = (label_t)secrecySet[i];
    (*dir_label.iList) = int_len;
    for (i = 0; i < int_len; i++)
        dir_label.iList[i + 1] = (label_t)integritySet[i];
    return mkdir_labeled(pathname, mode, &dir_label);
}

int create_labeled_file(char *pathname, int flags, int mode,unsigned long secrecySet[], int sec_len,
                      unsigned long integritySet[], int int_len)
{
    int i;
    struct label_struct flabel;
    (*flabel.sList) = sec_len;
    for (i = 0; i < sec_len; i++)
        flabel.sList[i + 1] = (label_t)secrecySet[i];
    (*flabel.iList) = int_len;
    for (i = 0; i < int_len; i++)
        flabel.iList[i + 1] = (label_t)integritySet[i];
    return sys_create_labeled_file(pathname, flags, mode, &flabel);
}

int modify_file_labels(const char *pathname, long secrecySet[], int sec_len, long integritySet[],
                       int int_len)
{
    int i;
    struct label_struct file_label;
    (*file_label.sList) = sec_len;
    for (i = 0; i < sec_len; i++)
        file_label.sList[i + 1] = (label_t)secrecySet[i];
    (*file_label.iList) = int_len;
    for (i = 0; i < int_len; i++)
        file_label.iList[i + 1] = (label_t)integritySet[i];
    return set_labeled_file(pathname, &file_label);
}

int do_permanent_declassification(capability_t labels[], int length, int type, int label_type)
{
    if (type == 0)
        return sys_permanent_declassify(labels, length, PLUS_CAPABILITY, label_type);
    if (type == 1)
        return sys_permanent_declassify(labels, length, MINUS_CAPABILITY, label_type);
    return sys_permanent_declassify(labels, length, PLUS_CAPABILITY | MINUS_CAPABILITY, label_type);
}

int do_temporarily_declassification(capability_t caps[], int length, int cap_type, int label_type)
{
    if (cap_type == 0)
        return sys_temporarily_declassify(caps, length, PLUS_CAPABILITY, label_type);
    if (cap_type == 1)
        return sys_temporarily_declassify(caps, length, MINUS_CAPABILITY, label_type);
    return sys_temporarily_declassify(caps, length, PLUS_CAPABILITY | MINUS_CAPABILITY, label_type);
}

int restore_suspended_capabilities(capability_t labels[], int length, int type, int label_type)
{
    if (type == 0)
        return sys_restore_suspended_capabilities(labels, length, PLUS_CAPABILITY, label_type);
    if (type == 1)
        return sys_restore_suspended_capabilities(labels, length, MINUS_CAPABILITY, label_type);
    return sys_restore_suspended_capabilities(labels, length, PLUS_CAPABILITY | MINUS_CAPABILITY,
                                              label_type);
}
int map_to_domain(unsigned long addr, unsigned long counts, int domain)
{
    // ZTODOD: do some chaceking on valid domains, address, or .... here
    return set_task_domain(addr, counts, domain);
}



#endif