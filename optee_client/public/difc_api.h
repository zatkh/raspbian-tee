#ifndef _UAPI_DIFC_H
#define _UAPI_DIFC_H

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <linux/types.h>
#include <unistd.h>
#include <sys/stat.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  
#include <linux/sched.h> 
#endif
#include <sched.h>
#include </usr/include/linux/sched.h>


#ifndef ENABLE_TEE_DIFC
#define ENABLE_TEE_DIFC
#endif

// labels and capabilities related variables & data structs should be here
// typedef uint64_t label_t;
typedef unsigned long long capability_t;
typedef capability_t *capList_t;

//typedef unsigned long long __uint64_t;
typedef __uint64_t label_t;
// typedef __uint64_t capability_t;
// typedef capability_t *capList_t;
typedef __uint64_t handle_t;
typedef __uint64_t caph_t;
typedef handle_t labelvec_t;
typedef labelvec_t x_handlevec_t;

#define LABEL_LIST_BYTES 256
#define LABEL_LIST_LABELS (LABEL_LIST_BYTES / sizeof(label_t))
#define LABEL_LIST_MAX_ENTRIES (LABEL_LIST_BYTES / sizeof(label_t)) - 1
/*cap lists max size */
#define CAP_LIST_BYTES 256
#define CAP_LIST_CAPS (LABEL_LIST_BYTES / sizeof(capability_t))
#define CAP_LIST_MAX_ENTRIES (CAP_LIST_BYTES / sizeof(capability_t)) - 1
/* Use the upper two bits for +/- */
#define PLUS_CAPABILITY (1 << 30)
#define MINUS_CAPABILITY (1 << 31)
#define CAP_LABEL_MASK (0xFFFFFFFF ^ (PLUS_CAPABILITY | MINUS_CAPABILITY))

#define THREAD_NONE 0 // useless only for debuging
#define THREAD_SELF 1 // only the calling thread
#define THREAD_GROUP \
    2 // in case of labeling a group of labels at the same time instead of several syscalls

// label operations
#define ADD_LABEL 0
#define REMOVE_LABEL 1
#define REPLACE_LABEL 2

// my test domains
#define DOMAIN_SANDBOX 4
#define DOMAIN_TRUSTED 5
#define DOMAIN_UNTRUSTED 6

#define SECRECY_LABEL 0
#define INTEGRITY_LABEL 1

// difc syscalls
#define __NR_clone_temp 220
#define __NR_permanent_declassify 402
#define __NR_temporarily_declassify 403
#define __NR_restore_suspended_capabilities 404


#define __NR_set_task_domain 428
#define __NR_udom_ops 429
#define __NR_udom_mem_ops 430
#define __NR_udom_alloc 431
#define __NR_udom_free 432
#define __NR_udom_mprotect 433
#define __NR_udom_get 434
#define __NR_udom_set 435
#define __NR_udom_mmap 436
#define __NR_udom_mmap_cache 437
#define __NR_udom_mprotect_set 438
#define __NR_udom_mprotect_evict 439
#define __NR_udom_mprotect_grouping 440
#define __NR_udom_mprotect_exec 441
#define __NR_mprotect_exec 442
#define __NR_udom_munmap 443
#define __NR_alloc_label 444
#define __NR_set_task_label 445
#define __NR_udom_clone 446
#define __NR_mkdir_labeled 447
#define __NR_create_labeled 448
#define __NR_set_labeled_file 449




#define DOMAIN_NOACCESS	0
#define DOMAIN_CLIENT	1
#define DOMAIN_MANAGER	3

struct label_struct {

    label_t sList[LABEL_LIST_LABELS]; // secrecy label
    label_t iList[LABEL_LIST_LABELS]; // integrity label
};

enum label_type_t {
    NO_LABEL = 0x0,
    S_LABEL = 0x1,
    I_LABEL = 0x2,
    O_LABEL = 0x4,
    SI_LABELS = 0x3,
    ALL_LABELS = 0x7
};

enum label_types {OWNERSHIP_ADD = 0, OWNERSHIP_DROP, SEC_LABEL, INT_LABEL, SEC_LABEL_FLOATING, INT_LABEL_FLOATING, NO_OP};
enum smv_ops {INIT = 0, INIT_CREATE, CREATE, KILL, REGISTER, EXISTS,NO_SMV_OPS};
enum smv_udom_ops {JOIN = 0, LEAVE, CHECK,NO_UDOM_OPS};
enum udom_ops {UDOM_CREATE = 0, UDOM_KILL, UDOM_MMAP_REG, UDOM_DATA,UDOM_MAINID,UDOM_QUERYID,UDOM_PRIVID,UDOM_PRIV_OPS};
enum udom_priv_ops {UDOM_GET = 0, UDOM_ADD, UDOM_REMOVE,NO_UDOM_PRIV_OPS};


#endif /*_UAPI_DIFC_H */