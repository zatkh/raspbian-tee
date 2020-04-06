#define TEMP_PATH "/tmp/test"
#define TASK_STACK_SIZE (8 * 1024)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  
#include <linux/sched.h> 
#endif
#include <sched.h>


#define CSIGNAL 0x000000ff       /* signal mask to be sent at exit */
#define CLONE_VM 0x00000100      /* set if VM shared between processes */
#define CLONE_FS 0x00000200      /* set if fs info shared between processes */
#define CLONE_FILES 0x00000400   /* set if open files shared between processes */
#define CLONE_SIGHAND 0x00000800 /* set if signal handlers and blocked signals shared */
#define CLONE_PTRACE 0x00002000  /* set if we want to let tracing continue on the child too */
#define CLONE_VFORK 0x00004000   /* set if the parent wants the child to wake it up on mm_release */
#define CLONE_PARENT 0x00008000  /* set if we want to have the same parent as the cloner */
#define CLONE_THREAD 0x00010000  /* Same thread group? */
#define CLONE_NEWNS 0x00020000   /* New mount namespace group */
#define CLONE_SYSVSEM 0x00040000 /* share system V SEM_UNDO semantics */
#define CLONE_SETTLS 0x00080000  /* create a new TLS for the child */
#define CLONE_PARENT_SETTID 0x00100000  /* set the TID in the parent */
#define CLONE_CHILD_CLEARTID 0x00200000 /* clear the TID in the child */
#define CLONE_DETACHED 0x00400000       /* Unused, ignored */
#define CLONE_UNTRACED \
    0x00800000 /* set if the tracing process can't force CLONE_PTRACE on this clone */
#define CLONE_CHILD_SETTID 0x01000000 /* set the TID in the child */
#define CLONE_NEWCGROUP 0x02000000    /* New cgroup namespace */
#define CLONE_NEWUTS 0x04000000       /* New utsname namespace */
#define CLONE_NEWIPC 0x08000000       /* New ipc namespace */
#define CLONE_NEWUSER 0x10000000      /* New user namespace */
#define CLONE_NEWPID 0x20000000       /* New pid namespace */
#define CLONE_NEWNET 0x40000000       /* New network namespace */
#define CLONE_IO 0x80000000           /* Clone io context */

void test_unallowed_mkdir(void);
void test_unallowed_file(void);
void test_declassification(void);
void test_difc_domain_entreis(void);
void test_label_existing_file(void);
void difc_threading_test_labeld(void);
void difc_threading_test(void);
void difc_labeled_domain_dcl(void);
void udom_test(void);
void fl_test(void);
int sw_udom_test(void);
int sw_udom_test2(void);
int swu_malloc(void);