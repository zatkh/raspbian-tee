#include "defs.h"
#include "seccomp.h"
#include <stdarg.h>
#include <err.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <sys/utsname.h>
#include "bpf.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <malloc.h>
#include <sys/types.h>
#include <assert.h>
#include <sys/mman.h>

#define DEBUGMODE
#define DEFAULT_ROOT "/tmp/sandbox-"
#define PATH_DEV_NULL "/dev/null"
#define PATH_DEV_ZERO "/dev/zero"
#define PATH_DEV_NOT_ALLOWED "/dev/tty1"

#if defined __NR_tkill
#define my_tkill(tid, sig) syscall(__NR_tkill, (tid), (sig))
#else
/* kill() may choose arbitrarily the target task of the process group
   while we later wait on a that specific TID.  PID process waits become
   TID task specific waits for a process under ptrace(2).  */
#warning "Neither tkill(2) nor tgkill(2) available, risk of strace hangs!"
#define my_tkill(tid, sig) kill((tid), (sig))
#endif


static inline int seccomp(unsigned int op, unsigned int flags, void *args)
{
    errno = 0;
    return syscall(__NR_seccomp, op, flags, args);
}
// initializing the sandbox with allowed path-whitlisting
void sandbox_init(const char *allowed_path)
{
    struct sock_filter filter0[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
        // Check the objects of group 5 matching the first argument
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ARG_EVAL | 1 << 8 | 5),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog0 = {
        .len = (unsigned short)ARRAY_SIZE(filter0),
        .filter = filter0,
    };
    struct sock_filter filter1[] = {
        /* Does not need to check for arch nor syscall number because
         * of the @checker_group check
         */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, checker_group)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 5, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* Kill if not a valid syscall (unknown open‽) */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, is_valid_syscall)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        /* Denied access if the first argument was not validated by the
         * checker.
         */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, match_arg(0)),
        /* Match the first two checkers, if any */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* Use an impossible errno value to ensure it comes from our
         * filter (should be EACCES most of the time).
         */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | E2BIG),
    };
    struct sock_fprog prog1 = {
        .len = (unsigned short)ARRAY_SIZE(filter1),
        .filter = filter1,
    };
    struct seccomp_object_path path0 = SECCOMP_MAKE_PATH_DENTRY(allowed_path);
    struct seccomp_checker checker0[] = {
        SECCOMP_MAKE_OBJ_PATH(FS_LITERAL, &path0),
    };
    /* Group 5 */
    struct seccomp_checker_group checker_group0 = {
        .version = 1,
        .id = 5,
        .len = ARRAY_SIZE(checker0),
        .checkers = &checker0,
    };

    int ret = seccomp(SECCOMP_ADD_CHECKER_GROUP, 0, &checker_group0);
    if (ret != 0) {
        printf("faild to add the checker group\n");
    }
    // load prog1 and prog0 filters
    ret = seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog1);
    if (ret != 0) {
        printf("faild to load filters\n");
    }

    ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog0);
    if (ret != 0) {
        printf("faild to load filters\n");
    }

    // printf("we are good for now\n");
}

void seccomp_sb_test(void)
{

    int fd;

    // this allowed path
    fd = open(PATH_DEV_ZERO, O_RDONLY);
    if (fd == -1) {
        printf("before enabling sandbox :faild to open %s\n", PATH_DEV_ZERO);
    }
    close(fd);

    fd = open(PATH_DEV_NOT_ALLOWED, O_RDONLY);
    if (fd == -1) {
        printf("before enabling sandbox :faild to open %s\n", PATH_DEV_NOT_ALLOWED);
    }
    printf("before enabling sandbox : opening %s is ok\n", PATH_DEV_NOT_ALLOWED);
    close(fd);

    // enabling sandbox with allowed path
    printf("initializing the sandbox with allowed path: %s\n", PATH_DEV_ZERO);
    sandbox_init(PATH_DEV_ZERO);

    // alowed path should be ok after enabling the sandbox
    fd = open(PATH_DEV_ZERO, O_RDONLY);
    if (fd == -1) {
        printf("after enabling sandbox :faild to open %s\n", PATH_DEV_ZERO);
    }
    printf("after enabling sandbox oppenning %s is ok\n", PATH_DEV_ZERO);

    close(fd);

    // sandbox shouldn't let us open the unallowed path
    fd = open(PATH_DEV_NOT_ALLOWED, O_RDONLY);
    if (fd == -1) {
        printf("after enabling sandbox :faild to open %s\n", PATH_DEV_NOT_ALLOWED);
    }
    close(fd);
}
