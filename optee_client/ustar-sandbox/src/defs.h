/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef _LARGEFILE64_SOURCE
/* This is the macro everything checks before using foo64 names.  */
#ifndef _LFS64_LARGEFILE
#define _LFS64_LARGEFILE 1
#endif
#endif
#ifdef MIPS
#include <sgidefs.h>
#endif
#include <features.h>
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#ifdef STDC_HEADERS
#include <stddef.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <stdbool.h>


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define match_arg(_n) (offsetof(struct seccomp_data, arg_matches[_n]))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]) + sizeof(__u32))
#define match_arg(_n) (offsetof(struct seccomp_data, arg_matches[_n]) + sizeof(__u32))
#else
#error "wut? Unknown __BYTE_ORDER?!"
#endif

#ifndef PATH_MAX
#define PATH_MAX MAXPATHLEN
#endif

#ifndef HAVE_STPCPY
/* Some libc have stpcpy, some don't. Sigh...
 * Roll our private implementation...
 */
#undef stpcpy
#define stpcpy strace_stpcpy
extern char *stpcpy(char *dst, const char *src);
#endif

#if !defined __GNUC__
#define __attribute__(x) /*nothing*/
#endif

#ifndef offsetof
#define offsetof(type, member) (((char *)&(((type *)NULL)->member)) - ((char *)(type *)NULL))
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* Glibc has an efficient macro for sigemptyset
 * (it just does one or two assignments of 0 to internal vector of longs).
 */
#if defined(__GLIBC__) && defined(__sigemptyset) && !defined(sigemptyset)
#define sigemptyset __sigemptyset
#endif

/* Configuration section */
#ifndef MAX_QUALS
#if defined(MIPS)
#define MAX_QUALS 7000 /* maximum number of syscalls, signals, etc. */
#else
#define MAX_QUALS 2048 /* maximum number of syscalls, signals, etc. */
#endif
#endif
#ifndef DEFAULT_STRLEN
/* default maximum # of bytes printed in `printstr', change with -s switch */
#define DEFAULT_STRLEN 32
#endif
#ifndef DEFAULT_ACOLUMN
#define DEFAULT_ACOLUMN 40 /* default alignment column for results */
#endif
/*
 * Maximum number of args to a syscall.
 *
 * Make sure that all entries in all syscallent.h files have nargs <= MAX_ARGS!
 * linux/<ARCH>/syscallent.h: all have nargs <= 6.
 */
#ifndef MAX_ARGS
#define MAX_ARGS 6
#endif
/* default sorting method for call profiling */
#ifndef DEFAULT_SORTBY
#define DEFAULT_SORTBY "time"
#endif

#if defined(SPARC) || defined(SPARC64)
#define LINUXSPARC
#endif
#if defined(MIPS) && _MIPS_SIM == _MIPS_SIM_ABI32
#define LINUX_MIPSO32
#endif
#if defined(MIPS) && _MIPS_SIM == _MIPS_SIM_NABI32
#define LINUX_MIPSN32
#define LINUX_MIPS64
#endif
#if defined(MIPS) && _MIPS_SIM == _MIPS_SIM_ABI64
#define LINUX_MIPSN64
#define LINUX_MIPS64
#endif

#if (defined(LINUXSPARC) || defined(X86_64) || defined(ARM) || defined(AVR32)) && defined(__GLIBC__)
#include <sys/ptrace.h>
#else
/* Work around awkward prototype in ptrace.h. */
#define ptrace xptrace
#include <sys/ptrace.h>
#undef ptrace
#ifdef POWERPC
#define __KERNEL__
#include <asm/ptrace.h>
#undef __KERNEL__
#endif
extern long ptrace(int, int, char *, long);
#endif

/*
#if !defined(__GLIBC__)
# define PTRACE_PEEKUSER PTRACE_PEEKUSR
# define PTRACE_POKEUSER PTRACE_POKEUSR
#endif
*/

#if defined(X86_64) || defined(X32) || defined(I386)
/* For struct pt_regs. x86 strace uses PTRACE_GETREGS.
 * PTRACE_GETREGS returns registers in the layout of this struct.
 */
#include <asm/ptrace.h>
#endif
#ifdef ALPHA
#define REG_R0 0
#define REG_A0 16
#define REG_A3 19
#define REG_FP 30
#define REG_PC 64
#endif /* ALPHA */
#ifdef MIPS
#define REG_V0 2
#define REG_A0 4
#define REG_A3 7
#define REG_SP 29
#define REG_EPC 64
#endif /* MIPS */
#ifdef HPPA
#define PT_GR20 (20 * 4)
#define PT_GR26 (26 * 4)
#define PT_GR28 (28 * 4)
#define PT_IAOQ0 (106 * 4)
#define PT_IAOQ1 (107 * 4)
#endif /* HPPA */
#ifdef SH64
/* SH64 Linux - this code assumes the following kernel API for system calls:
       PC           Offset 0
       System Call  Offset 16 (actually, (syscall no.) | (0x1n << 16),
                    where n = no. of parameters.
       Other regs   Offset 24+

       On entry:    R2-7 = parameters 1-6 (as many as necessary)
       On return:   R9   = result. */

/* Offset for peeks of registers */
#define REG_OFFSET (24)
#define REG_GENERAL(x) (8 * (x) + REG_OFFSET)
#define REG_PC (0 * 8)
#define REG_SYSCALL (2 * 8)
#endif /* SH64 */

#define SUPPORTED_PERSONALITIES 1
#define DEFAULT_PERSONALITY 0

#ifdef LINUXSPARC
/* Indexes into the pt_regs.u_reg[] array -- UREG_XX from kernel are all off
 * by 1 and use Ix instead of Ox.  These work for both 32 and 64 bit Linux. */
#define U_REG_G1 0
#define U_REG_O0 7
#define U_REG_O1 8
#define PERSONALITY0_WORDSIZE 4
#define PERSONALITY1_WORDSIZE 4
#undef SUPPORTED_PERSONALITIES
#if defined(SPARC64)
#include <asm/psrcompat.h>
#define SUPPORTED_PERSONALITIES 3
#define PERSONALITY2_WORDSIZE 8
#else
#include <asm/psr.h>
#define SUPPORTED_PERSONALITIES 2
#endif /* SPARC64 */
#endif /* LINUXSPARC */

#ifdef X86_64
#undef SUPPORTED_PERSONALITIES
#define SUPPORTED_PERSONALITIES 3
#define PERSONALITY0_WORDSIZE 8
#define PERSONALITY1_WORDSIZE 4
#define PERSONALITY2_WORDSIZE 4
#endif

#ifdef X32
#undef SUPPORTED_PERSONALITIES
#define SUPPORTED_PERSONALITIES 2
#define PERSONALITY0_WORDSIZE 4
#define PERSONALITY1_WORDSIZE 4
#endif

#ifdef ARM
#undef SUPPORTED_PERSONALITIES
#define SUPPORTED_PERSONALITIES 2
#define PERSONALITY0_WORDSIZE 4
#define PERSONALITY1_WORDSIZE 4
#endif

#ifdef POWERPC64
#undef SUPPORTED_PERSONALITIES
#define SUPPORTED_PERSONALITIES 2
#define PERSONALITY0_WORDSIZE 8
#define PERSONALITY1_WORDSIZE 4
#endif

#ifndef PERSONALITY0_WORDSIZE
#define PERSONALITY0_WORDSIZE sizeof(long)
#endif

#if !HAVE_DECL_PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS 0x4200
#endif
#if !HAVE_DECL_PTRACE_GETEVENTMSG
#define PTRACE_GETEVENTMSG 0x4201
#endif
#if !HAVE_DECL_PTRACE_GETSIGINFO
#define PTRACE_GETSIGINFO 0x4202
#endif

#if !HAVE_DECL_PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 0x00000001
#endif
#if !HAVE_DECL_PTRACE_O_TRACEFORK
#define PTRACE_O_TRACEFORK 0x00000002
#endif
#if !HAVE_DECL_PTRACE_O_TRACEVFORK
#define PTRACE_O_TRACEVFORK 0x00000004
#endif
#if !HAVE_DECL_PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE 0x00000008
#endif
#if !HAVE_DECL_PTRACE_O_TRACEEXEC
#define PTRACE_O_TRACEEXEC 0x00000010
#endif
#if !HAVE_DECL_PTRACE_O_TRACEEXIT
#define PTRACE_O_TRACEEXIT 0x00000040
#endif
#if !HAVE_DECL_PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP 0x00000080
#endif
#if !HAVE_DECL_PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL 0x00100000
#endif

#if !HAVE_DECL_PTRACE_EVENT_FORK
#define PTRACE_EVENT_FORK 1
#endif
#if !HAVE_DECL_PTRACE_EVENT_VFORK
#define PTRACE_EVENT_VFORK 2
#endif
#if !HAVE_DECL_PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif
#if !HAVE_DECL_PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC 4
#endif
#if !HAVE_DECL_PTRACE_EVENT_VFORK_DONE
#define PTRACE_EVENT_VFORK_DONE 5
#endif
#if !HAVE_DECL_PTRACE_EVENT_EXIT
#define PTRACE_EVENT_EXIT 6
#endif
#if !HAVE_DECL_PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP 7
#endif

/* Experimental code using PTRACE_SEIZE can be enabled here: */
//# define USE_SEIZE 1

#ifdef USE_SEIZE
#undef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#undef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#undef PTRACE_LISTEN
#define PTRACE_LISTEN 0x4208
#undef PTRACE_SEIZE_DEVEL
#define PTRACE_SEIZE_DEVEL 0x80000000
#undef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 7
#define PTRACE_EVENT_STOP1 128
#endif

#if defined(I386)
extern struct pt_regs i386_regs;
#endif
#if defined(IA64)
extern long ia32;
#endif

#define ARG_RET (6)

// uni-directional list of per-process log
struct auditlog {
    char log[128];
    struct auditlog *prev;
};

// uni-directional log of system-wide log
struct systemlog {
    int pid;
    struct auditlog *logs;
    struct systemlog *next;
};

extern struct systemlog *systemlog;


/* TCB flags */
#define TCB_INUSE 00001 /* This table entry is in use */
/* We have attached to this process, but did not see it stopping yet */
#define TCB_STARTUP 00002
#define TCB_IGNORE_ONE_SIGSTOP 00004 /* Next SIGSTOP is to be ignored */
/*
 * Are we in system call entry or in syscall exit?
 *
 * This bit is set after all syscall entry processing is done.
 * Therefore, this bit will be set when next ptrace stop occurs,
 * which should be syscall exit stop. Other stops which are possible
 * directly after syscall entry (death, ptrace event stop)
 * are simpler and handled without calling trace_syscall(), therefore
 * the places where TCB_INSYSCALL can be set but we aren't in syscall stop
 * are limited to trace(), this condition is never observed in trace_syscall()
 * and below.
 * The bit is cleared after all syscall exit processing is done.
 * User-generated SIGTRAPs and post-execve SIGTRAP make it necessary
 * to be very careful and NOT set TCB_INSYSCALL bit when they are encountered.
 * TCB_WAITEXECVE bit is used for this purpose (see below).
 *
 * Use entering(tcp) / exiting(tcp) to check this bit to make code more readable.
 */
#define TCB_INSYSCALL 00010
#define TCB_ATTACHED 00020 /* It is attached already */
/* Are we PROG from "strace PROG [ARGS]" invocation? */
#define TCB_STRACE_CHILD 0040
#define TCB_BPTSET 00100   /* "Breakpoint" set after fork(2) */
#define TCB_REPRINT 00200  /* We should reprint this syscall on exit */
#define TCB_FILTERED 00400 /* This system call has been filtered out */
/* x86 does not need TCB_WAITEXECVE.
 * It can detect SIGTRAP by looking at eax/rax.
 * See "not a syscall entry (eax = %ld)\n" message
 * in syscall_fixup_on_sysenter().
 */
#if defined(ALPHA) || defined(AVR32) || defined(SPARC) || defined(SPARC64) || defined(POWERPC) || \
    defined(IA64) || defined(HPPA) || defined(SH) || defined(SH64) || defined(S390) ||            \
    defined(S390X) || defined(ARM) || defined(MIPS) || defined(BFIN) || defined(TILE)
/* This tracee has entered into execve syscall. Expect post-execve SIGTRAP
 * to happen. (When it is detected, tracee is continued and this bit is cleared.)
 */
#define TCB_WAITEXECVE 01000
#endif

/* qualifier flags */
#define QUAL_TRACE 0001   /* this system call should be traced */
#define QUAL_ABBREV 0002  /* abbreviate the structures of this syscall */
#define QUAL_VERBOSE 0004 /* decode the structures of this syscall */
#define QUAL_RAW 0010     /* print all args in hex for this syscall */
#define QUAL_SIGNAL 0020  /* report events with this signal */
#define QUAL_FAULT 0040   /* report events with this fault */
#define QUAL_READ 0100    /* dump data read on this file descriptor */
#define QUAL_WRITE 0200   /* dump data written to this file descriptor */

#define entering(tcp) (!((tcp)->flags & TCB_INSYSCALL))
#define exiting(tcp) ((tcp)->flags & TCB_INSYSCALL)
#define syserror(tcp) ((tcp)->u_error != 0)
#define verbose(tcp) (qual_flags[(tcp)->scno] & QUAL_VERBOSE)
#define abbrev(tcp) (qual_flags[(tcp)->scno] & QUAL_ABBREV)
#define filtered(tcp) ((tcp)->flags & TCB_FILTERED)

struct xlat {
    int val;
    const char *str;
};

extern const struct xlat open_mode_flags[];
extern const struct xlat addrfams[];
extern const struct xlat struct_user_offsets[];
extern const struct xlat open_access_modes[];

/* Format of syscall return values */
#define RVAL_DECIMAL 000  /* decimal format */
#define RVAL_HEX 001      /* hex format */
#define RVAL_OCTAL 002    /* octal format */
#define RVAL_UDECIMAL 003 /* unsigned decimal format */
#if defined(LINUX_MIPSN32) || defined(X32)
#if 0                     /* unused so far */
#define RVAL_LDECIMAL 004 /* long decimal format */
#define RVAL_LHEX 005     /* long hex format */
#define RVAL_LOCTAL 006   /* long octal format */
#endif
#define RVAL_LUDECIMAL 007 /* long unsigned decimal format */
#endif
#define RVAL_MASK 007 /* mask for these values */

#define RVAL_STR 010  /* Print `auxstr' field after return val */
#define RVAL_NONE 020 /* Print nothing */

#define TRACE_FILE 001           /* Trace file-related syscalls. */
#define TRACE_IPC 002            /* Trace IPC-related syscalls. */
#define TRACE_NETWORK 004        /* Trace network-related syscalls. */
#define TRACE_PROCESS 010        /* Trace process-related syscalls. */
#define TRACE_SIGNAL 020         /* Trace signal-related syscalls. */
#define TRACE_DESC 040           /* Trace file descriptor-related syscalls. */
#define SYSCALL_NEVER_FAILS 0100 /* Syscall is always successful. */

typedef enum { CFLAG_NONE = 0, CFLAG_ONLY_STATS, CFLAG_BOTH } cflag_t;

extern cflag_t cflag;
extern int *qual_flags;
extern bool debug_flag;
extern bool Tflag;
extern bool qflag;
extern bool not_failing_only;
extern bool show_fd_path;
extern bool tracing_paths;
extern unsigned int xflag;
extern unsigned int followfork;
extern unsigned int ptrace_setoptions;
extern unsigned int max_strlen;

extern char *opt_root;
extern int opt_root_len;
extern bool opt_seccomp;
extern bool opt_interactive;
extern bool opt_no_nw;
extern bool opt_fakeroot;
extern bool opt_md5;


enum bitness_t { BITNESS_CURRENT = 0, BITNESS_32 };

void error_msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void perror_msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void error_msg_and_die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
void perror_msg_and_die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
void die_out_of_memory(void) __attribute__((noreturn));

#ifdef USE_CUSTOM_PRINTF
/*
 * Speed-optimized vfprintf implementation.
 * See comment in vsprintf.c for allowed formats.
 * Short version: %h[h]u, %zu, %tu are not allowed, use %[l[l]]u.
 *
 * It results in strace using about 5% less CPU in user space
 * (compared to glibc version).
 * But strace spends a lot of time in kernel space,
 * so overall it does not appear to be a significant win.
 * Thus disabled by default.
 */
int strace_vfprintf(FILE *fp, const char *fmt, va_list args);
#else
#define strace_vfprintf vfprintf
#endif

extern void set_sortby(const char *);
extern void set_overhead(int);
extern void qualify(const char *);
extern void call_summary(FILE *);

/*
 * On Linux, "setbpt" is a misnomer: we don't set a breakpoint
 * (IOW: no poking in user's text segment),
 * instead we change fork/vfork/clone into clone(CLONE_PTRACE).
 * On newer kernels, we use PTRACE_O_TRACECLONE/TRACE[V]FORK instead.
 */


typedef unsigned char byte;




/* Strace log generation machinery.
 *
 * printing_tcp: tcb which has incomplete line being printed right now.
 * NULL if last line has been completed ('\n'-terminated).
 * printleader(tcp) examines it, finishes incomplete line if needed,
 * the sets it to tcp.
 * line_ended() clears printing_tcp and resets ->curcol = 0.
 * tcp->curcol == 0 check is also used to detect completeness
 * of last line, since in -ff mode just checking printing_tcp for NULL
 * is not enough.
 *
 * If you change this code, test log generation in both -f and -ff modes
 * using:
 * strace -oLOG -f[f] test/threaded_execve
 * strace -oLOG -f[f] test/sigkill_rain
 * strace -oLOG -f[f] -p "`pidof web_browser`"
 */


#define tprintf(fmt, ...)                \
    ({                                   \
        if (debug_flag) {                \
            __tprintf(fmt, __VA_ARGS__); \
        }                                \
    })

#define tprints(str)        \
    ({                      \
        if (debug_flag) {   \
            __tprints(str); \
        }                   \
    })

#define line_ended()        \
    ({                      \
        if (debug_flag) {   \
            __line_ended(); \
        }                   \
    })

#define tabto()           \
    ({                    \
        if (debug_flag) { \
            __tabto();    \
        }                 \
    })

#if SUPPORTED_PERSONALITIES > 1
extern void set_personality(int personality);
extern int current_personality;
extern const int personality_wordsize[];
#define current_wordsize (personality_wordsize[current_personality])
#else
#define set_personality(personality) ((void)0)
#define current_personality 0
#define current_wordsize PERSONALITY0_WORDSIZE
#endif

struct sysent {
    unsigned nargs;
    int sys_flags;
    int (*sys_func)(void);
    int (*sbox_func)(void);
    const char *sys_name;
};

struct ioctlent {
    const char *doth;
    const char *symbol;
    unsigned long code;
};

extern const struct sysent *sysent;
extern unsigned nsyscalls;
extern const char *const *errnoent;
extern unsigned nerrnos;
extern const struct ioctlent *ioctlent;
extern unsigned nioctlents;
extern const char *const *signalent;
extern unsigned nsignals;

#define SCNO_IN_RANGE(scno) ((unsigned long)(scno) < nsyscalls && sysent[scno].sys_func)
