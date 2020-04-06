#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <linux/fs.h>
//Constants
#define WEIRIO 'w'

//#define WEIR_HELLO _IOWR(WEIRIO, 0, struct hello)
#define WEIR_GET_PROC_SECLABEL _IOWR(WEIRIO, 1, struct seclabel_struct)
#define WEIR_ADD_GLOBAL_CAP _IOWR(WEIRIO, 2, struct global_cap)
#define WEIR_INIT_PROC_SEC_CONTEXT _IOWR(WEIRIO, 3, struct process_sec_context)
#define WEIR_ADD_TAG_TO_LABEL _IOWR(WEIRIO, 4, struct add_tag_struct)
#define WEIR_ADD_PROCESS_CAP _IOWR(WEIRIO, 5, struct process_cap)

/*IO Datatypes*/
typedef signed long long tag_t;
struct seclabel_struct{
	pid_t pid;
	tag_t *sec;
	int *secsize;
};

struct global_cap{
	tag_t tag;
	int pos; //1=pos, -1=neg, do nothing for 0
	int add; //1=add, -1=rem, do nothing for 0
};

struct process_cap{
	pid_t pid;
	tag_t tag;
	int pos; //1=pos, -1=neg, do nothing for 0
	int add; //1=add, -1=rem, do nothing for 0
};


struct add_tag_struct{
	pid_t pid;
	tag_t tag;
};

struct process_sec_context{
	pid_t pid;
	uid_t uid;
	tag_t* sec;
	tag_t* pos;
	tag_t* neg;
	int secsize;
	int possize;
	int negsize;
};
