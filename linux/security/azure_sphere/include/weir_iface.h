#ifndef _SECURITY_WEIR_IFACE_H
#define _SECURITY_WEIR_IFACE_H
#include <linux/list.h>
#include <linux/ioctl.h>
#include <linux/xattr.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include "weir_objsec.h"
//Constants
#define WEIRIO 'w'

/*IO Datatypes*/
struct hello
{
	char* hellomsg;
	long hellolen;
};

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

//Protocol
enum WEIRIfaceProtocol {
	WEIR_HELLO = _IOWR(WEIRIO, 0, struct hello),
	WEIR_GET_PROC_SECLABEL = _IOWR(WEIRIO, 1, struct seclabel_struct),
	WEIR_ADD_GLOBAL_CAP = _IOWR(WEIRIO, 2, struct global_cap),
	WEIR_INIT_PROC_SEC_CONTEXT = _IOWR(WEIRIO, 3, struct process_sec_context),
	WEIR_ADD_TAG_TO_LABEL = _IOWR(WEIRIO, 4, struct add_tag_struct),
	WEIR_ADD_PROCESS_CAP = _IOWR(WEIRIO, 5, struct process_cap),
};

//Functions

#endif  /* _SECURITY_WEIR_IFACE_H */
