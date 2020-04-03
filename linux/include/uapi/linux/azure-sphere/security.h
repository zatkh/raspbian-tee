// SPDX-License-Identifier: GPL-2.0
/*
 * Azure Sphere Linux Security Module
 *
 * Copyright (c) 2018 Microsoft Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */
#ifndef __UAPI_AZURE_SPHERE_SECURITY_H
#define __UAPI_AZURE_SPHERE_SECURITY_H
#include <linux/types.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mutex.h>

#ifdef CONFIG_EXTENDED_LSM_DIFC
// labels and capabilities related variables & data structs should be here
typedef uint64_t label_t;
typedef uint64_t capability_t;
typedef capability_t* capList_t;

#define LABEL_LIST_BYTES 256
#define LABEL_LIST_LABELS (LABEL_LIST_BYTES / sizeof(label_t))
#define LABEL_LIST_MAX_ENTRIES (LABEL_LIST_BYTES / sizeof(label_t)) - 1 
/*cap lists max size */
#define CAP_LIST_BYTES 256
#define CAP_LIST_CAPS (LABEL_LIST_BYTES / sizeof(capability_t))
#define CAP_LIST_MAX_ENTRIES (CAP_LIST_BYTES / sizeof(capability_t)) - 1
/* Use the upper two bits for +/- */
#define PLUS_CAPABILITY  (1<<30)
#define MINUS_CAPABILITY (1<<31)
#define CAP_MAX_VAL    (1<<29)
#define CAP_LABEL_MASK (0xFFFFFFFF ^ (PLUS_CAPABILITY | MINUS_CAPABILITY))

#define THREAD_NONE  0
#define THREAD_SELF  1
#define THREAD_GROUP 2

//should verfy it's sandbox image before setting this, 
//the tcb should be uniqe based on forexample hash of images signitarure
//I'm just using random numbers here for debugging 
#define TEMP_DCL_TCB  1029
#define APPMAN_TCB   4875
#define REGULAR_TCB 3847
#define FLOATING_TCB 2938

extern struct kmem_cache *tag_struct;


struct label_struct {
    label_t sList[LABEL_LIST_LABELS]; //secrecy label
    label_t iList[LABEL_LIST_LABELS]; //integrity label
};

struct cap_segment{
	struct list_head list;
	capability_t caps[CAP_LIST_CAPS];
};

struct object_security_struct {
	struct label_struct label;
	struct rw_semaphore label_change_sem; 
};

//enum label_types {OWNERSHIP_ADD = 0, OWNERSHIP_DROP, SEC_LABEL, INT_LABEL, SEC_LABEL_FLOATING, INT_LABEL_FLOATING};
enum smv_ops {INIT = 0, INIT_CREATE, CREATE, KILL, REGISTER, EXISTS,NO_SMV_OPS};
enum smv_udom_ops {JOIN = 0, LEAVE, CHECK,NO_UDOM_OPS};
enum udom_ops {UDOM_CREATE = 0, UDOM_KILL, UDOM_MMAP_REG, UDOM_DATA,UDOM_MAINID,UDOM_QUERYID,UDOM_PRIVID,UDOM_PRIV_OPS};
enum udom_priv_ops {UDOM_GET = 0, UDOM_ADD, UDOM_REMOVE,NO_UDOM_PRIV_OPS};
enum tag_type {TAG_CONF = 0, TAG_EXP, TAG_FLO};

struct tag {
	struct list_head next;
	unsigned long content;
	int type;

};


struct inode_difc {
	struct list_head slabel;
	struct list_head ilabel;
	int type;

};



struct socket_difc {
	struct inode_difc *isp;
	struct inode_difc *peer_isp;
};
#endif /*CONFIG_EXTENDED_LSM_DIFC */


#ifdef CONFIG_EXTENDED_FLOATING_DIFC
typedef s64 tag_t;

struct file_security_struct {
	struct tag* seclabel; /* Secrecy label  */
	struct mutex lock;
};

//extern size_t difc_label_change(struct file *file, const char __user *buf, 
//			size_t size, loff_t *ppos, struct task_security_struct *tsp, enum label_types ops);

//extern size_t difc_confine_task(struct file *file, const char __user *buf, 
//				size_t size, loff_t *ppos, struct task_security_struct *tsp);

#endif //CONFIG_EXTENDED_FLOATING_DIFC//

// exposed through /proc/<pid>/attr/exec
struct task_security_struct {

#ifdef CONFIG_EXTENDED_LSM_DIFC

    struct label_struct label; //each task has a secrecy or integrity label

	int type;  //special tag: fthread=1 ethread=2 not_labeld=3

	struct list_head slabel;
	struct list_head ilabel;
	struct list_head olabel;



#endif  

#ifdef CONFIG_EXTENDED_FLOATING_DIFC
    pid_t pid;         
    uid_t uid;
	struct tag* seclabel; /* Secrecy label  */
	struct tag* poscaps; /* + capabilities */
	struct tag* negcaps; /* - capabilities */
	struct mutex lock;
#endif //CONFIG_EXTENDED_FLOATING_DIFC//



};


#endif