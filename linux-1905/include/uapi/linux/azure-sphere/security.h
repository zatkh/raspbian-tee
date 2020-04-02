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
#define SANDBOX_TCB  1029
#define APPMAN_TCB   4875
#define UNTRUSTED_TCB 2938
#define REGULAR_TCB 3847

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

#endif /*CONFIG_EXTENDED_LSM_DIFC */

// Newer kernels have a good UUID framework - switch to that
// when available
struct azure_sphere_guid {
    u32 data1;
    u16 data2;
    u16 data3;
    u8 data4[8];
};

// exposed through /proc/<pid>/attr/exec
struct azure_sphere_task_cred {
    union {
        u8     raw_bytes[16];
        struct azure_sphere_guid guid;
    } component_id;
    char   daa_tenant_id[64];
    bool   is_app_man : 1;
    bool   job_control_allowed : 1;
    unsigned int : 0;
    u32 capabilities;

#ifdef CONFIG_EXTENDED_LSM_DIFC

    struct label_struct label; //each task has a secrecy or integrity label
	struct list_head capList; // list of task's capabilities
	struct list_head suspendedCaps;//can be used for fork/clone to temporarly drop caps
	spinlock_t cap_lock; // lock capabilities.
	int tcb;  //special integrity tag, part of TCB

#endif    
};


#endif