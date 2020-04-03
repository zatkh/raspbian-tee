// SPDX-License-Identifier: GPL-2.0
/*
 * Azure Sphere Linux Security Module
 *
 * Copyright (c) 2018 Microsoft Corporation. All rights reseret_valed.
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

#include <linux/device.h>
#include <linux/lsm_hooks.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/binfmts.h>
#include <linux/types.h>
#include <linux/security.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>

#include <azure-sphere/security.h>

#ifdef CONFIG_EXTENDED_LSM_DIFC

#include <asm/syscall.h>
#include <linux/compat.h>
#include <linux/slab.h>
#include <linux/syscalls.h>	
#include <linux/mm.h>

#include <asm/elf.h>
#include <asm/unistd.h>
#include <asm/domain.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/bug.h>
#include <asm/tlbflush.h>
#include <asm/udom.h>
#include "lsm.h"


#endif /*CONFIG_EXTENDED_LSM_DIFC */


#ifdef CONFIG_EXTENDED_LSM_DIFC

static struct kmem_cache *difc_obj_kcache;
static struct kmem_cache *difc_caps_kcache;

atomic_t max_caps_num;
typedef label_t* labelList_t;
static int debug = 1;

#define alloc_cap_segment() kmem_cache_zalloc(difc_caps_kcache, GFP_KERNEL)
#define free_cap_segment(s) kmem_cache_free(difc_caps_kcache, s)



#define difc_lsm_debug(fmt, arg...)					\
	do {							\
		if (debug)					\
			printk(KERN_INFO "(pid %d) %s: [%s]: " fmt ,	\
			       current->pid, "[difc_lsm]" , __FUNCTION__ , 	\
				## arg);			\
	} while (0)

/* labellist iterator */
#define list_for_each_label(index, l, head)	\
	for(index = 1; index <= *(head) && ({l = head[index]; 1; }); index++)

/* caplist iterator */
#define list_for_each_cap(index, l, n, head)				\
	list_for_each_entry(n, &(head), list)				\
	for(index = 1; index <= (n)->caps[0] && ({l = (n)->caps[index]; 1; }); index++)


#endif /*CONFIG_EXTENDED_LSM_DIFC */



#ifdef CONFIG_EXTENDED_LSM


struct syscall_argdesc (*seccomp_syscalls_argdesc)[] = NULL;


static const struct syscall_argdesc *__init
find_syscall_argdesc(const struct syscall_argdesc *start,
		const struct syscall_argdesc *stop, const void *addr)
{
	if (unlikely(!addr || !start || !stop)) {
		WARN_ON(1);
		return NULL;
	}

	for (; start < stop; start++) {
		if (start->addr == addr)
			return start;
	}
	return NULL;
}

static inline void __init init_argdesc(void)
{
	const struct syscall_argdesc *argdesc;
	const void *addr;
	int i;

	seccomp_syscalls_argdesc = kcalloc(NR_syscalls,
			sizeof((*seccomp_syscalls_argdesc)[0]), GFP_KERNEL);
	if (unlikely(!seccomp_syscalls_argdesc)) {
		WARN_ON(1);
		return;
	}
	for (i = 0; i < NR_syscalls; i++) {
		addr = (const void *)sys_call_table[i];
		argdesc = find_syscall_argdesc(__start_syscalls_argdesc,
				__stop_syscalls_argdesc, addr);
		if (!argdesc)
			continue;

		(*seccomp_syscalls_argdesc)[i] = *argdesc;
	}
	
}

void __init seccomp_init(void)
{
	pr_info("[seccomp_init] initializing seccomp-based sandboxing\n");
	init_argdesc();
}


#endif /* CONFIG_EXTENDED_LSM */


#ifdef CONFIG_EXTENDED_LSM_DIFC

//allocate a new label and add it to the task's cap set 
static label_t difc_alloc_label(int cap_type, int group_mode)
{

	capability_t new_cap = atomic_inc_return(&max_caps_num);
	struct cred *cred ;
	struct azure_sphere_task_cred *tsec;
	struct cap_segment *cap_seg;
	int is_max=0;

	tsec = kzalloc(sizeof(struct azure_sphere_task_cred), GFP_KERNEL);
	//difc_lsm_debug("after kalloc\n");
  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug("not enough memory\n");
        return -ENOENT;
    }

    //difc_lsm_debug("after creds check\n");

	//get the requested t+ or t- cpabilty
	new_cap |= (cap_type & (PLUS_CAPABILITY| MINUS_CAPABILITY));
/*
	if((new_cap & PLUS_CAPABILITY))
		difc_lsm_debug("allocating cap with PLUS_CAPABILITY \n");

	if((new_cap & MINUS_CAPABILITY))
		difc_lsm_debug("allocating cap with MINUS_CAPABILITY \n");
*/
//difc_lsm_debug("before spinlock\n");
	////spin_lock(&tsec->cap_lock);

//	difc_lsm_debug("after spinlock\n");
	
	list_for_each_entry(cap_seg, &tsec->capList, list){
		if(cap_seg->caps[0] < CAP_LIST_MAX_ENTRIES){
			//difc_lsm_debug("cap_seg->caps[0]%lld \n",cap_seg->caps[0]);
			is_max = 0;
			break;
		}
	}
	if(is_max){
		cap_seg = alloc_cap_segment();
		INIT_LIST_HEAD(&cap_seg->list);
		list_add_tail(&cap_seg->list, &tsec->capList);
	}
	//difc_lsm_debug("after caplist list for ech entry\n");
		
	cap_seg->caps[++(cap_seg->caps[0])] = new_cap;

//labeling mark
	if(tsec->is_app_man)
		tsec->tcb=APPMAN_TCB;
	else
		tsec->tcb=REGULAR_TCB;
	//difc_lsm_debug("tsec tcb %d \n",tsec->tcb);

	////spin_unlock(&tsec->cap_lock);

	// in case we want to give appman extra capabilities to declassify or etc

	//difc_lsm_debug("before commit\n");

	cred->security = tsec;
	commit_creds(cred);

	return (new_cap & CAP_LABEL_MASK);
}

// get capability of a label
static inline capability_t cred_get_capability(struct azure_sphere_task_cred *tsec, label_t label)
{

	capability_t index, cap;
	struct cap_segment *cap_seg;
	list_for_each_cap(index, cap, cap_seg, tsec->capList)
		if((cap & CAP_LABEL_MASK) == label)
			return cap;

	return -1;
}

//copy user's label to kernel label_struct
static void *difc_copy_user_label(const char __user *label)
{
	int ret_val;
	void *buf;
	buf = kmalloc(sizeof(struct label_struct), GFP_KERNEL);
	if(!buf)
		return NULL;
	ret_val = copy_from_user(buf, label, sizeof(struct label_struct));
	if(ret_val){
		difc_lsm_debug(" copy failed missing bytes: %d\n", ret_val);
		kfree(buf);
		return NULL;
	}
	return buf;
}


//check if the task is labeld(or tainted)
static inline int is_task_labeled(struct task_struct *tsk)
{
	const struct cred *cred;
    struct azure_sphere_task_cred *tsec;
	
    cred = get_task_cred(tsk);
    tsec = cred->security;
    if (!tsec) {
        put_cred(cred);
        return 1;
    }

	if((tsec->tcb != REGULAR_TCB) && (tsec->tcb != APPMAN_TCB))
	{
		//difc_lsm_debug("the task is not labeled \n");
		return 1;
	}

	difc_lsm_debug("this task is labeled \n");
	put_cred(cred);
	return 0;
}

int difc_check_task_labeled(struct task_struct *tsk)
{
	return is_task_labeled(tsk);

}


// add label to lables list: 
// secrecy or integrity labels are seperated via label_type 

static inline int add_label(struct label_struct *lables_list, label_t label, int label_type)
{
	label_t index, l;
	labelList_t list;

	//difc_lsm_debug("start adding %llu to the labels\n", label);
	
    switch(label_type){
	case SECRECY_LABEL: list = lables_list->sList; break;
	case INTEGRITY_LABEL: list = lables_list->iList; break;
	default: 
	  difc_lsm_debug("Invalid label, only secrecy & integrity labels are allowed\n");
	  return -EINVAL;
	}
	//check for not repeated label
	list_for_each_label(index, l, list)
	  if(label == l){
	   // difc_lsm_debug("Label already exists\n");
			return -EEXIST;
	  }
	//check the first cell for not exceeding max number of labells
	if((*list) == LABEL_LIST_MAX_ENTRIES){
	  	difc_lsm_debug("reached the max number of label entries\n");
		return -ENOMEM;
	}
    // add the lable to the list
    list[++(*list)] = label;
	//difc_lsm_debug("added the label to the list\n");

	return 0;
}

// remove label from lables list: 
// secrecy or integrity labels are seperated via label_type 

static inline int remove_label(struct label_struct *lables_list, label_t label, int label_type)
{
	label_t index, l;
	labelList_t list;

	//difc_lsm_debug("start removing %llu from the labels\n", label);
	
    switch(label_type){
	case SECRECY_LABEL: list = lables_list->sList; break;
	case INTEGRITY_LABEL: list = lables_list->iList; break;
	default: 
	  difc_lsm_debug("Invalid label, only secrecy & integrity labels\n");
	  return -EINVAL;
	}
	// Find the label 
	list_for_each_label(index, l, list)
		if(label == l)
			break;

	if(index > (*list)){
	  	  difc_lsm_debug("Label doesn't exist\n");
		return -ENOENT;
	}

	//shifting others after removing the label
	while(index < (*list)){
		list[index] = list[index+1];
		index++;
	}
	(*list)--;

  //  difc_lsm_debug("removed the label from the list\n");

	
    return 0;
}

static int __difc_set_task_label(struct task_struct *tsk, struct label_struct *lables_list, label_t label, int operation_type, int label_type, int check_only)
{

	struct cred *cred ;
	struct azure_sphere_task_cred *tsec;
	capability_t cap;

	tsec = kzalloc(sizeof(struct azure_sphere_task_cred), GFP_KERNEL);

	if(tsk != current)
	{
		difc_lsm_debug("can only set labels in current task credential\n");
		return -EPERM;
	}

  	cred = prepare_creds();

    if (!cred) {
		difc_lsm_debug("no cred!\n");
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug("not enough memory\n");
        return -ENOENT;
    }

	//spin_lock(&tsec->cap_lock);
	cap = cred_get_capability(tsec, label); 
	//spin_unlock(&tsec->cap_lock);

	if(!cap){
		difc_lsm_debug(" Failed to find capability for %llu\n", label);
		return -EPERM;
	}

	//difc_lsm_debug("Found the capability \n");

	if(operation_type == ADD_LABEL){
		if((cap & PLUS_CAPABILITY)){
			return check_only ? 0 :  add_label(lables_list, label, label_type);
		} else  {
			difc_lsm_debug(" no PLUS_CAPABILITY for label %llu, cap %llu\n", label, cap);
			return -EPERM;
		}

	} else if(operation_type == REMOVE_LABEL)
	{
		if((cap & MINUS_CAPABILITY)){
			return check_only ? 0 : remove_label(lables_list, label, label_type);
		} else {
			difc_lsm_debug(" no MINUS_CAPABILITY for label %llu, cap %llu\n", label, cap);
			return -EPERM;
		}

	} else {
	        difc_lsm_debug(" Invalid label operation\n");
		return -EINVAL;
	}


	cred->security = tsec;
	commit_creds(cred);

}


// this checks if a label replacement is allowed 
//ZTODO: if we are gonna give appman extra declassification power, it should be checked here,for now we don't

static int check_replacing_labels_allowed(struct task_struct *tsk, struct label_struct *old_label, struct label_struct *new_label)
{

	int ret_val;
	label_t src_index, src_label, dest_index, dest_label;

 	//difc_lsm_debug("enter\n");
 	//difc_lsm_debug("new_label->sList[0]=%lld, new_label->sList[1]=%lld\n", new_label->sList[0],new_label->sList[1]);
	
	// check secrecy constraints based on the operation
	list_for_each_label(src_index, src_label, new_label->sList)
    {
		int ok = 0;
			
		list_for_each_label(dest_index, dest_label, old_label->sList)
        {
			if(src_label == dest_label)
            {
				ok = 1;
				break;
			}
		}
		if(!ok){
			if((ret_val = __difc_set_task_label(tsk, old_label, src_label, ADD_LABEL, SECRECY_LABEL, 1)) < 0)
            {
				difc_lsm_debug("Failed to add secrecy label %llu\n", src_label);
				return ret_val;
			}
		}
	}

	
	list_for_each_label(src_index, src_label, old_label->sList){

		int ok = 0;

		list_for_each_label(dest_index, dest_label, new_label->sList){
			if(src_label == dest_label)
            {
				ok = 1;
				break;
			}
		}
		if(!ok){
			if((ret_val = __difc_set_task_label(tsk, old_label, src_label, REMOVE_LABEL, SECRECY_LABEL, 1)) < 0){
				difc_lsm_debug("Failed to drop secrecy label %llu\n", src_label);
				return ret_val;
			}
		}
	}


	// the same for integrity constraint 
	list_for_each_label(src_index, src_label, new_label->iList)
    {
		int ok = 0;

		list_for_each_label(dest_index, dest_label, old_label->iList)
        {
			if(src_label == dest_label)
            {
				ok = 1;
				break;
			}
		}
		if(!ok){
			if((ret_val = __difc_set_task_label(tsk, old_label, src_label, ADD_LABEL, INTEGRITY_LABEL, 1)) < 0)
            {
				difc_lsm_debug("Failed to add integrity label %llu\n", src_label);
				return ret_val;
			}
		}
	}


	list_for_each_label(src_index, src_label, old_label->iList)
    {
		int ok = 0;
		list_for_each_label(dest_index, dest_label, new_label->iList)
        {
			if(src_label == dest_label)
            {
				ok = 1;
				break;
			}
		}
		if(!ok){
			if((ret_val = __difc_set_task_label(tsk, old_label, src_label, REMOVE_LABEL, INTEGRITY_LABEL, 1)) < 0)
            {
				difc_lsm_debug("Failed to drop integrity label %llu\n", src_label);
				return ret_val;
			}
		}
	}

	return 0;
}

static int difc_set_task_label(struct task_struct *tsk, label_t label, int operation_type, int label_type, void __user *bulk_label)
{
	int return_val;
	struct label_struct *user_label;
	struct cred *cred ;
	struct azure_sphere_task_cred *tsec;


	tsec = kzalloc(sizeof(struct azure_sphere_task_cred), GFP_KERNEL);

  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug("not enough memory\n");
        return -ENOENT;
    }

	//difc_lsm_debug( "operation_type: %d, label_type: %d\n",operation_type,label_type);


	if(operation_type == REPLACE_LABEL)
    {
		user_label = difc_copy_user_label(bulk_label);
		if(!user_label)
        {
		  difc_lsm_debug(" Bad user_label\n");
		  return -ENOMEM;
		}
        // check if it's ok to replace

		//difc_lsm_debug(": slist[0]=%lld, slist[1]=%lld\n", user_label->sList[0],user_label->sList[1]);
		if((return_val = check_replacing_labels_allowed(tsk, &tsec->label, user_label)) == 0)
        {
			memcpy(&tsec->label, user_label, sizeof(struct label_struct));
			//difc_lsm_debug(" replace: %lld, %lld\n", tsec->label.sList[0],tsec->label.sList[1]);

		} 
		cred->security = tsec;
	    commit_creds(cred);
		kfree(user_label);
		return return_val;
	} 
 
	//difc_lsm_debug("not a replace operation, so add/remove then %d\n", operation_type);
	return_val=__difc_set_task_label(tsk, &tsec->label, label, operation_type, label_type, 0);

	cred->security = tsec;
	commit_creds(cred);

	return return_val;
		

}

// this checks if difc constraints are ok for two labels
static int check_labaling_allowed(struct label_struct *src, struct label_struct *dest)
{

	label_t src_index, src_label, dest_index, dest_label;

	//check secrecy constraint if ok
	if(src != NULL){
		list_for_each_label(src_index, src_label, src->sList){
			int ok = 0;
			list_for_each_label(dest_index, dest_label, dest->sList){
				if(src_label == dest_label){
					ok = 1;
					break;
				}
			}
			if(!ok){
				difc_lsm_debug("failed secrecy check\n");
				//difc_lsm_debug("failed secrecy check (source label %llu != dest_label %llu)\n", src_label, dest_label);
				return -EPERM;
			}
		}
	}
	//check integrity constraint if ok
	
	if(dest != NULL){
		list_for_each_label(dest_index, dest_label, dest->iList){
			int ok = 0;
			list_for_each_label(src_index, src_label, src->iList){
				if(src_label == dest_label){
					ok = 1;
					break;
				}
			}
			if(!ok){
				difc_lsm_debug("failed integrity check\n");
				//difc_lsm_debug("failed integrity check (source label %llu != dest_label %llu)\n", src_label, dest_label);
				return -EPERM;
			}
		}
	}

	return 0;
}



// this hook can be used for comparing threads labels, for example in case of labeling domains for each thread
//ZTODO: we need to store domains labels seperatly similar to inodes using object_security_struct 
//where? probably extra security feaild in kthread_info instead of cred?

static int difc_tasks_labels_allowed(struct task_struct *s_tsk,struct task_struct *d_tsk)
{

	const struct cred *scred;
	const struct cred *rcred;
	struct azure_sphere_task_cred *tsec;
	struct azure_sphere_task_cred *rsec;
	int unlabeled_source_tsk, unlabeled_dest_tsk;


  	scred = get_task_cred(s_tsk);
    if (!scred) {
		difc_lsm_debug(" no cred!\n");
        return -ENOMEM;
    }
    tsec = scred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

  	rcred = get_task_cred(d_tsk);
    if (!rcred) {
		difc_lsm_debug(" no cred!\n");
        return -ENOMEM;
    }
    rsec = rcred->security;

    if (!rsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	// check both tasks are labeled first
	unlabeled_source_tsk = is_task_labeled(s_tsk);
	unlabeled_dest_tsk = is_task_labeled(d_tsk);


	//no permission check required here
	if (unlabeled_source_tsk && unlabeled_dest_tsk)
		{	
			//difc_lsm_debug(" both tasks are not labeld!\n");
			return -1;
		}

	if(!unlabeled_source_tsk && !unlabeled_dest_tsk)
	{
		difc_lsm_debug(" both tasks are labeld! lets check difc allowance then\n");
		return check_labaling_allowed(&tsec->label, &rsec->label);
	}

	else
	{	
		//difc_lsm_debug(" one of the tasks is not labeld\n");
		return -1;

	}


}

	
// these two are helper funtions used for more clean way of our custome hooks to set/get inode labels without having EA support
static inline size_t inode_labels_to_buf(char *buf, size_t len, struct label_struct *isec)
{ 
	size_t ret_val = (*isec->sList) + (*isec->iList) + 2;
	size_t offset;
	ret_val *= sizeof(label_t);

	
	if(ret_val < len){// not sure having len is necessarly really!
	  difc_lsm_debug("Bad inode label %d %d\n", ret_val, len);
		return -ERANGE;
	}

	offset = ((*isec->sList) + 1) * sizeof(label_t);
	memcpy(buf, isec->sList, offset);
	memcpy(buf + offset, isec->iList, ret_val - offset);
	return ret_val;
}

static inline size_t buf_to_inode_labels(const char *buf, size_t len, struct label_struct *isec)
{ 
	label_t *lbuf = (label_t *) buf;
	size_t bound = 0;

//copy secrecy labels
	if((*lbuf) + 1 + bound > len)
	{
		difc_lsm_debug(" wrong buf len\n");
	}
	memcpy(isec->sList, buf, ((*buf) + 1) * sizeof(label_t));
	bound = (*lbuf) + 1;
	lbuf += (*lbuf) + 1;
	
// copy integrity labels
	if((*lbuf) + 1 + bound > len)
	{
		difc_lsm_debug(" wrong buf len\n");
	}
	memcpy(isec->iList, buf, ((*buf) + 1) * sizeof(label_t));
	return 0;
}

// we use the inode_get_security hook that is diffrent from inode_getsecurity hook that also used for handling EA that we don't, 
// used custome hooks to avoid conflicts
static int difc_inode_get_security(const struct inode *inode, const char *name, void *buffer, size_t size, int err)
{
	struct object_security_struct *isec = inode->i_security;
	difc_lsm_debug("getting inode sec for path %s\n", name);

	return inode_labels_to_buf(buffer, size, &isec->label);
}


static int difc_inode_set_security(struct inode *inode, const char *name,
				  const char __user *value, size_t size, int flags)
{

	struct object_security_struct *isec;
	struct label_struct *user_label;

	isec = inode->i_security;
	if(!isec) {
	  difc_lsm_debug("not enough memory\n");
		return -ENOMEM;
	}
	user_label = difc_copy_user_label(value);
	if(!user_label)
	{
		difc_lsm_debug(" Bad user_label\n");
		return -ENOMEM;
	}

	down_write(&isec->label_change_sem);


	memcpy(&isec->label, user_label, sizeof(struct label_struct));
	//difc_lsm_debug(": slist[0]=%lld, slist[1]=%lld\n", isec->label.sList[0],isec->label.sList[1]);

	up_write(&isec->label_change_sem);
	inode->i_security = isec;
	kfree(user_label);
	/* 
	struct object_security_struct *isec = inode->i_security;
	struct label_struct *user_label;

	if(!isec){
	   difc_lsm_debug("not initialzed isec\n");
	   return -EOPNOTSUPP;
	}

	user_label = difc_copy_user_label(value);
	if(!user_label)
	{
		difc_lsm_debug(" Bad user_label\n");
		return -ENOMEM;
	}

	memcpy(&isec->label, user_label, sizeof(struct label_struct));

	difc_lsm_debug(": slist[0]=%lld, slist[1]=%lld\n", user_label->sList[0],user_label->sList[1]);

	kfree(user_label);
	*/
	return 0;//buf_to_inode_labels(value, size, &isec->label);
}

static int difc_inode_alloc_security(struct inode *inode)
{

	struct object_security_struct *isec;
	isec = kmem_cache_zalloc(difc_obj_kcache, GFP_KERNEL);
	if(!isec) {
	  difc_lsm_debug("not enough memory\n");
		return -ENOMEM;
	}

	init_rwsem(&isec->label_change_sem);
	inode->i_security = isec;
	//difc_lsm_debug("successfull inode alloc init\n");
	return 0;

}

static void difc_inode_free_security(struct inode *inode)
{
	struct object_security_struct *tsec = inode->i_security;
	inode->i_security = NULL;
	if(tsec)
		kmem_cache_free(difc_obj_kcache, tsec);

	//difc_lsm_debug("[difc_inode_free_security] successfull cleanup\n");
	
}


static int difc_inode_init_security (struct inode *inode, struct inode *dir,
				     char **name, void **value, size_t *len, 
				     void *lables_list)
{
	const struct cred *cred;
	struct object_security_struct *isec = inode->i_security;
    struct azure_sphere_task_cred *tsec;
	struct label_struct *input_label = (struct label_struct *)lables_list;
	int lret;
	int rret;
	size_t labels_len;

    cred = get_task_cred(current);
    tsec = cred->security;

    if (!tsec) 
	{
        put_cred(cred);
		difc_lsm_debug(" tsec not enough memory\n");
        return -ENOMEM; // another errno later
    }

	if(!isec)
	{
		difc_lsm_debug(" isec not enough memory\n");
        return -ENOMEM;

	}

	if(input_label)
	{
		//difc_lsm_debug(" inode lables_list is not empty, check if labing is allowed\n");

	 	lret = check_labaling_allowed(&tsec->label, input_label);
		rret = check_replacing_labels_allowed(current, &tsec->label, input_label);

		if((lret==0) && (rret == 0))
			memcpy(&isec->label, input_label, sizeof(struct label_struct));
		else {
			difc_lsm_debug(" Ignoring requested label on inode %lu: %d, %d\n", inode->i_ino, lret, rret);
			return -EPERM;
		}
			
	} 
	else 
		memcpy(&isec->label, &tsec->label, sizeof(struct label_struct));

	
	labels_len = (*isec->label.sList) + (*isec->label.iList);
	if(labels_len == 0)
	{
		return -EOPNOTSUPP;
	}

	//ZTODO: we are not supporing persistent label storage, but here is the place to initilaze it if we wanted to support it
	return 0;
}


//instead of checking permissions fo each fs seperatly, we use use the inode permissions hooks
static int difc_inode_permission (struct inode *inode, int mask)
{

	const struct cred *cred ;
	struct object_security_struct *isec = inode->i_security;
	struct azure_sphere_task_cred *tsec;

	int unlabeled_inode, unlabeled_task;
	int ret_val = 0;

	//difc_lsm_debug("enter\n");

  	cred = get_current_cred();
    if (!cred) {
		difc_lsm_debug(" no cred!\n");
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	if(!isec || ((*isec->label.sList) == 0 && (*isec->label.iList) == 0))
		unlabeled_inode = 1;
	else
		unlabeled_inode = 0;

	// get the current task label 
	unlabeled_task = is_task_labeled(current);

	//no permission check required here
	if (unlabeled_task && unlabeled_inode)
		return 0;

	if(unlabeled_task && !unlabeled_inode){
		//difc_lsm_debug("unlabled task want to access with mask %d, inode %lu\n", mask, inode->i_ino);
		return -1;
	}

	// check if operations are fine with the task and inode labels
	if((mask & (MAY_READ|MAY_EXEC)) != 0)
		{	
			//difc_lsm_debug(" read&exec check \n");
			ret_val |= check_labaling_allowed(&isec->label, &tsec->label);
		}

		

	if((mask & MAY_WRITE) == MAY_WRITE)
		{	
			//difc_lsm_debug(" write check \n");
			ret_val |= check_labaling_allowed(&tsec->label, &isec->label);
		}
	
	return ret_val;
}

//this hook should be used for adding new label to already existing inodes, for initialization the inode_set_lable is ok
static int difc_inode_set_label(struct inode *inode, void __user *new_label)
{
	
	struct object_security_struct *isec = inode->i_security;
	struct label_struct *user_label;
	int ret_val;

	if(!isec){
	  difc_lsm_debug("Bad isec\n");
		return -EOPNOTSUPP;
	}

	user_label = difc_copy_user_label(new_label);
	if(!user_label)
	{
		difc_lsm_debug("Bad user_label\n");
		return -ENOMEM;
	}

	down_write(&isec->label_change_sem);
	// only set new lables if based on curent task lables it is allowed
	ret_val = check_replacing_labels_allowed(current, &isec->label, user_label);

	//now check difc inode permissions for parent list as well
	if(ret_val == 0)
	{	
		struct dentry *dentry;
		struct dentry *parent;
		struct inode *p_inode;
		spin_lock(&inode->i_lock);// right locking mechanism?
		hlist_for_each_entry(dentry, &inode->i_dentry, d_u.d_alias) {

			spin_lock(&dentry->d_lock);
			parent = dentry->d_parent;
			p_inode = parent->d_inode;
		
			ret_val |= difc_inode_permission(p_inode, MAY_WRITE);

			if(ret_val)
				{
				spin_unlock(&dentry->d_lock);
				spin_unlock(&inode->i_lock);
					break;
				}
		}
		spin_unlock(&dentry->d_lock);
	} 

	spin_unlock(&inode->i_lock);

	if(ret_val == 0)
		memcpy(&isec->label, user_label, sizeof(struct label_struct));

	up_write(&isec->label_change_sem);

	difc_lsm_debug("setting new lable for the inode is done\n");
	return ret_val;
}

// difc_permanent_declassify  should be used for dropping capabilities permanently. 
// the temporarly version is used before cloning new thread instead of setting other tasks credentials that is not a good practice from securitypoint of view 
static int difc_permanent_declassify  (void __user *ucap_list, unsigned int ucap_list_size, int cap_type, int label_type)
{
	
	struct cred *cred ;
	struct azure_sphere_task_cred *tsec;
	int ret_val=0;
	int found_cap = 0;
	capability_t *capList;
	capability_t temp;
	struct cap_segment *cap_seg;
	int i;
	capability_t cap;
	label_t label;
	int len;


	tsec = kzalloc(sizeof(struct azure_sphere_task_cred), GFP_KERNEL);

  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	capList = kmalloc(sizeof(capability_t) * ucap_list_size, GFP_KERNEL);
	if(!capList){
	  	difc_lsm_debug(" not enough memory\n");
		return -ENOMEM;
	}
	ret_val = copy_from_user(capList, ucap_list, sizeof(capability_t) * ucap_list_size);
	if(ret_val){
		difc_lsm_debug(" Bad copy: %d bytes missing\n", ret_val);
		kfree(capList);
		return -ENOMEM;
	}
	//spin_lock(&tsec->cap_lock);

	
	list_for_each_entry(cap_seg, &tsec->capList, list){
			if(cap_seg->caps[0] > 0){
		//	difc_lsm_debug("not empty caplist %lld \n",cap_seg->caps[0]);
			break;
		}
	}	

	if(label_type==SECRECY_LABEL){

		len=tsec->label.sList[0];
		for(i = 0; i < len; i++){
			label=tsec->label.sList[i+1];
			cap=cap_seg->caps[i+1];
			temp=capList[i];

			if(( temp & CAP_LABEL_MASK) == label)
			{
				//difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		
/*
			if((cap_type & PLUS_CAPABILITY)){
				difc_lsm_debug("plus cap\n");
			}
			if((cap_type & MINUS_CAPABILITY)){			
				difc_lsm_debug("minus cap\n");}
*/
			if(found_cap)
			{
				cap_seg->caps[i+1] = cap_seg->caps[i+2];
				(cap_seg->caps[0])--;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

		}
	}
	else if(label_type==INTEGRITY_LABEL)
	{
		len=tsec->label.iList[0];
		for(i = 0; i < len; i++){
			label=tsec->label.iList[i+1];
			cap=cap_seg->caps[i+1];
			temp=capList[i];

			if(( temp & CAP_LABEL_MASK) == label)
			{
			//	difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

			if(found_cap)
			{
				cap_seg->caps[i+1] = cap_seg->caps[i+2];
				(cap_seg->caps[0])--;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

		}
	}else{
		difc_lsm_debug("not vaid label_type, only secrecy and integrety support\n");
		return -1;
	}

	//spin_unlock(&tsec->cap_lock);
	cred->security = tsec;
	commit_creds(cred);

	kfree(capList);
	return ret_val;
}

// difc_temporarily_declassify stores caps in suspendedCaps that can be used before clone if we don'twant the child to inherits the capabilities 
// ZTODO: it can be merged with permanent_declassify as well

static int difc_temporarily_declassify(void __user *ucap_list, int ucap_list_size, int cap_type,int label_type)
{
	
	struct cred *cred ;
	struct azure_sphere_task_cred *tsec;
	int ret_val=0;
	int found_cap = 0;
	int not_max  = 0;
	capability_t *capList;
	capability_t temp;
	struct cap_segment *cap_seg;
	struct cap_segment *sus_caps;
	int i;
	capability_t cap;
	label_t label;
	int len;

	tsec = kzalloc(sizeof(struct azure_sphere_task_cred), GFP_KERNEL);

  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	capList = kmalloc(sizeof(capability_t) * ucap_list_size, GFP_KERNEL);
	if(!capList){
	  	difc_lsm_debug(" not enough memory\n");
		return -ENOMEM;
	}
	ret_val = copy_from_user(capList, ucap_list, sizeof(capability_t) * ucap_list_size);
	if(ret_val){
		difc_lsm_debug(" Bad copy: %d bytes missing\n", ret_val);
		kfree(capList);
		return -ENOMEM;
	}
	//spin_lock(&tsec->cap_lock);

	

// drop from the main capList first but then store in suspendedCaps list

	list_for_each_entry(cap_seg, &tsec->capList, list){
			if(cap_seg->caps[0] > 0){
			//difc_lsm_debug("not empty caplist %lld \n",cap_seg->caps[0]);
			break;
		}
	}	

	//difc_lsm_debug(" just checking: %lld, %lld\n", tsec->label.sList[0],tsec->label.sList[1]);
	if(label_type==SECRECY_LABEL){
		len=tsec->label.sList[0];

		for(i = 0; i < len; i++){
			label=tsec->label.sList[i+1];
			cap=cap_seg->caps[i+1];
			temp=capList[i];

			if(( cap & CAP_LABEL_MASK) == label)
			{
				//difc_lsm_debug("cap[%d] matches the label \n",i+1);
			}
			if(( temp & CAP_LABEL_MASK) == label)
			{
				//difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

	/*		if((cap_type & PLUS_CAPABILITY)){
				difc_lsm_debug("plus cap\n");
			}
			if((cap_type & MINUS_CAPABILITY)){			
				difc_lsm_debug("minus cap\n");}
*/
			if(found_cap)
			{
			cap_seg->caps[i+1] = cap_seg->caps[i+2];
			(cap_seg->caps[0])--;

	// store caps in the suspendedCaps list

			list_for_each_entry(sus_caps, &tsec->suspendedCaps, list){
					if(sus_caps->caps[0] < CAP_LIST_MAX_ENTRIES){
						not_max  = 1;
						break;
					}
				}
				if(!not_max ){
					sus_caps = alloc_cap_segment();
					INIT_LIST_HEAD(&sus_caps->list);
					list_add_tail(&sus_caps->list, &tsec->suspendedCaps);
				}

				sus_caps->caps[++(sus_caps->caps[0])] = temp ;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

		}
	}
	else if(label_type==INTEGRITY_LABEL)
	{
		len=tsec->label.iList[0];
		for(i = 0; i < len; i++){
			label=tsec->label.iList[i+1];
			cap=cap_seg->caps[i+1];
			temp=capList[i];

			if(( temp & CAP_LABEL_MASK) == label)
			{
			//	difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

			if(found_cap)
			{
				cap_seg->caps[i+1] = cap_seg->caps[i+2];
				(cap_seg->caps[0])--;

	// store caps in the suspendedCaps list

			list_for_each_entry(sus_caps, &tsec->suspendedCaps, list){
					if(sus_caps->caps[0] < CAP_LIST_MAX_ENTRIES){
						not_max  = 1;
						break;
					}
				}
				if(!not_max ){
					sus_caps = alloc_cap_segment();
					INIT_LIST_HEAD(&sus_caps->list);
					list_add_tail(&sus_caps->list, &tsec->suspendedCaps);
				}

				sus_caps->caps[++(sus_caps->caps[0])] = temp ;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

	}
	}
	else{
		difc_lsm_debug("not vaid label_type, only secrecy and integrety support\n");
		return -1;
	}
	
/* //just for debugging
	list_for_each_entry(cs, &tsec->capList, list){
			if(cs->caps[0] ==0){
		difc_lsm_debug("yep empty %lld \n",cap_seg->caps[0]);
			break;
		}
	}

	list_for_each_entry(cs2, &tsec->suspendedCaps, list){
			if(cs2->caps[0] ==1){
		difc_lsm_debug("yep added %lld \n",cs2->caps[0]);
			break;
		}
	}		
*/
	//spin_unlock(&tsec->cap_lock);
	tsec->tcb=UNTRUSTED_TCB;
	cred->security = tsec;
	commit_creds(cred);

	kfree(capList);
	return ret_val;
}

// resume the suspended capabilities
static int difc_restore_suspended_capabilities(void __user *ucap_list, unsigned int ucap_list_size, int cap_type,int label_type)
{
	
	struct cred *cred ;
	struct azure_sphere_task_cred *tsec;
	int ret_val=0;
	int found_cap = 0;
	int not_max  = 0;
	capability_t *capList;
	capability_t temp;
	struct cap_segment *cap_seg;
	struct cap_segment *sus_caps;
	int i;
	capability_t cap;
	label_t label;
	int len;

	tsec = kzalloc(sizeof(struct azure_sphere_task_cred), GFP_KERNEL);

  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	capList = kmalloc(sizeof(capability_t) * ucap_list_size, GFP_KERNEL);
	if(!capList){
	  	difc_lsm_debug(" not enough memory\n");
		return -ENOMEM;
	}
	ret_val = copy_from_user(capList, ucap_list, sizeof(capability_t) * ucap_list_size);
	if(ret_val){
		difc_lsm_debug(" Bad copy: %d bytes missing\n", ret_val);
		kfree(capList);
		return -ENOMEM;
	}

	//spin_lock(&tsec->cap_lock);

// drop from the suspended capList first then restore it to main capList

	list_for_each_entry(sus_caps, &tsec->suspendedCaps, list){
			if(sus_caps->caps[0] > 0){
			//difc_lsm_debug("not empty caplist %lld \n",sus_caps->caps[0]);
			break;
		}
	}	

	if(label_type==SECRECY_LABEL){

		len=tsec->label.sList[0];
		for(i = 0; i < len; i++){
			label=tsec->label.sList[i+1];
			cap=sus_caps->caps[i+1];
			temp=capList[i];

			if(( temp & CAP_LABEL_MASK) == label)
			{
				//difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

			if(found_cap)
			{
				sus_caps->caps[i+1] = sus_caps->caps[i+2];
				(sus_caps->caps[0])--;

	// store suspended caps in the capList 

			list_for_each_entry(cap_seg, &tsec->capList, list){
					if(cap_seg->caps[0] < CAP_LIST_MAX_ENTRIES){
						not_max  = 1;
						break;
					}
				}
				if(!not_max ){
					cap_seg = alloc_cap_segment();
					INIT_LIST_HEAD(&cap_seg->list);
					list_add_tail(&cap_seg->list, &tsec->capList);
				}

				cap_seg->caps[++(cap_seg->caps[0])] = temp ;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

		}
	}
	else if(label_type==INTEGRITY_LABEL)
	{
		len=tsec->label.iList[0];
		for(i = 0; i < len; i++){
			label=tsec->label.iList[i+1];
			cap=sus_caps->caps[i+1];
			temp=capList[i];

			if(( temp & CAP_LABEL_MASK) == label)
			{
				//difc_lsm_debug("cap[%d] matches the label \n",i+1);
				found_cap=1;
			}		

			if(found_cap)
			{
				sus_caps->caps[i+1] = sus_caps->caps[i+2];
				(sus_caps->caps[0])--;

	// store suspended caps in the capList 

			list_for_each_entry(cap_seg, &tsec->capList, list){
					if(cap_seg->caps[0] < CAP_LIST_MAX_ENTRIES){
						not_max  = 1;
						break;
					}
				}
				if(!not_max ){
					cap_seg = alloc_cap_segment();
					INIT_LIST_HEAD(&cap_seg->list);
					list_add_tail(&cap_seg->list, &tsec->capList);
				}

				cap_seg->caps[++(cap_seg->caps[0])] = temp ;

			}
			else{
				difc_lsm_debug("no cap\n");
				return -1;
			}

		}
	}else{
		difc_lsm_debug("not vaid label_type, only secrecy and integrety support\n");
		return -1;
	}

	//spin_unlock(&tsec->cap_lock);
	tsec->tcb=REGULAR_TCB;
	cred->security = tsec;
	commit_creds(cred);

	kfree(capList);
	return ret_val;
}

//ZTODO: find a better way of passing caps than direct change of another task's credentials
static int difc_send_task_capabilities(pid_t pid, void __user *ucap_list, unsigned int ucap_list_size, int cap_type){


	struct cred *cred;
	const struct cred *rcred;
	struct azure_sphere_task_cred *tsec;// curent cred
	struct azure_sphere_task_cred *rsec;// reciver cred
	struct task_struct *dest_task = pid_task(find_vpid(pid), PIDTYPE_PID); 
	capability_t *capList;
	int ret_val=0;

	tsec = kzalloc(sizeof(struct azure_sphere_task_cred), GFP_KERNEL);
	rsec = kzalloc(sizeof(struct azure_sphere_task_cred), GFP_KERNEL);


  	cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    if (!tsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	rcred=get_task_cred(dest_task);
	if (!rcred) {
        return -ENOMEM;
    }
    rsec = rcred->security;

    if (!rsec) {
		difc_lsm_debug(" not enough memory\n");
        return -ENOENT;
    }

	capList = kmalloc(sizeof(capability_t) * ucap_list_size, GFP_KERNEL);
	if(!capList){
	  	difc_lsm_debug(" not enough memory\n");
		return -ENOMEM;
	}

	ret_val = copy_from_user(capList, ucap_list, sizeof(capability_t) * ucap_list_size);
	if(ret_val){
		difc_lsm_debug(" Bad copy: %d bytes missing\n", ret_val);
		kfree(capList);
		return -ENOMEM;
	}
	
	if(&tsec->cap_lock < &rsec->cap_lock){
		//spin_lock(&tsec->cap_lock);
		//spin_lock(&rsec->cap_lock);
	} else {
		//spin_lock(&rsec->cap_lock);
		//spin_lock(&tsec->cap_lock);
	}

	if(&tsec->cap_lock < &rsec->cap_lock){
		//spin_unlock(&rsec->cap_lock);
		//spin_unlock(&tsec->cap_lock);
	} else {
		//spin_unlock(&tsec->cap_lock);
		//spin_unlock(&rsec->cap_lock);
	}



	//store the reciver task cred, current task doesn't need to be saved
	//rcred->security = rsec;
	//commit_creds(rcred);

	kfree(capList);
	return ret_val;
}

static inline const char *get_pmd_domain_name(pmd_t *pmd)
{
	switch (pmd_val(*pmd) & PMD_DOMAIN_MASK) {
	case PMD_DOMAIN(DOMAIN_KERNEL):
		return "KERNEL ";
	case PMD_DOMAIN(DOMAIN_USER):
		return "USER   ";
	case PMD_DOMAIN(DOMAIN_IO):
		return "IO     ";
	case PMD_DOMAIN(DOMAIN_VECTORS):
		return "VECTORS";
	case PMD_DOMAIN(DOMAIN_SANDBOX):
		return "SANDBOX";	
	case PMD_DOMAIN(DOMAIN_TRUSTED):
		return "TRUSTED";
	case PMD_DOMAIN(DOMAIN_UNTRUSTED):
		return "UNTRUSTED";
	default:
		return "unknown";
	}
}

static inline const char *get_pte_domain_name(pte_t *pte)
{
	switch (pte_val(*pte) & PTE_DOMAIN_MASK) {
	case PTE_DOMAIN(DOMAIN_KERNEL):
		return "KERNEL ";
	case PTE_DOMAIN(DOMAIN_USER):
		return "USER   ";
	case PTE_DOMAIN(DOMAIN_IO):
		return "IO     ";
	case PTE_DOMAIN(DOMAIN_VECTORS):
		return "VECTORS";
	case PTE_DOMAIN(DOMAIN_SANDBOX):
		return "SANDBOX";	
	case PTE_DOMAIN(DOMAIN_TRUSTED):
		return "TRUSTED";
	case PTE_DOMAIN(DOMAIN_UNTRUSTED):
		return "UNTRUSTED";
	default:
		return "unknown";
	}
}

static inline unsigned int get_pmd_domain(pmd_t *pmd)
{
	switch (pmd_val(*pmd) & PMD_DOMAIN_MASK) {
	case PMD_DOMAIN(DOMAIN_KERNEL):
		return DOMAIN_KERNEL;
	case PMD_DOMAIN(DOMAIN_USER):
		return DOMAIN_USER;
	case PMD_DOMAIN(DOMAIN_IO):
		return DOMAIN_IO;
	case PMD_DOMAIN(DOMAIN_VECTORS):
		return DOMAIN_VECTORS;
	case PMD_DOMAIN(DOMAIN_SANDBOX):
		return DOMAIN_SANDBOX;	
	case PMD_DOMAIN(DOMAIN_TRUSTED):
		return DOMAIN_TRUSTED;
	case PMD_DOMAIN(DOMAIN_UNTRUSTED):
		return DOMAIN_UNTRUSTED;
	default:
		return -1; //just for now we keep track of registerd domains 
	}
}

 
static inline void difc_set_domain(unsigned long addr, unsigned long counts, int domain)
{
    struct mm_struct *mm = current->mm;
	//unsigned long dacr = 0;
	unsigned int i;
	int domain_copy=domain;
	int unlabeled_task=1;

    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

    spin_lock(&mm->page_table_lock);
    pgd = pgd_offset(mm, addr);
    pud = pud_offset(pgd, addr);
    pmd = pmd_offset(pud, addr);
	//ptep = pte_offset_map(pmd, addr);
	
    if (addr & SECTION_SIZE)
        pmd++;

// bits[8:5] first level entry is domain number-->0xfffffe1f
    for (i = 0; i < counts; ++i) {
		difc_lsm_debug(" pmd domain: %s\n",get_pmd_domain_name(pmd));
        *pmd = (*pmd & 0xfffffe1f) | (domain << 5);
        flush_pmd_entry(pmd);
		difc_lsm_debug(" pmd domain: %s\n",get_pmd_domain_name(pmd));

        pmd++;
    }
    spin_unlock(&mm->page_table_lock);
    difc_lsm_debug(" addr=0x%lx, counts=%ld\n", addr, counts);
	//isb();
	unlabeled_task = is_task_labeled(current);

/* 
		  __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    printk("dacr=0x%lx\n", dacr);
*/
	if(!unlabeled_task)
		{
			difc_lsm_debug(" task is labedl so make its domain(%d) NoAcc\n",domain);
			modify_domain(domain_copy,DOMAIN_NOACCESS);

/* 	
	__asm__ __volatile__(
    "mrc p15, 0, %[result], c3, c0, 0\n"
    : [result] "=r" (dacr) : );
    printk("dacr=0x%lx\n", dacr);

*/
		}
	else
	{
		difc_lsm_debug(" task is not labeled so its domain is in client mode\n");

	}
		

}



#endif /*CONFIG_EXTENDED_LSM_DIFC */


//btw why this is not actually setting pgid, just a dummy?
static int azure_sphere_task_setpgid(struct task_struct *p, pid_t pgid)
{
    struct azure_sphere_task_cred *tsec = p->cred->security;

    if (!tsec->is_app_man && !tsec->job_control_allowed) {
        return -ENOSYS;
    }

    return 0;
}

static struct azure_sphere_task_cred *azure_sphere_new_task(struct azure_sphere_task_cred *task,
					struct azure_sphere_task_cred *forked, gfp_t gfp)
{
	struct azure_sphere_task_cred *tsec;

	tsec = kzalloc(sizeof(struct azure_sphere_task_cred), gfp);
	if (tsec == NULL)
		return NULL;

	INIT_LIST_HEAD(&tsec->capList);
	INIT_LIST_HEAD(&tsec->suspendedCaps);
	tsec->tcb=UNTRUSTED_TCB;

	if (list_empty(&tsec->capList))
		{
		difc_lsm_debug(" tsec->capList empty\n");

		}

	return tsec;
}


static int azure_sphere_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{

	struct azure_sphere_task_cred *tsec;
	difc_lsm_debug(" azure_sphere_cred_alloc_blank\n");
/*
	tsec = kzalloc(sizeof(struct azure_sphere_task_cred), gfp);
	if (!tsec)
		return -ENOMEM;

	////spin_lock_init(&tsec->cap_lock);
	INIT_LIST_HEAD(&tsec->capList);
	INIT_LIST_HEAD(&tsec->suspendedCaps);
	tsec->tcb=UNTRUSTED_TCB;
	
*/
	tsec = azure_sphere_new_task(NULL, NULL, gfp);
	if (tsec == NULL)
		return -ENOMEM;

	
	cred->security = tsec;
	difc_lsm_debug(" end of azure_sphere_cred_alloc_blank\n");

	return 0;

}

static void azure_sphere_cred_free(struct cred *cred)
{
	struct azure_sphere_task_cred *tsec = cred->security;
	kfree(table);
	kfree(tsec);
//	difc_lsm_debug("successfull free\n");

}


static int azure_sphere_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	const struct azure_sphere_task_cred *old_tsec;//=azs_cred(old);
	struct azure_sphere_task_cred *tsec;//=azs_cred(new);

//	*tsec = *old_tsec;

	old_tsec = old->security;

	tsec = kmemdup(old_tsec, sizeof(struct azure_sphere_task_cred), gfp);
	if (!tsec)
		return -ENOMEM;

	new->security = tsec;
	
	return 0;
}

static void azure_sphere_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct azure_sphere_task_cred *old_tsec = old->security;
	struct azure_sphere_task_cred *tsec = new->security;

	*tsec = *old_tsec;
}

static void azure_sphere_cred_init_security(void)
{
	struct cred *cred = (struct cred *) current->real_cred;
	struct azure_sphere_task_cred *tsec;
	struct cap_segment *cap_seg;
	struct cap_segment *sus_seg;



	tsec = kzalloc(sizeof(struct azure_sphere_task_cred), GFP_KERNEL);
	if (!tsec)
		panic("Failed to initialize initial task security object.\n");


	//spin_lock_init(&tsec->cap_lock);
	
	INIT_LIST_HEAD(&tsec->capList);
	INIT_LIST_HEAD(&tsec->suspendedCaps);
	tsec->tcb=UNTRUSTED_TCB;

	cap_seg = alloc_cap_segment();
	INIT_LIST_HEAD(&cap_seg->list);
	cap_seg->caps[0]=0;//first cell keeps the total number of caps
	list_add_tail(&cap_seg->list, &tsec->capList);

	sus_seg = alloc_cap_segment();
	INIT_LIST_HEAD(&sus_seg->list);
	sus_seg->caps[0]=0;
	list_add_tail(&sus_seg->list, &tsec->suspendedCaps);


	//spin_unlock(&tsec->cap_lock);

	tsec->is_app_man = true;
    tsec->capabilities = AZURE_SPHERE_CAP_ALL;
    cred->security = tsec;


	alloc_hash();
    if (table == NULL) {
        panic("couldn't allocate udoms hash_table.\n");
 
    }

	difc_lsm_debug("[azure_sphere_cred_init_security] initialized, tsec->tcb %d\n",tsec->tcb);


}	

bool azure_sphere_capable(azure_sphere_capability_t cap)
{
    const struct cred *cred;
    const struct azure_sphere_task_cred *tsec;
    bool ret = false;

    cred = get_task_cred(current);
    tsec = cred->security;
    if (!cred->security) {
        put_cred(cred);
        return false;
    }

    ret = ((tsec->capabilities & cap) == cap);

    put_cred(cred);
    return ret;
}

bool azure_sphere_get_component_id(struct azure_sphere_guid *component_id, struct task_struct *p)
{
    const struct cred *cred;
    const struct azure_sphere_task_cred *tsec;

    cred = get_task_cred(p);
    tsec = cred->security;
    if (!cred->security) {
        put_cred(cred);
        return false;
    }

    *component_id = tsec->component_id.guid;

    put_cred(cred);

    return true;
}

static int azure_sphere_security_getprocattr(struct task_struct *p, char *name, char **value)
{
    const struct cred *cred;
    const struct azure_sphere_task_cred *tsec;
    int ret = 0;

    cred = get_task_cred(p);
    tsec = cred->security;

    //if no security entry then fail
    if (!tsec) {
        put_cred(cred);
        return -ENOENT;
    }

    if (strcmp(name, "exec") == 0) {
        *value = kmalloc(sizeof(*tsec), GFP_KERNEL);
        if (*value == NULL) {
            ret = -ENOMEM;
        } else {
            memcpy(*value, tsec, sizeof(*tsec));
            ret = sizeof(*tsec);
        }
    } else if (strcmp(name, "current") == 0) {
        int tenant_id_strlen = strnlen(tsec->daa_tenant_id, sizeof(tsec->daa_tenant_id));
        int len = 5 + 36 + 1 + 5 + tenant_id_strlen + 1 + 15 + 1; // "CID: " + <guid> + "\n" + "TID: " + <tenant id> + "\n" + "CAPS: 00000000\n" + NULL
        *value = kmalloc(len, GFP_KERNEL);
        if (*value == NULL) {
            ret = -ENOMEM;
        } else {
            ret = snprintf(*value, len, "CID: %08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\nTID: %.*s\nCAPS: %08X\n", 
                tsec->component_id.guid.data1, tsec->component_id.guid.data2, tsec->component_id.guid.data3, 
                tsec->component_id.guid.data4[0], tsec->component_id.guid.data4[1], tsec->component_id.guid.data4[2], tsec->component_id.guid.data4[3],
                tsec->component_id.guid.data4[4], tsec->component_id.guid.data4[5], tsec->component_id.guid.data4[6], tsec->component_id.guid.data4[7],
                tenant_id_strlen, tsec->daa_tenant_id, tsec->capabilities);
        }
    } else {
        ret = -ENOTSUPP;
    }

    put_cred(cred);
    return ret;    
}

static int azure_sphere_security_setprocattr(const char *name, void *value, size_t size) 
{
    struct azure_sphere_security_set_process_details *data = value;
    struct cred *cred;
    struct azure_sphere_task_cred *tsec;
    int ret;

    // Can only set in binary format
    if (strcmp(name, "exec") != 0) {
        return -EINVAL;
    }

    if (value == NULL || size < sizeof(*data)) {
        return -EINVAL;
    }

    cred = prepare_creds();
    if (!cred) {
        return -ENOMEM;
    }
    tsec = cred->security;

    //if no security entry then fail
    if (!tsec) {
        ret = -ENOENT;
        goto error;
    }

    if (!tsec->is_app_man) {
        ret = -EPERM;
        goto error;
    }


    memcpy(&tsec->component_id, data->component_id, sizeof(tsec->component_id));
    memset(&tsec->daa_tenant_id, 0, sizeof(tsec->daa_tenant_id));
    memcpy(&tsec->daa_tenant_id, data->daa_tenant_id, strnlen(data->daa_tenant_id, sizeof(tsec->daa_tenant_id) - 1));
    tsec->is_app_man = false;
    tsec->job_control_allowed = data->job_control_allowed;
    tsec->capabilities = data->capabilities;

   	return commit_creds(cred);
	//return 0;

error:
    abort_creds(cred);
    return ret;
}

#ifdef CONFIG_AZURE_SPHERE_MMAP_EXEC_PROTECTION
int azure_sphere_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags) {
    // if attempting write and execute at the same time then deny
    if((reqprot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
        return -EPERM;

    //all good
    return 0;
}

int azure_sphere_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot) {
    // if attempting write and execute at the same time then deny
    if((reqprot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
        return -EPERM;

    // check the current VMA flags, if swapping between write and execute then fail
    if((vma->vm_flags & VM_WRITE) && (reqprot & PROT_EXEC)) {
        return -EPERM;
    }
    else if((vma->vm_flags & VM_EXEC) && (reqprot & PROT_WRITE)) {
        return -EPERM;
    }

    return 0;
}
#endif


#ifdef CONFIG_EXTENDED_LSM_DIFC

// allocate a new label fro one or group of threads
asmlinkage long sys_alloc_label(int type, int group_mode){

//	difc_lsm_debug("enter, group_mode: %d,%d\n",type,group_mode);

	return difc_alloc_label(type,group_mode);
	//return 0;
	
}


asmlinkage long sys_permanent_declassify(void __user *ucap_list, unsigned int ucap_list_size, int cap_type,int label_type){

	//difc_lsm_debug("enter\n");
	return difc_permanent_declassify(ucap_list, ucap_list_size, cap_type,label_type);
	return 0;

}

asmlinkage long sys_temporarily_declassify(void __user *ucap_list, int ucap_list_size, int cap_type,int label_type){

//	difc_lsm_debug("enter %d\n",ucap_list_size);
	return difc_temporarily_declassify(ucap_list, ucap_list_size, cap_type,label_type);
//	return 0;
}


asmlinkage long sys_restore_suspended_capabilities(void __user *ucap_list, unsigned int ucap_list_size, int cap_type, int label_type){

//	difc_lsm_debug("enter\n");
	return difc_restore_suspended_capabilities(ucap_list, ucap_list_size, cap_type,label_type);
return 0;
}


//set current task labels
asmlinkage long sys_set_task_label(unsigned long label, int operation_type, int label_type, void *bulk_label)
{

	return difc_set_task_label(current,  label,  operation_type,  label_type, bulk_label);

}

// map an address to a specific domain
 asmlinkage int sys_set_task_domain(unsigned long addr, unsigned long counts, int domain)
 {
	//difc_lsm_debug(" enter\n");
	if(domain >= 0 && domain <16)
		{
			difc_set_domain(addr,counts, domain);
			return 0;
		}
	else {
		difc_lsm_debug("arm only supports 16 domains\n");
		return -1;
	}
	return 0;
	
}

// since this needs one thread to set credentials of another task, it's better to implement an alternative usersapce api instead
asmlinkage long sys_send_task_capabilities(pid_t pid, void __user *ucap_list, unsigned int ucap_list_size, int cap_type)
{

	//difc_lsm_debug(" enter\n");
	return difc_send_task_capabilities(pid,ucap_list,ucap_list_size,cap_type);
	return 0;
}

// this tries to enter a domain that is labeld for another task. 
// can find the domain based on the target address, does not need be exact addr.
// we could ask for specific domain_id, but i think finding domains based on addr is more convinient (and possibly safe)
// we will find the doamin
asmlinkage unsigned long sys_difc_enter_domain(unsigned long addr,
        unsigned long stack, struct pt_regs *regs)
{

		//difc_lsm_debug("enter \n");
		return 0;

	unsigned long dacr = 0;
	unsigned int domain;
	int domain_copy;

	int ret_val=0;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;

	difc_lsm_debug("enter\n");
	difc_lsm_debug("pid = %d, tid = %d\n", task_tgid_vnr(current), task_pid_vnr(current));
	difc_lsm_debug("domain fault at 0x%08lx\n", addr);
	difc_lsm_debug("domain fault pc=0x%08lx, sp=0x%08lx\n", regs->ARM_pc, regs->ARM_sp);

    pgd = pgd_offset(current->mm, addr);
    pud = pud_offset(pgd, addr);
    pmd = pmd_offset(pud, addr);
    if (addr & SECTION_SIZE)
       { pmd++;}

	domain=get_pmd_domain(pmd);
	domain_copy=domain;
	if(domain<0)
		difc_lsm_debug("not registered domain\n");


	difc_lsm_debug("pmd_domain %u\n",domain);


    __asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    printk("dacr=0x%lx\n", dacr);

	return ret_val;
	


}

asmlinkage void sys_difc_exit_domain(struct pt_regs *regs)
{
	difc_lsm_debug(" enter\n");
}

#endif /*CONFIG_EXTENDED_LSM_DIFC */


/*struct lsm_blob_sizes azs_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct azure_sphere_task_cred),

};
*/

static struct security_hook_list azure_sphere_hooks[] __lsm_ro_after_init = {

    LSM_HOOK_INIT(cred_alloc_blank, azure_sphere_cred_alloc_blank),
	LSM_HOOK_INIT(cred_prepare, azure_sphere_cred_prepare),
	//LSM_HOOK_INIT(cred_free, azure_sphere_cred_free),


	/*    LSM_HOOK_INIT(task_setpgid, azure_sphere_task_setpgid),
    LSM_HOOK_INIT(cred_prepare, azure_sphere_cred_prepare),
    LSM_HOOK_INIT(cred_transfer, azure_sphere_cred_transfer),
    LSM_HOOK_INIT(getprocattr, azure_sphere_security_getprocattr),
    LSM_HOOK_INIT(setprocattr, azure_sphere_security_setprocattr),

*/
#ifdef CONFIG_EXTENDED_LSM_DIFC

	LSM_HOOK_INIT(set_task_label,difc_set_task_label),
	LSM_HOOK_INIT(copy_user_label,difc_copy_user_label),
	LSM_HOOK_INIT(check_tasks_labels_allowed, difc_tasks_labels_allowed),
	LSM_HOOK_INIT(check_task_labeled,difc_check_task_labeled),
/*	LSM_HOOK_INIT(inode_alloc_security,difc_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security,difc_inode_free_security),
	LSM_HOOK_INIT(inode_label_init_security,difc_inode_init_security),
	LSM_HOOK_INIT(inode_get_security,difc_inode_get_security),
	LSM_HOOK_INIT(inode_set_security,difc_inode_set_security),
	LSM_HOOK_INIT(inode_set_label,difc_inode_set_label),
	LSM_HOOK_INIT(inode_permission, difc_inode_permission),


*/
#endif


};


static int __init azure_sphere_lsm_init(void)
{
	/*
    if (!security_module_enable("AzureSphere")) {
        printk(KERN_INFO "Azure Sphere LSM disabled by boot time parameter");
		return 0;
	}
	*/
    printk(KERN_INFO "Azure Sphere LSM enabled by boot time parameter");

	difc_caps_kcache = 
		kmem_cache_create("difc_cap_segment",
				  sizeof(struct cap_segment),
				  0, SLAB_PANIC, NULL);			  

	difc_obj_kcache = 
		kmem_cache_create("difc_object_struct",
				  sizeof(struct object_security_struct),
				  0, SLAB_PANIC, NULL);

	atomic_set(&max_caps_num, CAPS_INIT);

    azure_sphere_cred_init_security();

    security_add_hooks(azure_sphere_hooks, ARRAY_SIZE(azure_sphere_hooks),"AzureSphere");

    return 0;
}



security_initcall(azure_sphere_lsm_init);


