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
#include <linux/random.h>

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
#include <azure-sphere/difc.h>

#include "lsm.h"
#include "linux/smv.h"
#include "linux/memdom.h"




#ifdef CONFIG_EXTENDED_FLOATING_DIFC

#include "weir_lsm.h"
#include "weir_objsec.h"
#include "weir_netlink.h"

#endif

#endif /*CONFIG_EXTENDED_LSM_DIFC */


#ifdef CONFIG_SW_UDOM
#include <linux/mm.h>
#endif

#ifdef CONFIG_EXTENDED_LSM_DIFC

struct kmem_cache *tag_struct;


atomic_t max_caps_num;
typedef label_t* labelList_t;

#ifdef CONFIG_EXTENDED_FLOATING_DIFC

struct tag* globalpos;
struct tag* globalneg;

unsigned char *empty_address="0000:0000:0000:0000:0000:0000:0000:0000";

#endif


//#define alloc_cap_segment() kmem_cache_zalloc(difc_caps_kcache, GFP_KERNEL)
//#define free_cap_segment(s) kmem_cache_free(difc_caps_kcache, s)

#define alloc_tag_struct() kmem_cache_zalloc(tag_struct, GFP_KERNEL)





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





#ifdef CONFIG_EXTENDED_FLOATING_DIFC


static struct task_security_struct *new_task_security_struct(gfp_t gfp) {
	struct task_security_struct *tsp;
	tsp = kzalloc(sizeof(struct task_security_struct), gfp);
	
	if (!tsp)
		return NULL;
	tsp->type = TAG_CONF;
	INIT_LIST_HEAD(&tsp->slabel);
	INIT_LIST_HEAD(&tsp->ilabel);
	INIT_LIST_HEAD(&tsp->olabel);
	
	return tsp;
} 

static void difc_free_label(struct list_head *label) {
	struct tag *t, *t_next;
	list_for_each_entry_safe(t, t_next, label, next) {
		list_del_rcu(&t->next);
		kmem_cache_free(tag_struct, t);
	}
}



static int difc_copy_label(struct list_head *old, struct list_head *new) {
	struct tag *t;
	
	list_for_each_entry(t, old, next) {
		struct tag *new_tag;
		new_tag = kmem_cache_alloc(tag_struct, GFP_NOFS);
		if (new_tag == NULL)
			goto out;
		new_tag->content = t->content;
		list_add_tail(&new_tag->next, new);
	}
	return 0;

out:
	return -ENOMEM;
}



//List shims
int add_tag(struct tag* orig_list, tag_t value){
	int ret = add_list(orig_list, value);
	return ret;
}
bool exists_tag(struct tag* orig_list, tag_t value){
	bool ret = exists_list(orig_list, value);
	return ret;
}
int remove_tag(struct tag* orig_list, tag_t value){
	int ret = remove_list(orig_list, value);
	return ret;
}
int copy_lists(struct tag* orig_list, struct tag* new_list){
	int ret=0;
	if(orig_list==NULL){
	    ret=-1;
	    return ret;
	}
	if(new_list==NULL){
	    ret=init_list(&new_list);
	    if(ret==ENOMEM)
		return ret;
	}
	ret=copy_list(orig_list, new_list);
	return ret;
}

//Helpers
//tag array->taglist
void get_list_from_array(tag_t *array, struct tag **listaddr,int size){
	int i;
	if(size<=0 || array == NULL)
	    return;
	//label should be null when initialized, else we will make it.
	if(*listaddr!=NULL) kfree(*listaddr);
	init_list(listaddr);

	for(i=0; i<size; i++){
	    add_list(*listaddr, array[i]);
	}
}
void get_list_from_array2(tag_t *array, struct tag *listaddr,int size){
	int i;
	if(size<=0 || array == NULL)
	    return;
	//assuming initialized list
	for(i=0; i<size; i++){
	    add_list(listaddr, array[i]);
	}
}
//taglist->tag array
tag_t* get_array_from_list(struct tag* taglist){
	struct list_head* pos;
	struct tag* tmp;
	int i=0;
	tag_t* retarray = NULL;
	int size = list_size(taglist);

	if(taglist==NULL || size <=0){
		return NULL;
	}
	
	retarray = (tag_t*)kzalloc(sizeof(tag_t) * size, GFP_KERNEL);
	//Iterate to check if "value" exists in the list
	list_for_each(pos, &(taglist->next)){
		tmp=list_entry(pos, struct tag, next);
		retarray[i] = tmp->content;
		i++;
	}

	return retarray;
}

//Uses the given negcaps, globalneg and given tag, and returns true 
//if the tag is present in either
bool can_declassify(tag_t tag, struct tag *negcaps){
    //TODO: Lock on globalneg
    if(exists_list(negcaps, tag) || exists_list(globalneg, tag)){
	return true;
    }
    return false;
}

//Populates the queryLabel with seclabel tags are not present in negcaps and
//globalneg. Returns the number of such tags, i.e., queryLabelCount.
int get_declassify_tag(char *queryLabel, struct tag *seclabel, struct
		tag *negcaps, int queryLabelSize)
{
    int queryLabelCount=0;	
    struct list_head* pos;
    struct tag* tmp;
    tag_t tag;
	
    char *cur = queryLabel, *const end = queryLabel+queryLabelSize; 
    list_for_each(pos, &(seclabel->next)){
	tmp=list_entry(pos, struct tag, next);
	tag = tmp->content;

	if(!can_declassify(tag, negcaps)){
	    //FIXME: Why is there a '-' after the tag? Is this for separating tags?
	    //Fix this and also make sure that the userspace knows how tags are separated
	    //FIXME: Made it '+'.
	    cur += snprintf(cur, end-cur, "%lld#", tag);
	    queryLabelCount++;
	}

	if(cur>=end)
	    break;
    }

    return queryLabelCount;
}



struct task_security_struct* get_task_security_from_task_struct_unlocked(struct task_struct* task){
    const struct cred* cred; 
    rcu_read_lock();
    cred= __task_cred(task);
    rcu_read_unlock();
    if(cred==NULL){
	//difc_lsm_debug(" cred NULL\n");
	return NULL;
    }
    return cred->security;
}
//get task security struct from pid
struct task_security_struct* get_task_security_from_task_struct(struct task_struct* task){
    const struct cred* cred; 
    rcu_read_lock();
    cred= __task_cred(task);
    //rcu_read_unlock();
    if(cred==NULL){
	//difc_lsm_debug(" cred NULL\n");
	return NULL;
    }
    return cred->security;
}

//get task security struct from pid
struct task_security_struct* get_task_security_from_pid(pid_t pid){
    struct task_struct* task;
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if(task==NULL){
	//difc_lsm_debug(" task NULL for pid %d\n",pid);
	return NULL;
    }
    return get_task_security_from_task_struct(task);
}

//Add tag to the process's seclabel
void add_tag_to_label(pid_t pid, tag_t tag)
{
    struct task_security_struct* tsec = get_task_security_from_pid(pid);
    //struct tag* seclabel;

    if(tsec==NULL){
	    //difc_lsm_debug(" tsec NULL for pid %d\n",pid);
	    goto out;
    }
    //LOCK on TSEC
    mutex_lock(&tsec->lock);
    tsec->pid = pid;
    if(tsec->seclabel==NULL){
	//difc_lsm_debug("Allocating tsec->seclabel for pid %d\n",pid);
	tsec->seclabel = (struct tag*)kzalloc(sizeof(struct tag), GFP_KERNEL);
	init_list2(tsec->seclabel);
    }
    add_list(tsec->seclabel, tag);
    //Release LOCK on TSEC
    mutex_unlock(&tsec->lock);
out:
    rcu_read_unlock();
    return;
}

//init process security
int init_process_security_context(pid_t pid, uid_t uid, tag_t* sec, tag_t* pos, tag_t* neg, int secsize, int possize, int negsize){
	int ret=0;
	struct task_security_struct* tsec = get_task_security_from_pid(pid);
	if(tsec==NULL){
	    //difc_lsm_debug("tsec is null for pid %d\n",pid);
	    ret = -1;
	    goto out;
	}

	//LOCK on TSEC
	mutex_lock(&tsec->lock);

	tsec->pid = pid;
	tsec->uid = uid;

	//For tsec->seclabel
	if(sec==NULL || secsize <=0){
	    //difc_lsm_debug("WEIR_DEBUG: No sec suplied for %d, secsize=%d!\n", pid, secsize);
	} else {
	    //difc_lsm_debug("WEIR_DEBUG: init_proc_security first element of sec = %lld\n", sec[0]);
	    //tsec->seclabel = (struct tag*)kzalloc(sizeof(struct tag), GFP_KERNEL);
	    //init_list2(tsec->seclabel);
	    //tsec->seclabel = get_list_from_array2(sec, tsec->seclabel, secsize);
	    get_list_from_array(sec, &(tsec->seclabel), secsize);

	}
	//For tsec->poscaps
	if(pos==NULL || possize <=0){
	    //difc_lsm_debug("WEIR_DEBUG: No pos suplied for %d, possize=%d!\n", pid, possize);
	} else {
	    //difc_lsm_debug("WEIR_DEBUG: init_proc_security first element of pos = %lld\n", pos[0]);
	    get_list_from_array(pos, &(tsec->poscaps), possize);
	}
	//For tsec->negcaps
	if(neg==NULL || negsize <=0){
	    //difc_lsm_debug("WEIR_DEBUG: No neg suplied for %d, negsize=%d!\n", pid, negsize);
	} else {
	    //difc_lsm_debug("WEIR_DEBUG: init_proc_security first element of neg = %lld\n", neg[0]);
	    get_list_from_array(neg, &(tsec->negcaps), negsize);
	}

	//Resease LOCK on TSEC
	mutex_unlock(&tsec->lock);
	//difc_lsm_debug("INITIALIZED SECURITY CONTEXT for pid %d, secsize %d\n",pid, secsize);
out:
	rcu_read_unlock();
	return ret;
}
  
//get label size (for ioctl)
int get_label_size(pid_t pid){
	int ret=0;
	struct task_security_struct* tsec = get_task_security_from_pid(pid);
	if(tsec==NULL){
	    //difc_lsm_debug("tsec is null for pid %d\n", pid);
	    ret = -1;
	    goto out;
	}
	// TODO: LOCK on TSEC; figure out why this crashes
	//mutex_lock(&tsec->lock);
	if(tsec->seclabel==NULL){
	    //difc_lsm_debug("tsec->seclabel is null for pid %d\n", pid);
	    ret = -1;
		//TODO: Release LOCK on TSEC
		//mutex_unlock(&tsec->lock);
	    goto out;
	}
	//difc_lsm_debug("tsec->seclabel is not null for pid %d\n", pid);
	ret = list_size(tsec->seclabel);
	//TODO: Release LOCK on TSEC
	//mutex_unlock(&tsec->lock);
out:
	rcu_read_unlock();
	return ret;
}
//get label
tag_t* get_label(pid_t pid){
	tag_t *ret;
	struct task_security_struct* tsec = get_task_security_from_pid(pid);
	if(tsec==NULL){
	    ret = NULL;
	    goto out;
	}

	// TODO: LOCK on TSEC; figure out why this crashes
	//mutex_lock(&tsec->lock);
	if(tsec->seclabel==NULL){
	    ret = NULL;
		//TODO: Release LOCK on TSEC
		//mutex_unlock(&tsec->lock);
	    goto out;
	}
	//difc_lsm_debug("tsec->seclabel is not null for pid %d\n", pid);
	ret = get_array_from_list(tsec->seclabel);
	//TODO: Release LOCK on TSEC
	//mutex_unlock(&tsec->lock);
out:
	rcu_read_unlock();
	return ret;
}

//Add/remove process pos/neg caps
void change_proccap(pid_t pid, tag_t t, int pos, int add){
	struct task_security_struct* tsec = get_task_security_from_pid(pid);
	if(tsec==NULL){
	    goto out;
	}   

	//Lock on tsec	
	mutex_lock(&tsec->lock);
    if(add==1) {//add
	    if(pos==1){//poscaps
			if(tsec->poscaps==NULL){
			    init_list(&tsec->poscaps);
			}
			add_list(tsec->poscaps, t);
	    }else if(pos==-1){//negcaps
			if(tsec->negcaps==NULL){
				init_list(&tsec->negcaps);
			}
			add_list(tsec->negcaps, t);
	    } else {}
	}
	else if(add==-1) 
	{//remove
	    if(pos==1){//poscaps
			if(tsec->poscaps==NULL){
				//Release lock on tsec
				mutex_unlock(&tsec->lock);
				goto out;
			}
			remove_list(tsec->poscaps, t);
	    }else if(pos==-1){//negcaps
			if(tsec->negcaps==NULL){
				//Release lock on tsec
				mutex_unlock(&tsec->lock);
				goto out;
			}
			remove_list(tsec->negcaps, t);
	    } else {}
	} 
	else{}

	//Release lock on tsec
	mutex_unlock(&tsec->lock);
out:
	rcu_read_unlock();
	return;


}
void change_global(tag_t t, int pos, int add){
	if(add==1) {//add
	    if(pos==1){//globalpos
		if(globalpos==NULL){
		    init_list(&globalpos);
		}
		add_list(globalpos, t);
	    }else if(pos==-1){//globalneg
		if(globalneg==NULL){
		    init_list(&globalneg);
		}
		add_list(globalneg, t);
	    } else {}
	}else if(add==-1) {//remove
	    if(pos==1){//globalpos
		if(globalpos==NULL){
		    return;
		}
		remove_list(globalpos, t);
	    }else if(pos==-1){//globalneg
		if(globalneg==NULL){
		    return;
		}
		remove_list(globalneg, t);
	    } else {}
	
	} else{}
}

/* Function that prepares the netlink upcall*/
static int send_to_uspace_pid(char* buffer) {
	//Attach the current thread's pid
	//+1 for the delimiter ';'
	char buffer_with_pid[MAX_DATA_BUFFER+sizeof(long int)+1];
	snprintf(buffer_with_pid, MAX_DATA_BUFFER+sizeof(long int)+1, "%ld;%s", (long int)(current->pid), buffer);
	return send_to_uspace(buffer_with_pid);
}

/*
 * Check if Exempted
 */
static bool exempt(int euid){
    //TODO: This exception (the <=2002 case) is for debug only. Remove it.
    if(euid==0 || euid==1000 || euid <= 2002){
	return true;
    }

    return false;
}

/*
 * Check if SDCARD
 */
static bool sdcard(int inode_gid){
    //TODO: This exception (the <=2002 case) is for debug only. Remove it.
    int SDCARD_RW=1015;
    int SDCARD_R=1028;
    if(inode_gid==SDCARD_RW || inode_gid==SDCARD_R){
	return true;
    }

    return false;
}
/*
 * Check if Exempted System apps
 */
static bool exempt_system_apps(int euid){
    //TODO: This exception (the <=2002 case) is for debug only. Remove it.
    if(euid <= 10036){
	return true;
    }

    return false;
}

/*
 * Declassification Check
 */
static int declassification_check(const char *hook, struct socket *sock, struct sockaddr *address, int addrlen)
{
    int ret = 0;

    kuid_t euid = current->cred->euid;
    //Does using the tgid make sense? We ensure that new kernel threads
    //(current->pid) have creds "prepared (copied)" from the original thread
    //(i.e., tgid == pid). Moreover, we apply new labels, tags, etc. to
    //current->pids; 
    //int pid = current->tgid;
    int pid = current->pid;
    char buffer[MAX_DATA_BUFFER];
    struct task_security_struct* tsec;
    struct tag *seclabel, *negcaps;
    int queryLabelSize = MAX_DATA_BUFFER/2;
    char queryLabel[queryLabelSize];
    int queryLabelCount = 0;
    //TODO: Currently gueryLabel is enough to hold ~60 tags, total 500B. Figure
    //out an optimum size

    //if(exempt(euid)){//ztodo
	//goto out;
    //}
    
    tsec = get_task_security_from_pid(pid);
    if(!tsec){
	//difc_lsm_debug("WEIR_DEBUG: declassification_check. tsec NULL for pid %d\n",pid);
	goto out;
    }
    
    seclabel = tsec->seclabel;
    negcaps = tsec->negcaps;

    //If label == empty, allow;
    if(!seclabel || list_size(seclabel)<=0){
	//difc_lsm_debug("WEIR_DEBUG: declassification_check. seclabel NULL or empty for pid %d\n",pid);
	goto out;
    }

    //Check if the tags in seclabel are included in globalneg or negcaps
    //If not included, add them to querylabel, separated by '-'
    queryLabelCount = get_declassify_tag(queryLabel, seclabel, negcaps, queryLabelSize);

    if(queryLabelCount==0){
	//declassification capability owned for all tags, allow
	goto out;
    }
    
    //Tags need to be domain-declassified; make an upcall
    if(address->sa_family==AF_INET){
	struct	sockaddr_in* temp_sockaddr;
	temp_sockaddr=(struct sockaddr_in *)address;
	if(temp_sockaddr->sin_addr.s_addr==0){
	    goto out;
	}
	//difc_lsm_debug("Weir: socket_connectv4:%pI4;%d;%u;%d\n", &(temp_sockaddr->sin_addr), euid, pid, addrlen);
	snprintf(buffer, MAX_DATA_BUFFER, "socket%sv4;%pI4;%d;%u;%s", hook, &(temp_sockaddr->sin_addr), euid, pid, queryLabel);
	ret = send_to_uspace_pid(buffer);
    }
    else if(address->sa_family==AF_INET6){
	struct sockaddr_in6* temp_sockaddr;
	temp_sockaddr=(struct sockaddr_in6 *)address;

	//This was to check empty addresses for bind, but we aren't doing that anymore.
	/*
	 *
	unsigned char temp[71];
	snprintf(temp, 71, "%pI6", &(temp_sockaddr->sin6_addr));
	if(strcmp(temp, empty_address)==0){
	    //difc_lsm_debug("Weir: EMPTY socket_v6:%pI6;%d;\n", &(temp_sockaddr->sin6_addr), euid);
	    goto out;
	}*/
	//difc_lsm_debug("Weir: socket_connectv6:%pI6;%d;%u;%d\n", &(temp_sockaddr->sin6_addr), euid, pid, addrlen);
	snprintf(buffer, MAX_DATA_BUFFER, "socket%sv6;%pI6;%d;%u;%s", hook, &(temp_sockaddr->sin6_addr), euid, pid, queryLabel);
	ret = send_to_uspace_pid(buffer);
    }
    else {}

    //TODO: Remove after this
    //ret = 0;

out:
    rcu_read_unlock();
    return ret;
}

//BINDER check
static int binder_check(struct task_struct *to, struct task_struct *from){
    int ret = 0;
    kuid_t to_euid = to->cred->euid;
    kuid_t from_euid = from->cred->euid;
    //int to_pid = to->pid;
    //int from_pid = from->pid;
    struct task_security_struct *to_tsec, *from_tsec;
    struct tag *to_seclabel, *from_seclabel;
    //Exempt calls to and from root and system, as we handle their internal
    //state in the framework. This is to prevent system services from
    //accumulating taint.
    //difc_lsm_debug("WEIR_DEBUG: binder_check. for (pid,uid) to:(%d,%d), from:(%d,%d).\n",to_pid, to_euid, from_pid, from_euid);

    to_tsec = get_task_security_from_task_struct_unlocked(to);
    from_tsec = get_task_security_from_task_struct_unlocked(from);

    //if(exempt(to_euid) || exempt(from_euid) || exempt_system_apps(to_euid) || exempt_system_apps(from_euid)){
	//return ret;
    //}//ztodo
    //TODO: Return -1. Apart from root which has already been exempted,
    //everyone else must have a tsec.
    if(!to_tsec || !from_tsec){
	//difc_lsm_debug("WEIR_DEBUG: binder_check. tsec NULL for to:%d or from:%d.\n",to_pid, from_pid);
	goto out;
    }
    
    to_seclabel = to_tsec->seclabel;
    from_seclabel = from_tsec->seclabel;

    //Weir does not allow hypothetical label changes. Labels are compared as
    //is. Polyinstantiation ensures that bound instances often share the same
    //label. 
    //Since we need to assume synchronous communication, we check if both
    //labels dominate each other, i.e., are equal.
    if(!equals(to_seclabel, from_seclabel)){
	//difc_lsm_debug("WEIR_DEBUG: binder_check. denial for (pid,uid) to:(%d,%d), from:(%d,%d).\n",to_pid, to_euid, from_pid, from_euid);
	ret = -1;
    }
out:
    //rcu_read_unlock();
    return ret;
}



int getFilePath(struct file *file, char **pathname)
{
    char *tmp;
    struct path path;
    path =file->f_path;
    path_get(&file->f_path);
    tmp = (char *)__get_free_page(GFP_KERNEL);//ztodo(GFP_TEMPORARY)
    if (!tmp) {
	return -ENOMEM;
    }
    *pathname = d_path(&path, tmp, PAGE_SIZE);
    path_put(&path);
    if (IS_ERR(*pathname)) {
	free_page((unsigned long)tmp);
	return PTR_ERR(*pathname);
    }
    free_page((unsigned long)tmp);
    return 0;
}


/*
 * Socket bind
 */
static int weir_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
    int ret = 0;
    //No need to call since bind is to own address space
    //ret = declassification_check("bind", sock, address, addrlen);
    return ret;
}

/*
 * Socket Connect
 */
static int weir_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
    int ret = 0;
    ret = declassification_check("connect", sock, address, addrlen);
    return ret;
}

/* Binder Hooks
 */
static int weir_binder_set_context_mgr(struct task_struct *mgr)
{
    return 0;
}

static int weir_binder_transaction(struct task_struct *from, struct task_struct *to)
{
    return binder_check(to, from);	
}

static int weir_binder_transfer_binder(struct task_struct *from, struct task_struct *to)
{
    return binder_check(to, from);	
}

static int weir_binder_transfer_file(struct task_struct *from, struct task_struct *to, struct file *file)
{
    //As file labels are propagated during individual reads and writes, we do
    //not need to worry about the file descriptor's label right here.  Instead,
    //we just check the "to" and "from" label.	struct file_security_struct
    //*fsec = lsm_get_file(file, &selinux_ops);
    return binder_check(to, from);	
}


#endif



#ifdef CONFIG_EXTENDED_LSM_DIFC

//allocate a new label and add it to the task's cap set 
static unsigned long difc_alloc_label(int cap_type, enum label_types mode)
{
	struct task_security_struct *tsec=current_security();
	struct tag *new_tag,*label_tag, *t;
	unsigned long tag_content;
	struct list_head new_label;
	int is_max=0;
	int ret=-EINVAL;
	bool present = false;



    if (!tsec) {
		difc_lsm_debug("not enough memory\n");
        return -ENOENT;
    }


	tag_content =get_random_long() ;


	list_for_each_entry_rcu(t, &tsec->olabel, next){
		difc_lsm_debug("t->content: %lu\n", t->content);
		if (t->content == tag_content) {
			present = true;
			break;
		}
	}
	if (!present) {

		// TODO: check authenticity of ownership before adding it

		if (tag_struct == NULL)
			difc_lsm_debug(" tag_struct is NULL\n");
		new_tag = kmem_cache_alloc(tag_struct, GFP_NOFS);
		if (!new_tag) {
			ret = -ENOMEM;
			return ret;
		}

		new_tag->content = tag_content;


		if((cap_type & PLUS_CAPABILITY)){
			if(tsec->poscaps==NULL){
			    init_list(&tsec->poscaps);
			}
				add_list(tsec->poscaps, tag_content);
				difc_lsm_debug("plus cap\n");
			}

		if((cap_type & MINUS_CAPABILITY)){

			if(tsec->negcaps==NULL){
			init_list(&tsec->negcaps);
			}
			add_list(tsec->negcaps, tag_content);			
			difc_lsm_debug("minus cap\n");
				
		}




		if(mode==SEC_LABEL_FLOATING )
		{	
			// merge floating initializations here
			pid_t tid=task_pid_vnr(current);
			new_tag->type=TAG_FLO;
			list_add_tail_rcu(&new_tag->next, &tsec->olabel);


  		  //LOCK on TSEC
   			mutex_lock(&tsec->lock);
    		tsec->pid = tid;
   			if(tsec->seclabel==NULL)
			   {
				difc_lsm_debug("Allocating tsec->seclabel for tid %d\n",tid);
				tsec->seclabel = (struct tag*)kzalloc(sizeof(struct tag), GFP_KERNEL);
				init_list2(tsec->seclabel);
 			   }
    		add_list(tsec->seclabel, tag_content);

		
   			//Release LOCK on TSEC
  			mutex_unlock(&tsec->lock);

			return tag_content;
		
		
		}
		
		else if (mode == SEC_LABEL || mode == INT_LABEL) 
		{
			label_tag = kmem_cache_alloc(tag_struct, GFP_NOFS);
			if (!label_tag) {
				ret = -ENOMEM;
				return ret;
			}
			tsec->type = TAG_EXP;
			label_tag->content = tag_content;

			list_add_tail_rcu(&new_tag->next, &tsec->olabel);
			difc_lsm_debug("after adding to olabel\n");

			INIT_LIST_HEAD(&new_label);
			list_add_tail_rcu(&label_tag->next, &new_label);

			if (mode == SEC_LABEL) { 

			ret = can_label_change(&tsec->slabel, &new_label, &tsec->olabel);
			if (ret != 0) {
				clean_label(&new_label);
				difc_lsm_debug("secrecy label denied\n");
				goto out;
			} else {
				change_label(&tsec->slabel, &new_label);
			}
		} else {
			ret = can_label_change(&tsec->ilabel, &new_label, &tsec->olabel);
			if (ret != 0) {
				clean_label(&new_label);
				difc_lsm_debug( "integrity label denied\n");
				goto out;
			} else {
				change_label(&tsec->ilabel, &new_label);
			}
		}

		return tag_content;
	}else{

		list_add_tail_rcu(&new_tag->next, &tsec->olabel);
		difc_lsm_debug( "no specific label mode;just owning a tag\n");

	}



}


//kfree(new_tag);
//list_del(&new_label);
return tag_content;

out:
	list_del(&new_label);
	if(mode==SEC_LABEL_FLOATING )
  	  rcu_read_unlock();
	return ret;		
}


static unsigned long difc_set_task_label(struct task_struct *tsk, unsigned long label, enum label_types ops, enum label_types label_type, void __user *bulk_label)
{

	struct task_security_struct *tsec=current_security();


// for now removed the group tag (label) support, just one by one tag operations


    if (!tsec) {
		difc_lsm_debug("not enough memory\n");
        return -ENOENT;
    }

	if(tsk!=current)
	{
		difc_lsm_debug("only current task supported for now\n");
        return -ENOENT;
    }


	if(label==0)
	{
		difc_lsm_debug("no label to set, creating one\n");

		return difc_alloc_label(PLUS_CAPABILITY|MINUS_CAPABILITY,label_type);
    }

	return 0;
	

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
    struct task_security_struct *tsec;
	
    cred = get_task_cred(tsk);
    tsec = cred->security;
    if (!tsec) {
        put_cred(cred);
        return -1;
    }

	if(tsec->type != TAG_CONF)
	{
		put_cred(cred);
		return 1;
	}

	difc_lsm_debug("this task is not labeled \n");
	put_cred(cred);
	return -1;
}

int difc_check_task_labeled(struct task_struct *tsk)
{
	return is_task_labeled(tsk);

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
	struct task_security_struct *tsec;
	struct task_security_struct *rsec;
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



static int difc_inode_set_security(struct inode *inode, const char *name,void *value, size_t size, int flags)
{

	struct inode_difc *isec;
	struct label_struct *user_label;
	struct tag* new_tag, *t;
	int sec_num=0;
	int integ_num=0;
	int i=1;
	unsigned long tag_content;

	isec = inode->i_security;
	if(!isec) {
	  difc_lsm_debug("not enough memory\n");
		return -ENOMEM;
	}

	if(value==NULL)
	{
		tag_content =get_random_long() ;
		if(flags==SEC_LABEL)
			sec_num=1;
		else if	(flags==INT_LABEL)
			integ_num=1;

	}	
	else{
		
		user_label = value;// difc_copy_user_label(value);
		if(!user_label)
		{
		difc_lsm_debug(" Bad user_label\n");
		return -ENOMEM;
		}
		sec_num= (user_label->sList[0] );
		integ_num=(user_label->iList[0]);

	}	


	//difc_lsm_debug(": slist[0]=%lld, slist[1]=%lld, sec %d, integ %d\n", user_label->sList[0],user_label->sList[1],sec_num,integ_num);


	if ( sec_num || integ_num) {

	

		if (sec_num && value != NULL) {
 
			for(i; i<=sec_num; i++){
			new_tag = kmem_cache_alloc(tag_struct, GFP_NOFS);
			isec->type = TAG_EXP;//user_label->sList[sec_num+1];
			new_tag->content = user_label->sList[i];

			list_add_tail_rcu(&new_tag->next, &isec->slabel);
			}

		} 
		else if (sec_num && value == NULL) {
 
			new_tag = kmem_cache_alloc(tag_struct, GFP_NOFS);
			isec->type = TAG_EXP;//user_label->sList[sec_num+1];
			new_tag->content = tag_content;

			list_add_tail_rcu(&new_tag->next, &isec->slabel);
		}

		
		else if(integ_num && value == NULL) 
		{
			new_tag = kmem_cache_alloc(tag_struct, GFP_NOFS);
			isec->type= TAG_EXP;//user_label->iList[integ_num+1];		
			new_tag->content = tag_content;
			list_add_tail_rcu(&new_tag->next, &isec->ilabel);
		}
			
		
		else if(integ_num && value != NULL) 
		{
			new_tag = kmem_cache_alloc(tag_struct, GFP_NOFS);
			isec->type= TAG_EXP;//user_label->iList[integ_num+1];
 
			for(i; i<=integ_num; i++){
			
			new_tag->content = user_label->iList[i];

			list_add_tail_rcu(&new_tag->next, &isec->ilabel);
			}
			
		}
		else
			difc_lsm_debug("inode label type is not clear!\n");
	
	}




	kfree(user_label);
	return 0;
/*
out:
	list_del(&new_label);
	if(ops==SEC_LABEL_FLOATING )
  	  rcu_read_unlock();
*/
}

static struct inode_difc *new_inode_difc(void) {
	struct inode_difc *isp;
	struct task_security_struct *tsp;
	int rc = -ENOMEM;
	
	isp = kzalloc(sizeof(struct inode_difc), GFP_NOFS);
	
	if(!isp)
		return NULL;

	INIT_LIST_HEAD(&isp->slabel);
	INIT_LIST_HEAD(&isp->ilabel);
	isp->type=TAG_CONF;

	tsp = current_security();

	/*
	* Label of inode is the label of the task creating the inode
	*/
/*
	rc = difc_copy_label(&tsp->slabel, &isp->slabel);
	if (rc < 0)
		goto out;

	rc = difc_copy_label(&tsp->ilabel, &isp->ilabel);
	if (rc < 0)
		goto out;
*/
	return isp;

//out:
//	kfree(isp);
//	return NULL;
}

static int difc_inode_alloc_security(struct inode *inode) {
	struct inode_difc *isp;

	isp = new_inode_difc();
	if (!isp)
		return -ENOMEM;

	inode->i_security = isp;

	return 0;
}

static void difc_inode_free_security(struct inode *inode) {
	struct inode_difc *isp = inode->i_security;

	if (isp == NULL)
		return;
	inode->i_security = NULL;

	if(isp->type!=TAG_CONF)
	{	difc_free_label(&isp->ilabel);
	  	list_del(&isp->ilabel);

		difc_free_label(&isp->slabel);
		list_del(&isp->slabel);
	}
	kfree(isp);
	

//	difc_lsm_debug("successful free");
}

static int difc_inode_init_security(struct inode *inode, struct inode *dir,
				const struct qstr *qstr, const char **name,
				void **value, size_t *len) {
	struct inode_difc *isp = inode->i_security;
	int rc, llen;
	char *labels;
	struct task_security_struct *tsp = current_security();

	
	if (!isp) {
		difc_lsm_debug("inode->i_security is null (%s)\n", __func__);
		return 0;
	}

/*	// for now even xattr is not necessary

	if (tsp->confined) {
		difc_lsm_debug("new inode is created %ld\n", inode->i_ino);
	}

	if (name)
		*name = XATTR_DIFC_SUFFIX;
	
	if (value && len) {
		rc = security_to_labels(&isp->slabel, &isp->ilabel, &labels, &llen);
		if (rc < 0)
			return rc;
		*value = kstrdup(labels, GFP_NOFS);
		kfree(labels);
		if (!*value) {
			difc_lsm_debug( "memory error in %s, %d\n",__LINE__);
			return -ENOMEM;
		}	
		*len = llen;
	}
*/
	return 0;
}




static int difc_inode_getsecurity(struct inode *inode,
				const char *name, void **buffer,
				bool alloc) {
	struct inode_difc *isp = inode->i_security;
	int len;
	int rc = 0;

	if (!isp) {
		difc_lsm_debug( "inode->i_security is null (%s)\n", __func__);
		return rc; 
	}

	if (strcmp(name, XATTR_DIFC_SUFFIX) == 0) {
		rc = security_to_labels(&isp->slabel, &isp->ilabel, (char **)buffer, &len);
		if (rc < 0)
			return rc;
		else
			return len;
	}

	return rc;
}

// called by difc_inode_setxattr()
static int difc_inode_setsecurity(struct inode *inode, const char *name,
				const void *value, size_t size, int flags) {

	struct inode_difc *isp = inode->i_security;
	struct task_security_struct *tsp = current_security();
	int rc = 0;	

	if (size >= MAX_LABEL_SIZE || value ==NULL || size == 0)
		return -EINVAL;

	if (!isp) {
		difc_lsm_debug( "inode->i_security is null (%s)\n", __func__);
		return rc; 
	}

	isp->type=TAG_EXP;

	rc = security_set_labels(&isp->slabel, &isp->ilabel, tsp, value, size);
	if (rc < 0)
		return rc;

	return 0;
}

static int difc_inode_listsecurity(struct inode *inode, char *buffer, 
					size_t buffer_size) {
	int len = sizeof(XATTR_NAME_DIFC);
	if (buffer != NULL && len <= buffer_size)
		memcpy(buffer, XATTR_NAME_DIFC, len);
	return len;
}

static int difc_inode_getxattr(struct dentry *dentry, const char *name) {
	return 0;
}

static int difc_inode_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags) {
	return 0;
}


static void difc_inode_post_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags) 
{
	
	struct inode *inode = dentry->d_inode;

	difc_inode_setsecurity(inode, name, value, size, flags);
	
	return;
}


static int difc_inode_unlink(struct inode *dir, struct dentry *dentry) {
	int rc = 0;
	struct task_security_struct *tsp = current_security();
	struct super_block *sbp = dentry->d_inode->i_sb;
	struct inode_difc *isp = dentry->d_inode->i_security;
	struct tag *t;

	if (tsp->type == TAG_CONF)
		return rc;

	if ((dir->i_mode & S_ISVTX) == 0)
		return rc;

	switch (sbp->s_magic) {
		case PIPEFS_MAGIC:
		case SOCKFS_MAGIC:
		case CGROUP_SUPER_MAGIC:
		case DEVPTS_SUPER_MAGIC:
		case PROC_SUPER_MAGIC:
		case TMPFS_MAGIC:
		case SYSFS_MAGIC:
		case RAMFS_MAGIC:
		case DEBUGFS_MAGIC:
			return rc;
		default:
			/* For now, only check on the rest cases */
			break;
	}

	/* Only allow when current can integrity write the dentry inode */
	list_for_each_entry_rcu(t, &isp->ilabel, next)
		if (t->content == 0)
			return rc;

	rc = is_label_subset(&isp->ilabel, &tsp->olabel, &tsp->ilabel);
	if (rc < 0) {
		difc_lsm_debug( "cannot delete file (%s)\n", dentry->d_name.name);
		rc = -EPERM;
		goto out;
	}
	
out:
	/* For debugging, always return 0 */
	rc = 0;
	return rc;
}

static int difc_inode_rmdir(struct inode *dir, struct dentry *dentry) {
	/* 
	* Currently, we assume files under the directory would have the same label
	* if a dir is a/b/c and labels are a(1), b(1;2), c(1;2;3)
	* Impossible, since otherwise the file cannot be read due to parent directories have less integrity
	*/
	return difc_inode_unlink(dir, dentry);
}

static int difc_inode_permission(struct inode *inode, int mask) {
	int rc = 0;
	struct task_security_struct *tsp = current_security();
	struct inode_difc *isp = inode->i_security;
	struct super_block *sbp = inode->i_sb;
	struct tag *t;
	int top, down;

	mask &= (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);

	/* For some reason, label of / is not persistent.  Thus if /, return */
	if (mask == 0 || !isp || inode->i_ino == 2) 
		return rc;

	if (tsp->type==TAG_CONF && isp->type==TAG_CONF)
		return rc;

	if (tsp->type==TAG_CONF && isp->type==TAG_EXP)
		{	
			difc_lsm_debug("unlabled task want to access exlictly taged file with mask %d, inode %lu\n", mask, inode->i_ino);
			return 0;
		}

	if (tsp->type==TAG_CONF && isp->type==TAG_FLO)
		{	
			difc_lsm_debug("unlabled task want to access floating tagged file with mask %d, inode %lu\n", mask, inode->i_ino);
			return 0;
		}

	switch (sbp->s_magic) {
		case PIPEFS_MAGIC:
		case SOCKFS_MAGIC:
		case CGROUP_SUPER_MAGIC:
		case DEVPTS_SUPER_MAGIC:
		case PROC_SUPER_MAGIC:
		case TMPFS_MAGIC:
		case SYSFS_MAGIC:
		case RAMFS_MAGIC:
		case DEBUGFS_MAGIC:
			return rc;
		default:
			// For now, only check on the rest cases 
			break;
	}


	if (mask & (MAY_READ | MAY_EXEC)) {
		/*
		* Check for special tag: 65535 and 0
		* If integrity label contains 65535 and secrecy label contains 0, the inode is globally readable
		*/
		top = -1;
		down = -1;
		list_for_each_entry_rcu(t, &isp->ilabel, next)
			if (t->content == 65535)
				top = 0;
		list_for_each_entry_rcu(t, &isp->slabel, next)
		{
			if (t->content == 0)
				down = 0;
		}
		if (top ==0 && down == 0)
			goto out;

		if (top != 0) {
			/*
			*  Integrity: Ip <= Iq + Op
			*/
			rc = is_label_subset(&tsp->ilabel, &tsp->olabel, &isp->ilabel);
			if (rc < 0) {
				difc_lsm_debug( "integrity cannot read (0x%08x: %ld)\n", sbp->s_magic, inode->i_ino);
				rc = -EACCES;
				goto out;
			}
		}
	
		if (down != 0) {
			/*
			*  Secrecy: Sq <= Sp + Op
			*/

			rc = is_label_subset(&isp->slabel, &tsp->olabel, &tsp->slabel);
			if (rc < 0 && down != 0) {
				difc_lsm_debug("secrecy cannot read (0x%08x: %ld)\n", sbp->s_magic, inode->i_ino);
				rc = -EACCES;
				goto out;
			}
		}
	} 
	
	if(mask & (MAY_WRITE | MAY_APPEND)) {
		/*
		* Check for special tag: 65535 and 0
		* If integrity label contains 0 and secrecy label contains 65535, the inode is globally writable
		*/

		top = -1;
		down = -1;
		list_for_each_entry_rcu(t, &isp->ilabel, next)
			if (t->content == 0)
				top = 0;
		list_for_each_entry_rcu(t, &isp->slabel, next)
			if (t->content == 65535)
				down = 0;
			
		if (top ==0 && down == 0)
			goto out;

		if (top != 0) {
			/*
			*  Integrity: Iq <= Ip + Op
			*/
			rc = is_label_subset(&isp->ilabel, &tsp->olabel, &tsp->ilabel);
			if (rc < 0) {
				difc_lsm_debug("integrity cannot write (0x%08x: %ld)\n", sbp->s_magic, inode->i_ino);
				rc = -EACCES;
				goto out;
			}
		}

		if (down != 0) {
			/*
			*  Secrecy: Sp <= Sq + Op
			*/
				difc_lsm_debug("before check\n");

			rc = is_label_subset(&tsp->slabel, &tsp->olabel, &isp->slabel);
			if (rc < 0) {
				difc_lsm_debug("secrecy cannot write (0x%08x: %ld)\n", sbp->s_magic, inode->i_ino);
				rc = -EACCES;
				goto out;
			}
		}
	}

out:
	/* Always allow for debugging */
	rc = 0;
	return rc;
}



static int difc_file_permission(struct file *file, int mask)
{
	struct inode *inode = file->f_path.dentry->d_inode;

	return difc_inode_permission(inode,mask);

	}

static void difc_d_instantiate(struct dentry *opt_dentry, struct inode *inode) {
	struct inode_difc *isp;
	struct super_block *sbp;
	struct dentry *dp;
	char *buffer;
	int rc;
	ssize_t len;

	if (!inode)
		return;

	isp = inode->i_security;
	sbp = inode->i_sb;

	// root
	if (opt_dentry->d_parent == opt_dentry)
		return;

	switch (sbp->s_magic) {
		case PIPEFS_MAGIC:
		case SOCKFS_MAGIC:
		case CGROUP_SUPER_MAGIC:
		case DEVPTS_SUPER_MAGIC:
		case PROC_SUPER_MAGIC:
		case TMPFS_MAGIC:
			break;
		default:
			if (S_ISSOCK(inode->i_mode)) 
				return;
		//	if (inode->i_op->getxattr == NULL) //ztodo
		//		return;
				
			dp = dget(opt_dentry);
			buffer = kzalloc(MAX_LABEL_SIZE, GFP_KERNEL);
			if (!buffer) {
				difc_lsm_debug("oops@%s\n", __func__);
				return;
			}
		//	len = inode->i_op->getxattr(dp, XATTR_NAME_DIFC, buffer, MAX_LABEL_SIZE);
			
			len=__vfs_getxattr(dp, inode,  XATTR_NAME_DIFC, buffer, MAX_LABEL_SIZE);


			if (len > 0) {
				rc = security_set_labels(&isp->slabel, &isp->ilabel, NULL, buffer, len);
				if (rc < 0) {
					
					difc_lsm_debug("security_set_labels (%s) @ %s\n", buffer, __func__);
				}
			}
			dput(dp);
			kfree(buffer);
			break;
	}
	return;
}


static int difc_sk_alloc_security(struct sock *sk, int family, gfp_t priority) 
{
	struct socket_difc *ssp;

	ssp = kzalloc(sizeof(struct socket_difc), priority);
	if (!ssp)
		return -ENOMEM;

	// Set in difc_socket_post_create()?
	ssp->isp = NULL;
	ssp->peer_isp = NULL;
	sk->sk_security =  ssp;

	return 0;
}

static void difc_sk_free_security(struct sock *sk) {
	struct socket_difc *ssp = sk->sk_security;
	sk->sk_security = NULL;

	if (!ssp)
		kfree(ssp);
}

static void difc_sk_clone_security(const struct sock *sk, struct sock *newsk) {
	struct socket_difc *ssp = sk->sk_security;
	struct socket_difc *newssp = newsk->sk_security;

	newssp->isp = ssp->isp;
	newssp->peer_isp = ssp->peer_isp;
}

static int difc_socket_create(int family, int type, int protocol, int kern) {
	/*
	* Seems like no need to set up
	*/
	return 0;
}


//instead of checking permissions fo each fs seperatly, we use use the inode permissions hooks
/*
static int difc_inode_permission (struct inode *inode, int mask)
{

	const struct cred *cred ;
	struct object_security_struct *isec = inode->i_security;
	struct task_security_struct *tsec;

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
*/


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

	if(!unlabeled_task)
		{
			difc_lsm_debug(" task is labedl so make its domain(%d) NoAcc\n",domain);
			modify_domain(domain_copy,DOMAIN_NOACCESS);

		}
	else
	{
		difc_lsm_debug(" task is not labeled so its domain is in client mode\n");

	}
		

}



#endif /*CONFIG_EXTENDED_LSM_DIFC */


static struct task_security_struct *azs_new_task(struct task_security_struct *task,
					struct task_security_struct *forked, gfp_t gfp)
{
	struct task_security_struct *tsec;
	struct tag* tag_seg;


	tsec = kzalloc(sizeof(struct task_security_struct), gfp);
	if (tsec == NULL)

	tsec->type=TAG_CONF;

	INIT_LIST_HEAD(&tsec->slabel);
	INIT_LIST_HEAD(&tsec->ilabel);
	INIT_LIST_HEAD(&tsec->olabel);

	tag_seg=alloc_tag_struct();
	INIT_LIST_HEAD(&tag_seg->next);


#ifdef CONFIG_EXTENDED_FLOATING_DIFC
mutex_init(&tsec->lock);
	tsec->pid = current->pid;
	tsec->seclabel=NULL;
	tsec->poscaps=NULL;
	tsec->negcaps=NULL;
#endif

	return tsec;
}



static int difc_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{

	struct task_security_struct *tsec;
	difc_lsm_debug(" azure_sphere_cred_alloc_blank\n");

	tsec = azs_new_task(NULL, NULL, gfp);
	if (tsec == NULL)
		return -ENOMEM;

	
	cred->security = tsec;
	difc_lsm_debug(" end of azure_sphere_cred_alloc_blank\n");

	return 0;

}



static void difc_cred_free(struct cred *cred) {

	struct task_security_struct *tsec;

	if((cred->security)==NULL)
		return;

	else
		{
		tsec=cred->security;
		cred->security = NULL;
		}
	
	
/*	
		difc_free_label(&tsec->ilabel);
		list_del(&tsec->ilabel);

		difc_free_label(&tsec->slabel);
		list_del(&tsec->slabel);

		difc_free_label(&tsec->olabel);
		list_del(&tsec->olabel);

	*/
#ifdef CONFIG_EXTENDED_FLOATING_DIFC

	    mutex_lock(&tsec->lock);
	    if(tsec->seclabel!=NULL)  kfree(tsec->seclabel);
	    if(tsec->poscaps!=NULL)	 kfree(tsec->poscaps);
	    if(tsec->negcaps!=NULL)	 kfree(tsec->negcaps);
	    //UNLOCK TSEC (free mutex after this, before freeing tsec?)
	    mutex_unlock(&tsec->lock);

#endif



	kfree(table);
	kfree(tsec);
}




static int difc_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	const struct task_security_struct *old_tsec;
	struct task_security_struct *tsec;
	struct tag* tag_seg;

	int rc=0;

	if(old==NULL)
		return 0;
	else
	{
		old_tsec=old->security;
	}
		
	tsec = azs_new_task(NULL, NULL, gfp);
	if (tsec == NULL)
		return -ENOMEM;


/*
	
	tsec->type = old_tsec->type;

	INIT_LIST_HEAD(&tsec->slabel);
	INIT_LIST_HEAD(&tsec->ilabel);
	INIT_LIST_HEAD(&tsec->olabel);

	tag_seg=alloc_tag_struct();
	INIT_LIST_HEAD(&tag_seg->next);	
	rc = difc_copy_label(&old_tsec->slabel, &tsec->slabel);
	if (rc != 0)
		return rc;

	rc = difc_copy_label(&old_tsec->ilabel, &tsec->ilabel);
	if (rc != 0)
		return rc;
*/

// for floating threads we need a deep copy but for explicit one no inheritance
#ifdef CONFIG_EXTENDED_FLOATING_DIFC

	//difc_lsm_debug("in prepare for pid %d\n", current->pid);


	if(old_tsec==NULL){

	    mutex_init(&tsec->lock);
	    //tsec->uid = current->uid;
	    tsec->pid = current->pid;
	    tsec->seclabel=NULL;
	    tsec->poscaps=NULL;
	    tsec->negcaps=NULL;

	} else{

	    mutex_init(&tsec->lock);
	    tsec->seclabel=NULL;
	    tsec->poscaps=NULL;
	    tsec->negcaps=NULL;

	    //LOCK on OLD_TSEC
	    mutex_lock(&old_tsec->lock);
	    
	    //Commenting this as we have chosen to make deep copies.
	    //*tsec = *old_tsec;

	    tsec->pid = old_tsec->pid;
	    tsec->uid = old_tsec->uid;

	    if(old_tsec->seclabel!=NULL){
		//difc_lsm_debug("Copying seclabel for pid current = %d old_tsec = %d\n", current->pid, old_tsec->pid);
		tsec->seclabel = (struct tag*)kzalloc(sizeof(struct tag), GFP_KERNEL);
		init_list2(tsec->seclabel);
		copy_lists(old_tsec->seclabel, tsec->seclabel);
	    }
	    if(old_tsec->poscaps!=NULL){
		tsec->poscaps = (struct tag*)kzalloc(sizeof(struct tag), GFP_KERNEL);
		init_list2(tsec->poscaps);
		copy_lists(old_tsec->poscaps, tsec->poscaps);
	    }
	    if(old_tsec->negcaps!=NULL){
		tsec->negcaps = (struct tag*)kzalloc(sizeof(struct tag), GFP_KERNEL);
		init_list2(tsec->negcaps);
		copy_lists(old_tsec->negcaps, tsec->negcaps);
	    }
    
	    mutex_unlock(&old_tsec->lock);
	}
#endif

//	*tsec = *old_tsec;
		new->security = tsec;


	return 0;
}

static void difc_cred_transfer(struct cred *new, const struct cred *old)
{
	struct task_security_struct *old_tsec;
	struct task_security_struct *tsec;

	difc_lsm_debug("in transfer for pid %d\n", current->pid);
	if(new == NULL || old == NULL)
	    return;
	old_tsec = old->security;
	tsec = new->security;

	mutex_lock(&old_tsec->lock);
	if(old_tsec==NULL || tsec==NULL)
	    return;

	tsec->pid = old_tsec->pid;	   
	tsec->uid = old_tsec->uid;
	
	if(old_tsec->seclabel!=NULL){
	    if(tsec->seclabel == NULL){
		tsec->seclabel = (struct tag*)kzalloc(sizeof(struct tag), GFP_KERNEL);
		init_list2(tsec->seclabel);
	    }
	    copy_lists(old_tsec->seclabel, tsec->seclabel);
	}
	if(old_tsec->poscaps!=NULL){
	    if(tsec->poscaps == NULL){
		tsec->poscaps = (struct tag*)kzalloc(sizeof(struct tag), GFP_KERNEL);
		init_list2(tsec->poscaps);
	    }
	    copy_lists(old_tsec->poscaps, tsec->poscaps);
	}
	if(old_tsec->negcaps!=NULL){
	    if(tsec->negcaps == NULL){
		tsec->negcaps = (struct tag*)kzalloc(sizeof(struct tag), GFP_KERNEL);
		init_list2(tsec->negcaps);
	    }
	    copy_lists(old_tsec->negcaps, tsec->negcaps);
	}
	mutex_unlock(&old_tsec->lock);
	difc_lsm_debug("out transfer for pid %d\n", current->pid);
}

static void azure_sphere_cred_init_security(void)
{

	tag_struct = kmem_cache_create("difc_tag",
				  sizeof(struct tag),
				  0, SLAB_PANIC, NULL);	
	//KMEM_CACHE(tag, SLAB_PANIC);

	atomic_set(&max_caps_num, CAPS_INIT);

	alloc_hash();
    if (table == NULL) {
        panic("couldn't allocate udoms hash_table.\n");
 
    }



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

// allocate a new label (explict or floating))
asmlinkage long sys_alloc_label(int type, enum label_types mode)
{


	return difc_alloc_label(type,mode);
	
}


asmlinkage long sys_permanent_declassify(void __user *ucap_list, unsigned int ucap_list_size, int cap_type,int label_type){

	difc_lsm_debug("enter\n");
	//return difc_permanent_declassify(ucap_list, ucap_list_size, cap_type,label_type);
	return 0;

}

asmlinkage long sys_temporarily_declassify(void __user *ucap_list, int ucap_list_size, int cap_type,int label_type){

	difc_lsm_debug("enter %d\n",ucap_list_size);
	//return difc_temporarily_declassify(ucap_list, ucap_list_size, cap_type,label_type);
	return 0;
}


asmlinkage long sys_restore_suspended_capabilities(void __user *ucap_list, unsigned int ucap_list_size, int cap_type, int label_type){

	difc_lsm_debug("enter\n");
//	return difc_restore_suspended_capabilities(ucap_list, ucap_list_size, cap_type,label_type);
return 0;
}


//set current task labels
asmlinkage unsigned long sys_set_task_label(unsigned long label, enum label_types ops, int label_type, void *bulk_label)
{

	return difc_set_task_label(current,  label,  ops,  label_type, bulk_label);

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

	difc_lsm_debug(" enter\n");
	//return difc_send_task_capabilities(pid,ucap_list,ucap_list_size,cap_type);
	return 0;
}

// this tries to enter a domain that is labeld for another task. 
// can find the domain based on the target address, does not need be exact addr.
// we could ask for specific domain_id, but i think finding domains based on addr is more convinient (and possibly safe)
// we will find the doamin

//enum smv_ops {INIT = 0, INIT_CREATE, CREATE, KILL, REGISTER, UDOM_OPS};
//enum smv_udom_ops {JOIN = 0, LEAVE, CHECK};

asmlinkage int sys_udom_ops(enum smv_ops smv_op, long smv_id, enum smv_udom_ops smv_domain_op,
                                          long memdom_id1)
{

    int rc = 0;
	if(smv_op == 0){
        difc_lsm_debug( "smv_main_init()\n");
        rc = smv_main_init();
    }else if(smv_op == 1){
        difc_lsm_debug( "smv_init_create()\n");
		rc=smv_main_init();
		if (rc != 0) {
    		difc_lsm_debug("smv_main_init() failed\n");
  			  return -1;
  		}
        rc = smv_create();
    }else if(smv_op == 2){
        difc_lsm_debug( "smv_create()\n");
        rc = smv_create();
    }else if(smv_op == 3){
        difc_lsm_debug( "smv_kill(%ld)\n", smv_id);
        rc = smv_kill(smv_id, NULL);
    }else if(smv_op == 4){
        difc_lsm_debug( " register_smv_thread(%ld)\n", smv_id);

		register_smv_thread(smv_id);
		
    }else if(smv_op == 5){
		rc= smv_exists(smv_id);
        difc_lsm_debug( " smv_exists(%ld)\n", smv_id);
    } else if(smv_op == 6){
        if(smv_domain_op == 0){
            difc_lsm_debug( "smv_join_domain(%ld, %ld)\n", memdom_id1, smv_id);
            rc = smv_join_memdom(memdom_id1, smv_id);
        }else if(smv_domain_op == 1){
            difc_lsm_debug( "[%s] smv_leave_domain(%ld, %ld)\n",smv_id, memdom_id1);
            rc = smv_leave_memdom(memdom_id1, smv_id, NULL);
        }else if(smv_domain_op == 2){
            difc_lsm_debug("[%s] smv_is_in_domain(%ld, %ld)\n",memdom_id1, smv_id);
            rc = smv_is_in_memdom(memdom_id1, smv_id);
        }

    }
    return rc;
	


}


//enum udom_ops {UDOM_CREATE = 0, UDOM_KILL, UDOM_MMAP_REG, UDOM_DATA,UDOM_MAINID,UDOM_QUERYID,UDOM_PRIV_OPS};
//enum udom_priv_ops {UDOM_GET = 0, UDOM_ADD, UDOM_REMOVE,NO_UDOM_PRIV_OPS};

asmlinkage int sys_udom_mem_ops(enum udom_ops memdom_op, long memdom_id1,long smv_id,
                                         enum udom_priv_ops memdom_priv_op, long memdom_priv_value){
    int rc = 0;


//  unsigned long memdom_data_addr = 0;
    if(memdom_op == UDOM_CREATE){        
        difc_lsm_debug( "memdom_create()\n");
        rc = memdom_create();        
    }
    else if(memdom_op == UDOM_KILL){        
        difc_lsm_debug( "memdom_kill(%ld)\n",memdom_id1);
        rc = memdom_kill(memdom_id1, NULL);        
    }
    else if(memdom_op == UDOM_MMAP_REG){        
        difc_lsm_debug( " memdom_mmap_register(%ld)\n",memdom_id1);
        rc = memdom_mmap_register(memdom_id1);
    }
    else if(memdom_op == UDOM_DATA){
//      difc_lsm_debug("[%s] converting %s to unsigned long\n",memdom_data);
//      rc = kstrtoul(memdom_data, 10, &memdom_data_addr);
//      if (rc) {
//          difc_lsm_debug("[%s] Error: convert memdom_data address to unsigned long failed, returned %d\n",rc);
//      }
//      difc_lsm_debug("[%s] memdom_munmap(%ld, 0x%08lx)\n",memdom_id1, memdom_data_addr);
//      rc = memdom_munmap(memdom_data_addr);
    }
	else if(memdom_op == UDOM_MAINID){
			rc= memdom_main_id();
    }
	else if(memdom_op == UDOM_QUERYID){//ztodo:fix this
			unsigned long address = 0;
			rc=memdom_query_id(address);

    }

	else if(memdom_op == UDOM_PRIVID){
		rc = memdom_private_id();
	}
    else if(memdom_op == UDOM_PRIV_OPS){      
        if(memdom_priv_op == UDOM_GET){            
            difc_lsm_debug( "memdom_priv_get(%ld, %ld)\n", memdom_id1, smv_id);
            rc = memdom_priv_get(memdom_id1, smv_id);            
        }        
        else if(memdom_priv_op == UDOM_ADD){            
            difc_lsm_debug( "memdom_priv_add(%ld, %ld, %ld)\n",memdom_id1, smv_id, memdom_priv_value);
            rc = memdom_priv_add(memdom_id1, smv_id, memdom_priv_value);            
        }        
        else if(memdom_priv_op == UDOM_REMOVE){            
            difc_lsm_debug( "memdom_priv_del(%ld, %ld, %ld)\n",memdom_id1, smv_id, memdom_priv_value);
            rc = memdom_priv_del(memdom_id1, smv_id, memdom_priv_value);            
        }   


    }

    return rc;
}



#endif /*CONFIG_EXTENDED_LSM_DIFC */







static struct security_hook_list azure_sphere_hooks[] __lsm_ro_after_init = {

 
	//LSM_HOOK_INIT(cred_free, difc_cred_free),
//LSM_HOOK_INIT(cred_transfer, difc_cred_transfer),

//for basline test
/*
 	LSM_HOOK_INIT(cred_alloc_blank, difc_cred_alloc_blank),
	LSM_HOOK_INIT(cred_prepare, difc_cred_prepare),
	LSM_HOOK_INIT(set_task_label,difc_set_task_label),
	LSM_HOOK_INIT(copy_user_label,difc_copy_user_label),
	LSM_HOOK_INIT(inode_alloc_security,difc_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security,difc_inode_free_security),
	LSM_HOOK_INIT(inode_init_security,difc_inode_init_security),
	LSM_HOOK_INIT(inode_set_security,difc_inode_set_security),
	LSM_HOOK_INIT(inode_permission, difc_inode_permission),
	LSM_HOOK_INIT(file_permission,difc_file_permission),
	LSM_HOOK_INIT(sk_alloc_security, difc_sk_alloc_security),
	LSM_HOOK_INIT(sk_free_security, difc_sk_free_security),
	LSM_HOOK_INIT(sk_clone_security, difc_sk_clone_security),
	

//	LSM_HOOK_INIT(check_tasks_labels_allowed, difc_tasks_labels_allowed),
//	LSM_HOOK_INIT(check_task_labeled,difc_check_task_labeled),


	/*
	
	LSM_HOOK_INIT(inode_getxattr, difc_inode_getxattr),
	LSM_HOOK_INIT(inode_setxattr, difc_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr, difc_inode_post_setxattr),
	LSM_HOOK_INIT(inode_getsecurity, difc_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity, difc_inode_setsecurity),
	LSM_HOOK_INIT(inode_listsecurity, difc_inode_listsecurity),
	LSM_HOOK_INIT(inode_unlink, difc_inode_unlink),
	LSM_HOOK_INIT(inode_rmdir, difc_inode_rmdir),
	*/
	//LSM_HOOK_INIT(d_instantiate, difc_d_instantiate),

	




//	LSM_HOOK_INIT(inode_label_init_security,difc_inode_init_security),
/*	LSM_HOOK_INIT(inode_get_security,difc_inode_get_security),
	LSM_HOOK_INIT(inode_set_label,difc_inode_set_label),


*/




};


static int __init azure_sphere_lsm_init(void)
{

  azure_sphere_cred_init_security();

    security_add_hooks(azure_sphere_hooks, ARRAY_SIZE(azure_sphere_hooks),"AzureSphere");

    return 0;
}



security_initcall(azure_sphere_lsm_init);


