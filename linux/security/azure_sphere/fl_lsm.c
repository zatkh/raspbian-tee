/*
 *  WEIR DIFC System - LSM
 *
 *  Author:
 *     Adwait Nadkarni <apnadkar@ncsu.edu>
 */
#include "weir_lsm.h"
#include "weir_objsec.h"
#include "weir_netlink.h"
struct tag* globalpos;
struct tag* globalneg;

unsigned char *empty_address="0000:0000:0000:0000:0000:0000:0000:0000";

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
	//printk("WEIR: cred NULL\n");
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
	//printk("WEIR: cred NULL\n");
	return NULL;
    }
    return cred->security;
}

//get task security struct from pid
struct task_security_struct* get_task_security_from_pid(pid_t pid){
    struct task_struct* task;
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if(task==NULL){
	//printk("WEIR: task NULL for pid %d\n",pid);
	return NULL;
    }
    return get_task_security_from_task_struct(task);
}

//Add tag to the process's seclabel
void add_tag_to_label(pid_t pid, tag_t tag){
    struct task_security_struct* tsec = get_task_security_from_pid(pid);
    //struct tag* seclabel;

    if(tsec==NULL){
	    //printk("WEIR: tsec NULL for pid %d\n",pid);
	    goto out;
    }
    //LOCK on TSEC
    mutex_lock(&tsec->lock);
    tsec->pid = pid;
    if(tsec->seclabel==NULL){
	//printk("WEIR: Allocating tsec->seclabel for pid %d\n",pid);
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
	    //printk("WEIR: tsec is null for pid %d\n",pid);
	    ret = -1;
	    goto out;
	}

	//LOCK on TSEC
	mutex_lock(&tsec->lock);

	tsec->pid = pid;
	tsec->uid = uid;

	//For tsec->seclabel
	if(sec==NULL || secsize <=0){
	    //printk("WEIR_DEBUG: No sec suplied for %d, secsize=%d!\n", pid, secsize);
	} else {
	    //printk("WEIR_DEBUG: init_proc_security first element of sec = %lld\n", sec[0]);
	    //tsec->seclabel = (struct tag*)kzalloc(sizeof(struct tag), GFP_KERNEL);
	    //init_list2(tsec->seclabel);
	    //tsec->seclabel = get_list_from_array2(sec, tsec->seclabel, secsize);
	    get_list_from_array(sec, &(tsec->seclabel), secsize);

	}
	//For tsec->poscaps
	if(pos==NULL || possize <=0){
	    //printk("WEIR_DEBUG: No pos suplied for %d, possize=%d!\n", pid, possize);
	} else {
	    //printk("WEIR_DEBUG: init_proc_security first element of pos = %lld\n", pos[0]);
	    get_list_from_array(pos, &(tsec->poscaps), possize);
	}
	//For tsec->negcaps
	if(neg==NULL || negsize <=0){
	    //printk("WEIR_DEBUG: No neg suplied for %d, negsize=%d!\n", pid, negsize);
	} else {
	    //printk("WEIR_DEBUG: init_proc_security first element of neg = %lld\n", neg[0]);
	    get_list_from_array(neg, &(tsec->negcaps), negsize);
	}

	//Resease LOCK on TSEC
	mutex_unlock(&tsec->lock);
	//printk("WEIR: INITIALIZED SECURITY CONTEXT for pid %d, secsize %d\n",pid, secsize);
out:
	rcu_read_unlock();
	return ret;
}
  
//get label size (for ioctl)
int get_label_size(pid_t pid){
	int ret=0;
	struct task_security_struct* tsec = get_task_security_from_pid(pid);
	if(tsec==NULL){
	    //printk("WEIR: tsec is null for pid %d\n", pid);
	    ret = -1;
	    goto out;
	}
	// TODO: LOCK on TSEC; figure out why this crashes
	//mutex_lock(&tsec->lock);
	if(tsec->seclabel==NULL){
	    //printk("WEIR: tsec->seclabel is null for pid %d\n", pid);
	    ret = -1;
		//TODO: Release LOCK on TSEC
		//mutex_unlock(&tsec->lock);
	    goto out;
	}
	//printk("WEIR: tsec->seclabel is not null for pid %d\n", pid);
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
	//printk("WEIR: tsec->seclabel is not null for pid %d\n", pid);
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

    int euid = current->cred->euid;
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

    if(exempt(euid)){
	goto out;
    }
    
    tsec = get_task_security_from_pid(pid);
    if(!tsec){
	//printk("WEIR_DEBUG: declassification_check. tsec NULL for pid %d\n",pid);
	goto out;
    }
    
    seclabel = tsec->seclabel;
    negcaps = tsec->negcaps;

    //If label == empty, allow;
    if(!seclabel || list_size(seclabel)<=0){
	//printk("WEIR_DEBUG: declassification_check. seclabel NULL or empty for pid %d\n",pid);
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
	//printk("Weir: socket_connectv4:%pI4;%d;%u;%d\n", &(temp_sockaddr->sin_addr), euid, pid, addrlen);
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
	    //printk("Weir: EMPTY socket_v6:%pI6;%d;\n", &(temp_sockaddr->sin6_addr), euid);
	    goto out;
	}*/
	//printk("Weir: socket_connectv6:%pI6;%d;%u;%d\n", &(temp_sockaddr->sin6_addr), euid, pid, addrlen);
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
    int to_euid = to->cred->euid;
    int from_euid = from->cred->euid;
    //int to_pid = to->pid;
    //int from_pid = from->pid;
    struct task_security_struct *to_tsec, *from_tsec;
    struct tag *to_seclabel, *from_seclabel;
    //Exempt calls to and from root and system, as we handle their internal
    //state in the framework. This is to prevent system services from
    //accumulating taint.
    //printk("WEIR_DEBUG: binder_check. for (pid,uid) to:(%d,%d), from:(%d,%d).\n",to_pid, to_euid, from_pid, from_euid);

    to_tsec = get_task_security_from_task_struct_unlocked(to);
    from_tsec = get_task_security_from_task_struct_unlocked(from);

    if(exempt(to_euid) || exempt(from_euid) || exempt_system_apps(to_euid) || exempt_system_apps(from_euid)){
	return ret;
    }
    //TODO: Return -1. Apart from root which has already been exempted,
    //everyone else must have a tsec.
    if(!to_tsec || !from_tsec){
	//printk("WEIR_DEBUG: binder_check. tsec NULL for to:%d or from:%d.\n",to_pid, from_pid);
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
	//printk("WEIR_DEBUG: binder_check. denial for (pid,uid) to:(%d,%d), from:(%d,%d).\n",to_pid, to_euid, from_pid, from_euid);
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
    tmp = (char *)__get_free_page(GFP_TEMPORARY);
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
	
static int weir_file_permission(struct file *file, int mask)
{
	const struct cred *cred=get_current_cred();
	const struct task_security_struct *tsec = cred->security;
	struct inode *inode = file->f_path.dentry->d_inode;
	int uid = inode->i_uid;
	int euid = current->cred->euid;
	int pid=current->pid;
	int gid=inode->i_gid;
	int inode_no = inode->i_ino;
	int rc=0;
	int i =0 ;
	int xattr_res = 0;
	tag_t xattr_label_size = 0;
	tag_t *label_array = NULL;
	struct tag *fseclabel = NULL;
	char *path=NULL;
	int XATTR_SIZE = MAX_LABEL_SIZE+1;
	tag_t xattr_buffer[XATTR_SIZE];//everything initialized to 0
	mask &= (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);

	//If no xattr, return
	if(inode->i_op->getxattr==NULL){
	    //printk("WEIR_DEBUG: xattr null for pid %d, gid %d\n",pid, gid);
	    goto out;
	}
	//Always allow for no tsec.
	if(!tsec){
	    printk("WEIR_DEBUG: file_permission. tsec NULL for pid %d file %d\n",pid, inode_no);
	    goto out;
	} 

	//Exempt root and system. 
	//System apps exempted for debugging.
	//FIXME: SDCARD XATTR
	if((exempt(uid) || exempt(euid)) || sdcard(gid) || exempt_system_apps(euid) || exempt_system_apps(uid)){//do nothing
	    goto out;
	}

	//Get the file path. Remove after DEBUG:
	getFilePath(file,&path);
	if(path==NULL){
	    goto out;
	}
	//printk("WEIR_DEBUG: File Permission. pid %d, file %s\n",pid,path);


	//1. Get the xattr on the file
	xattr_res = inode->i_op->getxattr(file->f_path.dentry, XATTR_NAME_WEIR, (void*)xattr_buffer, sizeof(tag_t)*(XATTR_SIZE));
	xattr_label_size = xattr_buffer[0];
	//printk("WEIR_DEBUG: xattr_label_size after getxattr=%lld\n", xattr_label_size);

	//2. If it has never been set
	//	a. If this is a read, goto out; //i.e. ALLOW
	//	b. If this is a write, set the label, and goto out; Set the
	//	label to 0 size if the current task has no label.  
	if(xattr_res <= 0){
	    if(xattr_res == -ENODATA) {
		if( (mask & MAY_READ) || (mask & MAY_EXEC) ){
		    goto out;
		} else if ((mask & MAY_WRITE) || (mask & MAY_APPEND)){
		    //DEBUG begins
		    /*
		    printk("WEIR_DEBUG: Initializing label for file: pid %d, file %d, i_gid %d, path=%s\n", pid, inode_no, gid, path);
		    printk("WEIR_DEBUG: Label on pid %d is:\n", pid);
		    list_print(tsec->seclabel);
		    */
		    //DEBUG ends

		    //Get the size of the label we want to write
		    xattr_label_size = list_size(tsec->seclabel);
		    if(xattr_label_size <=0){
			xattr_label_size=0;//list_size returns -1 for NULL and 0 for empty. We must make it uniform.
		    } else if (xattr_label_size > MAX_LABEL_SIZE){
			goto out;
		    }
		
		    //label_array can be NULL if tsec->seclabel is NULL or if xattr_label_size=0
		    label_array = get_array_from_list(tsec->seclabel);
		    //We create an array whose first element is the size, and the rest are the tags.
		    xattr_buffer[0]=xattr_label_size;
		    for(i = 0; i < xattr_label_size; i++){
			xattr_buffer[i+1] = label_array[i];
		    }
		    //printk("WEIR_DEBUG: temp_label_array[0] before setxattr=%lld\n", temp_label_array[0]);
		    xattr_res = inode->i_op->setxattr(file->f_path.dentry, XATTR_NAME_WEIR, xattr_buffer, sizeof(tag_t)*(XATTR_SIZE), XATTR_CREATE);
		    //printk("WEIR_DEBUG: Label set for file: res=%d pid %d, file %d, i_gid %d, xattr_label_size %lld\n", xattr_res, pid, inode_no, gid, xattr_label_size);

		    //DEBUG ONLY. Get xattr and verify
		    /*
		    xattr_res = inode->i_op->getxattr(file->f_path.dentry, XATTR_NAME_WEIR, (void*)temp_label_array, sizeof(tag_t)*(MAX_LABEL_SIZE+1));
		    printk("WEIR_DEBUG: Getting xattr after setting it, xattr_label_size is %lld\n",temp_label_array[0]);
		    */
		    if(label_array!=NULL)   kfree(label_array);
		    goto out;
		}
	    } else {
		printk("WEIR_DEBUG: file_permission. xattr_error_unknown:%d, for pid %d file %d\n",xattr_res, pid, inode_no);
		goto out;
	    }
	}

	//3. If it has been set, then retrieve it into fseclabel. Then,
	//	 perform a label check.
	//	 xattr_buffer has the file label.
	get_list_from_array(&(xattr_buffer[1]), &(fseclabel), xattr_label_size);

	//DEBUG begins
	printk("WEIR_DEBUG: Performing check for file access: res=%d pid %d, file %d, i_gid %d, path %s\n", xattr_res, pid, inode_no, gid, path);
	printk("proc_label=");
	list_print(tsec->seclabel);
	printk("file_label=");
	list_print(fseclabel);
	
	//DEBUG ends
	
	//The check.
	if( (mask & MAY_READ) || (mask & MAY_EXEC) ){
	    if(!dominates(tsec->seclabel, fseclabel)){
		//TODO: FIXME
		//rc = -1;
		printk("WEIR_DEBUG: file_permission denied: res=%d for pid %d, file %d, i_gid %d\n",xattr_res, pid, inode_no, gid);
		goto out;
	    }
	}
	if( (mask & MAY_WRITE) || (mask & MAY_APPEND) ){
	    if(!dominates(fseclabel, tsec->seclabel)){
		//TODO: FIXME
		//rc = -1;
		printk("WEIR_DEBUG: file_permission denied: res=%d for pid %d, file %d, i_gid %d\n",xattr_res, pid, inode_no, gid);
		goto out;
	    }
	}
out:
	if(fseclabel!=NULL) kfree(fseclabel);
	return rc;
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

/*
struct security_operations weir_ops = {
	.name =				"weir",
	.cred_alloc_blank   =		weir_cred_alloc_blank,
	.file_permission    =		weir_file_permission,
	.cred_free	    =		weir_cred_free,
	.cred_prepare	    =		weir_cred_prepare,
	.cred_transfer	    =		weir_cred_transfer,
	.socket_bind	    =		weir_socket_bind,
	.socket_connect	    =		weir_socket_connect,
	.binder_set_context_mgr =	weir_binder_set_context_mgr,
	.binder_transaction =		weir_binder_transaction,
	.binder_transfer_binder =	weir_binder_transfer_binder,
	.binder_transfer_file =		weir_binder_transfer_file,


};  

*/

/**
 * weir_init - initialize the weir-lsm system
 *
 * Returns 0
 */

/*
static __init int weir_init(void)
{
	printk(KERN_INFO "WEIR:  Enabling...\n");

	if (security_module_enable(&weir_ops) != 0){
		printk(KERN_INFO "WEIR disabled!!");
		return 0;
	}
	printk(KERN_INFO "WEIR:  Initializing.\n");
	// Set the security state for the initial task. 
	if(false)
	    cred_init_security();

	return 0;
}

security_initcall(weir_init);
*/