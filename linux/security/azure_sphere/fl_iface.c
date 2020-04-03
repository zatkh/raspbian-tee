#include "include/weir_iface.h"
#include "include/weir_netlink.h"

DEFINE_MUTEX(weir_seclabel);
long weir_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{      
	//TODO: Locking, error handling
	int ret = 0;
	size_t size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;
	struct hello *hello_msg=NULL;
	struct seclabel_struct* seclabel=NULL;
	struct seclabel_struct* __user seclabel_user = NULL;
	struct global_cap* global=NULL;
	struct process_cap* proccap=NULL;
	struct process_sec_context* psec=NULL;
	struct add_tag_struct* add_tag=NULL;
	int *secsize2=NULL;
	tag_t* seclocal2=NULL;
	tag_t* seclocal=NULL;
	tag_t* poslocal=NULL;
	tag_t* neglocal=NULL;
	switch(cmd) {
	case WEIR_HELLO:
		hello_msg = (struct hello*)kmalloc(sizeof(struct hello), GFP_KERNEL);
		ret = copy_from_user(hello_msg, ubuf, size);
		if(hello_msg!=NULL) kfree(hello_msg);
		break;	

	case WEIR_GET_PROC_SECLABEL:
		mutex_lock(&weir_seclabel);
		
		seclabel = (struct seclabel_struct*)kmalloc(sizeof(struct seclabel_struct), GFP_KERNEL);
		ret = copy_from_user(seclabel, ubuf, size);
		
		secsize2 = (int*) kmalloc(sizeof(int), GFP_KERNEL);
		secsize2[0]=-1;
		seclabel_user = (struct seclabel_struct*) ubuf;
		
		if(seclabel->secsize!=NULL){
		    ret = copy_from_user(secsize2, seclabel->secsize, sizeof(int));    
		}
		//if size <=0, return size;
		
		//printk("WEIR: get_proc_seclabel called for pid %d\n",seclabel->pid);
		if(secsize2[0]<=0){
		    secsize2[0] = get_label_size(seclabel->pid);
		    //printk("WEIR: get_proc_seclabel, for pid %d size = %d\n",seclabel->pid, secsize2[0]);
		    ret=copy_to_user(seclabel_user->secsize, secsize2, sizeof(int));
		} else {
		    seclocal2 = get_label(seclabel->pid);
		    ret=copy_to_user(((struct seclabel_struct*)ubuf)->sec, seclocal2, sizeof(tag_t)*secsize2[0]);
		}
		
		if(seclocal2!=NULL) kfree(seclocal2);
		if(secsize2!=NULL)  kfree(secsize2);
		if(seclabel!=NULL)  kfree(seclabel);
		mutex_unlock(&weir_seclabel);
		break;	

	case WEIR_ADD_TAG_TO_LABEL:
		
		mutex_lock(&weir_seclabel);
		add_tag = (struct add_tag_struct*) kmalloc(sizeof(struct add_tag_struct), GFP_KERNEL);
		ret = copy_from_user(add_tag, ubuf, size);
		///*
		//printk("WEIR: Adding tag %lld for pid %d\n", add_tag->tag, add_tag->pid);
		add_tag_to_label(add_tag->pid, add_tag->tag);
		//*/
		if(add_tag!=NULL)   kfree(add_tag);
		mutex_unlock(&weir_seclabel);
		break;

	case WEIR_ADD_GLOBAL_CAP:
		global = (struct global_cap*)kmalloc(sizeof(struct global_cap), GFP_KERNEL);
		ret = copy_from_user(global, ubuf, size);
		change_global(global->tag, global->pos, global->add);
		if(global!=NULL)    kfree(global);
		break;

	case WEIR_ADD_PROCESS_CAP:
		proccap = (struct process_cap*)kmalloc(sizeof(struct process_cap), GFP_KERNEL);
		ret = copy_from_user(proccap, ubuf, size);
		change_proccap(proccap->pid, proccap->tag, proccap->pos, proccap->add);
		if(proccap!=NULL)    kfree(proccap);
		break;

	case WEIR_INIT_PROC_SEC_CONTEXT:
		psec = (struct process_sec_context*)kmalloc(sizeof(struct process_sec_context), GFP_KERNEL);
		ret = copy_from_user(psec, ubuf, size);

		//printk("WEIR: Inside init_proc_sec secsize for pid %d\n", psec->pid);
		//sec,pos,neg
		seclocal=NULL; 
		poslocal=NULL; 
		neglocal=NULL;
		if(psec->secsize>0){
		    //printk("WEIR: init_proc_sec secsize =%d\n", psec->secsize);
		    seclocal=(tag_t*)kmalloc(sizeof(tag_t) * psec->secsize, GFP_KERNEL);
		    ret=copy_from_user(seclocal, psec->sec, psec->secsize*sizeof(tag_t));
		}
		if(psec->possize>0){
		    poslocal=(tag_t*)kmalloc(sizeof(tag_t) * psec->possize, GFP_KERNEL);
		    ret=copy_from_user(poslocal, psec->pos, psec->possize*sizeof(tag_t));
		}
		if(psec->negsize>0){
		    neglocal=(tag_t*)kmalloc(sizeof(tag_t) * psec->negsize, GFP_KERNEL);
		    ret=copy_from_user(neglocal, psec->neg, psec->negsize*sizeof(tag_t));
		}
	    
		init_process_security_context(psec->pid, psec->uid, seclocal, poslocal, neglocal, psec->secsize, psec->possize, psec->negsize);
		if(seclocal!=NULL)  kfree(seclocal);
		if(poslocal!=NULL)  kfree(poslocal);
		if(neglocal!=NULL)  kfree(neglocal);
		if(psec!=NULL)	    kfree(psec);
		break;	
	default:
		ret = -1;
		break;
	}
	return ret;
}

static struct file_operations weir_fops = {
	.unlocked_ioctl = weir_ioctl,
};

static struct miscdevice weir_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "weir",
	.fops = &weir_fops,
};

static int __init weir_init(void)
{
	int ret;
	ret = misc_register(&weir_miscdev);
	if(ret<0) {
		printk("Registering char device weir failed with %d\n", ret);
	}
	else {
		printk("weir device registered!!\n");
	}

	//Create the netlink socket for the upcall
	//for more information, goto weir_netlink.c
	kernel_socket_create();
	return ret;
}
device_initcall(weir_init);
MODULE_LICENSE("GPL v2");
