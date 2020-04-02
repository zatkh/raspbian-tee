
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

#include <asm/syscall.h>
#include <linux/compat.h>
#include <linux/slab.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>


#include <asm/elf.h>
#include <asm/udom.h>

#include "lsm.h"

int udom_total; /* total udoms as per device tree */
u32 initial_allocation_mask; /*  bits set for the initially allocated keys */
u32 reserved_allocation_mask; /* bits set for reserved keys */

char *table;
HashEntry* mmap_table;
int *udom_arr;




//set current task labels
asmlinkage long sys_udom_alloc(unsigned long flags, unsigned long init_val)
{

	int udom;
	int ret;
	unsigned long dacr = 0;

	/* No flags supported yet. */
	if (flags)
		return -EINVAL;
	/* check for unsupported init values */
	//if (init_val & ~UDOM_ACCESS_MASK)
		//return -EINVAL;

	down_write(&current->mm->mmap_sem);
	udom = mm_udom_alloc(current->mm);

	ret = -ENOSPC;
	if (udom == -1)
		goto out;

	modify_domain(udom,init_val);

	ret = udom;

	__asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    printk("allocated udom:%d, dacr=0x%lx\n",udom, dacr);

out:
	up_write(&current->mm->mmap_sem);
	return ret;
}

asmlinkage int sys_udom_free(unsigned long udom)
{

	int ret;
	unsigned long dacr = 0;

	down_write(&current->mm->mmap_sem);


	modify_domain(udom,DOMAIN_CLIENT);

	mm_udom_free(current->mm, udom);

	int udom_client_acc= udom_get(DOMAIN_KERNEL);
	if(udom_client_acc==DOMAIN_CLIENT)
	    printk("client udom acc:%d\n",udom_client_acc);


	__asm__ __volatile__(
            "mrc p15, 0, %[result], c3, c0, 0\n"
            : [result] "=r" (dacr) : );
    printk("allocated udom:%d, dacr=0x%lx\n",udom, dacr);

out:
	up_write(&current->mm->mmap_sem);
	return ret;


}

asmlinkage int sys_udom_get(int udom)
{	
	

	return  udom_get(udom);	

}

asmlinkage int sys_udom_set(int udom, unsigned val)
{
	//check labels here to make sure not every body can change udom permissions		
	 modify_udom(udom,val);
	 return 0;
	
}


int __execute_only_udom(struct mm_struct *mm)
{
	bool need_to_set_mm_udom = false;
	int execute_only_udom = mm->context.execute_only_udom;
	int ret;

	/* Do we need to assign a udom for mm's execute-only maps? */
	if (execute_only_udom == -1) {
		/* Go allocate one to use, which might fail */
		execute_only_udom = mm_udom_alloc(mm);
		if (execute_only_udom < 0)
			return -1;
		need_to_set_mm_udom = true;
	}

	/*
	 * We do not want to go through the relatively costly
	 * dance to set DACR if we do not need to.  Check it
	 * first and assume that if the execute-only udom is
	 * write-disabled that we do not have to set it
	 * ourselves.  We need preempt off so that nobody
	 * can make fpregs inactive.
	 */
	/*preempt_disable();
	if (!need_to_set_mm_udom &&
	    current->thread.fpu.initialized &&
	    !__pkru_allows_read(read_pkru(), execute_only_udom)) {
		preempt_enable();
		return execute_only_udom;
	}
	preempt_enable();
*/
	/*
	 * Set up PKRU so that it denies access for everything
	 * other than execution.
	 */
	//ret = arch_set_user_udom_access(current, execute_only_udom,
	//		udom_DISABLE_ACCESS);
	/*
	 * If the PKRU-set operation failed somehow, just return
	 * 0 and effectively disable execute-only support.
	 */
	if (ret) {
		mm_set_udom_free(mm, execute_only_udom);
		return -1;
	}

	/* We got one, store it and use it from here on out */
	if (need_to_set_mm_udom)
		mm->context.execute_only_udom = execute_only_udom;
	return execute_only_udom;
}




SYSCALL_DEFINE3(udom_munmap, unsigned long, addr, size_t, len, int, id)
{
  mpt_node *mn = hash_get(id);
  memset(mn, 0, sizeof(mpt_node));
  //if(udom_arr[mn->udom] != -1)
  udom_arr[mn->udom] = -1;
  mn->udom = -1;
  //printk("udom_munmap\n");
  return sys_munmap(addr, len);
}

SYSCALL_DEFINE5(udom_mmap_cache, unsigned long, addr, unsigned long, len,
    unsigned long, prot, unsigned long, flags,
    int, id) {

 // long raddr = sys_mmap_pgoff(addr, len, prot, flags, -1, 0);
  long raddr=sys_udom_mmap_pgoff(id,addr, len, prot, flags, -1);
  mpt_node mn = {.buf = (void*)raddr, .len = len, .prot = prot, .udom = -1, .next = NULL, .id = id};
  hash_put(id, &mn);
  //printk("udom_mmap\n");
  return raddr;
}

SYSCALL_DEFINE5(udom_mprotect_set, unsigned long, start, unsigned long, len,
    unsigned long, prot, int, udom,
    int, id) {
  udom_arr[udom] = id;
  mpt_node *mn = hash_get(id);
  mn->udom = udom;
  mn->prot = prot;
  //printk("udom_mprotect_set\n");
  return sys_udom_mprotect(start, len, prot, udom);
}

SYSCALL_DEFINE5(udom_mprotect_evict, unsigned long, start, unsigned long, len,
    unsigned long, prot, int, udom,
    int, id) {
  mpt_node *mn = hash_get(id);
  mn->udom = -1;
  //printk("udom_mprotect_evict\n");
  return sys_udom_mprotect(start, len, prot, udom);
}
SYSCALL_DEFINE4(mprotect_exec, unsigned long, start, unsigned long, len,
    unsigned long, prot, int, udom) {
  mpt_node* cur = hash_get(udom_arr[udom]);
  mpt_node* prev = NULL;

  // still has exec-only
  while(cur) {
    if(cur->buf == start) {
      if(!prev) {
        udom_arr[udom] = cur->next->id;
      }
      else if(cur->next) {
        prev->next = cur->next->next;
      }
      cur->udom = -1;
      break;
    }
    prev = cur;
    cur = cur->next;
  }
  //printk("mprotect_exec\n");
  return sys_udom_mprotect(start, len, prot, -1);
}

SYSCALL_DEFINE5(udom_mprotect_exec, unsigned long, start, unsigned long, len,
    unsigned long, prot, int, udom,
    int, id) {
  mpt_node *mn = hash_get(id);
  if(mn->prot == PROT_EXEC && prot != PROT_EXEC) {
    mpt_node* cur = hash_get(udom_arr[mn->udom]);
    mpt_node* prev = NULL;
    if(!cur->next) {
      // this is last exec-only page 
    } 
    else {
      // still has exec-only
      //PORT how to handle this case?
      while(cur) {
        if(cur->buf == start) {
          if(!prev) {
            udom_arr[mn->udom] = cur->next->id;
          }
          else if(cur->next) {
            prev->next = cur->next->next;
          }
          cur->udom = -1;
          break;
        }
        prev = cur;
        cur = cur->next;
      }
    }
  }
  udom_arr[udom] = id;
  mn->udom = udom;
  mn->prot = prot;
  //printk("udom_mprotect_exec\n");
  return sys_udom_mprotect(start, len, prot, udom);
}

SYSCALL_DEFINE5(udom_mprotect_grouping, unsigned long, start, unsigned long, len,
    unsigned long, prot, int, grouping_key,
    int, id) {
  // TODO it's single link list now, but I will change to tree for binary search
  mpt_node* cur = hash_get(udom_arr[grouping_key]);
  mpt_node *mn = hash_get(id);
  if (!cur->next) {
    cur->next = mn;
  }
  else {
    while (cur) {
      if(!cur->next) {
        cur->next = mn;
        break;
      }
      cur = cur->next;
    }
  }
  mn->udom = grouping_key;

  //printk("udom_mprotect_grouping\n");
  return sys_udom_mprotect(start, len, prot, grouping_key);
}

void alloc_hash(void) {
  int i = 0;
	table = kzalloc(TABLE_SIZE * sizeof(HashEntry), GFP_KERNEL);
  memset(table, -1, 0x1000);
  udom_arr = (int *) table;
  mmap_table = (HashEntry *)(table + 0x1000);
	for(i = 0; i < TABLE_SIZE; i++) {
		mmap_table[i].key = -1;
		memset(&mmap_table[i].value, 0, sizeof(mpt_node));
    mmap_table[i].value.udom = -1;
  }
}
   
mpt_node* hash_get(int key) {
	int hash = (key % TABLE_SIZE);
  //printk("key : %d, %d\n", mmap_table[hash].key, key);
	while (mmap_table[hash].key != -1 && mmap_table[hash].key != key)
		hash = (hash + 1) % TABLE_SIZE;
	if (mmap_table[hash].key == -1)
		return NULL;
	else
		return &mmap_table[hash].value;
}

void hash_put(int key, mpt_node* value) {
	int hash = (key % TABLE_SIZE);
	while (mmap_table[hash].key != -1 && mmap_table[hash].key != key)
		hash = (hash + 1) % TABLE_SIZE;
/*	
 *	if (table[hash].key != -1) {
		table[hash].key = -1;
		table[hash].value = NULL;
	}	
  */
	mmap_table[hash].key = key;
  memcpy(&mmap_table[hash].value, value, sizeof(mpt_node));
//	table[hash].value = value;
}


