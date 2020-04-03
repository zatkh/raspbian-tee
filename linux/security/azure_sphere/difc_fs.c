/*
* Author: Yuqiong Sun <yus138@cse.psu.edu>
*/
#include <linux/seq_file.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/uaccess.h>

#include <azure-sphere/difc.h>

int add_ownership(struct task_security_struct *tsp, int tag_content) {
	bool present = false;
	struct tag *t, *new_tag;
	int result = -EINVAL;

	list_for_each_entry_rcu(t, &tsp->olabel, next)
		if (t->content == tag_content) {
			present = true;
			break;
		}
	if (!present) {

		// TODO: check authenticity of ownership before adding it

		if (tag_struct == NULL)
			printk(KERN_DEBUG "SYQ: tag_struct is NULL\n");
		new_tag = kmem_cache_alloc(tag_struct, GFP_NOFS);
		if (!new_tag) {
			result = -ENOMEM;
			return result;
		}
		new_tag->content = tag_content;
		list_add_tail_rcu(&new_tag->next, &tsp->olabel);
	}
	return 0;
}
 
int drop_ownership(struct task_security_struct *tsp, int tag_content) {
	struct tag *t;
	struct tag *next_tag;

	list_for_each_entry_safe(t, next_tag, &tsp->olabel, next) {
		if (t->content == tag_content) {
			list_del_rcu(&t->next);
			kmem_cache_free(tag_struct, t);
		}
	}
	return 0;	
}


size_t difc_confine_task(struct file *file, const char __user *buf, 
				size_t size, loff_t *ppos, struct task_security_struct *tsp) {
	int confine;
	char temp[2];

	if (size > sizeof(temp) || *ppos != 0)
		return -EINVAL;
	
	if (copy_from_user(temp, buf, size) != 0)
		return -EFAULT;

	temp[size]= '\0';

	if (sscanf(temp, "%d", &confine) != 1)
		return -EINVAL;

	if (confine == 1)
		tsp->type = TAG_CONF;
	else if (confine == 0)
		tsp->type = TAG_CONF;
	else
		return -EINVAL;

	return size;

}

size_t difc_label_change(struct file *file, const char __user *buf, 
				size_t size, loff_t *ppos, 
				struct task_security_struct *tsp, enum label_types ops) {
	char *data, *pos, *next_tag;
	int result;
	long int tag_content;
	struct list_head new_label;
	struct tag *new_tag;

	if (size >= PAGE_SIZE)
		size = PAGE_SIZE -1;

	result = -EINVAL;
	if (*ppos != 0)
		return result;

	result = -ENOMEM;
	data = kmalloc(size + 1, GFP_KERNEL);
	if (!data)
		return result;

	*(data + size) = '\0';
	
	INIT_LIST_HEAD(&new_label);
	result = -EFAULT;
	if (copy_from_user(data, buf, size))
		goto out;

	pos = data;	
	for(; pos; pos = next_tag) {
		next_tag = strchr(pos, ';');
		if (next_tag) {
			*next_tag = '\0';
			next_tag++;
			if (*next_tag == '\0')
				next_tag = NULL;
		}
		
		pos = skip_spaces(pos);
		tag_content = simple_strtoul(pos, &pos, 10);
		//printk(KERN_DEBUG "SYQ: ownership: %ld\n", tag_content);
		if (ops == OWNERSHIP_ADD) {
			result = add_ownership(tsp, tag_content);
			if (result < 0)
				goto out;	
		} 
		else if (ops == OWNERSHIP_DROP) {
			result = drop_ownership(tsp, tag_content);
			if (result < 0)
				goto out;	
		}
		else {
			new_tag = kmem_cache_alloc(tag_struct, GFP_NOFS);
			if (!new_tag) {
				result = -ENOMEM;
				goto out;
			}
			new_tag->content = tag_content;
			list_add_tail_rcu(&new_tag->next, &new_label);
		}

	}

	
	if (ops == SEC_LABEL || ops == INT_LABEL) {
		if (ops == SEC_LABEL) { 
			result = can_label_change(&tsp->slabel, &new_label, &tsp->olabel);
			if (result != 0) {
				clean_label(&new_label);
				printk(KERN_ALERT "SYQ: %s secrecy label (%s) denied\n", __func__, data);
				goto out;
			} else {
				change_label(&tsp->slabel, &new_label);
			}
		} else {
			result = can_label_change(&tsp->ilabel, &new_label, &tsp->olabel);
			if (result != 0) {
				clean_label(&new_label);
				printk(KERN_ALERT "SYQ: %s integrity label (%s) denied\n", __func__, data);
				goto out;
			} else {
				change_label(&tsp->ilabel, &new_label);
			}
		}
	}
	result = size;
out:
	list_del(&new_label);
	kfree(data);
	return result;
}
