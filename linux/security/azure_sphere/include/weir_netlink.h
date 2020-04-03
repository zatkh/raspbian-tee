/*********************************************************************

    File          : weir_netlink.h
    Author(s)     : Adwait Nadkarni <apnadkar@ncsu.edu>
    Description   : description

    Last Modified : %+
    By            : Adwait Nadkarni <apnadkar@ncsu.edu>

    Copyright (c) 2015 North Carolina State University

**********************************************************************/

#ifndef _SECURITY_WEIR_NETLINK_H
#define _SECURITY_WEIR_NETLINK_H
#include <linux/completion.h>
#include <linux/param.h>
#include <linux/wait.h>
#include <linux/time.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/skbuff.h>

/*Synchronous Upcall*/
//Weir Manager Allow and deny 
#define MAX_KTHREADS 29200
#define WEIR_MGR_ALLOW 0
#define WEIR_MGR_DENY 1
extern wait_queue_head_t upcall_queue[MAX_KTHREADS];
extern int upcall_result[MAX_KTHREADS];

/* Netlink Message specifics */
#define NETLINK_HELLO 17
#define MAX_PAYLOAD 2048
#define MAX_DATA_BUFFER 900

extern int send_to_uspace(char* msg);
extern int kernel_socket_create(void);

#endif /* _SECURITY_WEIR_NETLINK_H */
