/*********************************************************************

    File          : weir_netlink.c
    Author(s)     : Adwait Nadkarni <apnadkar@ncsu.edu>
    Description   : description

    Last Modified : %+
    By            : Adwait Nadkarni <apnadkar@ncsu.edu>

    Copyright (c) 2015 North Carolina State University

**********************************************************************/
#include "include/weir_netlink.h"

DEFINE_MUTEX(sync_netlink_mutex);
//Global variables for the netlink socket
static struct sock *nl_sk = NULL;
static int uspace_pid=-1;
static int seq;
char data_string[] = "Hello User!This is a message from kernel!\0";
static bool socket_initialized = false;

//Defining ASM upcall synchronization variables
wait_queue_head_t upcall_queue[MAX_KTHREADS];
int upcall_result[MAX_KTHREADS];

//Send a message to userspace
int send_to_uspace(char* msg)
{    
        u8 * payload = NULL;
        int length=MAX_PAYLOAD;
        struct sk_buff* rskb;
        struct nlmsghdr* nlh;
        int error=0;
        int reply=0;
        int init_reply=0;
        int jiffies;
        //printk("asm_iface.c: send_to_uspace(): %s\n", msg);
        if(nl_sk==NULL)
        {   
                //printk("\n UNINITIALIZED SOCK \n");
                return 0;
        }   

        rskb=alloc_skb( MAX_PAYLOAD, GFP_KERNEL);
        skb_put( rskb, length );
        rskb->sk=nl_sk;
        nlh = (struct nlmsghdr *) rskb->data;
        nlh->nlmsg_len = length;
        nlh->nlmsg_pid = uspace_pid;
        nlh->nlmsg_flags = 0;
        nlh->nlmsg_type = 2;
        nlh->nlmsg_seq   = seq++;
        payload = NLMSG_DATA( nlh );
 
        //printk("\nknetlink_process: reply nlmsg len %d type %d pid %d seq %d\n",nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_pid, nlh->nlmsg_seq);
        strlcpy(payload, msg,nlh->nlmsg_len);
        *(payload + strlen(msg)) = '\0';
       // NETLINK_CB(rskb).pid = 0; //from kernel //ztodo
        NETLINK_CB(rskb).dst_group= 0;  // unicast 
        //printk("Message to be sent=%s\n", (char*)(NLMSG_DATA(nlh)));

        //reset the result before going in.
        upcall_result[current->pid]=0;
        init_waitqueue_head (&upcall_queue[current->pid]);

        //send the netlink message
        error=netlink_unicast( nl_sk, rskb, uspace_pid, MSG_DONTWAIT );
        //printk("Error while sending unicast msg:%d\n",error);
    
        //wait for the reply
        jiffies=wait_event_timeout(upcall_queue[current->pid], ((init_reply=upcall_result[current->pid])>0), HZ);
        //get the result.
        reply = upcall_result[current->pid];
        //printk("Reply for %ld=%d,%d , saved %d ms\n", (long)current->pid, reply, init_reply, (jiffies * 1000 / HZ));
        if(reply==WEIR_MGR_ALLOW)
                reply=0;
        else
                reply=-1;//either uninitialized or WEIR_MGR_DENY, default DENY
        //reset the result again.
        upcall_result[current->pid]=0;
        return reply;
}

//Processes data received via the socket (only for the initial request)
int knetlink_initialize( struct sk_buff * skb, struct nlmsghdr *nlh )
{
        u8 * payload = NULL;
        int   payload_size;
        int   length;
        //int   seq;
        pid_t pid;
        char buffer_with_pid[256];

        pid = nlh->nlmsg_pid;
        uspace_pid=pid;
        length = nlh->nlmsg_len;
        seq = nlh->nlmsg_seq;
        //printk("\nknetlink_process: nlmsg len %d type %d pid %d seq %d\n",length, nlh->nlmsg_type, pid, seq );

        payload_size = nlh->nlmsg_len - NLMSG_LENGTH(0);
        if ( payload_size > 0 ) {
                payload = NLMSG_DATA(nlh);
                //printk("\nknetlink_process: Payload is %s ", payload);
        }

        snprintf(buffer_with_pid, 256, "%ld;%s", (long)(current->pid), data_string);
        //send_to_uspace(buffer_with_pid);

        return 0;
}

// Receives the initial message from the userspace daemon
static void nl_receive_initial(struct sk_buff *skb)
{       struct nlmsghdr *nlh = NULL;
        nlh = (struct nlmsghdr *)skb->data;
        if(!socket_initialized){
                mutex_lock(&sync_netlink_mutex);
                if(skb == NULL) {
                        //printk("skb is NULL \n");
                        return ;
                }
                knetlink_initialize(skb,nlh);
        //      printk("\n Call to knetlink process done\n");
                socket_initialized=true;
                mutex_unlock(&sync_netlink_mutex);
        }
        else{
                int reply;
                long int pid_to_complete;//replace with actual tid from message
                sscanf(NLMSG_DATA(nlh), "%ld;%d", &pid_to_complete, &reply);
                //Process the reply
                //Get the data from the message, probably the first byte, 0/1
                //the second byte contains the tid sent with the request.
                upcall_result[pid_to_complete]=reply;
                if(&upcall_queue[pid_to_complete]!=NULL)
                        wake_up(&upcall_queue[pid_to_complete]);
                //printk("%ld:: Reply for %ld=%d\n",(long)current->pid, pid_to_complete,reply);
        }
}

int kernel_socket_create()
{
//      printk("Call to netlink_kernel_create");

	struct netlink_kernel_cfg cfg = {
		.input	= nl_receive_initial,
	
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_HELLO, &cfg);
	if (nl_sk == NULL)
		panic("FL_LSM:  Cannot create netlink socket.");
	return 0;

       // nl_sk = netlink_kernel_create(&init_net,NETLINK_HELLO,0, nl_receive_initial,NULL, THIS_MODULE);

        return 0;
}
