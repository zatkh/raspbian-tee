#include "difc_fl.h"


int get_process_label_native(pid_t pid) 
{

    struct seclabel_struct seclabel;
    seclabel.pid=pid;
    seclabel.secsize=(int*)malloc(sizeof(int));
    seclabel.secsize[0]=0;
    int fd = open("/dev/weir", O_RDWR);
    if(fd == -1)
    {
	    printf( "get_process_label cannot access /dev/weir\n");
    	return -1;
    }

    //Get the size
    int ret = ioctl(fd, WEIR_GET_PROC_SECLABEL, &seclabel);
    printf("get_process_label first ioctl succeeds for pid = %d, secsize=%d\n", seclabel.pid, seclabel.secsize[0]);

    if(seclabel.secsize[0]<=0){
	    close(fd);
	    return 0;
    }
    //get the actual label
    seclabel.sec = (tag_t*)malloc(sizeof(tag_t)*seclabel.secsize[0]);
    ret = ioctl(fd, WEIR_GET_PROC_SECLABEL, &seclabel);
    close(fd);


    if(seclabel.sec!=NULL)  free(seclabel.sec);
    if(seclabel.secsize!=NULL)  free(seclabel.secsize);
    return ret;
}


static void init_process_security_context_native(pid_t pid, uid_t uid, tag_t sec, tag_t pos, tag_t neg, int secsize, int possize, int negsize)
{
    struct process_sec_context psec;
    psec.pid = pid;
    psec.uid = uid;
    psec.secsize=0; psec.possize=0; psec.negsize=0;
    psec.sec=NULL; psec.pos=NULL; psec.neg=NULL;
    //Convert sec and assign to psec, if needed
    if(secsize>0){
	psec.secsize = secsize;
	psec.sec = (tag_t*) malloc(sizeof(tag_t) * secsize);
    }
    //Convert pos and assign to psec, if needed
    if(possize>0){
	psec.possize = possize;
	psec.pos = (tag_t*) malloc(sizeof(tag_t) * possize);
    }
    //Convert neg and assign to psec, if needed
    if(negsize>0){
	psec.negsize = negsize;
	psec.neg = (tag_t*) malloc(sizeof(tag_t) * negsize);
    }

    //ioctl
    int fd = open("/dev/weir", O_RDWR);
    if(fd == -1){
	    printf( "init_process_security_context cannot access /dev/weir\n");
    	return;
    }
    //__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "init_process_security_context ioctl /dev/weir before call.\n");
    int ret = ioctl(fd, WEIR_INIT_PROC_SEC_CONTEXT, &psec);
    printf( "init_process_security_context ioctl /dev/weir returned %d\n",ret);

    if(psec.sec!=NULL)	free(psec.sec);
    if(psec.pos!=NULL)	free(psec.pos);
    if(psec.neg!=NULL)	free(psec.neg);
    close(fd);
}

static void add_global_cap_native(long long tagvalue, int pos, int add)
{
    struct global_cap global;
    global.tag = tagvalue;
    global.pos = pos;
    global.add = add;

    int fd = open("/dev/weir", O_RDWR);
    int ret = ioctl(fd, WEIR_ADD_GLOBAL_CAP, &global);
    close(fd);
}

static void add_proc_cap_native(int pid, long long tagvalue, int pos, int add)
{
    struct process_cap proccap;
    proccap.pid = pid;
    proccap.tag = tagvalue;
    proccap.pos = pos;
    proccap.add = add;

    int fd = open("/dev/weir", O_RDWR);
    int ret = ioctl(fd, WEIR_ADD_PROCESS_CAP, &proccap);
    close(fd);

}

static void add_tag_to_label_native(int pid, long long tagvalue){
    struct add_tag_struct add_tag;
    add_tag.pid = pid;
    add_tag.tag = tagvalue;

    printf("add_tag. pid=%d, add_tag.pid=%d, tagvalue=%lld, add_tag.tag_value=%lld\n", pid, add_tag.pid, tagvalue, add_tag.tag);

    int fd = open("/dev/weir", O_RDWR);
    if(fd==-1){
	printf("add_tag_to_label_native cannot access /dev/weir\n");
    	return;
    }
    printf("add_tag_to_label ioctl /dev/weir before call. pid=%d, tagvalue=%lld\n", pid, tagvalue);
    int ret = ioctl(fd, WEIR_ADD_TAG_TO_LABEL, &add_tag);
    close(fd);
    printf("add_tag_to_label ioctl /dev/weir returned %d\n",ret);
}

void fl_test(void)
{
    pid_t pid= getpid();
    printf("[udom_test] pid %u \n",pid);
    get_process_label_native(pid);


}

