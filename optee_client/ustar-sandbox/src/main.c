#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <main.h>
#include <unistd.h>


#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

#define DIFC_LSM_ENABLED
#ifdef DIFC_LSM_ENABLED
#include "difc_api.h"
#include "difc_demos.h"
#include "defs.h"
#include "seccomp.h"
#endif

#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

static void usage(void)
{
    printf(
        "usage: \n\
        -s      : seccomp demo \n\
        -dd      : difc labeled dir demo \n\
        -df      : difc labeled file demo\n\
        -dm: difc labling memory domains\n\
        -ddcl: difc declassification memory domains\n\
        -uthrd: udom threading\n\
        -udom: udom tests\n");

}

int main(int argc, char *argv[])
{
    if (argc == 2) {
        
        if (strcmp(argv[1], "-s") == 0) {
            seccomp_sb_test();
        } else if (strcmp(argv[1], "-dd") == 0) {
           test_unallowed_mkdir();
        } else if (strcmp(argv[1], "-df") == 0) {
           test_unallowed_file();
        } else if (strcmp(argv[1], "-dm") == 0) {
            difc_threading_test_labeld();
        } else if (strcmp(argv[1], "-ddcl") == 0) {
            difc_labeled_domain_dcl();
        } else if (strcmp(argv[1], "-dcl") == 0) {
           test_declassification();
          } else if (strcmp(argv[1], "-dde") == 0) {
             test_difc_domain_entreis();
          } else if (strcmp(argv[1], "-def") == 0) {
              test_label_existing_file();
            }
        else if (strcmp(argv[1], "-uthrd") == 0) {
              difc_threading_test();
            }  
        else if (strcmp(argv[1], "-swu") == 0) {
            // sw_udom_test();
             //sw_udom_test2();
              swu_malloc();

            }


        else if (strcmp(argv[1], "-udom") == 0) {
               udom_test();    }

        else if (strcmp(argv[1], "-fl") == 0) {
               fl_test();    }    


        else {
            usage();
        }  
    } else {
        printf("which demo? \n");
        usage();
    }
}