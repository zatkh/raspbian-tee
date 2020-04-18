/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <hello_world_ta.h>
/* Registers the TEEC_SharedMemory to the TEE. */
static TEEC_Result RegisterSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm, size_t size,
					uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	return TEEC_RegisterSharedMemory(ctx, shm);
}

/* Allocates shared memory inside of the TEE. */
static TEEC_Result AllocateSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm, size_t size,
					uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	return TEEC_AllocateSharedMemory(ctx, shm);
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
	static TEEC_SharedMemory shm1;
	static TEEC_SharedMemory shm2;
	size_t shm_len = 1024 * 1024;
	size_t membloc_len=0;

	uint32_t err_origin;
	char * memblk=NULL;
	  struct timespec start,end;
    long sub=0,sum1=0,avg1=0,sum2=0,avg2=0,sum3=0,sum4=0,sum5=0;
	

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);



	
	memset(&shm1, 0, sizeof(shm1));
	memset(&shm2, 0, sizeof(shm2));	

	shm1.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shm2.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;	
	shm1.size=shm_len;
	shm2.size=shm_len;
	membloc_len=32;


/************teec****************/
//clock_gettime(CLOCK_MONOTONIC_RAW,&start);
//	res=TEEC_RegisterSharedMemory(&ctx, &shm2);
//clock_gettime(CLOCK_MONOTONIC_RAW,&end);

//	if (res != TEEC_SUCCESS)
//		errx(1, "TEEC_AllocateSharedMemory failed with code 0x%x origin 0x%x",
//			res, err_origin);

	shm2.size=membloc_len;
clock_gettime(CLOCK_MONOTONIC_RAW,&start);
	res=TEEC_AllocateSharedMemory(&ctx, &shm2);
clock_gettime(CLOCK_MONOTONIC_RAW,&end);
sub = ( end.tv_nsec )-(start.tv_nsec );
printf("TEEC_AllocateSharedMemory: %ld\n",sub);
sum1 +=sub;

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_AllocateSharedMemory failed with code 0x%x origin 0x%x",
			res, err_origin);

clock_gettime(CLOCK_MONOTONIC_RAW,&start);
	TEEC_ReleaseSharedMemory(&shm2);
clock_gettime(CLOCK_MONOTONIC_RAW,&end);
sub = ( end.tv_nsec )-(start.tv_nsec );
printf("TEEC_ReleaseSharedMemory: %ld\n",sub);
sum2 +=sub;

/************ustar****************/
	res=teec_difc_udom_create(&ctx, &shm1);

	if (res != TEEC_SUCCESS)
		errx(1, "teec_difc_udom_create failed with code 0x%x origin 0x%x",
			res, err_origin);



clock_gettime(CLOCK_MONOTONIC_RAW,&start);
	memblk= (char*)teec_difc_alloc(&ctx, &shm1,membloc_len);
clock_gettime(CLOCK_MONOTONIC_RAW,&end);
sub = ( end.tv_nsec )-(start.tv_nsec );
printf("udom_test malloc: %ld\n",sub);
sum3 +=sub;

	if (memblk == NULL)
		errx(1, "teec_difc_malloc failed with code 0x%x origin 0x%x",
			res, err_origin);

clock_gettime(CLOCK_MONOTONIC_RAW,&start);
  	teec_difc_free(memblk);
clock_gettime(CLOCK_MONOTONIC_RAW,&end);
sub = ( end.tv_nsec )-(start.tv_nsec );
printf("udom_test free: %ld\n",sub);
sum4 +=sub;



	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 42;

	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
	printf("Invoking TA to increment %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CMD_INC_VALUE, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("TA incremented value to %d\n", op.params[0].value.a);

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
