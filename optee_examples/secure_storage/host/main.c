/*
 * Copyright (c) 2017, Linaro Limited
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

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <secure_storage_ta.h>
//#include <ta_storage.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>


#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <inttypes.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

FILE *fresult;
FILE *fs_results;
#define _1_SEC_TO_NS 1000000000


static unsigned long diff_time(struct timespec * op1, struct timespec * op2){
  return (op1->tv_sec - op2->tv_sec)*_1_SEC_TO_NS + op1->tv_nsec - op2->tv_nsec;
}

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};


static uint32_t storage_ids[] = {
	TEE_STORAGE_PRIVATE,
#ifdef CFG_REE_FS
	TEE_STORAGE_PRIVATE_REE,
#endif
#ifdef CFG_RPMB_FS
	TEE_STORAGE_PRIVATE_RPMB,
#endif
};



static uint8_t file_00[] = {
	0x00, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
	0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
	0xE9, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
	0xF0, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x8E
};

static uint8_t file_01[] = {
	0x01, 0x00
};

static uint8_t file_02[] = {
	0x02, 0x11, 0x02
};

static uint8_t file_03[] = {
	0x03, 0x13, 0x03
};

static uint8_t file_04[] = {
	0x00, 0x01, 0x02
};

static uint8_t data_00[] = {
	0x00, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
	0x00, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
	0x00, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
	0x00, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x00
};

static uint8_t data_01[] = {
	0x01, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
	0x01, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
	0x01, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
	0x01, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x01
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	uint32_t origin;
	TEEC_Result res;


	#ifndef ENABLE_TEE_DIFC


	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);


	#else 

		/* Initialize a context connecting us to the TEE */
	//res = TEEC_InitializeContext(NULL, &ctx->ctx);
	//if (res != TEEC_SUCCESS)
	//	errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = difc_create_enclave(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "difc_create_enclave failed with code 0x%x origin 0x%x",
			res, origin);

	printf("difc_create_enclave test\n");
	#endif	
}

void terminate_tee_session(struct test_ctx *ctx)
{	
	#ifndef ENABLE_TEE_DIFC

		TEEC_CloseSession(&ctx->sess);
		TEEC_FinalizeContext(&ctx->ctx);
	#else
		difc_cleanup_enclave(&ctx->sess);

		#endif	

}

TEEC_Result read_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_READ_RAW,
				 &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_SHORT_BUFFER:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result write_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_WRITE_RAW,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

	switch (res) {
	case TEEC_SUCCESS:
		break;
	default:
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result delete_secure_object(struct test_ctx *ctx, char *id)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_DELETE,
				 &op, &origin);

	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command DELETE failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

#define TEST_OBJECT_SIZE	7000

int hello_main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
	uint32_t err_origin;

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


	if (res != TEEC_SUCCESS)
		errx(1, "teec_difc_udom_create failed with code 0x%x origin 0x%x",
			res, err_origin);

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

static TEEC_Result fs_open(TEEC_Session *sess, void *id, uint32_t id_size,
			   uint32_t flags, uint32_t *obj, uint32_t storage_id)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t org = 0;

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;
	op.params[1].value.a = flags;
	op.params[1].value.b = 0;
	op.params[2].value.a = storage_id;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INOUT, TEEC_VALUE_INPUT,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_OPEN, &op, &org);

	if (res == TEEC_SUCCESS)
		*obj = op.params[1].value.b;

	return res;
}


static TEEC_Result fs_create(TEEC_Session *sess, void *id, uint32_t id_size,
			     uint32_t flags, uint32_t attr, void *data,
			     uint32_t data_size, uint32_t *obj,
			     uint32_t storage_id)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t org = 0;

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;
	op.params[1].value.a = flags;
	op.params[1].value.b = 0;
	op.params[2].value.a = attr;
	op.params[2].value.b = storage_id;
	op.params[3].tmpref.buffer = data;
	op.params[3].tmpref.size = data_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INOUT, TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_CREATE, &op, &org);

	if (res == TEEC_SUCCESS)
		*obj = op.params[1].value.b;

	return res;
}


static TEEC_Result fs_create_overwrite(TEEC_Session *sess, void *id,
				       uint32_t id_size, uint32_t storage_id)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t org = 0;

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;
	op.params[1].value.a = storage_id;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_CREATE_OVERWRITE, &op, &org);

	return res;
}

static TEEC_Result fs_close(TEEC_Session *sess, uint32_t obj)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].value.a = obj;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_CLOSE, &op, &org);
}

static TEEC_Result fs_read(TEEC_Session *sess, uint32_t obj, void *data,
			   uint32_t data_size, uint32_t *count)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].tmpref.buffer = data;
	op.params[0].tmpref.size = data_size;
	op.params[1].value.a = obj;
	op.params[1].value.b = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_READ, &op, &org);

	if (res == TEEC_SUCCESS)
		*count = op.params[1].value.b;

	return res;
}

static TEEC_Result fs_write(TEEC_Session *sess, uint32_t obj, void *data,
			    uint32_t data_size)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].tmpref.buffer = data;
	op.params[0].tmpref.size = data_size;
	op.params[1].value.a = obj;
	op.params[1].value.b = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_WRITE, &op, &org);
}

static TEEC_Result fs_seek(TEEC_Session *sess, uint32_t obj, int32_t offset,
			   int32_t whence)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].value.a = obj;
	op.params[0].value.b = *(uint32_t *)&offset;
	op.params[1].value.a = whence;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_SEEK, &op, &org);
}


static TEEC_Result fs_unlink(TEEC_Session *sess, uint32_t obj)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].value.a = obj;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_UNLINK, &op, &org);
}

static TEEC_Result fs_trunc(TEEC_Session *sess, uint32_t obj, uint32_t len)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].value.a = obj;
	op.params[0].value.b = len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_TRUNC, &op, &org);
}

static TEEC_Result fs_rename(TEEC_Session *sess, uint32_t obj, void *id,
			     uint32_t id_size)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].value.a = obj;
	op.params[1].tmpref.buffer = id;
	op.params[1].tmpref.size = id_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_RENAME, &op, &org);
}

static TEEC_Result fs_alloc_enum(TEEC_Session *sess, uint32_t *e)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_ALLOC_ENUM, &op, &org);

	if (res == TEEC_SUCCESS)
		*e = op.params[0].value.a;

	return res;
}

static TEEC_Result fs_reset_enum(TEEC_Session *sess, uint32_t e)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = e;
	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_RESET_ENUM, &op, &org);

	return res;
}

static TEEC_Result fs_free_enum(TEEC_Session *sess, uint32_t e)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	op.params[0].value.a = e;

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_FREE_ENUM, &op, &org);
}

static TEEC_Result fs_start_enum(TEEC_Session *sess, uint32_t e,
				 uint32_t storage_id)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = e;
	op.params[0].value.b = storage_id;

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_START_ENUM, &op, &org);
}

static TEEC_Result fs_next_enum(TEEC_Session *sess, uint32_t e, void *obj_info,
				size_t info_size, void *id, uint32_t id_size)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	if (obj_info && info_size)
		op.paramTypes |= (TEEC_MEMREF_TEMP_OUTPUT << 4);

	op.params[0].value.a = e;
	op.params[1].tmpref.buffer = obj_info;
	op.params[1].tmpref.size = info_size;
	op.params[2].tmpref.buffer = id;
	op.params[2].tmpref.size = id_size;

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_NEXT_ENUM, &op, &org);
}

static TEEC_Result fs_restrict_usage(TEEC_Session *sess, uint32_t obj,
				     uint32_t obj_usage)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].value.a = obj;
	op.params[0].value.b = obj_usage;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_RESTRICT_USAGE,
				  &op, &org);
}

static TEEC_Result fs_alloc_obj(TEEC_Session *sess, uint32_t obj_type,
				     uint32_t max_key_size, uint32_t *obj)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].value.a = obj_type;
	op.params[0].value.b = max_key_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_ALLOC_OBJ, &op, &org);
	*obj = op.params[1].value.a;
	return res;
}

static TEEC_Result fs_free_obj(TEEC_Session *sess, uint32_t obj)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].value.a = obj;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_FREE_OBJ, &op, &org);
}

static TEEC_Result fs_reset_obj(TEEC_Session *sess, uint32_t obj)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.params[0].value.a = obj;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_RESET_OBJ, &op, &org);
}

static TEEC_Result fs_get_obj_info(TEEC_Session *sess, uint32_t obj,
				void *obj_info, size_t info_size)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					TEEC_MEMREF_TEMP_OUTPUT,
					TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = obj;
	op.params[1].tmpref.buffer = obj_info;
	op.params[1].tmpref.size = info_size;

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_GET_OBJ_INFO, &op, &org);
}

int ___main(void)
{
	//struct test_ctx ctx;
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	uint32_t origin;

	uint32_t orig = 0;
	uint32_t obj = 0;
	uint32_t o2 = 0;
	uint32_t e = 0;
	uint32_t f = 0;
	uint8_t data[1024] = { };
	char out[1024] = { };
	uint32_t n = 0;
		uint32_t count = 0;

	char buf[13]="hellomyfriend";

	printf("Prepare session with the TA\n");

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);




	//prepare_tee_session(&ctx);



	obj = 0;
	f = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
	    TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_SHARE_READ |
	    TEE_DATA_FLAG_SHARE_WRITE | TEE_DATA_FLAG_OVERWRITE;
	if ( fs_create(&sess, file_00, sizeof(file_00), f, 0, data,
			  sizeof(data), &obj, storage_ids[0]) !=TEEC_SUCCESS)
		printf("fs create faild\n");

			if (fs_close(&sess, obj)!=TEEC_SUCCESS)
					printf("fs close faild\n");

		if ( fs_open(&sess, file_00, sizeof(file_00),
			TEE_DATA_FLAG_ACCESS_WRITE, &obj, storage_ids[0]) !=TEEC_SUCCESS )
					printf("fs open faild\n");


	if (fs_write(&sess, obj, buf, sizeof(buf))!=TEEC_SUCCESS)
					printf("fs write faild\n");

	if (fs_close(&sess, obj)!=TEEC_SUCCESS)
					printf("fs close faild\n");



	/* verify */
		res=fs_open(&sess, file_00, sizeof(file_00),
			TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_ids[0]);
		if (res != TEEC_SUCCESS)
			printf("fs open faild\n");

	res=fs_read(&sess, obj, out, sizeof(buf), &count);
		if (res != TEEC_SUCCESS)
			printf("fs_read faild\n");

	if(memcmp( buf, out, count) !=0)
		printf("fs_read not match\n");

printf("read out: %s\n",out);
	/* clean */
	res=fs_unlink(&sess, obj);
		if (res != TEEC_SUCCESS)
			printf("fs_unlink faild\n");



	printf("\nWe're done, close and release TEE resources\n");
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
	//terminate_tee_session(&ctx);
	return 0;
}


int tfs_test(size_t ITERATION)
{
	//struct test_ctx ctx;
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	uint32_t origin;

	uint32_t orig = 0;
	uint32_t obj = 0;
	uint32_t o2 = 0;
	uint32_t e = 0;
	uint32_t f = 0;
	uint8_t data[1024] = { };
	char out[1024] = { };
	uint32_t n = 0;
		uint32_t count = 0;
	unsigned long diff = 0;
    struct timespec init_second, current_time;
    struct timespec * init_secondp = &init_second, \
                        * current_timep = &current_time;
					 

	char buf[13]="hellomyfriend";

	printf("Prepare session with the TA\n");

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);




	//prepare_tee_session(&ctx);



	obj = 0;
	f = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
	    TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_SHARE_READ |
	    TEE_DATA_FLAG_SHARE_WRITE | TEE_DATA_FLAG_OVERWRITE;
	if ( fs_create(&sess, file_00, sizeof(file_00), f, 0, data,
			  sizeof(data), &obj, storage_ids[0]) !=TEEC_SUCCESS)
		printf("fs create faild\n");

	if (fs_close(&sess, obj)!=TEEC_SUCCESS)
					printf("fs close faild\n");

	for(int i=0;i<ITERATION;i++)
	{	
		clock_gettime(CLOCK_MONOTONIC_RAW, init_secondp);
	if ( fs_open(&sess, file_00, sizeof(file_00),
			TEE_DATA_FLAG_ACCESS_WRITE, &obj, storage_ids[0]) !=TEEC_SUCCESS ){return 0;}
		clock_gettime(CLOCK_MONOTONIC_RAW, current_timep);
		diff = diff_time(current_timep, init_secondp);	
		printf("fs open: %ld\n",(unsigned long)(diff/ITERATION));

clock_gettime(CLOCK_MONOTONIC_RAW, init_secondp);
	if (fs_write(&sess, obj, buf, sizeof(buf))!=TEEC_SUCCESS){return 0;}
			clock_gettime(CLOCK_MONOTONIC_RAW, current_timep);
		diff = diff_time(current_timep, init_secondp);	
		printf("fs write: %ld\n",(unsigned long)(diff/ITERATION));


clock_gettime(CLOCK_MONOTONIC_RAW, init_secondp);
	if (fs_close(&sess, obj)!=TEEC_SUCCESS) {return 0;}
				clock_gettime(CLOCK_MONOTONIC_RAW, current_timep);
		diff = diff_time(current_timep, init_secondp);	
		printf("fs close: %ld\n",(unsigned long)(diff/ITERATION));



clock_gettime(CLOCK_MONOTONIC_RAW, init_secondp);
		res=fs_open(&sess, file_00, sizeof(file_00),
			TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_ids[0]);
clock_gettime(CLOCK_MONOTONIC_RAW, current_timep);
		diff = diff_time(current_timep, init_secondp);	
		printf("fs open: %ld\n",(unsigned long)(diff/ITERATION));

		if (res != TEEC_SUCCESS)
			printf("fs open faild\n");

clock_gettime(CLOCK_MONOTONIC_RAW, init_secondp);
	res=fs_read(&sess, obj, out, sizeof(buf), &count);
clock_gettime(CLOCK_MONOTONIC_RAW, current_timep);
		diff = diff_time(current_timep, init_secondp);	
printf("fs read: %ld\n",(unsigned long)(diff/ITERATION));

		if (res != TEEC_SUCCESS)
			printf("fs_read faild\n");

	if(memcmp( buf, out, count) !=0)
		printf("fs_read not match\n");
clock_gettime(CLOCK_MONOTONIC_RAW, init_secondp);		
	if (fs_close(&sess, obj)!=TEEC_SUCCESS){return 0;}
clock_gettime(CLOCK_MONOTONIC_RAW, current_timep);
		diff = diff_time(current_timep, init_secondp);	
printf("fs read: %ld\n",(unsigned long)(diff/ITERATION));	

printf("read out: %s\n",out);

	}
	/* clean */
//	res=fs_unlink(&sess, obj);
//		if (res != TEEC_SUCCESS)
//			printf("fs_unlink faild\n");



	printf("\nWe're done, close and release TEE resources\n");
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
	//terminate_tee_session(&ctx);
	return 0;
}


int main(int argc, char *argv[])
{
     if (strcmp(argv[1], "-tfs") == 0) {
          		tfs_test(atoi(argv[2]));
        } 



	
	
	

}
