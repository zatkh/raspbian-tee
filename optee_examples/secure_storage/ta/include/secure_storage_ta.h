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
#ifndef __SECURE_STORAGE_H__
#define __SECURE_STORAGE_H__

/* UUID of the trusted application */
#define TA_SECURE_STORAGE_UUID \
		{ 0xf4e750bb, 0x1437, 0x4fbf, \
			{ 0x87, 0x85, 0x8d, 0x35, 0x80, 0xc3, 0x49, 0x94 } }


#define TEEC_OPERATION_INITIALIZER	{ }

#define TA_STORAGE_CMD_OPEN			0
#define TA_STORAGE_CMD_CLOSE			1
#define TA_STORAGE_CMD_READ			2
#define TA_STORAGE_CMD_WRITE			3
#define TA_STORAGE_CMD_CREATE			4
#define TA_STORAGE_CMD_SEEK			5
#define TA_STORAGE_CMD_UNLINK			6
#define TA_STORAGE_CMD_RENAME			7
#define TA_STORAGE_CMD_TRUNC			8
#define TA_STORAGE_CMD_ALLOC_ENUM		9
#define TA_STORAGE_CMD_FREE_ENUM		10
#define TA_STORAGE_CMD_RESET_ENUM		11
#define TA_STORAGE_CMD_START_ENUM		12
#define TA_STORAGE_CMD_NEXT_ENUM		13
#define TA_STORAGE_CMD_CREATE_OVERWRITE		14
#define TA_STORAGE_CMD_KEY_IN_PERSISTENT	15
#define TA_STORAGE_CMD_LOOP			16
#define TA_STORAGE_CMD_RESTRICT_USAGE		17
#define TA_STORAGE_CMD_ALLOC_OBJ		18
#define TA_STORAGE_CMD_FREE_OBJ			19
#define TA_STORAGE_CMD_RESET_OBJ		20
#define TA_STORAGE_CMD_GET_OBJ_INFO		21
#define TA_STORAGE_CMD_OPEN_ID_IN_SHM		22
#define TA_STORAGE_CMD_CREATE_ID_IN_SHM		23
#define TA_STORAGE_CMD_CREATEOVER_ID_IN_SHM	24
#define TA_STORAGE_CMD_RENAME_ID_IN_SHM		25



/*
 * TA_SECURE_STORAGE_CMD_READ_RAW - Create and fill a secure storage file
 * param[0] (memref) ID used the identify the persistent object
 * param[1] (memref) Raw data dumped from the persistent object
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_STORAGE_CMD_READ_RAW		26

/*
 * TA_SECURE_STORAGE_CMD_WRITE_RAW - Create and fill a secure storage file
 * param[0] (memref) ID used the identify the persistent object
 * param[1] (memref) Raw data to be writen in the persistent object
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_STORAGE_CMD_WRITE_RAW		27

/*
 * TA_SECURE_STORAGE_CMD_DELETE - Delete a persistent object
 * param[0] (memref) ID used the identify the persistent object
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_STORAGE_CMD_DELETE		28


#define TA_HELLO_WORLD_UUID \
	{ 0x8aaaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

/* The function IDs implemented in this TA */
#define TA_HELLO_WORLD_CMD_INC_VALUE		0
#define TA_HELLO_WORLD_CMD_DEC_VALUE		1





#endif /* __SECURE_STORAGE_H__ */
