// SPDX-License-Identifier: GPL-2.0
/*
 * Azure Sphere Linux Security Module
 *
 * Copyright (c) 2018 Microsoft Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */
#ifndef _SECURITY_AZURE_SPHERE_H
#define _SECURITY_AZURE_SPHERE_H
#include <linux/types.h>
#include <azure-sphere/security.h>

#ifdef CONFIG_EXTENDED_LSM
#include <linux/syscalls.h>	

extern const struct syscall_argdesc __start_syscalls_argdesc[];
extern const struct syscall_argdesc __stop_syscalls_argdesc[];


#endif /* CONFIG_EXTENDED_LSM */

#endif