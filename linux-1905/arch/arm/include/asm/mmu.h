/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM_MMU_H
#define __ARM_MMU_H

#ifdef CONFIG_MMU

typedef struct {
#ifdef CONFIG_CPU_HAS_ASID
	atomic64_t	id;
#else
	int		switch_pending;
#endif
	unsigned int	vmalloc_seq;
	unsigned long	sigpage;
#ifdef CONFIG_VDSO
	unsigned long	vdso;
#endif
#ifdef CONFIG_BINFMT_ELF_FDPIC
	unsigned long	exec_fdpic_loadmap;
	unsigned long	interp_fdpic_loadmap;
#endif

#ifdef CONFIG_EXTENDED_LSM_DIFC

	/*
	 * Each bit represents one protection key.
	 * bit set   -> key allocated
	 * bit unset -> key available for allocation
	 */
	u32 udom_allocation_map;
	s16 execute_only_udom; /* udom holding execute-only protection */
	s16 read_only_udom ; /* udom holding read-only protection */
	s16 write_only_udom ; /* udom holding write-only protection */
	
#endif

} mm_context_t;

#ifdef CONFIG_CPU_HAS_ASID
#define ASID_BITS	8
#define ASID_MASK	((~0ULL) << ASID_BITS)
#define ASID(mm)	((unsigned int)((mm)->context.id.counter & ~ASID_MASK))
#else
#define ASID(mm)	(0)
#endif

#else

/*
 * From nommu.h:
 *  Copyright (C) 2002, David McCullough <davidm@snapgear.com>
 *  modified for 2.6 by Hyok S. Choi <hyok.choi@samsung.com>
 */
typedef struct {
	unsigned long	end_brk;
#ifdef CONFIG_BINFMT_ELF_FDPIC
	unsigned long	exec_fdpic_loadmap;
	unsigned long	interp_fdpic_loadmap;
#endif
} mm_context_t;

#endif

#endif
