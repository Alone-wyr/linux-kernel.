/*
 *  linux/arch/arm/mm/pgd.c
 *
 *  Copyright (C) 1998-2005 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/mm.h>
#include <linux/highmem.h>

#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/tlbflush.h>

#include "mm.h"

#define FIRST_KERNEL_PGD_NR	(FIRST_USER_PGD_NR + USER_PTRS_PER_PGD)

/*
 * need to get a 16k page for level 1
 */
pgd_t *get_pgd_slow(struct mm_struct *mm)
{
	pgd_t *new_pgd, *init_pgd;
	pmd_t *new_pmd, *init_pmd;
	pte_t *new_pte, *init_pte;

	new_pgd = (pgd_t *)__get_free_pages(GFP_KERNEL, 2);
	if (!new_pgd)
		goto no_pgd;

	memset(new_pgd, 0, FIRST_KERNEL_PGD_NR * sizeof(pgd_t));

	/*
	 * Copy over the kernel and IO PGD entries
	 */
	//#define pgd_offset_k(addr)	pgd_offset(&init_mm, addr)
	//其实就是要拷贝内核空间的页表项...
	init_pgd = pgd_offset_k(0);
	//拷贝内核空间的pgd表项到新创建的pgd表项
	memcpy(new_pgd + FIRST_KERNEL_PGD_NR, init_pgd + FIRST_KERNEL_PGD_NR,
		       (PTRS_PER_PGD - FIRST_KERNEL_PGD_NR) * sizeof(pgd_t));
	//把Dcache行的数据写回到主存，并清除cache行的脏标记.
	//参数:主存的物理地址,(确定cache行) 需要写回的长度...
	clean_dcache_area(new_pgd, PTRS_PER_PGD * sizeof(pgd_t));
	
	//异常向量表是在高端地址或是在低端地址...
	if (!vectors_high()) {
		 //如果是在低端地址.那么异常向量表在第一页..
		/*
		 * On ARM, first page must always be allocated since it
		 * contains the machine vectors.
		 */
		//该函数是在new_pgd指定的PGD页表上找到地址0对应的表项，然后分配一个页.
		//接着填充PGD的页表项(PMD).
		//哦，好像略过了PUD了、对于ARM来说PMD也是直接返回pgd.
		new_pmd = pmd_alloc(mm, new_pgd, 0);
		if (!new_pmd)
			goto no_pmd;
		//如果为空则分配一个页面，然后设置PGD的页表项.
		new_pte = pte_alloc_map(mm, new_pmd, 0);
		if (!new_pte)
			goto no_pte;
		//init_pgd就是init进程的页表,这里得到地址0的PGD页表的表项(PMD)
		init_pmd = pmd_offset(init_pgd, 0);
		//根据init_pmd，得到了PMD页表，然后根据0地址得到了PMD的表项(PTE)
		init_pte = pte_offset_map_nested(init_pmd, 0);
		//new_pte指定了要存放PTE的地址，init_pte就是PTE的值。
		set_pte_ext(new_pte, *init_pte, 0);
		pte_unmap_nested(init_pte);
		pte_unmap(new_pte);
	}

	return new_pgd;

no_pte:
	pmd_free(mm, new_pmd);
no_pmd:
	free_pages((unsigned long)new_pgd, 2);
no_pgd:
	return NULL;
}

void free_pgd_slow(struct mm_struct *mm, pgd_t *pgd)
{
	pmd_t *pmd;
	pgtable_t pte;

	if (!pgd)
		return;

	/* pgd is always present and good */
	pmd = pmd_off(pgd, 0);
	if (pmd_none(*pmd))
		goto free;
	if (pmd_bad(*pmd)) {
		pmd_ERROR(*pmd);
		pmd_clear(pmd);
		goto free;
	}

	pte = pmd_pgtable(*pmd);
	pmd_clear(pmd);
	pte_free(mm, pte);
	pmd_free(mm, pmd);
free:
	free_pages((unsigned long) pgd, 2);
}
