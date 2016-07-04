/*
 *   linux/mm/fremap.c
 * 
 * Explicit pagetable population and nonlinear (random) mappings support.
 *
 * started by Ingo Molnar, Copyright (C) 2002, 2003
 */
#include <linux/backing-dev.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swapops.h>
#include <linux/rmap.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/mmu_notifier.h>

#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include "internal.h"
//清楚pte的内容，比如说需要非连续文件的映射..就会涉及到这个操作
//但是pte可能也有映射到某个物理页框..那么还需要释放掉它，比如下面调用到de
//page_remove_rmap... page_cache_release..
static void zap_pte(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long addr, pte_t *ptep)
{
	pte_t pte = *ptep;

	if (pte_present(pte)) {
		struct page *page;

		flush_cache_page(vma, addr, pte_pfn(pte));
		pte = ptep_clear_flush(vma, addr, ptep);
		page = vm_normal_page(vma, addr, pte);
		if (page) {
			if (pte_dirty(pte))
				set_page_dirty(page);
			//__mapcount..
			page_remove_rmap(page);
			//__count.
			page_cache_release(page);
			update_hiwater_rss(mm);
			dec_mm_counter(mm, file_rss);
		}
	} else {
		if (!pte_file(pte))
			free_swap_and_cache(pte_to_swp_entry(pte));
		pte_clear_not_present_full(mm, addr, ptep, 0);
	}
}

/*
 * Install a file pte to a given virtual memory address, release any
 * previously existing mapping.
 */
static int install_file_pte(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long addr, unsigned long pgoff, pgprot_t prot)
{
	int err = -ENOMEM;
	pte_t *pte;
	spinlock_t *ptl;

	pte = get_locked_pte(mm, addr, &ptl);
	if (!pte)
		goto out;
	//先清除涉及到的页表项。
	if (!pte_none(*pte))
		zap_pte(mm, vma, addr, pte);
	//pgoff_to_pte来设置一个新页表项。
	set_pte_at(mm, addr, pte, pgoff_to_pte(pgoff));
	/*
	 * We don't need to run update_mmu_cache() here because the "file pte"
	 * being installed by install_file_pte() is not a real pte - it's a
	 * non-present entry (like a swap entry), noting what file offset should
	 * be mapped there when there's a fault (in a non-linear vma where
	 * that's not obvious).
	 */
	pte_unmap_unlock(pte, ptl);
	err = 0;
out:
	return err;
}
//当前偏移量为pgoff，长度为size，将映射到addr指定的虚拟地址处。。。
static int populate_range(struct mm_struct *mm, struct vm_area_struct *vma,
			unsigned long addr, unsigned long size, pgoff_t pgoff)
{
	int err;

	do {
		err = install_file_pte(mm, vma, addr, pgoff, vma->vm_page_prot);
		if (err)
			return err;

		size -= PAGE_SIZE;
		addr += PAGE_SIZE;
		pgoff++;
	} while (size);

        return 0;

}

/**
 * sys_remap_file_pages - remap arbitrary pages of an existing VM_SHARED vma
 * @start: start of the remapped virtual memory range
 * @size: size of the remapped virtual memory range
 * @prot: new protection bits of the range (see NOTE)
 * @pgoff: to-be-mapped page of the backing store file
 * @flags: 0 or MAP_NONBLOCKED - the later will cause no IO.
 *
 * sys_remap_file_pages remaps arbitrary pages of an existing VM_SHARED vma
 * (shared backing store file).
 *
 * This syscall works purely via pagetables, so it's the most efficient
 * way to map the same (large) file into a given virtual window. Unlike
 * mmap()/mremap() it does not create any new vmas. The new mappings are
 * also safe across swapout.
 *
 * NOTE: the @prot parameter right now is ignored (but must be zero),
 * and the vma's default protection is used. Arbitrary protections
 * might be implemented in the future.
 */
SYSCALL_DEFINE5(remap_file_pages, unsigned long, start, unsigned long, size,
		unsigned long, prot, unsigned long, pgoff, unsigned long, flags)
{
	struct mm_struct *mm = current->mm;
	struct address_space *mapping;
	unsigned long end = start + size;
	struct vm_area_struct *vma;
	int err = -EINVAL;
	int has_write_lock = 0;

	if (prot)
		return err;
	/*
	 * Sanitize the syscall parameters:
	 */
	start = start & PAGE_MASK;
	size = size & PAGE_MASK;

	/* Does the address range wrap, or is the span zero-sized? */
	if (start + size <= start)
		return err;

	/* Can we represent this offset inside this architecture's pte's? */
#if PTE_FILE_MAX_BITS < BITS_PER_LONG
	if (pgoff + (size >> PAGE_SHIFT) >= (1UL << PTE_FILE_MAX_BITS))
		return err;
#endif

	/* We need down_write() to change vma->vm_flags. */
	down_read(&mm->mmap_sem);
 retry:
	vma = find_vma(mm, start);

	/*
	 * Make sure the vma is shared, that it supports prefaulting,
	 * and that the remapped range is valid and fully within
	 * the single existing vma.  vm_private_data is used as a
	 * swapout cursor in a VM_NONLINEAR vma.
	 */
	 //确定是VMA区是共享的。
	if (!vma || !(vma->vm_flags & VM_SHARED))
		goto out;

	if (vma->vm_private_data && !(vma->vm_flags & VM_NONLINEAR))
		goto out;

	if (!(vma->vm_flags & VM_CAN_NONLINEAR))
		goto out;
	//start和end在vma的这个线性区区间内。
	if (end <= start || start < vma->vm_start || end > vma->vm_end)
		goto out;

	/* Must set VM_NONLINEAR before any pages are populated. */
	//判断该VMA之前是不是进行过非线性的映射。
	if (!(vma->vm_flags & VM_NONLINEAR)) {
		/* Don't need a nonlinear mapping, exit success */
		if (pgoff == linear_page_index(vma, start)) {
			err = 0;
			goto out;
		}

		if (!has_write_lock) {
			up_read(&mm->mmap_sem);
			down_write(&mm->mmap_sem);
			has_write_lock = 1;
			goto retry;
		}
		mapping = vma->vm_file->f_mapping;
		/*
		 * page_mkclean doesn't work on nonlinear vmas, so if
		 * dirty pages need to be accounted, emulate with linear
		 * vmas.
		 */
		if (mapping_cap_account_dirty(mapping)) {
			unsigned long addr;
			struct file *file = vma->vm_file;

			flags &= MAP_NONBLOCK;
			get_file(file);
			addr = mmap_region(file, start, size,
					flags, vma->vm_flags, pgoff);
			fput(file);
			if (IS_ERR_VALUE(addr)) {
				err = addr;
			} else {
				BUG_ON(addr != start);
				err = 0;
			}
			goto out;
		}
		spin_lock(&mapping->i_mmap_lock);
		flush_dcache_mmap_lock(mapping);
		//设置该标记记录着该VMA线性区为非线性映射。
		vma->vm_flags |= VM_NONLINEAR;
		//从优先树上取下结点，对于非线性映射的VMA，不会在优先树上的。
		vma_prio_tree_remove(vma, &mapping->i_mmap);
		//VMA的vma->shared.vm_set.list字段作为结点添加到i_mmap_nonlinear链表上。
		vma_nonlinear_insert(vma, &mapping->i_mmap_nonlinear);
		flush_dcache_mmap_unlock(mapping);
		spin_unlock(&mapping->i_mmap_lock);
	}

	if (vma->vm_flags & VM_LOCKED) {
		/*
		 * drop PG_Mlocked flag for over-mapped range
		 */
		unsigned int saved_flags = vma->vm_flags;
		munlock_vma_pages_range(vma, start, start + size);
		vma->vm_flags = saved_flags;
	}

	mmu_notifier_invalidate_range_start(mm, start, start + size);
	//重点就是下面这个函数，进行设置页表项。
	err = populate_range(mm, vma, start, size, pgoff);
	mmu_notifier_invalidate_range_end(mm, start, start + size);
	//如果设置为非阻塞的，(MAP_NONBLOCK被清除的clear)那么需要对刚才非线性映射的区域所包含的页都调用缺页异常
	//来分配页框，读入数据.由函数make_pages_present来完成。
	if (!err && !(flags & MAP_NONBLOCK)) {
		if (vma->vm_flags & VM_LOCKED) {
			/*
			 * might be mapping previously unmapped range of file
			 */
			mlock_vma_pages_range(vma, start, start + size);
		} else {
			if (unlikely(has_write_lock)) {
				downgrade_write(&mm->mmap_sem);
				has_write_lock = 0;
			}
			make_pages_present(start, start+size);
		}
	}

	/*
	 * We can't clear VM_NONLINEAR because we'd have to do
	 * it after ->populate completes, and that would prevent
	 * downgrading the lock.  (Locks can't be upgraded).
	 */

out:
	if (likely(!has_write_lock))
		up_read(&mm->mmap_sem);
	else
		up_write(&mm->mmap_sem);

	return err;
}
