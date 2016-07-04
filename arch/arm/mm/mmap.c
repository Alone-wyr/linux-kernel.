/*
 *  linux/arch/arm/mm/mmap.c
 */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/shm.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <asm/cputype.h>
#include <asm/system.h>

#define COLOUR_ALIGN(addr,pgoff)		\
	((((addr)+SHMLBA-1)&~(SHMLBA-1)) +	\
	 (((pgoff)<<PAGE_SHIFT) & (SHMLBA-1)))

/*
 * We need to ensure that shared mappings are correctly aligned to
 * avoid aliasing issues with VIPT caches.  We need to ensure that
 * a specific page of an object is always mapped at a multiple of
 * SHMLBA bytes.
 *
 * We unconditionally provide this function for all cases, however
 * in the VIVT case, we optimise out the alignment rules.
 */
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr;
#ifdef CONFIG_CPU_V6
	unsigned int cache_type;
	int do_align = 0, aliasing = 0;

	/*
	 * We only need to do colour alignment if either the I or D
	 * caches alias.  This is indicated by bits 9 and 21 of the
	 * cache type register.
	 */
	cache_type = read_cpuid_cachetype();
	if (cache_type != read_cpuid_id()) {
		aliasing = (cache_type | cache_type >> 12) & (1 << 11);
		if (aliasing)
			do_align = filp || flags & MAP_SHARED;
	}
#else
#define do_align 0
#define aliasing 0
#endif

	/*
	 * We enforce the MAP_FIXED case.
	 */
	if (flags & MAP_FIXED) {
		if (aliasing && flags & MAP_SHARED && addr & (SHMLBA - 1))
			return -EINVAL;
		return addr;
	}

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (addr) {
		if (do_align)
			addr = COLOUR_ALIGN(addr, pgoff);
		else
			addr = PAGE_ALIGN(addr);
		//find_vma返回第一个end > addr的vma数据结构...
		vma = find_vma(mm, addr);
		// 前提的条件是，不能让addr + len 的虚拟地址超过了用户空间的界限，接着判断
		// 1.如果vma为NULL，但是不存在大于addr的vma。那么该addr就是可以使用的
		// 2.或者是，因为vma为第一个大于addr的vma，那么要判断addr + len <= vm_start。就是请求的区域
		//   不能覆盖到现存的vma。
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}
	//cached_hole_size记录着低于free_area_cache记录的分配的起始地址的最大洞
	//因此大于hole_size的时候就从最开始的地方开始查找，在达到free_area_cache的地址会得到那个hole的
	//如果是小于的话，那只能往下继续寻找了...free_area_cache记录上次分配的虚拟地址。
	if (len > mm->cached_hole_size) {
	        start_addr = addr = mm->free_area_cache;
	} else {
	        start_addr = addr = TASK_UNMAPPED_BASE;
	        mm->cached_hole_size = 0;
	}

full_search:
	if (do_align)
		addr = COLOUR_ALIGN(addr, pgoff);
	else
		addr = PAGE_ALIGN(addr);

	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (TASK_SIZE - len < addr) {
			//达到了用户空间的界限..
			/*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			//判断一下start_addr是不是从BASE开始，如果不是则从最BASE开始重新进行查找
			//如果是从BASE开始，那么就是找不到了合适的vma了。返回错误码ENOMEM。
			if (start_addr != TASK_UNMAPPED_BASE) {
				start_addr = addr = TASK_UNMAPPED_BASE;
				mm->cached_hole_size = 0;
				goto full_search;
			}
			return -ENOMEM;
		}
		//判断条件和前面描述过的一样....
		if (!vma || addr + len <= vma->vm_start) {
			/*
			 * Remember the place where we stopped the search:
			 */
			mm->free_area_cache = addr + len;
			return addr;
		}
		//遍历vma的过程中，保存下来最大的洞大小到字段cached_hole_size...
		if (addr + mm->cached_hole_size < vma->vm_start)
		        mm->cached_hole_size = vma->vm_start - addr;
		addr = vma->vm_end;
		if (do_align)
			addr = COLOUR_ALIGN(addr, pgoff);
	}
}


/*
 * You really shouldn't be using read() or write() on /dev/mem.  This
 * might go away in the future.
 */
int valid_phys_addr_range(unsigned long addr, size_t size)
{
	if (addr < PHYS_OFFSET)
		return 0;
	if (addr + size >= __pa(high_memory - 1))
		return 0;

	return 1;
}

/*
 * We don't use supersection mappings for mmap() on /dev/mem, which
 * means that we can't map the memory area above the 4G barrier into
 * userspace.
 */
int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
	return !(pfn + (size >> PAGE_SHIFT) > 0x00100000);
}
