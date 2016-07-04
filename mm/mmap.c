/*
 * mm/mmap.c
 *
 * Written by obz.
 *
 * Address space accounting code	<alan@lxorguk.ukuu.org.uk>
 */

#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/mm.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/ima.h>
#include <linux/hugetlb.h>
#include <linux/profile.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>

#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlb.h>
#include <asm/mmu_context.h>

#include "internal.h"

#ifndef arch_mmap_check
#define arch_mmap_check(addr, len, flags)	(0)
#endif

#ifndef arch_rebalance_pgtables
#define arch_rebalance_pgtables(addr, len)		(addr)
#endif

static void unmap_region(struct mm_struct *mm,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		unsigned long start, unsigned long end);

/*
 * WARNING: the debugging will use recursive algorithms so never enable this
 * unless you know what you are doing.
 */
#undef DEBUG_MM_RB

/* description of effects of mapping type and prot in current implementation.
 * this is due to the limited x86 page protection hardware.  The expected
 * behavior is in parens:
 *
 * map_type	prot
 *		PROT_NONE	PROT_READ	PROT_WRITE	PROT_EXEC
 * MAP_SHARED	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (yes) yes	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *		
 * MAP_PRIVATE	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (copy) copy	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *
 */
pgprot_t protection_map[16] = {
	__P000, __P001, __P010, __P011, __P100, __P101, __P110, __P111,
	__S000, __S001, __S010, __S011, __S100, __S101, __S110, __S111
};

pgprot_t vm_get_page_prot(unsigned long vm_flags)
{
	return __pgprot(pgprot_val(protection_map[vm_flags &
				(VM_READ|VM_WRITE|VM_EXEC|VM_SHARED)]) |
			pgprot_val(arch_vm_get_page_prot(vm_flags)));
}
EXPORT_SYMBOL(vm_get_page_prot);

int sysctl_overcommit_memory = OVERCOMMIT_GUESS;  /* heuristic overcommit */
int sysctl_overcommit_ratio = 50;	/* default is 50% */
int sysctl_max_map_count __read_mostly = DEFAULT_MAX_MAP_COUNT;
struct percpu_counter vm_committed_as;

/*
 * Check that a process has enough memory to allocate a new virtual
 * mapping. 0 means there is enough memory for the allocation to
 * succeed and -ENOMEM implies there is not.
 *
 * We currently support three overcommit policies, which are set via the
 * vm.overcommit_memory sysctl.  See Documentation/vm/overcommit-accounting
 *
 * Strict overcommit modes added 2002 Feb 26 by Alan Cox.
 * Additional code 2002 Jul 20 by Robert Love.
 *
 * cap_sys_admin is 1 if the process has admin privileges, 0 otherwise.
 *
 * Note this is a helper function intended to be used by LSMs which
 * wish to use this logic.
 */
int __vm_enough_memory(struct mm_struct *mm, long pages, int cap_sys_admin)
{
	unsigned long free, allowed;

	vm_acct_memory(pages);

	/*
	 * Sometimes we want to use more memory than we have
	 */
	if (sysctl_overcommit_memory == OVERCOMMIT_ALWAYS)
		return 0;

	if (sysctl_overcommit_memory == OVERCOMMIT_GUESS) {
		unsigned long n;

		free = global_page_state(NR_FILE_PAGES);
		free += nr_swap_pages;

		/*
		 * Any slabs which are created with the
		 * SLAB_RECLAIM_ACCOUNT flag claim to have contents
		 * which are reclaimable, under pressure.  The dentry
		 * cache and most inode caches should fall into this
		 */
		free += global_page_state(NR_SLAB_RECLAIMABLE);

		/*
		 * Leave the last 3% for root
		 */
		if (!cap_sys_admin)
			free -= free / 32;

		if (free > pages)
			return 0;

		/*
		 * nr_free_pages() is very expensive on large systems,
		 * only call if we're about to fail.
		 */
		n = nr_free_pages();

		/*
		 * Leave reserved pages. The pages are not for anonymous pages.
		 */
		if (n <= totalreserve_pages)
			goto error;
		else
			n -= totalreserve_pages;

		/*
		 * Leave the last 3% for root
		 */
		if (!cap_sys_admin)
			n -= n / 32;
		free += n;

		if (free > pages)
			return 0;

		goto error;
	}

	allowed = (totalram_pages - hugetlb_total_pages())
	       	* sysctl_overcommit_ratio / 100;
	/*
	 * Leave the last 3% for root
	 */
	if (!cap_sys_admin)
		allowed -= allowed / 32;
	allowed += total_swap_pages;

	/* Don't let a single process grow too big:
	   leave 3% of the size of this process for other processes */
	if (mm)
		allowed -= mm->total_vm / 32;

	if (percpu_counter_read_positive(&vm_committed_as) < allowed)
		return 0;
error:
	vm_unacct_memory(pages);

	return -ENOMEM;
}

/*
 * Requires inode->i_mapping->i_mmap_lock
 */
static void __remove_shared_vm_struct(struct vm_area_struct *vma,
		struct file *file, struct address_space *mapping)
{
	if (vma->vm_flags & VM_DENYWRITE)
		atomic_inc(&file->f_path.dentry->d_inode->i_writecount);
	//字段 i_mmap_writable /* count VM_SHARED mappings */
	if (vma->vm_flags & VM_SHARED)
		mapping->i_mmap_writable--;

	flush_dcache_mmap_lock(mapping);
	if (unlikely(vma->vm_flags & VM_NONLINEAR))
		list_del_init(&vma->shared.vm_set.list);
	else
		vma_prio_tree_remove(vma, &mapping->i_mmap);
	flush_dcache_mmap_unlock(mapping);
}

/*
 * Unlink a file-based vm structure from its prio_tree, to hide
 * vma from rmap and vmtruncate before freeing its page tables.
 */
void unlink_file_vma(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;

	if (file) {
		struct address_space *mapping = file->f_mapping;
		spin_lock(&mapping->i_mmap_lock);
		__remove_shared_vm_struct(vma, file, mapping);
		spin_unlock(&mapping->i_mmap_lock);
	}
}

/*
 * Close a vm structure and free it, returning the next.
 */
static struct vm_area_struct *remove_vma(struct vm_area_struct *vma)
{
	struct vm_area_struct *next = vma->vm_next;

	might_sleep();
	if (vma->vm_ops && vma->vm_ops->close)
		vma->vm_ops->close(vma);
	if (vma->vm_file) {
		fput(vma->vm_file);
		if (vma->vm_flags & VM_EXECUTABLE)
			removed_exe_file_vma(vma->vm_mm);
	}
	mpol_put(vma_policy(vma));
	kmem_cache_free(vm_area_cachep, vma);
	return next;
}

SYSCALL_DEFINE1(brk, unsigned long, brk)
{
	unsigned long rlim, retval;
	unsigned long newbrk, oldbrk;
	struct mm_struct *mm = current->mm;
	unsigned long min_brk;

	down_write(&mm->mmap_sem);

#ifdef CONFIG_COMPAT_BRK
	min_brk = mm->end_code;
#else
	min_brk = mm->start_brk;
#endif
	if (brk < min_brk)
		goto out;

	/*
	 * Check against rlimit here. If this check is done later after the test
	 * of oldbrk with newbrk then it can escape the test and let the data
	 * segment grow beyond its set limit the in case where the limit is
	 * not page aligned -Ram Gupta
	 */
	rlim = current->signal->rlim[RLIMIT_DATA].rlim_cur;
	if (rlim < RLIM_INFINITY && (brk - mm->start_brk) +
			(mm->end_data - mm->start_data) > rlim)
		goto out;

	newbrk = PAGE_ALIGN(brk);
	oldbrk = PAGE_ALIGN(mm->brk);
	if (oldbrk == newbrk)
		goto set_brk;

	/* Always allow shrinking brk. */
	if (brk <= mm->brk) {
		if (!do_munmap(mm, newbrk, oldbrk-newbrk))
			goto set_brk;
		goto out;
	}
	//检查oldbrk - newbrk + PAGE_SIZE和当前的线性地址区间是不是会有覆盖。
	//返回NULL代表没有覆盖。
	/* Check against existing mmap mappings. */
	if (find_vma_intersection(mm, oldbrk, newbrk+PAGE_SIZE))
		goto out;
	//在没有覆盖的情况下，才去执行do_brk操作。
	/* Ok, looks good - let it rip. */
	if (do_brk(oldbrk, newbrk-oldbrk) != oldbrk)
		goto out;
set_brk:
	mm->brk = brk;
out:
	retval = mm->brk;
	up_write(&mm->mmap_sem);
	return retval;
}

#ifdef DEBUG_MM_RB
static int browse_rb(struct rb_root *root)
{
	int i = 0, j;
	struct rb_node *nd, *pn = NULL;
	unsigned long prev = 0, pend = 0;

	for (nd = rb_first(root); nd; nd = rb_next(nd)) {
		struct vm_area_struct *vma;
		vma = rb_entry(nd, struct vm_area_struct, vm_rb);
		if (vma->vm_start < prev)
			printk("vm_start %lx prev %lx\n", vma->vm_start, prev), i = -1;
		if (vma->vm_start < pend)
			printk("vm_start %lx pend %lx\n", vma->vm_start, pend);
		if (vma->vm_start > vma->vm_end)
			printk("vm_end %lx < vm_start %lx\n", vma->vm_end, vma->vm_start);
		i++;
		pn = nd;
		prev = vma->vm_start;
		pend = vma->vm_end;
	}
	j = 0;
	for (nd = pn; nd; nd = rb_prev(nd)) {
		j++;
	}
	if (i != j)
		printk("backwards %d, forwards %d\n", j, i), i = 0;
	return i;
}

void validate_mm(struct mm_struct *mm)
{
	int bug = 0;
	int i = 0;
	struct vm_area_struct *tmp = mm->mmap;
	while (tmp) {
		tmp = tmp->vm_next;
		i++;
	}
	if (i != mm->map_count)
		printk("map_count %d vm_next %d\n", mm->map_count, i), bug = 1;
	i = browse_rb(&mm->mm_rb);
	if (i != mm->map_count)
		printk("map_count %d rb %d\n", mm->map_count, i), bug = 1;
	BUG_ON(bug);
}
#else
#define validate_mm(mm) do { } while (0)
#endif

static struct vm_area_struct *
find_vma_prepare(struct mm_struct *mm, unsigned long addr,
		struct vm_area_struct **pprev, struct rb_node ***rb_link,
		struct rb_node ** rb_parent)
{
	struct vm_area_struct * vma;
	struct rb_node ** __rb_link, * __rb_parent, * rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;
	vma = NULL;

	//下面这个while循环和find_vma几乎一样，只是添加了一个rb_prev来记录上一个vma
	//因此跳出while循环的时候，vma指向的是第一个vm_end大于addr的vma。
	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			vma = vma_tmp;
			if (vma_tmp->vm_start <= addr)
				break;
			__rb_link = &__rb_parent->rb_left;
		} else {
			//rb_prev记录上一个..如果跳出了循环那rb_prev就是vma的前一个。。
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	//如果rb_prev不是NULL，那么就是上一个，保存到参数pprev
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
//通过分析知道了，返回的__rb_parent都是一个叶子结点.
//而__rb_link的值为__rb_parent的结点对应的left或right字段的地址。
//假设要插入一个A的话，直接 *__rb_link = A. A->parent = __rb_parent;
//一个红黑结点有4个地址，至少有自身数据结构的地址,left字段的地址，right字段地址，还有parent地址(不过这里不去考虑)
//假设数据结构地址a, right地址b, left地址c。然后返回的__rb_parent = a, __rb_link = b(right).
//返回的话，那么该结点就是叶子结点。 A->parent = rb_parent , 这样指向了上一级的结点了
//                                   *__rb_link = A，这样就添加到了结点的right那边了.
	return vma;
}

static inline void
__vma_link_list(struct mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *prev, struct rb_node *rb_parent)
{
	if (prev) {
		//如果存在前面一个那么就直接插入...典型的链表插入动作。
		vma->vm_next = prev->vm_next;
		prev->vm_next = vma;
	} else {
		//如果没有前一个，那么就需要作为mmap字段的第一个结点...
		mm->mmap = vma;
		//如果没有parent，那就是当前的红黑树只有它一个叶子(也就是第一个vma数据结构啦.
		//否则的话，它的下一个就是parent指定的vma结点。
		if (rb_parent)
			vma->vm_next = rb_entry(rb_parent,
					struct vm_area_struct, vm_rb);
		else
			vma->vm_next = NULL;
	}
}

void __vma_link_rb(struct mm_struct *mm, struct vm_area_struct *vma,
		struct rb_node **rb_link, struct rb_node *rb_parent)
{
	rb_link_node(&vma->vm_rb, rb_parent, rb_link);
	rb_insert_color(&vma->vm_rb, &mm->mm_rb);
}

static void __vma_link_file(struct vm_area_struct *vma)
{
	struct file *file;

	file = vma->vm_file;
	if (file) {
		struct address_space *mapping = file->f_mapping;

		if (vma->vm_flags & VM_DENYWRITE)
			atomic_dec(&file->f_path.dentry->d_inode->i_writecount);
		if (vma->vm_flags & VM_SHARED)
			mapping->i_mmap_writable++;

		flush_dcache_mmap_lock(mapping);
		//作为非线性文件映射则让vma->shared.vm_set.list添加到mapping->i_mmap_nonlinear链表中
		//且vma->shared.vm_set.parent = NULL;设置为NULL。
		if (unlikely(vma->vm_flags & VM_NONLINEAR))
			vma_nonlinear_insert(vma, &mapping->i_mmap_nonlinear);
		else
			vma_prio_tree_insert(vma, &mapping->i_mmap);
		flush_dcache_mmap_unlock(mapping);
	}
}

static void
__vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, struct rb_node **rb_link,
	struct rb_node *rb_parent)
{
// 1.添加到链表
	__vma_link_list(mm, vma, prev, rb_parent);
// 2.添加到红黑树.
	__vma_link_rb(mm, vma, rb_link, rb_parent);
	__anon_vma_link(vma);
}

static void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
			struct vm_area_struct *prev, struct rb_node **rb_link,
			struct rb_node *rb_parent)
{
	struct address_space *mapping = NULL;

	if (vma->vm_file)
		mapping = vma->vm_file->f_mapping;

	if (mapping) {
		spin_lock(&mapping->i_mmap_lock);
		vma->vm_truncate_count = mapping->truncate_count;
	}
	anon_vma_lock(vma);

	__vma_link(mm, vma, prev, rb_link, rb_parent);
	__vma_link_file(vma);

	anon_vma_unlock(vma);
	if (mapping)
		spin_unlock(&mapping->i_mmap_lock);

	mm->map_count++;
	validate_mm(mm);
}

/*
 * Helper for vma_adjust in the split_vma insert case:
 * insert vm structure into list and rbtree and anon_vma,
 * but it has already been inserted into prio_tree earlier.
 */
static void __insert_vm_struct(struct mm_struct *mm, struct vm_area_struct *vma)
{
	struct vm_area_struct *__vma, *prev;
	struct rb_node **rb_link, *rb_parent;

	__vma = find_vma_prepare(mm, vma->vm_start,&prev, &rb_link, &rb_parent);
	BUG_ON(__vma && __vma->vm_start < vma->vm_end);
	__vma_link(mm, vma, prev, rb_link, rb_parent);
	mm->map_count++;
}

static inline void
__vma_unlink(struct mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *prev)
{
//该函数是删除线性区vma...

// 现在的操作是从链表上删除，很容易理解。
	prev->vm_next = vma->vm_next;
//从红黑树上删除。。
	rb_erase(&vma->vm_rb, &mm->mm_rb);
//如果删除的vma正好是mmap_cache指向的，那就指向prev。。。
	if (mm->mmap_cache == vma)
		mm->mmap_cache = prev;
}

/*
 * We cannot adjust vm_start, vm_end, vm_pgoff fields of a vma that
 * is already present in an i_mmap tree without adjusting the tree.
 * The following helper function should be used when such adjustments
 * are necessary.  The "insert" vma (if any) is to be inserted
 * before we drop the necessary locks.
 */
void vma_adjust(struct vm_area_struct *vma, unsigned long start,
	unsigned long end, pgoff_t pgoff, struct vm_area_struct *insert)
{
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *next = vma->vm_next;
	struct vm_area_struct *importer = NULL;
	struct address_space *mapping = NULL;
	struct prio_tree_root *root = NULL;
	struct file *file = vma->vm_file;
	struct anon_vma *anon_vma = NULL;
	long adjust_next = 0;
	int remove_next = 0;

	if (next && !insert) {
		if (end >= next->vm_end) {
			//到这里，那么至少是要remove掉一个VMA的。
			//就看end到底能够覆盖掉多少个VMA了。
			/*
			 * vma expands, overlapping all the next, and
			 * perhaps the one after too (mprotect case 6).
			 */
			 //查看移除的VMA个数...
			 //对于case 1来说 remove_next = 1.
			 //    case 6来说 remove_next = 2.
			 //判断标记end > next->vm_end很重要.
			 //如果是大于，那么就是完全覆盖，超过end。那么还不确定到底end覆盖掉多少个VMA，也许下一个也覆盖
			 //如果是小于等于，那么就是等于1，代表只有这个next指定的VMA需要释放掉。
again:			remove_next = 1 + (end > next->vm_end);
			end = next->vm_end;
			anon_vma = next->anon_vma;
			importer = vma;
		} else if (end > next->vm_start) {
			//而这里，代表的是需要remove掉一个就好了。
			/*
			 * vma expands, overlapping part of the next:
			 * mprotect case 5 shifting the boundary up.
			 */
			adjust_next = (end - next->vm_start) >> PAGE_SHIFT;
			anon_vma = next->anon_vma;
			importer = vma;
		} else if (end < vma->vm_end) {
			//这里是说，VMA收缩了。。。。
			/*
			 * vma shrinks, and !insert tells it's not
			 * split_vma inserting another: so it must be
			 * mprotect case 4 shifting the boundary down.
			 */
	/*这里非常奇怪...参考vma_merge函数里面说到的那个例子。[1 - 5) [10 - 20) 插入[3 - 10)
	那么vma 指向区域[1-5], start = 1, end = 3.
	vma->vm_end = 5 > 3，因此进入到这个if语句里面来了。
	计算adjust_next = - (5 - 3) = -2..
	在后面会调整下一个 next->start += adjust_next....那就是next->start = 10 + (-2) = 8.
	实际上next->start应该等于3的。区间为[3 - 20)
	*/
			adjust_next = - ((vma->vm_end - end) >> PAGE_SHIFT);
			anon_vma = next->anon_vma;
			importer = next;
		}
		//还有一种情况就是, end < next->start。。那就只需要要扩展vma的线性区大小就好。
		//不需要涉及到其他VMA的remove。
		//如果是这种情况直接往下走。。
	}

	if (file) {
		mapping = file->f_mapping;
		if (!(vma->vm_flags & VM_NONLINEAR))
			root = &mapping->i_mmap;
		spin_lock(&mapping->i_mmap_lock);
		if (importer &&
		    vma->vm_truncate_count != next->vm_truncate_count) {
			/*
			 * unmap_mapping_range might be in progress:
			 * ensure that the expanding vma is rescanned.
			 */
			importer->vm_truncate_count = 0;
		}
		if (insert) {
			insert->vm_truncate_count = vma->vm_truncate_count;
			/*
			 * Put into prio_tree now, so instantiated pages
			 * are visible to arm/parisc __flush_dcache_page
			 * throughout; but we cannot insert into address
			 * space until vma start or end is updated.
			 */
			__vma_link_file(insert);
		}
	}

	/*
	 * When changing only vma->vm_end, we don't really need
	 * anon_vma lock: but is that case worth optimizing out?
	 */
	if (vma->anon_vma)
		anon_vma = vma->anon_vma;
	if (anon_vma) {
		spin_lock(&anon_vma->lock);
		/*
		 * Easily overlooked: when mprotect shifts the boundary,
		 * make sure the expanding vma has anon_vma set if the
		 * shrinking vma had, to cover any anon pages imported.
		 */
		if (importer && !importer->anon_vma) {
			importer->anon_vma = anon_vma;
			__anon_vma_link(importer);
		}
	}
	//root对于文件映射来说。
	if (root) {
		flush_dcache_mmap_lock(mapping);
		vma_prio_tree_remove(vma, root);
		if (adjust_next)
			vma_prio_tree_remove(next, root);
	}

	vma->vm_start = start;
	vma->vm_end = end;
	vma->vm_pgoff = pgoff;
	if (adjust_next) {
		//因为是覆盖掉了VMA的部分，那么另外部分是被合并了。
		//那么就需要修改start和pgoff字段了。
		next->vm_start += adjust_next << PAGE_SHIFT;
		next->vm_pgoff += adjust_next;
	}

	if (root) {
		if (adjust_next)
			vma_prio_tree_insert(next, root);
		vma_prio_tree_insert(vma, root);
		flush_dcache_mmap_unlock(mapping);
	}

	if (remove_next) {
		/*
		 * vma_merge has merged next into vma, and needs
		 * us to remove next before dropping the locks.
		 */
		 //把next从链表和红黑树中remove掉。
		__vma_unlink(mm, next, vma);
		if (file)
			__remove_shared_vm_struct(next, file, mapping);
		if (next->anon_vma)
			__anon_vma_merge(vma, next);
	} else if (insert) {
		/*
		 * split_vma has split insert from vma, and needs
		 * us to insert it before dropping the locks
		 * (it may either follow vma or precede it).
		 */
		__insert_vm_struct(mm, insert);
	}

	if (anon_vma)
		spin_unlock(&anon_vma->lock);
	if (mapping)
		spin_unlock(&mapping->i_mmap_lock);

	if (remove_next) {
		if (file) {
			fput(file);
			if (next->vm_flags & VM_EXECUTABLE)
				removed_exe_file_vma(mm);
		}
		//前面remove掉了next了，当前的VMA数目少了一个。
		mm->map_count--;
		//释放VMA数据结构占据的内存。
		mpol_put(vma_policy(next));
		kmem_cache_free(vm_area_cachep, next);
		/*
		 * In mprotect's case 6 (see comments on vma_merge),
		 * we must remove another next too. It would clutter
		 * up the code too much to do both in one go.
		 */
		if (remove_next == 2) {
			//代表需要释放的不仅仅一个VMA，现在next只想了下一个...然后重复前面的动作
			//在释放掉已经覆盖的VMA。
			//意思就是start-end的区间覆盖了多个VMA。因此需要释放掉多个VMA。
			next = vma->vm_next;
			goto again;
		}
	}

	validate_mm(mm);
}

/* Flags that can be inherited from an existing mapping when merging */
#define VM_MERGEABLE_FLAGS (VM_CAN_NONLINEAR)

/*
 * If the vma has a ->close operation then the driver probably needs to release
 * per-vma resources, so we don't attempt to merge those.
 */
 //VMA合并调用的函数:
 //这里进行判断标记，然后如果是映射文件，在判断是不是同个文件。
 //	就算是匿名映射，进行也判断标记，然后在比较文件，当然都是NULL咯。
static inline int is_mergeable_vma(struct vm_area_struct *vma,
			struct file *file, unsigned long vm_flags)
{
// 判断两个vma 的flash 是否相同
	if ((vma->vm_flags ^ vm_flags) & ~VM_MERGEABLE_FLAGS)
		return 0;
//判断是不是同一个映射文件
	if (vma->vm_file != file)
		return 0;
//有解释, 如果vma有close的操作,那么驱动很可能要释放
//了这个vma了,所以我们不需要合并了。
	if (vma->vm_ops && vma->vm_ops->close)
		return 0;
	return 1;
}
//VMA合并调用的函数:
//这里进行判断是不是同一个匿名映射....匿名映射还需要在多了解一下。。。这里简单略过。。
//返回0的情况，应该是确定两个annon_vma不相等，且不为NULL。
//只要有一个不为NULL，就代表其中一个不是匿名映射，那么就该返回1.让上面那个函数去判断是不是相同的file。
static inline int is_mergeable_anon_vma(struct anon_vma *anon_vma1,
					struct anon_vma *anon_vma2)
{
	return !anon_vma1 || !anon_vma2 || (anon_vma1 == anon_vma2);
}

/*
 * Return true if we can merge this (vm_flags,anon_vma,file,vm_pgoff)
 * in front of (at a lower virtual address and file offset than) the vma.
 *
 * We cannot merge two vmas if they have differently assigned (non-NULL)
 * anon_vmas, nor if same anon_vma is assigned but offsets incompatible.
 *
 * We don't check here for the merged mmap wrapping around the end of pagecache
 * indices (16TB on ia32) because do_mmap_pgoff() does not permit mmap's which
 * wrap, nor mmaps which cover the final page at index -1UL.
 */
static int
can_vma_merge_before(struct vm_area_struct *vma, unsigned long vm_flags,
	struct anon_vma *anon_vma, struct file *file, pgoff_t vm_pgoff)
{
	if (is_mergeable_vma(vma, file, vm_flags) &&
	    is_mergeable_anon_vma(anon_vma, vma->anon_vma)) {
		if (vma->vm_pgoff == vm_pgoff)
			return 1;
	}
	return 0;
}

/*
 * Return true if we can merge this (vm_flags,anon_vma,file,vm_pgoff)
 * beyond (at a higher virtual address and file offset than) the vma.
 *
 * We cannot merge two vmas if they have differently assigned (non-NULL)
 * anon_vmas, nor if same anon_vma is assigned but offsets incompatible.
 */
static int
can_vma_merge_after(struct vm_area_struct *vma, unsigned long vm_flags,
	struct anon_vma *anon_vma, struct file *file, pgoff_t vm_pgoff)
{
	if (is_mergeable_vma(vma, file, vm_flags) &&
	    is_mergeable_anon_vma(anon_vma, vma->anon_vma)) {
		pgoff_t vm_pglen;
		vm_pglen = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
		//映射的文件在文件内部是否连续的.
		//如果为匿名映射，vm_pgoff参数在do_mmap_pgoff函数设置了addr>>PAGE_SHIFT..
		if (vma->vm_pgoff + vm_pglen == vm_pgoff)
			return 1;
	}
	return 0;
}

/*
 * Given a mapping request (addr,end,vm_flags,file,pgoff), figure out
 * whether that can be merged with its predecessor or its successor.
 * Or both (it neatly fills a hole).
 *
 * In most cases - when called for mmap, brk or mremap - [addr,end) is
 * certain not to be mapped by the time vma_merge is called; but when
 * called for mprotect, it is certain to be already mapped (either at
 * an offset within prev, or at the start of next), and the flags of
 * this area are about to be changed to vm_flags - and the no-change
 * case has already been eliminated.
 *
 * The following mprotect cases have to be considered, where AAAA is
 * the area passed down from mprotect_fixup, never extending beyond one
 * vma, PPPPPP is the prev vma specified, and NNNNNN the next vma after:
 *
 *     AAAA             AAAA                AAAA          AAAA
 *    PPPPPPNNNNNN    PPPPPPNNNNNN    PPPPPPNNNNNN    PPPPNNNNXXXX
 *    cannot merge    might become    might become    might become
 *                    PPNNNNNNNNNN    PPPPPPPPPPNN    PPPPPPPPPPPP 6 or
 *    mmap, brk or    case 4 below    case 5 below    PPPPPPPPXXXX 7 or
 *    mremap move:                                    PPPPNNNNNNNN 8
 *        AAAA
 *    PPPP    NNNN    PPPPPPPPPPPP    PPPPPPPPNNNN    PPPPNNNNNNNN
 *    might become    case 1 below    case 2 below    case 3 below
 *
 * Odd one out? Case 8, because it extends NNNN but needs flags of XXXX:
 * mprotect_fixup updates vm_flags & vm_page_prot on successful return.
 */
struct vm_area_struct *vma_merge(struct mm_struct *mm,
			struct vm_area_struct *prev, unsigned long addr,
			unsigned long end, unsigned long vm_flags,
		     	struct anon_vma *anon_vma, struct file *file,
			pgoff_t pgoff, struct mempolicy *policy)
{
	pgoff_t pglen = (end - addr) >> PAGE_SHIFT;
	struct vm_area_struct *area, *next;

	/*
	 * We later require that vma->vm_flags == vm_flags,
	 * so this tests vma->vm_flags & VM_SPECIAL, too.
	 */
//设置了该标记，代表不能和其他区域合并.
	if (vm_flags & VM_SPECIAL)
		return NULL;
//prev为空的时候, next就是第一个vma.
	if (prev)
		next = prev->vm_next;
	else
		next = mm->mmap;
	area = next;
//next的end 和要添加的end一样，那么next 就再次指向下一个.
//挺奇怪的，这样不就是代表有区间重合了嘛???
//从do_mmap函数看过来的,start - end区间是不会和现存的线性区重叠的。待确定吧。
	if (next && next->vm_end == end)		/* cases 6, 7, 8 */
		next = next->vm_next;

	/*	是否可以和前一个VMA合并。
	 * Can it merge with the predecessor?
	 */
	if (prev && prev->vm_end == addr &&
  			mpol_equal(vma_policy(prev), policy) &&
			can_vma_merge_after(prev, vm_flags,
						anon_vma, file, pgoff)) {
		/*
		 * OK, it can.  Can we now merge in the successor as well?
		 */
//case 1, 6:next的start和要添加的end重叠.
//case 2, 5, 7: 不重叠.

//貌似有点问题，当end == next->vm_start的时候是需要考虑和合并的VMA的标记等
//但是当end > next->vm_start的时候，在vma_adjust会把next这个VMA的next->start-end之间的区域
//进行合并的。但是好像并没有检测它的标记等信息。。。
		if (next && end == next->vm_start &&
				mpol_equal(policy, vma_policy(next)) &&
				can_vma_merge_before(next, vm_flags,
					anon_vma, file, pgoff+pglen) &&
				is_mergeable_anon_vma(prev->anon_vma,
						      next->anon_vma)) {
							/* cases 1, 6 */
			vma_adjust(prev, prev->vm_start,
				next->vm_end, prev->vm_pgoff, NULL);
		} else					/* cases 2, 5, 7 */ 
			vma_adjust(prev, prev->vm_start,
				end, prev->vm_pgoff, NULL);
		return prev;
	}

	/*	是否可以和后一个VMA合并。
	 * Can this new request be merged in front of next?
	 */
	if (next && end == next->vm_start &&
 			mpol_equal(policy, vma_policy(next)) &&
			can_vma_merge_before(next, vm_flags,
					anon_vma, file, pgoff+pglen)) {
		//prev->vm_end > addr的话，就是已经覆盖到了前一个VMA了。
		//这里也挺奇怪的,case 4，进去vma_adjust之后，调整了prev之后
		//对next的调整好像也不对。。
		//比如 prev: [1 - 5] next(area):[10 - 20] 要添加 [3 - 10)
		//那需要调整第一个为[1 - 3) 然后第二个为[3 - 20)
		//但是分析代码之后，只会设置[1-3) 对后面设置为[3 - 20)好像对不对。。
		//具体进入到vma_adjust函数里面查看...
		if (prev && addr < prev->vm_end)	/* case 4 */
			vma_adjust(prev, prev->vm_start,
				addr, prev->vm_pgoff, NULL);
		else					/* cases 3, 8 */
			vma_adjust(area, addr, next->vm_end,
				next->vm_pgoff - pglen, NULL);
		return area;
	}

	return NULL;
}

/*
该函数由anon_vma_prepare来调用，用来检查附近的vma是否有合适的anon_vma，在该函数进行
分配一个新的anon_vma之前。
 * find_mergeable_anon_vma is used by anon_vma_prepare, to check
 * neighbouring vmas for a suitable anon_vma, before it goes off
 * to allocate a new anon_vma.  It checks because a repetitive
 * sequence of mprotects and faults may otherwise lead to distinct
 * anon_vmas being allocated, preventing vma merge in subsequent
 * mprotect.
 */
struct anon_vma *find_mergeable_anon_vma(struct vm_area_struct *vma)
{
	struct vm_area_struct *near;
	unsigned long vm_flags;

	near = vma->vm_next;
	if (!near)
		goto try_prev;

	/*
	 * Since only mprotect tries to remerge vmas, match flags
	 * which might be mprotected into each other later on.
	 * Neither mlock nor madvise tries to remerge at present,
	 * so leave their flags as obstructing a merge.
	 */
	vm_flags = vma->vm_flags & ~(VM_READ|VM_WRITE|VM_EXEC);
	vm_flags |= near->vm_flags & (VM_READ|VM_WRITE|VM_EXEC);

	if (near->anon_vma && vma->vm_end == near->vm_start &&
 			mpol_equal(vma_policy(vma), vma_policy(near)) &&
			can_vma_merge_before(near, vm_flags,
				NULL, vma->vm_file, vma->vm_pgoff +
				((vma->vm_end - vma->vm_start) >> PAGE_SHIFT)))
		return near->anon_vma;
try_prev:
	/*
	 * It is potentially slow to have to call find_vma_prev here.
	 * But it's only on the first write fault on the vma, not
	 * every time, and we could devise a way to avoid it later
	 * (e.g. stash info in next's anon_vma_node when assigning
	 * an anon_vma, or when trying vma_merge).  Another time.
	 */
	BUG_ON(find_vma_prev(vma->vm_mm, vma->vm_start, &near) != vma);
	if (!near)
		goto none;

	vm_flags = vma->vm_flags & ~(VM_READ|VM_WRITE|VM_EXEC);
	vm_flags |= near->vm_flags & (VM_READ|VM_WRITE|VM_EXEC);

	if (near->anon_vma && near->vm_end == vma->vm_start &&
  			mpol_equal(vma_policy(near), vma_policy(vma)) &&
			can_vma_merge_after(near, vm_flags,
				NULL, vma->vm_file, vma->vm_pgoff))
		return near->anon_vma;
none:
	/*
	 * There's no absolute need to look only at touching neighbours:
	 * we could search further afield for "compatible" anon_vmas.
	 * But it would probably just be a waste of time searching,
	 * or lead to too many vmas hanging off the same anon_vma.
	 * We're trying to allow mprotect remerging later on,
	 * not trying to minimize memory used for anon_vmas.
	 */
	return NULL;
}

#ifdef CONFIG_PROC_FS
void vm_stat_account(struct mm_struct *mm, unsigned long flags,
						struct file *file, long pages)
{
	const unsigned long stack_flags
		= VM_STACK_FLAGS & (VM_GROWSUP|VM_GROWSDOWN);

	if (file) {
		mm->shared_vm += pages;
		if ((flags & (VM_EXEC|VM_WRITE)) == VM_EXEC)
			mm->exec_vm += pages;
	} else if (flags & stack_flags)
		mm->stack_vm += pages;
	if (flags & (VM_RESERVED|VM_IO))
		mm->reserved_vm += pages;
}
#endif /* CONFIG_PROC_FS */

/*
 * The caller must hold down_write(current->mm->mmap_sem).
 */

unsigned long do_mmap_pgoff(struct file *file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, unsigned long pgoff)
{
	struct mm_struct * mm = current->mm;
	struct inode *inode;
	unsigned int vm_flags;
	int error;
	unsigned long reqprot = prot;

	/*
	 * Does the application expect PROT_READ to imply PROT_EXEC?
	 *
	 * (the exception is when the underlying filesystem is noexec
	 *  mounted, in which case we dont add PROT_EXEC.)
	 */
	if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
		if (!(file && (file->f_path.mnt->mnt_flags & MNT_NOEXEC)))
			prot |= PROT_EXEC;
	//映射长度不应该为0.
	if (!len)
		return -EINVAL;
	//MAP_FIXED宏就是映射区间必须由addr参数指定。
	if (!(flags & MAP_FIXED))
		addr = round_hint_to_min(addr);

	error = arch_mmap_check(addr, len, flags);
	if (error)
		return error;

	//len不为0，len也不应该超过TASK_SIZE的大下。
	/* Careful about overflows.. */
	len = PAGE_ALIGN(len);
	if (!len || len > TASK_SIZE)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
               return -EOVERFLOW;
	//map_count记录一个进程的VMA数目。
	/* Too many mappings? */
	if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	/* Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
	addr = get_unmapped_area(file, addr, len, pgoff, flags);
//如果不是页对齐的,,那么返回的addr 代表的就是错误码了
//直接返回错误码给调用者.
	if (addr & ~PAGE_MASK)
		return addr;

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
	vm_flags = calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags) |
			mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

	if (flags & MAP_LOCKED) {
		if (!can_do_mlock())
			return -EPERM;
		vm_flags |= VM_LOCKED;
	}
	//一个进程可以lock的页面是有限制的，检测是否超过了限制。
	/* mlock MCL_FUTURE? */
	if (vm_flags & VM_LOCKED) {
		unsigned long locked, lock_limit;
		locked = len >> PAGE_SHIFT;
		locked += mm->locked_vm;
		lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
		lock_limit >>= PAGE_SHIFT;
		if (locked > lock_limit && !capable(CAP_IPC_LOCK))
			return -EAGAIN;
	}
	//映射的可能是文件，也可能是匿名映射。
	inode = file ? file->f_path.dentry->d_inode : NULL;

	if (file) {
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			if ((prot&PROT_WRITE) && !(file->f_mode&FMODE_WRITE))
				return -EACCES;

			/*
			 * Make sure we don't allow writing to an append-only
			 * file..
			 */
			if (IS_APPEND(inode) && (file->f_mode & FMODE_WRITE))
				return -EACCES;

			/*
			 * Make sure there are no mandatory locks on the file.
			 */
			if (locks_verify_locked(inode))
				return -EAGAIN;

			vm_flags |= VM_SHARED | VM_MAYSHARE;
			if (!(file->f_mode & FMODE_WRITE))
				vm_flags &= ~(VM_MAYWRITE | VM_SHARED);

			/* fall through */
		case MAP_PRIVATE:
			if (!(file->f_mode & FMODE_READ))
				return -EACCES;
			if (file->f_path.mnt->mnt_flags & MNT_NOEXEC) {
				if (vm_flags & VM_EXEC)
					return -EPERM;
				vm_flags &= ~VM_MAYEXEC;
			}

			if (!file->f_op || !file->f_op->mmap)
				return -ENODEV;
			break;

		default:
			return -EINVAL;
		}
	} else {
			//匿名映射...
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			/*
			 * Ignore pgoff.
			 */
			pgoff = 0;
			vm_flags |= VM_SHARED | VM_MAYSHARE;
			break;
		case MAP_PRIVATE:
			/*
			 * Set pgoff according to addr for anon_vma.
			 */
			pgoff = addr >> PAGE_SHIFT;
			break;
		default:
			return -EINVAL;
		}
	}

	error = security_file_mmap(file, reqprot, prot, flags, addr, 0);
	if (error)
		return error;
	error = ima_file_mmap(file, prot);
	if (error)
		return error;

	return mmap_region(file, addr, len, flags, vm_flags, pgoff);
}
EXPORT_SYMBOL(do_mmap_pgoff);

/*
 * Some shared mappigns will want the pages marked read-only
 * to track write events. If so, we'll downgrade vm_page_prot
 * to the private version (using protection_map[] without the
 * VM_SHARED bit).
 */
int vma_wants_writenotify(struct vm_area_struct *vma)
{
	unsigned int vm_flags = vma->vm_flags;

	/* If it was private or non-writable, the write bit is already clear */
	if ((vm_flags & (VM_WRITE|VM_SHARED)) != ((VM_WRITE|VM_SHARED)))
		return 0;

	/* The backer wishes to know when pages are first written to? */
	if (vma->vm_ops && vma->vm_ops->page_mkwrite)
		return 1;

	/* The open routine did something to the protections already? */
	if (pgprot_val(vma->vm_page_prot) !=
	    pgprot_val(vm_get_page_prot(vm_flags)))
		return 0;

	/* Specialty mapping? */
	if (vm_flags & (VM_PFNMAP|VM_INSERTPAGE))
		return 0;

	/* Can the mapping track the dirty pages? */
	return vma->vm_file && vma->vm_file->f_mapping &&
		mapping_cap_account_dirty(vma->vm_file->f_mapping);
}

/*
 * We account for memory if it's a private writeable mapping,
 * not hugepages and VM_NORESERVE wasn't set.
 */
static inline int accountable_mapping(struct file *file, unsigned int vm_flags)
{
	/*
	 * hugetlb has its own accounting separate from the core VM
	 * VM_HUGETLB may not be set yet so we cannot check for that flag.
	 */
	if (file && is_file_hugepages(file))
		return 0;

	return (vm_flags & (VM_NORESERVE | VM_SHARED | VM_WRITE)) == VM_WRITE;
}

unsigned long mmap_region(struct file *file, unsigned long addr,
			  unsigned long len, unsigned long flags,
			  unsigned int vm_flags, unsigned long pgoff)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *prev;
	int correct_wcount = 0;
	int error;
	struct rb_node **rb_link, *rb_parent;
	unsigned long charged = 0;
	struct inode *inode =  file ? file->f_path.dentry->d_inode : NULL;

	/* Clear old maps */
	error = -ENOMEM;
munmap_back:
	//这个函数很重要哈，它得到了VMA该链接到链表的位置..也得到了连接到红黑树的位置
	//vma的返回值和find_vma函数一样。链表上第一个vma->vm_end大于start的VMA。
	vma = find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);
	//判定是不是有重叠..如果有重叠就会出错咯。
	if (vma && vma->vm_start < addr + len) {
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
		goto munmap_back;
	}
	//VMA映射的页面数目有限制的,,在totoal_vm字段。。
	/* Check against address space limit. */
	if (!may_expand_vm(mm, len >> PAGE_SHIFT))
		return -ENOMEM;

	/*
	 * Set 'VM_NORESERVE' if we should not account for the
	 * memory use of this mapping.
	 */
	if ((flags & MAP_NORESERVE)) {
		/* We honor MAP_NORESERVE if allowed to overcommit */
		if (sysctl_overcommit_memory != OVERCOMMIT_NEVER)
			vm_flags |= VM_NORESERVE;

		/* hugetlb applies strict overcommit unless MAP_NORESERVE */
		if (file && is_file_hugepages(file))
			vm_flags |= VM_NORESERVE;
	}

	/*
	 * Private writable mapping: check memory availability
	 */
	if (accountable_mapping(file, vm_flags)) {
		charged = len >> PAGE_SHIFT;
		if (security_vm_enough_memory(charged))
			return -ENOMEM;
		vm_flags |= VM_ACCOUNT;
	}

	/*
	 * Can we just expand an old mapping?
	 */
	vma = vma_merge(mm, prev, addr, addr + len, vm_flags, NULL, file, pgoff, NULL);
	//如果有进行了合并，那么不需要在创建新的VMA了。
	if (vma)
		goto out;

	/*
	 * Determine the object being mapped and call the appropriate
	 * specific mapper. the address has already been validated, but
	 * not unmapped, but the maps are removed from the list.
	 */
	vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (!vma) {
		error = -ENOMEM;
		goto unacct_error;
	}

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = vm_flags;
	vma->vm_page_prot = vm_get_page_prot(vm_flags);
	vma->vm_pgoff = pgoff;

	if (file) {
		error = -EINVAL;
		if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
			goto free_vma;
		if (vm_flags & VM_DENYWRITE) {
			error = deny_write_access(file);
			if (error)
				goto free_vma;
			correct_wcount = 1;
		}
		vma->vm_file = file;
		get_file(file);
		//一般来说调用generic_file_mmap();
		error = file->f_op->mmap(file, vma);
		if (error)
			goto unmap_and_free_vma;
		if (vm_flags & VM_EXECUTABLE)
			added_exe_file_vma(mm);
	} else if (vm_flags & VM_SHARED) {
		//匿名映射区，且VM_SHARED置位，一般就是用来进程间通信。。
			//IPC shared memory.
		error = shmem_zero_setup(vma);
		if (error)
			goto free_vma;
	}

	/* Can addr have changed??
	 *
	 * Answer: Yes, several device drivers can do it in their
	 *         f_op->mmap method. -DaveM
	 */
	addr = vma->vm_start;
	pgoff = vma->vm_pgoff;
	vm_flags = vma->vm_flags;

	if (vma_wants_writenotify(vma))
		vma->vm_page_prot = vm_get_page_prot(vm_flags & ~VM_SHARED);
	//添加到链表和红黑树....
	vma_link(mm, vma, prev, rb_link, rb_parent);
	file = vma->vm_file;

	/* Once vma denies write, undo our temporary denial count */
	if (correct_wcount)
		atomic_inc(&inode->i_writecount);
out:
	mm->total_vm += len >> PAGE_SHIFT;
	vm_stat_account(mm, vm_flags, file, len >> PAGE_SHIFT);
	if (vm_flags & VM_LOCKED) {
		/*
		 * makes pages present; downgrades, drops, reacquires mmap_sem
		 */
		long nr_pages = mlock_vma_pages_range(vma, addr, addr + len);
		if (nr_pages < 0)
			return nr_pages;	/* vma gone! */
		mm->locked_vm += (len >> PAGE_SHIFT) - nr_pages;
	} else if ((flags & MAP_POPULATE) && !(flags & MAP_NONBLOCK))
		make_pages_present(addr, addr + len);
	return addr;

unmap_and_free_vma:
	if (correct_wcount)
		atomic_inc(&inode->i_writecount);
	vma->vm_file = NULL;
	fput(file);

	/* Undo any partial mapping done by a device driver. */
	unmap_region(mm, vma, prev, vma->vm_start, vma->vm_end);
	charged = 0;
free_vma:
	kmem_cache_free(vm_area_cachep, vma);
unacct_error:
	if (charged)
		vm_unacct_memory(charged);
	return error;
}

/* Get an address range which is currently unmapped.
 * For shmat() with addr=0.
 *
 * Ugly calling convention alert:
 * Return value with the low bits set means error value,
 * ie
 *	if (ret & ~PAGE_MASK)
 *		error = ret;
 *
 * This function "knows" that -ENOMEM has the bits set.
 */
#ifndef HAVE_ARCH_UNMAPPED_AREA
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr;

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;
//参数addr为优先选择分配的地址..
	if (addr) {
		addr = PAGE_ALIGN(addr);
//找到第一个vma->vm_end > addr的vm区域, 如果返回NULL
//代表当前的vm区域中没有比addr 更大的地址.
		vma = find_vma(mm, addr);
//判断条件: 1. 确定选择的区域不会超过TASK_SIZE
//				2.如果vma为NULL,那么代表addr ~ addr+len区域可以get
//				3.vma非NULL, 确定要get的区域是不是会重叠
//						addr + len <= vma->vm_start. 
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}
	if (len > mm->cached_hole_size) {
	        start_addr = addr = mm->free_area_cache;
	} else {
	        start_addr = addr = TASK_UNMAPPED_BASE;
	        mm->cached_hole_size = 0;
	}

full_search:
	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (TASK_SIZE - len < addr) {
			/*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			if (start_addr != TASK_UNMAPPED_BASE) {
				addr = TASK_UNMAPPED_BASE;
			        start_addr = addr;
				mm->cached_hole_size = 0;
				goto full_search;
			}
			return -ENOMEM;
		}
		//判断条件同上面优先选择addr 时候一样..
		if (!vma || addr + len <= vma->vm_start) {
			/*
			 * Remember the place where we stopped the search:
			 */
			mm->free_area_cache = addr + len;
			return addr;
		}
		//执行到这里代表, addr ~ addr+len 的区域会覆盖到
		//vma->vm_start,因此不可以用,  此时记录addr  ~ vma->vm_start
		//之间的长度作为hole 来记录下来
		//然后会从低端地址开始遍历到高端地址, 最后会记录
		//遍历到的最大的hole 记录下来.
		if (addr + mm->cached_hole_size < vma->vm_start)
		        mm->cached_hole_size = vma->vm_start - addr;
		addr = vma->vm_end;
	}
}
#endif	

void arch_unmap_area(struct mm_struct *mm, unsigned long addr)
{
	/*
	 * Is this a new hole at the lowest possible address?
	 */
	if (addr >= TASK_UNMAPPED_BASE && addr < mm->free_area_cache) {
		mm->free_area_cache = addr;
		mm->cached_hole_size = ~0UL;
	}
}

/*
 * This mmap-allocator allocates new areas top-down from below the
 * stack's low limit (the base):
 */
#ifndef HAVE_ARCH_UNMAPPED_AREA_TOPDOWN
unsigned long
arch_get_unmapped_area_topdown(struct file *filp, const unsigned long addr0,
			  const unsigned long len, const unsigned long pgoff,
			  const unsigned long flags)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long addr = addr0;

	/* requested length too big for entire address space */
	if (len > TASK_SIZE)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

	/* requesting a specific address */
	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
				(!vma || addr + len <= vma->vm_start))
			return addr;
	}

	/* check if free_area_cache is useful for us */
	if (len <= mm->cached_hole_size) {
 	        mm->cached_hole_size = 0;
 		mm->free_area_cache = mm->mmap_base;
 	}

	/* either no address requested or can't fit in requested address hole */
	addr = mm->free_area_cache;

	/* make sure it can fit in the remaining address space */
	if (addr > len) {
		vma = find_vma(mm, addr-len);
		if (!vma || addr <= vma->vm_start)
			/* remember the address as a hint for next time */
			return (mm->free_area_cache = addr-len);
	}

	if (mm->mmap_base < len)
		goto bottomup;

	addr = mm->mmap_base-len;

	do {
		/*
		 * Lookup failure means no vma is above this address,
		 * else if new region fits below vma->vm_start,
		 * return with success:
		 */
		vma = find_vma(mm, addr);
		if (!vma || addr+len <= vma->vm_start)
			/* remember the address as a hint for next time */
			return (mm->free_area_cache = addr);

 		/* remember the largest hole we saw so far */
 		if (addr + mm->cached_hole_size < vma->vm_start)
 		        mm->cached_hole_size = vma->vm_start - addr;

		/* try just below the current vma->vm_start */
		addr = vma->vm_start-len;
	} while (len < vma->vm_start);

bottomup:
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	mm->cached_hole_size = ~0UL;
  	mm->free_area_cache = TASK_UNMAPPED_BASE;
	addr = arch_get_unmapped_area(filp, addr0, len, pgoff, flags);
	/*
	 * Restore the topdown base:
	 */
	mm->free_area_cache = mm->mmap_base;
	mm->cached_hole_size = ~0UL;

	return addr;
}
#endif

void arch_unmap_area_topdown(struct mm_struct *mm, unsigned long addr)
{
	/*
	 * Is this a new hole at the highest possible address?
	 */
	if (addr > mm->free_area_cache)
		mm->free_area_cache = addr;

	/* dont allow allocations above current base */
	if (mm->free_area_cache > mm->mmap_base)
		mm->free_area_cache = mm->mmap_base;
}

unsigned long
get_unmapped_area(struct file *file, unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	unsigned long (*get_area)(struct file *, unsigned long,
				  unsigned long, unsigned long, unsigned long);

	get_area = current->mm->get_unmapped_area;
	if (file && file->f_op && file->f_op->get_unmapped_area)
		get_area = file->f_op->get_unmapped_area;
	addr = get_area(file, addr, len, pgoff, flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	if (addr > TASK_SIZE - len)
		return -ENOMEM;
	if (addr & ~PAGE_MASK)
		return -EINVAL;

	return arch_rebalance_pgtables(addr, len);
}

EXPORT_SYMBOL(get_unmapped_area);

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
//查找满足条件vma->end > addr的第一个vma。。
struct vm_area_struct *find_vma(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma = NULL;

	if (mm) {
		/* Check the cache first. */
		/* (Cache hit rate is typically around 35%.) */
		vma = mm->mmap_cache;
		if (!(vma && vma->vm_end > addr && vma->vm_start <= addr)) {
			struct rb_node * rb_node;

			rb_node = mm->mm_rb.rb_node;
			vma = NULL;

			while (rb_node) {
				struct vm_area_struct * vma_tmp;

				vma_tmp = rb_entry(rb_node,
						struct vm_area_struct, vm_rb);

				if (vma_tmp->vm_end > addr) {
					vma = vma_tmp;
					if (vma_tmp->vm_start <= addr)
						break;
					rb_node = rb_node->rb_left;
				} else
					rb_node = rb_node->rb_right;
			}
			if (vma)
				mm->mmap_cache = vma;
		}
	}
	return vma;
}

EXPORT_SYMBOL(find_vma);

/* Same as find_vma, but also return a pointer to the previous VMA in *pprev. */
struct vm_area_struct *
find_vma_prev(struct mm_struct *mm, unsigned long addr,
			struct vm_area_struct **pprev)
{
	struct vm_area_struct *vma = NULL, *prev = NULL;
	struct rb_node *rb_node;
	if (!mm)
		goto out;

	/* Guard against addr being lower than the first VMA */
	vma = mm->mmap;

	/* Go through the RB tree quickly. */
	rb_node = mm->mm_rb.rb_node;

	while (rb_node) {
		struct vm_area_struct *vma_tmp;
		vma_tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);

		if (addr < vma_tmp->vm_end) {
			rb_node = rb_node->rb_left;
		} else {
			prev = vma_tmp;
			if (!prev->vm_next || (addr < prev->vm_next->vm_end))
				break;
			rb_node = rb_node->rb_right;
		}
	}

out:
	*pprev = prev;
	return prev ? prev->vm_next : vma;
}

/*
 * Verify that the stack growth is acceptable and
 * update accounting. This is shared with both the
 * grow-up and grow-down cases.
 */
static int acct_stack_growth(struct vm_area_struct *vma, unsigned long size, unsigned long grow)
{
	struct mm_struct *mm = vma->vm_mm;
	struct rlimit *rlim = current->signal->rlim;
	unsigned long new_start;

	/* address space limit tests */
	//grow是要增长的页数目，首先要判断是不是增长后会超过了限制。(一个进程可拥有的映射页数目)
	if (!may_expand_vm(mm, grow))
		return -ENOMEM;

	/* Stack limit test */
	//这里是对一个VMA的角度来说的,VMA的大小也有限制。
	if (size > rlim[RLIMIT_STACK].rlim_cur)
		return -ENOMEM;

	/* mlock limit tests */
	//如果这个VMA是有LOCKED标记的。那么也要判断增长了grow个LOCKD数目，是不是会超过
	//进程对于LOCKED数目的限制。
	if (vma->vm_flags & VM_LOCKED) {
		unsigned long locked;
		unsigned long limit;
		locked = mm->locked_vm + grow;
		limit = rlim[RLIMIT_MEMLOCK].rlim_cur >> PAGE_SHIFT;
		if (locked > limit && !capable(CAP_IPC_LOCK))
			return -ENOMEM;
	}

	/* Check to ensure the stack will not grow into a hugetlb-only region */
	//一般情况下为DOWN的形式的stack，那么起点就是end - size。。
	new_start = (vma->vm_flags & VM_GROWSUP) ? vma->vm_start :
			vma->vm_end - size;
	if (is_hugepage_only_range(vma->vm_mm, new_start, size))
		return -EFAULT;

	/*
	 * Overcommit..  This must be the final test, as it will
	 * update security statistics.
	 */
	if (security_vm_enough_memory_mm(mm, grow))
		return -ENOMEM;
	//好了，到这里之后检测都通过了。
	//VMA的线性区会扩大，扩大映射数目为grow指示了，那么改变相关字段
	//total_mm和locked_vm..
	/* Ok, everything looks good - let it rip */
	mm->total_vm += grow;
	if (vma->vm_flags & VM_LOCKED)
		mm->locked_vm += grow;
	vm_stat_account(mm, vma->vm_flags, vma->vm_file, grow);
	return 0;
}

#if defined(CONFIG_STACK_GROWSUP) || defined(CONFIG_IA64)
/*
 * PA-RISC uses this for its stack; IA64 for its Register Backing Store.
 * vma is the last one with address > vma->vm_end.  Have to extend vma.
 */
#ifndef CONFIG_IA64
static
#endif
int expand_upwards(struct vm_area_struct *vma, unsigned long address)
{
	int error;

	if (!(vma->vm_flags & VM_GROWSUP))
		return -EFAULT;

	/*
	 * We must make sure the anon_vma is allocated
	 * so that the anon_vma locking is not a noop.
	 */
	if (unlikely(anon_vma_prepare(vma)))
		return -ENOMEM;
	anon_vma_lock(vma);

	/*
	 * vma->vm_start/vm_end cannot change under us because the caller
	 * is required to hold the mmap_sem in read mode.  We need the
	 * anon_vma lock to serialize against concurrent expand_stacks.
	 * Also guard against wrapping around to address 0.
	 */
	if (address < PAGE_ALIGN(address+4))
		address = PAGE_ALIGN(address+4);
	else {
		anon_vma_unlock(vma);
		return -ENOMEM;
	}
	error = 0;

	/* Somebody else might have raced and expanded it already */
	if (address > vma->vm_end) {
		unsigned long size, grow;

		size = address - vma->vm_start;
		grow = (address - vma->vm_end) >> PAGE_SHIFT;

		error = acct_stack_growth(vma, size, grow);
		if (!error)
			vma->vm_end = address;
	}
	anon_vma_unlock(vma);
	return error;
}
#endif /* CONFIG_STACK_GROWSUP || CONFIG_IA64 */

/*
 * vma is the first one with address < vma->vm_start.  Have to extend vma.
 */
 //这里要扩展VMA区域的线性区间，而且是对vma的start往前扩伸，参数start满足条件 start < vma->vm_start...
static int expand_downwards(struct vm_area_struct *vma,
				   unsigned long address)
{
	int error;

	/*
	 * We must make sure the anon_vma is allocated
	 * so that the anon_vma locking is not a noop.
	 */
	if (unlikely(anon_vma_prepare(vma)))
		return -ENOMEM;

	address &= PAGE_MASK;
	error = security_file_mmap(NULL, 0, 0, 0, address, 1);
	if (error)
		return error;

	anon_vma_lock(vma);

	/*
	 * vma->vm_start/vm_end cannot change under us because the caller
	 * is required to hold the mmap_sem in read mode.  We need the
	 * anon_vma lock to serialize against concurrent expand_stacks.
	 */

	/* Somebody else might have raced and expanded it already */
	if (address < vma->vm_start) {
		unsigned long size, grow;
		//计算该vma区间的大小..
		size = vma->vm_end - address;
		//需要增长的大小(页大小为单位)	
		grow = (vma->vm_start - address) >> PAGE_SHIFT;

		error = acct_stack_growth(vma, size, grow);
		if (!error) {
			//返回0，代表增长是允许的。那么现在就修改VMA的线性区...
			vma->vm_start = address;
			vma->vm_pgoff -= grow;
		}
	}
	anon_vma_unlock(vma);
	return error;
}

int expand_stack_downwards(struct vm_area_struct *vma, unsigned long address)
{
	return expand_downwards(vma, address);
}

#ifdef CONFIG_STACK_GROWSUP
int expand_stack(struct vm_area_struct *vma, unsigned long address)
{
	return expand_upwards(vma, address);
}

struct vm_area_struct *
find_extend_vma(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma, *prev;

	addr &= PAGE_MASK;
	vma = find_vma_prev(mm, addr, &prev);
	if (vma && (vma->vm_start <= addr))
		return vma;
	if (!prev || expand_stack(prev, addr))
		return NULL;
	if (prev->vm_flags & VM_LOCKED) {
		if (mlock_vma_pages_range(prev, addr, prev->vm_end) < 0)
			return NULL;	/* vma gone! */
	}
	return prev;
}
#else
int expand_stack(struct vm_area_struct *vma, unsigned long address)
{
	return expand_downwards(vma, address);
}

struct vm_area_struct *
find_extend_vma(struct mm_struct * mm, unsigned long addr)
{
	struct vm_area_struct * vma;
	unsigned long start;

	addr &= PAGE_MASK;
	vma = find_vma(mm,addr);
	if (!vma)
		return NULL;
	if (vma->vm_start <= addr)
		return vma;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		return NULL;
	start = vma->vm_start;
	if (expand_stack(vma, addr))
		return NULL;
	if (vma->vm_flags & VM_LOCKED) {
		if (mlock_vma_pages_range(vma, addr, start) < 0)
			return NULL;	/* vma gone! */
	}
	return vma;
}
#endif

/*
 * Ok - we have the memory areas we should free on the vma list,
 * so release them, and do the vma updates.
 *
 * Called with the mm semaphore held.
 */
static void remove_vma_list(struct mm_struct *mm, struct vm_area_struct *vma)
{
	/* Update high watermark before we lower total_vm */
	update_hiwater_vm(mm);
	do {
		long nrpages = vma_pages(vma);

		mm->total_vm -= nrpages;
		vm_stat_account(mm, vma->vm_flags, vma->vm_file, -nrpages);
		vma = remove_vma(vma);
	} while (vma);
	validate_mm(mm);
}

/*
 * Get rid of page table information in the indicated region.
 *
 * Called with the mm semaphore held.
 */
static void unmap_region(struct mm_struct *mm,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		unsigned long start, unsigned long end)
{
	struct vm_area_struct *next = prev? prev->vm_next: mm->mmap;
	struct mmu_gather *tlb;
	unsigned long nr_accounted = 0;

	lru_add_drain();
	tlb = tlb_gather_mmu(mm, 0);
	update_hiwater_rss(mm);
	//下面这个函数释放start ~ end占据的页表项
	unmap_vmas(&tlb, vma, start, end, &nr_accounted, NULL);
	vm_unacct_memory(nr_accounted);
	//下面这个函数释放掉要释放链表所插入到的链表或者是树
	//比如匿名线性区的anon_vma(vma->anon_vma_node)
	//    线性映射区的
	//  非线性映射区的vma->shared.vm_set.list
	free_pgtables(tlb, vma, prev? prev->vm_end: FIRST_USER_ADDRESS,
				 next? next->vm_start: 0);
	tlb_finish_mmu(tlb, start, end);
}

/*
 * Create a list of vma's touched by the unmap, removing them from the mm's
 * vma list as we go..
 */
static void
detach_vmas_to_be_unmapped(struct mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, unsigned long end)
{
	struct vm_area_struct **insertion_point;
	struct vm_area_struct *tail_vma = NULL;
	unsigned long addr;

	insertion_point = (prev ? &prev->vm_next : &mm->mmap);
	do {
		rb_erase(&vma->vm_rb, &mm->mm_rb);
		mm->map_count--;
		tail_vma = vma;
		vma = vma->vm_next;
	} while (vma && vma->vm_start < end);
	*insertion_point = vma;
	tail_vma->vm_next = NULL;
	if (mm->unmap_area == arch_unmap_area)
		addr = prev ? prev->vm_end : mm->mmap_base;
	else
		addr = vma ?  vma->vm_start : mm->mmap_base;
	mm->unmap_area(mm, addr);
	mm->mmap_cache = NULL;		/* Kill the cache. */
}

/*
 * Split a vma into two pieces at address 'addr', a new vma is allocated
 * either for the first part or the tail.
 */
int split_vma(struct mm_struct * mm, struct vm_area_struct * vma,
	      unsigned long addr, int new_below)
{
	struct mempolicy *pol;
	struct vm_area_struct *new;

	if (is_vm_hugetlb_page(vma) && (addr &
					~(huge_page_mask(hstate_vma(vma)))))
		return -EINVAL;

	if (mm->map_count >= sysctl_max_map_count)
		return -ENOMEM;

	new = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	/* most fields are the same, copy all, and then fixup */
	*new = *vma;

	if (new_below)
		new->vm_end = addr;
	else {
		new->vm_start = addr;
		new->vm_pgoff += ((addr - vma->vm_start) >> PAGE_SHIFT);
	}

	pol = mpol_dup(vma_policy(vma));
	if (IS_ERR(pol)) {
		kmem_cache_free(vm_area_cachep, new);
		return PTR_ERR(pol);
	}
	vma_set_policy(new, pol);

	if (new->vm_file) {
		get_file(new->vm_file);
		if (vma->vm_flags & VM_EXECUTABLE)
			added_exe_file_vma(mm);
	}

	if (new->vm_ops && new->vm_ops->open)
		new->vm_ops->open(new);

	if (new_below)
		vma_adjust(vma, addr, vma->vm_end, vma->vm_pgoff +
			((addr - new->vm_start) >> PAGE_SHIFT), new);
	else
		vma_adjust(vma, vma->vm_start, addr, vma->vm_pgoff, new);

	return 0;
}

/* Munmap is split into 2 main parts -- this part which finds
 * what needs doing, and the areas themselves, which do the
 * work.  This now handles partial unmappings.
 * Jeremy Fitzhardinge <jeremy@goop.org>
 */
int do_munmap(struct mm_struct *mm, unsigned long start, size_t len)
{
	unsigned long end;
	struct vm_area_struct *vma, *prev, *last;
	//如果start不是PAGE_SIZE对齐
	//或者是大于TASK_SIZE
	//或者是start + len超过了TASK_SIZE。
	if ((start & ~PAGE_MASK) || start > TASK_SIZE || len > TASK_SIZE-start)
		return -EINVAL;
	//len也不应该为0。
	if ((len = PAGE_ALIGN(len)) == 0)
		return -EINVAL;

	/* Find the first overlapping VMA */
	//类似find_vma函数，同时返回前一个存放到prev变量中。。
	//返回的是VMA链表中第一个满足条件vma_end > start的VMA.
	vma = find_vma_prev(mm, start, &prev);
	if (!vma)
		return 0;
	/* we have  start < vma->vm_end  */

	/* if it doesn't overlap, we have nothing.. */
	end = start + len;
	if (vma->vm_start >= end)
		return 0;

	/*
	 * If we need to split any vma, do it now to save pain later.
	 *
	 * Note: mremap's move_vma VM_ACCOUNT handling assumes a partially
	 * unmapped vm_area_struct will remain in use: so lower split_vma
	 * places tmp vma above, and higher split_vma places tmp vma below.
	 */
	if (start > vma->vm_start) {
		int error = split_vma(mm, vma, start, 0);
		if (error)
			return error;
		prev = vma;
	}

	/* Does it split the last one? */
	last = find_vma(mm, end);
	if (last && end > last->vm_start) {
		int error = split_vma(mm, last, end, 1);
		if (error)
			return error;
	}
	//vma指向要开始释放的第一个memory region..
	vma = prev? prev->vm_next: mm->mmap;

	/*
	 * unlock any mlock()ed ranges before detaching vmas
	 */
	if (mm->locked_vm) {
		struct vm_area_struct *tmp = vma;
		while (tmp && tmp->vm_start < end) {
			if (tmp->vm_flags & VM_LOCKED) {
				mm->locked_vm -= vma_pages(tmp);
				munlock_vma_pages_all(tmp);
			}
			tmp = tmp->vm_next;
		}
	}

	/*
	 * Remove the vma's, and unmap the actual pages
	 */
	//这个函数对红黑树，和链表进行操作。 由vma开始，vma指向要被unmap的第一个memory region.
    //然后vma = vma->next来遍历链表来erase掉，直接条件vma->start > end。。
    //需要注意的一点是，移除下来的VMA，还是组成一个链表的形式
    //起点就是vma这个结点。
	detach_vmas_to_be_unmapped(mm, vma, prev, end);
	//这里就是移除掉和当前被删除的VMA相关页表项，和使无效TLB咯。
	//还有从anon_vma或page_tree中移除咯,i_mmap_nonlinear和i_mmap链表/优先树..
    //该函数没有进去分析，有待理解。
	unmap_region(mm, vma, prev, start, end);

	/* Fix up all other VM information */
	//前面只是从list/rb tree中移除下来，并没有free掉内存
    //而且前面也说过了,vma是移除下来的链表起点，下面
    //这个函数进行对这个链表free掉它所占据的内存。
	remove_vma_list(mm, vma);

	return 0;
}

EXPORT_SYMBOL(do_munmap);

SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
{
	int ret;
	struct mm_struct *mm = current->mm;

	profile_munmap(addr);

	down_write(&mm->mmap_sem);
	ret = do_munmap(mm, addr, len);
	up_write(&mm->mmap_sem);
	return ret;
}

static inline void verify_mm_writelocked(struct mm_struct *mm)
{
#ifdef CONFIG_DEBUG_VM
	if (unlikely(down_read_trylock(&mm->mmap_sem))) {
		WARN_ON(1);
		up_read(&mm->mmap_sem);
	}
#endif
}

/*
 *  this is really a simplified "do_mmap".  it only handles
 *  anonymous maps.  eventually we may be able to do some
 *  brk-specific accounting here.
 */
unsigned long do_brk(unsigned long addr, unsigned long len)
{
	struct mm_struct * mm = current->mm;
	struct vm_area_struct * vma, * prev;
	unsigned long flags;
	struct rb_node ** rb_link, * rb_parent;
	pgoff_t pgoff = addr >> PAGE_SHIFT;
	int error;

	len = PAGE_ALIGN(len);
	if (!len)
		return addr;

	if ((addr + len) > TASK_SIZE || (addr + len) < addr)
		return -EINVAL;

	if (is_hugepage_only_range(mm, addr, len))
		return -EINVAL;

	error = security_file_mmap(NULL, 0, 0, 0, addr, 1);
	if (error)
		return error;

	flags = VM_DATA_DEFAULT_FLAGS | VM_ACCOUNT | mm->def_flags;

	error = arch_mmap_check(addr, len, flags);
	if (error)
		return error;

	/*
	 * mlock MCL_FUTURE?
	 */
	if (mm->def_flags & VM_LOCKED) {
		unsigned long locked, lock_limit;
		locked = len >> PAGE_SHIFT;
		locked += mm->locked_vm;
		lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
		lock_limit >>= PAGE_SHIFT;
		if (locked > lock_limit && !capable(CAP_IPC_LOCK))
			return -EAGAIN;
	}

	/*
	 * mm->mmap_sem is required to protect against another thread
	 * changing the mappings in case we sleep.
	 */
	verify_mm_writelocked(mm);

	/*
	 * Clear old maps.  this also does some error checking for us
	 */
 munmap_back:
	vma = find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);
	if (vma && vma->vm_start < addr + len) {
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
		goto munmap_back;
	}

	/* Check against address space limits *after* clearing old maps... */
	if (!may_expand_vm(mm, len >> PAGE_SHIFT))
		return -ENOMEM;

	if (mm->map_count > sysctl_max_map_count)
		return -ENOMEM;

	if (security_vm_enough_memory(len >> PAGE_SHIFT))
		return -ENOMEM;

	/* Can we just expand an old private anonymous mapping? */
	vma = vma_merge(mm, prev, addr, addr + len, flags,
					NULL, NULL, pgoff, NULL);
	if (vma)
		goto out;

	/*
	 * create a vma struct for an anonymous mapping
	 */
	vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (!vma) {
		vm_unacct_memory(len >> PAGE_SHIFT);
		return -ENOMEM;
	}

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_pgoff = pgoff;
	vma->vm_flags = flags;
	vma->vm_page_prot = vm_get_page_prot(flags);
	vma_link(mm, vma, prev, rb_link, rb_parent);
out:
	mm->total_vm += len >> PAGE_SHIFT;
	if (flags & VM_LOCKED) {
		if (!mlock_vma_pages_range(vma, addr, addr + len))
			mm->locked_vm += (len >> PAGE_SHIFT);
	}
	return addr;
}

EXPORT_SYMBOL(do_brk);

/* Release all mmaps. */
void exit_mmap(struct mm_struct *mm)
{
	struct mmu_gather *tlb;
	struct vm_area_struct *vma;
	unsigned long nr_accounted = 0;
	unsigned long end;

	/* mm's last user has gone, and its about to be pulled down */
	mmu_notifier_release(mm);

	if (mm->locked_vm) {
		vma = mm->mmap;
		while (vma) {
			if (vma->vm_flags & VM_LOCKED)
				munlock_vma_pages_all(vma);
			vma = vma->vm_next;
		}
	}

	arch_exit_mmap(mm);

	vma = mm->mmap;
	if (!vma)	/* Can happen if dup_mmap() received an OOM */
		return;

	lru_add_drain();
	flush_cache_mm(mm);
	tlb = tlb_gather_mmu(mm, 1);
	/* update_hiwater_rss(mm) here? but nobody should be looking */
	/* Use -1 here to ensure all VMAs in the mm are unmapped */
	end = unmap_vmas(&tlb, vma, 0, -1, &nr_accounted, NULL);
	vm_unacct_memory(nr_accounted);
	free_pgtables(tlb, vma, FIRST_USER_ADDRESS, 0);
	tlb_finish_mmu(tlb, 0, end);

	/*
	 * Walk the list again, actually closing and freeing it,
	 * with preemption enabled, without holding any MM locks.
	 */
	while (vma)
		vma = remove_vma(vma);

	BUG_ON(mm->nr_ptes > (FIRST_USER_ADDRESS+PMD_SIZE-1)>>PMD_SHIFT);
}

/* Insert vm structure into process list sorted by address
 * and into the inode's i_mmap tree.  If vm_file is non-NULL
 * then i_mmap_lock is taken here.
 */
int insert_vm_struct(struct mm_struct * mm, struct vm_area_struct * vma)
{
	struct vm_area_struct * __vma, * prev;
	struct rb_node ** rb_link, * rb_parent;

	/*
	 * The vm_pgoff of a purely anonymous vma should be irrelevant
	 * until its first write fault, when page's anon_vma and index
	 * are set.  But now set the vm_pgoff it will almost certainly
	 * end up with (unless mremap moves it elsewhere before that
	 * first wfault), so /proc/pid/maps tells a consistent story.
	 *
	 * By setting it to reflect the virtual start address of the
	 * vma, merges and splits can happen in a seamless way, just
	 * using the existing file pgoff checks and manipulations.
	 * Similarly in do_mmap_pgoff and in do_brk.
	 */
	if (!vma->vm_file) {
		BUG_ON(vma->anon_vma);
		vma->vm_pgoff = vma->vm_start >> PAGE_SHIFT;
	}
	__vma = find_vma_prepare(mm,vma->vm_start,&prev,&rb_link,&rb_parent);
	//返回的__vma是第一个vma链表上vma->end大于vma->vm_start的vma数据结构.
	//因此现在要判断要插入的vma和返回的__vma的区域之间是否有重叠
	//那就是判断vma的结束地址是不是超过了__vma的起始地址，如果超过了就是覆盖了。
	if (__vma && __vma->vm_start < vma->vm_end)
		return -ENOMEM;
	if ((vma->vm_flags & VM_ACCOUNT) &&
	     security_vm_enough_memory_mm(mm, vma_pages(vma)))
		return -ENOMEM;
	//通过find_vma_prepare函数，得到了应该插入到的链表的位置(prev)
	//得到了插入到红黑树的位置(rb_link)
	vma_link(mm, vma, prev, rb_link, rb_parent);
	return 0;
}

/*
 * Copy the vma structure to a new location in the same mm,
 * prior to moving page table entries, to effect an mremap move.
 */
struct vm_area_struct *copy_vma(struct vm_area_struct **vmap,
	unsigned long addr, unsigned long len, pgoff_t pgoff)
{
	struct vm_area_struct *vma = *vmap;
	unsigned long vma_start = vma->vm_start;
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *new_vma, *prev;
	struct rb_node **rb_link, *rb_parent;
	struct mempolicy *pol;

	/*
	 * If anonymous vma has not yet been faulted, update new pgoff
	 * to match new location, to increase its chance of merging.
	 */
	if (!vma->vm_file && !vma->anon_vma)
		pgoff = addr >> PAGE_SHIFT;

	find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);
	new_vma = vma_merge(mm, prev, addr, addr + len, vma->vm_flags,
			vma->anon_vma, vma->vm_file, pgoff, vma_policy(vma));
	if (new_vma) {
		/*
		 * Source vma may have been merged into new_vma
		 */
		if (vma_start >= new_vma->vm_start &&
		    vma_start < new_vma->vm_end)
			*vmap = new_vma;
	} else {
		new_vma = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
		if (new_vma) {
			*new_vma = *vma;
			pol = mpol_dup(vma_policy(vma));
			if (IS_ERR(pol)) {
				kmem_cache_free(vm_area_cachep, new_vma);
				return NULL;
			}
			vma_set_policy(new_vma, pol);
			new_vma->vm_start = addr;
			new_vma->vm_end = addr + len;
			new_vma->vm_pgoff = pgoff;
			if (new_vma->vm_file) {
				get_file(new_vma->vm_file);
				if (vma->vm_flags & VM_EXECUTABLE)
					added_exe_file_vma(mm);
			}
			if (new_vma->vm_ops && new_vma->vm_ops->open)
				new_vma->vm_ops->open(new_vma);
			vma_link(mm, new_vma, prev, rb_link, rb_parent);
		}
	}
	return new_vma;
}

/*
 * Return true if the calling process may expand its vm space by the passed
 * number of pages
 */
int may_expand_vm(struct mm_struct *mm, unsigned long npages)
{
	unsigned long cur = mm->total_vm;	/* pages */
	unsigned long lim;

	lim = current->signal->rlim[RLIMIT_AS].rlim_cur >> PAGE_SHIFT;

	if (cur + npages > lim)
		return 0;
	return 1;
}


static int special_mapping_fault(struct vm_area_struct *vma,
				struct vm_fault *vmf)
{
	pgoff_t pgoff;
	struct page **pages;

	/*
	 * special mappings have no vm_file, and in that case, the mm
	 * uses vm_pgoff internally. So we have to subtract it from here.
	 * We are allowed to do this because we are the mm; do not copy
	 * this code into drivers!
	 */
	pgoff = vmf->pgoff - vma->vm_pgoff;

	for (pages = vma->vm_private_data; pgoff && *pages; ++pages)
		pgoff--;

	if (*pages) {
		struct page *page = *pages;
		get_page(page);
		vmf->page = page;
		return 0;
	}

	return VM_FAULT_SIGBUS;
}

/*
 * Having a close hook prevents vma merging regardless of flags.
 */
static void special_mapping_close(struct vm_area_struct *vma)
{
}

static struct vm_operations_struct special_mapping_vmops = {
	.close = special_mapping_close,
	.fault = special_mapping_fault,
};

/*
 * Called with mm->mmap_sem held for writing.
 * Insert a new vma covering the given region, with the given flags.
 * Its pages are supplied by the given array of struct page *.
 * The array can be shorter than len >> PAGE_SHIFT if it's null-terminated.
 * The region past the last page supplied will always produce SIGBUS.
 * The array pointer and the pages it points to are assumed to stay alive
 * for as long as this mapping might exist.
 */
int install_special_mapping(struct mm_struct *mm,
			    unsigned long addr, unsigned long len,
			    unsigned long vm_flags, struct page **pages)
{
	struct vm_area_struct *vma;

	vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (unlikely(vma == NULL))
		return -ENOMEM;

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;

	vma->vm_flags = vm_flags | mm->def_flags | VM_DONTEXPAND;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

	vma->vm_ops = &special_mapping_vmops;
	vma->vm_private_data = pages;

	if (unlikely(insert_vm_struct(mm, vma))) {
		kmem_cache_free(vm_area_cachep, vma);
		return -ENOMEM;
	}

	mm->total_vm += len >> PAGE_SHIFT;

	return 0;
}

static DEFINE_MUTEX(mm_all_locks_mutex);

static void vm_lock_anon_vma(struct mm_struct *mm, struct anon_vma *anon_vma)
{
	if (!test_bit(0, (unsigned long *) &anon_vma->head.next)) {
		/*
		 * The LSB of head.next can't change from under us
		 * because we hold the mm_all_locks_mutex.
		 */
		spin_lock_nest_lock(&anon_vma->lock, &mm->mmap_sem);
		/*
		 * We can safely modify head.next after taking the
		 * anon_vma->lock. If some other vma in this mm shares
		 * the same anon_vma we won't take it again.
		 *
		 * No need of atomic instructions here, head.next
		 * can't change from under us thanks to the
		 * anon_vma->lock.
		 */
		if (__test_and_set_bit(0, (unsigned long *)
				       &anon_vma->head.next))
			BUG();
	}
}

static void vm_lock_mapping(struct mm_struct *mm, struct address_space *mapping)
{
	if (!test_bit(AS_MM_ALL_LOCKS, &mapping->flags)) {
		/*
		 * AS_MM_ALL_LOCKS can't change from under us because
		 * we hold the mm_all_locks_mutex.
		 *
		 * Operations on ->flags have to be atomic because
		 * even if AS_MM_ALL_LOCKS is stable thanks to the
		 * mm_all_locks_mutex, there may be other cpus
		 * changing other bitflags in parallel to us.
		 */
		if (test_and_set_bit(AS_MM_ALL_LOCKS, &mapping->flags))
			BUG();
		spin_lock_nest_lock(&mapping->i_mmap_lock, &mm->mmap_sem);
	}
}

/*
 * This operation locks against the VM for all pte/vma/mm related
 * operations that could ever happen on a certain mm. This includes
 * vmtruncate, try_to_unmap, and all page faults.
 *
 * The caller must take the mmap_sem in write mode before calling
 * mm_take_all_locks(). The caller isn't allowed to release the
 * mmap_sem until mm_drop_all_locks() returns.
 *
 * mmap_sem in write mode is required in order to block all operations
 * that could modify pagetables and free pages without need of
 * altering the vma layout (for example populate_range() with
 * nonlinear vmas). It's also needed in write mode to avoid new
 * anon_vmas to be associated with existing vmas.
 *
 * A single task can't take more than one mm_take_all_locks() in a row
 * or it would deadlock.
 *
 * The LSB in anon_vma->head.next and the AS_MM_ALL_LOCKS bitflag in
 * mapping->flags avoid to take the same lock twice, if more than one
 * vma in this mm is backed by the same anon_vma or address_space.
 *
 * We can take all the locks in random order because the VM code
 * taking i_mmap_lock or anon_vma->lock outside the mmap_sem never
 * takes more than one of them in a row. Secondly we're protected
 * against a concurrent mm_take_all_locks() by the mm_all_locks_mutex.
 *
 * mm_take_all_locks() and mm_drop_all_locks are expensive operations
 * that may have to take thousand of locks.
 *
 * mm_take_all_locks() can fail if it's interrupted by signals.
 */
int mm_take_all_locks(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	int ret = -EINTR;

	BUG_ON(down_read_trylock(&mm->mmap_sem));

	mutex_lock(&mm_all_locks_mutex);

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (signal_pending(current))
			goto out_unlock;
		if (vma->vm_file && vma->vm_file->f_mapping)
			vm_lock_mapping(mm, vma->vm_file->f_mapping);
	}

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (signal_pending(current))
			goto out_unlock;
		if (vma->anon_vma)
			vm_lock_anon_vma(mm, vma->anon_vma);
	}

	ret = 0;

out_unlock:
	if (ret)
		mm_drop_all_locks(mm);

	return ret;
}

static void vm_unlock_anon_vma(struct anon_vma *anon_vma)
{
	if (test_bit(0, (unsigned long *) &anon_vma->head.next)) {
		/*
		 * The LSB of head.next can't change to 0 from under
		 * us because we hold the mm_all_locks_mutex.
		 *
		 * We must however clear the bitflag before unlocking
		 * the vma so the users using the anon_vma->head will
		 * never see our bitflag.
		 *
		 * No need of atomic instructions here, head.next
		 * can't change from under us until we release the
		 * anon_vma->lock.
		 */
		if (!__test_and_clear_bit(0, (unsigned long *)
					  &anon_vma->head.next))
			BUG();
		spin_unlock(&anon_vma->lock);
	}
}

static void vm_unlock_mapping(struct address_space *mapping)
{
	if (test_bit(AS_MM_ALL_LOCKS, &mapping->flags)) {
		/*
		 * AS_MM_ALL_LOCKS can't change to 0 from under us
		 * because we hold the mm_all_locks_mutex.
		 */
		spin_unlock(&mapping->i_mmap_lock);
		if (!test_and_clear_bit(AS_MM_ALL_LOCKS,
					&mapping->flags))
			BUG();
	}
}

/*
 * The mmap_sem cannot be released by the caller until
 * mm_drop_all_locks() returns.
 */
void mm_drop_all_locks(struct mm_struct *mm)
{
	struct vm_area_struct *vma;

	BUG_ON(down_read_trylock(&mm->mmap_sem));
	BUG_ON(!mutex_is_locked(&mm_all_locks_mutex));

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->anon_vma)
			vm_unlock_anon_vma(vma->anon_vma);
		if (vma->vm_file && vma->vm_file->f_mapping)
			vm_unlock_mapping(vma->vm_file->f_mapping);
	}

	mutex_unlock(&mm_all_locks_mutex);
}

/*
 * initialise the VMA slab
 */
void __init mmap_init(void)
{
	int ret;

	ret = percpu_counter_init(&vm_committed_as, 0);
	VM_BUG_ON(ret);
}
