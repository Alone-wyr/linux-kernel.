/*
 *  linux/mm/swap_state.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *
 *  Rewritten to use page cache, (C) 1998 Stephen Tweedie
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/migrate.h>
#include <linux/page_cgroup.h>

#include <asm/pgtable.h>

/*
 * swapper_space is a fiction, retained to simplify the path through
 * vmscan's shrink_page_list, to make sync_page look nicer, and to allow
 * future use of radix_tree tags in the swap cache.
 */
static const struct address_space_operations swap_aops = {
	.writepage	= swap_writepage,
	.sync_page	= block_sync_page,
	.set_page_dirty	= __set_page_dirty_nobuffers,
	.migratepage	= migrate_page,
};

static struct backing_dev_info swap_backing_dev_info = {
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK | BDI_CAP_SWAP_BACKED,
	.unplug_io_fn	= swap_unplug_io_fn,
};

struct address_space swapper_space = {
	.page_tree	= RADIX_TREE_INIT(GFP_ATOMIC|__GFP_NOWARN),
	.tree_lock	= __SPIN_LOCK_UNLOCKED(swapper_space.tree_lock),
	.a_ops		= &swap_aops,
	.i_mmap_nonlinear = LIST_HEAD_INIT(swapper_space.i_mmap_nonlinear),
	.backing_dev_info = &swap_backing_dev_info,
};

#define INC_CACHE_INFO(x)	do { swap_cache_info.x++; } while (0)

static struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
} swap_cache_info;

void show_swap_cache_info(void)
{
	printk("%lu pages in swap cache\n", total_swapcache_pages);
	printk("Swap cache stats: add %lu, delete %lu, find %lu/%lu\n",
		swap_cache_info.add_total, swap_cache_info.del_total,
		swap_cache_info.find_success, swap_cache_info.find_total);
	printk("Free swap  = %ldkB\n", nr_swap_pages << (PAGE_SHIFT - 10));
	printk("Total swap = %lukB\n", total_swap_pages << (PAGE_SHIFT - 10));
}

/*
 * add_to_swap_cache resembles add_to_page_cache_locked on swapper_space,
 * but sets SwapCache flag and private instead of mapping and index.
 */
 /*
 		//1. 设置private的值为swap entry identification.
		//2. 会设置flag有PageSwapCache标记
		//3. 增加_count的计数值...
*/
int add_to_swap_cache(struct page *page, swp_entry_t entry, gfp_t gfp_mask)
{
	int error;

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(PageSwapCache(page));
	VM_BUG_ON(!PageSwapBacked(page));

	error = radix_tree_preload(gfp_mask);
	if (!error) {
		//增加page描述符的_count计数器
		page_cache_get(page);
		//设置标记PG_swapcache..
		SetPageSwapCache(page);
		//设置page描述符的private的值为换出标记符.
		set_page_private(page, entry.val);

		spin_lock_irq(&swapper_space.tree_lock);
		//添加到radix tree..
		//有可能发生错误，因为entry.val指定的位置已经有了指向page了.
		error = radix_tree_insert(&swapper_space.page_tree,
						entry.val, page);
		if (likely(!error)) {
			total_swapcache_pages++;
			__inc_zone_page_state(page, NR_FILE_PAGES);
			INC_CACHE_INFO(add_total);
		}
		spin_unlock_irq(&swapper_space.tree_lock);
		radix_tree_preload_end();

		if (unlikely(error)) {
		//下面是出错的处理,可以根据这些处理来知道插入到sawp cache对page的设置
		//1. 设置private的值为swap entry identification.
		//2. 会设置flag有PageSwapCache标记
		//3. 增加_count的计数值...
			set_page_private(page, 0UL);
			ClearPageSwapCache(page);
			page_cache_release(page);
		}
	}
	return error;
}

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache.
 */
void __delete_from_swap_cache(struct page *page)
{
	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(!PageSwapCache(page));
	VM_BUG_ON(PageWriteback(page));
	//从radix tree移除出来.
	radix_tree_delete(&swapper_space.page_tree, page_private(page));
	//清除掉private存放的换出描述符.
	set_page_private(page, 0);
	//清除掉设置的PG_swapcache标记
	ClearPageSwapCache(page);
	total_swapcache_pages--;
	__dec_zone_page_state(page, NR_FILE_PAGES);
	INC_CACHE_INFO(del_total);
}

/**
 * add_to_swap - allocate swap space for a page
 * @page: page we want to move to swap
 * @gfp_mask: memory allocation flags
 *
 * Allocate swap space for the page and add the page to the
 * swap cache.  Caller needs to hold the page lock. 
 */
 
 /*
 新添加一个页到swap cache..
 	1.分配一个free slot.(get_swap_cache函数).可以认为是对slot的引用递增1.
	2.调用函数add_to_swap_cache
		2.1 递增_count计数器
		2.2 设置PG_swapcached标记
		2.3 设置page.private为交换标识符.
		2.3 insert到swapper_space的基树上.
	3.设置PG_dirty标记.
 */
int add_to_swap(struct page *page)
{
	swp_entry_t entry;
	int err;

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(!PageUptodate(page));

	for (;;) {
		//获取一个free slot用来存放要换出的页框...
		//entry可以确定存放的swap area和存放的slot索引值.
		entry = get_swap_page();
		if (!entry.val)
			return 0;

		/*
		 * Radix-tree node allocations from PF_MEMALLOC contexts could
		 * completely exhaust the page allocator. __GFP_NOMEMALLOC
		 * stops emergency reserves from being allocated.
		 *
		 * TODO: this could cause a theoretical memory reclaim
		 * deadlock in the swap out path.
		 */
		/*
		 * Add it to the swap cache and mark it dirty
		 */
		err = add_to_swap_cache(page, entry,
				__GFP_HIGH|__GFP_NOMEMALLOC|__GFP_NOWARN);

		switch (err) {
		case 0:				/* Success */
			//设置为脏..因为这样shrink_list函数才会把该页写入到磁盘去..
			SetPageDirty(page);
			return 1;
		case -EEXIST:
			/* Raced with "speculative" read_swap_cache_async */
			swap_free(entry);
			continue;
		default:
			/* -ENOMEM radix-tree allocation failure */
			swap_free(entry);
			return 0;
		}
	}
}

/*
 * This must be called only on pages that have
 * been verified to be in the swap cache and locked.
 * It will never put the page into the free list,
 * the caller has a reference on the page.
 * 该函数必须在验证了参数页框是在swap cache中并且被上锁了的才可以调用.
 * 它不会把页放回到free_list的，因为调用者会先对该页进行了引用.(get_page).
 */
 /*
 当一个页框加入到swap cache的时候调用add_to_swap，可以参考加入的时候设置了什么。
 现在要删除的动作，就是要跟它相反。
 	1.调用函数__delete_from_swap_cache
 		1.1 从radix tree中remove掉.
 		1.2 清除掉private存放的换出描述符.
 		1.3 清除掉设置的PG_swapcache标记
 	2.递减slot的引用...(插入的时候调用get_swap_page相当于在递增).
 	3.递减_count的引用..
 */
void delete_from_swap_cache(struct page *page)
{
	swp_entry_t entry;

	entry.val = page_private(page);

	spin_lock_irq(&swapper_space.tree_lock);
	__delete_from_swap_cache(page);
	spin_unlock_irq(&swapper_space.tree_lock);

	mem_cgroup_uncharge_swapcache(page, entry);
	//递减swap_map的计数.
	swap_free(entry);
	//递减_count计数器.
	page_cache_release(page);
}

/* 
 * If we are the only user, then try to free up the swap cache. 
 * 
 * Its ok to check for PageSwapCache without the page lock
 * here because we are going to recheck again inside
 * try_to_free_swap() _with_ the lock.
 * 					- Marcelo
 */
static inline void free_swap_cache(struct page *page)
{
	if (PageSwapCache(page) && !page_mapped(page) && trylock_page(page)) {
		try_to_free_swap(page);
		unlock_page(page);
	}
}

/* 
 * Perform a free_page(), also freeing any swap cache associated with
 * this page if it is the last user of the page.
 */
void free_page_and_swap_cache(struct page *page)
{
	free_swap_cache(page);
	page_cache_release(page);
}

/*
 * Passed an array of pages, drop them all from swapcache and then release
 * them.  They are removed from the LRU and freed if this is their last use.
 */
void free_pages_and_swap_cache(struct page **pages, int nr)
{
	struct page **pagep = pages;

	lru_add_drain();
	while (nr) {
		int todo = min(nr, PAGEVEC_SIZE);
		int i;

		for (i = 0; i < todo; i++)
			free_swap_cache(pagep[i]);
		release_pages(pagep, todo, 0);
		pagep += todo;
		nr -= todo;
	}
}

/*
 * Lookup a swap entry in the swap cache. A found page will be returned
 * unlocked and with its refcount incremented - we rely on the kernel
 * lock getting page table operations atomic even if we drop the page
 * lock before returning.
 */
struct page * lookup_swap_cache(swp_entry_t entry)
{
	struct page *page;

	page = find_get_page(&swapper_space, entry.val);

	if (page)
		INC_CACHE_INFO(find_success);

	INC_CACHE_INFO(find_total);
	return page;
}

/* 
 * Locate a page of swap in physical memory, reserving swap cache space
 * and reading the disk if it is not already cached.
 * A failure return means that either the page allocation failed or that
 * the swap entry is no longer in use.
 */
 /*
 该函数:read_swap_cache_async
 		//1. 设置flag有PageSwapBacked 标记
		//2. 设置flag有PG_locked标记
		//3. 对swap map的计数器递增1，表示对其引用.
函数:add_to_swap_cache
	 	//1. 设置private的值为swap entry identification.
		//2. 会设置flag有PageSwapCache标记
		//3. 增加_count的计数值...
*/
struct page *read_swap_cache_async(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr)
{
	struct page *found_page, *new_page = NULL;
	int err;

	do {
		/*
		 * First check the swap cache.  Since this is normally
		 * called after lookup_swap_cache() failed, re-calling
		 * that would confuse statistics.
		 */
		//先在swap cache中查找...
		found_page = find_get_page(&swapper_space, entry.val);
		if (found_page)	//如果得到，那么直接break....
			break;

		/*
		 * Get a new page to read into from swap.
		 */
		if (!new_page) {
			//否则分配一个新页来存放等下读取slot of swap area.
			new_page = alloc_page_vma(gfp_mask, vma, addr);
			if (!new_page)
				break;		/* Out of memory */
		}

		/*
		 * Swap entry may have been freed since our caller observed it.
		 */
		/*
		判断该页是否已经释放了，需要去看一下释放的过程如何处理，才能确定说这个函数就是来
		判断的。因为这个函数其实就是递增swap_map的计数器..不过如果对应的slot的计数器为0，它会返回0.
		更详细的进入函数查看。

		这里面会递增swap_map的计数器，因为后面添加到swap cache中。。。在swap cache中也需要该引用..
		函数获取当前swap cache引用的进程数目，page_swapcount..
		可以看到要减掉1，然后返回。。因为放在swap cache中，它也有引用计数。
		*/
		if (!swap_duplicate(entry))
			break;

		/*
		 * Associate the page with swap entry in the swap cache.
		 * May fail (-EEXIST) if there is already a page associated
		 * with this entry in the swap cache: added by a racing
		 * read_swap_cache_async, or add_to_swap or shmem_writepage
		 * re-using the just freed swap entry for an existing page.
		 * May fail (-ENOMEM) if radix-tree node allocation failed.
		 */
		__set_page_locked(new_page);
		SetPageSwapBacked(new_page);
		err = add_to_swap_cache(new_page, entry, gfp_mask & GFP_KERNEL);
		if (likely(!err)) {
			/*
			 * Initiate read into locked page and return.
			 */
			 //添加到lru链表上..这里面也会添加_count的计数器...
			lru_cache_add_anon(new_page);
			swap_readpage(NULL, new_page);
			return new_page;
		}
		//一样，通过对错误的处理来判断进行异步读的时候做的处理..
		//1. 设置flag有PageSwapBacked 标记
		//2. 设置flag有PG_locked标记
		//3. 对swap map的计数器递增1，表示对其引用.
		ClearPageSwapBacked(new_page);
		__clear_page_locked(new_page);
		swap_free(entry);
	} while (err != -ENOMEM);

	if (new_page)
		page_cache_release(new_page);
	return found_page;
}

/**
 * swapin_readahead - swap in pages in hope we need them soon
 * @entry: swap entry of this memory
 * @gfp_mask: memory allocation flags
 * @vma: user vma this address belongs to
 * @addr: target address for mempolicy
 *
 * Returns the struct page for entry and addr, after queueing swapin.
 *
 * Primitive swap readahead code. We simply read an aligned block of
 * (1 << page_cluster) entries in the swap area. This method is chosen
 * because it doesn't cost us any seek time.  We also make sure to queue
 * the 'original' request together with the readahead ones...
 *
 * This has been extended to use the NUMA policies from the mm triggering
 * the readahead.
 *
 * Caller must hold down_read on the vma->vm_mm if vma is not NULL.
 */
struct page *swapin_readahead(swp_entry_t entry, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr)
{
	int nr_pages;
	struct page *page;
	unsigned long offset;
	unsigned long end_offset;

	/*
	 * Get starting offset for readaround, and number of pages to read.
	 * Adjust starting address by readbehind (for NUMA interleave case)?
	 * No, it's very unlikely that swap layout would follow vma layout,
	 * more likely that neighbouring swap pages came from the same node:
	 * so use the same "addr" to choose the same node for each swap read.
	 */
	 //下面的读包含了预读的页数..
	 //但是可能有发生错误，然后没有把目标页读取出来...
	nr_pages = valid_swaphandles(entry, &offset);
	for (end_offset = offset + nr_pages; offset < end_offset; offset++) {
		/* Ok, do the async read-ahead now */
		page = read_swap_cache_async(swp_entry(swp_type(entry), offset),
						gfp_mask, vma, addr);
		if (!page)
			break;
		page_cache_release(page);
	}
	lru_add_drain();	/* Push any new pages onto the LRU now */
	//专门调用一次从swap area中获取出来..因为上面可能出错导致说没有读取出来
	//有时候这个步奏看起来就是有点多余.
	return read_swap_cache_async(entry, gfp_mask, vma, addr);
}
