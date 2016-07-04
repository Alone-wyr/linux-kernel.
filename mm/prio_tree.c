/*
 * mm/prio_tree.c - priority search tree for mapping->i_mmap
 *
 * Copyright (C) 2004, Rajesh Venkatasubramanian <vrajesh@umich.edu>
 *
 * This file is released under the GPL v2.
 *
 * Based on the radix priority search tree proposed by Edward M. McCreight
 * SIAM Journal of Computing, vol. 14, no.2, pages 257-276, May 1985
 *
 * 02Feb2004	Initial version
 */

#include <linux/mm.h>
#include <linux/prio_tree.h>

/*
 * See lib/prio_tree.c for details on the general radix priority search tree
 * code.
 */

/*
 * The following #defines are mirrored from lib/prio_tree.c. They're only used
 * for debugging, and should be removed (along with the debugging code using
 * them) when switching also VMAs to the regular prio_tree code.
 */

#define RADIX_INDEX(vma)  ((vma)->vm_pgoff)
#define VMA_SIZE(vma)	  (((vma)->vm_end - (vma)->vm_start) >> PAGE_SHIFT)
/* avoid overflow */
#define HEAP_INDEX(vma)   ((vma)->vm_pgoff + (VMA_SIZE(vma) - 1))

/*
 * Radix priority search tree for address_space->i_mmap
 *
 * For each vma that map a unique set of file pages i.e., unique [radix_index,
 * heap_index] value, we have a corresponding priority search tree node. If
 * multiple vmas have identical [radix_index, heap_index] value, then one of
 * them is used as a tree node and others are stored in a vm_set list. The tree
 * node points to the first vma (head) of the list using vm_set.head.
 *
 * prio_tree_root
 *      |
 *      A       vm_set.head
 *     / \      /
 *    L   R -> H-I-J-K-M-N-O-P-Q-S
 *    ^   ^    <-- vm_set.list -->
 *  tree nodes
 *
 * We need some way to identify whether a vma is a tree node, head of a vm_set
 * list, or just a member of a vm_set list. We cannot use vm_flags to store
 * such information. The reason is, in the above figure, it is possible that
 * vm_flags' of R and H are covered by the different mmap_sems. When R is
 * removed under R->mmap_sem, H replaces R as a tree node. Since we do not hold
 * H->mmap_sem, we cannot use H->vm_flags for marking that H is a tree node now.
 * That's why some trick involving shared.vm_set.parent is used for identifying
 * tree nodes and list head nodes.
 *
 * vma radix priority search tree node rules:
 *
 * vma->shared.vm_set.parent != NULL    ==> a tree node
 *      vma->shared.vm_set.head != NULL ==> list of others mapping same range
 *      vma->shared.vm_set.head == NULL ==> no others map the same range
 *
 * vma->shared.vm_set.parent == NULL
 * 	vma->shared.vm_set.head != NULL ==> list head of vmas mapping same range
 * 	vma->shared.vm_set.head == NULL ==> a list node
 */

/*
 * Add a new vma known to map the same set of pages as the old vma:
 * useful for fork's dup_mmap as well as vma_prio_tree_insert below.
 * Note that it just happens to work correctly on i_mmap_nonlinear too.
 */
void vma_prio_tree_add(struct vm_area_struct *vma, struct vm_area_struct *old)
{
	/* Leave these BUG_ONs till prio_tree patch stabilizes */
	BUG_ON(RADIX_INDEX(vma) != RADIX_INDEX(old));
	BUG_ON(HEAP_INDEX(vma) != HEAP_INDEX(old));

	vma->shared.vm_set.head = NULL;
	vma->shared.vm_set.parent = NULL;

	if (!old->shared.vm_set.parent)
		list_add(&vma->shared.vm_set.list,
				&old->shared.vm_set.list);
	else if (old->shared.vm_set.head)
		list_add_tail(&vma->shared.vm_set.list,
				&old->shared.vm_set.head->shared.vm_set.list);
	else {
		INIT_LIST_HEAD(&vma->shared.vm_set.list);
		vma->shared.vm_set.head = old;
		old->shared.vm_set.head = vma;
	}
}

void vma_prio_tree_insert(struct vm_area_struct *vma,
			  struct prio_tree_root *root)
{
	struct prio_tree_node *ptr;
	struct vm_area_struct *old;

	vma->shared.vm_set.head = NULL;

	ptr = raw_prio_tree_insert(root, &vma->shared.prio_tree_node);
	if (ptr != (struct prio_tree_node *) &vma->shared.prio_tree_node) {
		old = prio_tree_entry(ptr, struct vm_area_struct,
					shared.prio_tree_node);
		vma_prio_tree_add(vma, old);
	}
}

//参考本文件34行的注释.....
//parent是否为空来判断这个节点是不是在priority tree上..
//head的节点用来判断后面有没有外接一个链表..
//需要注意的是链表的第一个结点的head指向了头(也就是在tree的结点).
//假设在tree的结点为A，后面链表接了B和C.
//A->head = B...
//B->head = A... 就是这个意思。B作为链表第一个结点，它的head指向头。而B和C是通过list字段链接的。
void vma_prio_tree_remove(struct vm_area_struct *vma,
			  struct prio_tree_root *root)
{
	struct vm_area_struct *node, *head, *new_head;
	if (!vma->shared.vm_set.head) {
		
		if (!vma->shared.vm_set.parent)
			//这里代表vma指向的只是priority tree node的链表中的一个node。并且不是第一个node。否则head字段不为NULL。
			list_del_init(&vma->shared.vm_set.list);
		else
			//这里代表vma是priority tree node，并且没有后接链表，直接从tree上remove掉。
			raw_prio_tree_remove(root, &vma->shared.prio_tree_node);
		//上面的else就是从priority search tree中直接移除掉..而且是在没有相同映射区间的..
		//如果有相同映射区间的话vm_set.head不为NULL。
	} else {
		/* Leave this BUG_ON till prio_tree patch stabilizes */
		BUG_ON(vma->shared.vm_set.head->shared.vm_set.head != vma);
		if (vma->shared.vm_set.parent) {
			//*****来到这里代表要移除的是priority tree node,而且后面接着一个链表(vma->node != NULL).
			
			//head获取了vma的下一个结点..
			head = vma->shared.vm_set.head;
			//然后在判断head是不是最后一个结点..因为等下head要作为树的结点替代vma..
			if (!list_empty(&head->shared.vm_set.list)) {
				//不是最后一个那么保存下一个vm_area_struct结点，它等下作为链表的第一个结点.
				//替换掉head的位置...而head要替换掉vma的位置.
				new_head = list_entry(
					head->shared.vm_set.list.next,
					struct vm_area_struct,
					shared.vm_set.list);
				//如果不是最后一个，那么把head从链表中删除.
				list_del_init(&head->shared.vm_set.list);
			} else
				new_head = NULL; //否则设置为NULL，代表链表没有结点咯。

			//前面处理完成了。先把head替换掉vma的位置
			raw_prio_tree_replace(root, &vma->shared.prio_tree_node,
					&head->shared.prio_tree_node);
			//设置它的第一个链表结点，这些结点都是具有相同的映射区域的。
			head->shared.vm_set.head = new_head;
			//第一个结点的head指向头结点...
			if (new_head)
				new_head->shared.vm_set.head = head;

		} else {
		//******来到这里代表vma指向的是链表的第一个结点..记住它的head是指向头结点的(priority tree node).
		
			node = vma->shared.vm_set.head;
			if (!list_empty(&vma->shared.vm_set.list)) {
				new_head = list_entry(
					vma->shared.vm_set.list.next,
					struct vm_area_struct,
					shared.vm_set.list);
				list_del_init(&vma->shared.vm_set.list);
				node->shared.vm_set.head = new_head;
				new_head->shared.vm_set.head = node;
			} else
				node->shared.vm_set.head = NULL;
		}
	}
}

/*
 * Helper function to enumerate vmas that map a given file page or a set of
 * contiguous file pages. The function returns vmas that at least map a single
 * page in the given range of contiguous file pages.
 */
struct vm_area_struct *vma_prio_tree_next(struct vm_area_struct *vma,
					struct prio_tree_iter *iter)
{
	struct prio_tree_node *ptr;
	struct vm_area_struct *next;

	if (!vma) {
		/*
		 * First call is with NULL vma
		 */
		ptr = prio_tree_next(iter);
		if (ptr) {
			next = prio_tree_entry(ptr, struct vm_area_struct,
						shared.prio_tree_node);
			prefetch(next->shared.vm_set.head);
			return next;
		} else
			return NULL;
	}

	if (vma->shared.vm_set.parent) {
		if (vma->shared.vm_set.head) {
			next = vma->shared.vm_set.head;
			prefetch(next->shared.vm_set.list.next);
			return next;
		}
	} else {
		next = list_entry(vma->shared.vm_set.list.next,
				struct vm_area_struct, shared.vm_set.list);
		if (!next->shared.vm_set.head) {
			prefetch(next->shared.vm_set.list.next);
			return next;
		}
	}

	ptr = prio_tree_next(iter);
	if (ptr) {
		next = prio_tree_entry(ptr, struct vm_area_struct,
					shared.prio_tree_node);
		prefetch(next->shared.vm_set.head);
		return next;
	} else
		return NULL;
}
