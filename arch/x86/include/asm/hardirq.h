#ifndef _ASM_X86_HARDIRQ_H
#define _ASM_X86_HARDIRQ_H

#include <linux/threads.h>
#include <linux/irq.h>
/*
linux 软中断有个原则就是"谁触发，谁执行" "who marks, who runs" ..因为对于每个CPU
来说，都需要一个数据结构来描述触发和控制....那就是下面这个结构体咯..
被定义在softirq.c文件，数组项的数目当前就是系统CPU的数目:
#ifndef __ARCH_IRQ_STAT
irq_cpustat_t irq_stat[NR_CPUS] ____cacheline_aligned;
EXPORT_SYMBOL(irq_stat);
#endif

当前linux支持32个软终端...
下面的字段和触发与控制是相关的.
__softirq_pending,,记录当前这个CPU的某个软中断是否被挂起..每个bit代表一个中断咯..

*/
typedef struct {
	unsigned int __softirq_pending;
	unsigned int __nmi_count;	/* arch dependent */
	unsigned int irq0_irqs;
#ifdef CONFIG_X86_LOCAL_APIC
	unsigned int apic_timer_irqs;	/* arch dependent */
	unsigned int irq_spurious_count;
#endif
	unsigned int generic_irqs;	/* arch dependent */
#ifdef CONFIG_SMP
	unsigned int irq_resched_count;
	unsigned int irq_call_count;
	unsigned int irq_tlb_count;
#endif
#ifdef CONFIG_X86_MCE
	unsigned int irq_thermal_count;
# ifdef CONFIG_X86_64
	unsigned int irq_threshold_count;
# endif
#endif
} ____cacheline_aligned irq_cpustat_t;

DECLARE_PER_CPU_SHARED_ALIGNED(irq_cpustat_t, irq_stat);

/* We can have at most NR_VECTORS irqs routed to a cpu at a time */
#define MAX_HARDIRQS_PER_CPU NR_VECTORS

#define __ARCH_IRQ_STAT

#define inc_irq_stat(member)	percpu_add(irq_stat.member, 1)

#define local_softirq_pending()	percpu_read(irq_stat.__softirq_pending)

#define __ARCH_SET_SOFTIRQ_PENDING

#define set_softirq_pending(x)	percpu_write(irq_stat.__softirq_pending, (x))
#define or_softirq_pending(x)	percpu_or(irq_stat.__softirq_pending, (x))

extern void ack_bad_irq(unsigned int irq);

extern u64 arch_irq_stat_cpu(unsigned int cpu);
#define arch_irq_stat_cpu	arch_irq_stat_cpu

extern u64 arch_irq_stat(void);
#define arch_irq_stat		arch_irq_stat

#endif /* _ASM_X86_HARDIRQ_H */
