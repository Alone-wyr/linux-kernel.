#ifndef __LINUX_NETLINK_H
#define __LINUX_NETLINK_H

#include <linux/socket.h> /* for sa_family_t */
#include <linux/types.h>

#define NETLINK_ROUTE		0	/* Routing/device hook				*/
#define NETLINK_UNUSED		1	/* Unused number				*/
#define NETLINK_USERSOCK	2	/* Reserved for user mode socket protocols 	*/
#define NETLINK_FIREWALL	3	/* Firewalling hook				*/
#define NETLINK_INET_DIAG	4	/* INET socket monitoring			*/
#define NETLINK_NFLOG		5	/* netfilter/iptables ULOG */
#define NETLINK_XFRM		6	/* ipsec */
#define NETLINK_SELINUX		7	/* SELinux event notifications */
#define NETLINK_ISCSI		8	/* Open-iSCSI */
#define NETLINK_AUDIT		9	/* auditing */
#define NETLINK_FIB_LOOKUP	10	
#define NETLINK_CONNECTOR	11
#define NETLINK_NETFILTER	12	/* netfilter subsystem */
#define NETLINK_IP6_FW		13
#define NETLINK_DNRTMSG		14	/* DECnet routing messages */
#define NETLINK_KOBJECT_UEVENT	15	/* Kernel messages to userspace */
#define NETLINK_GENERIC		16
/* leave room for NETLINK_DM (DM Events) */
#define NETLINK_SCSITRANSPORT	18	/* SCSI Transports */
#define NETLINK_ECRYPTFS	19

#define MAX_LINKS 32		

struct net;

struct sockaddr_nl
{
	sa_family_t	nl_family;	/* AF_NETLINK	*/
	unsigned short	nl_pad;		/* zero		*/
	__u32		nl_pid;		/* port ID	*/
       	__u32		nl_groups;	/* multicast groups mask */
};

/*
该结构体是netlink的头...在用户进程中设置好各字段的值...然后调用sendmsg发送到内核.
创建socket的时候指定了消息发送给哪个protocol...但是可能protocol里面还要细分更多的处理..
此时就需要通过type字段来细分啦.当然也可以通过flags来细分...

对于NETLINK_GENERIC协议来说....它根据type来确定一个family...
确定了family,,family有个cmd字段来确定操作集合(ops)..然后每个操作集合又有doit和dumpit函数.
在根据下面的nlmsg_flags的标记来判断到底是调用doit还是dumpit.
*/
struct nlmsghdr
{
			//消息和头的长度和...这个长度需要特别注意..
			//它指示的应该是header(对齐后的长度) + message的长度(没有经过对齐!!!)
	__u32		nlmsg_len;	/* Length of message including header */
	__u16		nlmsg_type;	/* Message content */
	__u16		nlmsg_flags;	/* Additional flags */
	__u32		nlmsg_seq;	/* Sequence number */
	__u32		nlmsg_pid;	/* Sending process port ID */
};

/* Flags values */

#define NLM_F_REQUEST		1	/* It is request message. 	*/
#define NLM_F_MULTI		2	/* Multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK		4	/* Reply with ack, with zero or error code */
#define NLM_F_ECHO		8	/* Echo this request 		*/

/* Modifiers to GET request */
#define NLM_F_ROOT	0x100	/* specify tree	root	*/
#define NLM_F_MATCH	0x200	/* return all matching	*/
#define NLM_F_ATOMIC	0x400	/* atomic GET		*/
#define NLM_F_DUMP	(NLM_F_ROOT|NLM_F_MATCH)

/* Modifiers to NEW request */
#define NLM_F_REPLACE	0x100	/* Override existing		*/
#define NLM_F_EXCL	0x200	/* Do not touch, if it exists	*/
#define NLM_F_CREATE	0x400	/* Create, if it does not exist	*/
#define NLM_F_APPEND	0x800	/* Add to end of list		*/

/*
   4.4BSD ADD		NLM_F_CREATE|NLM_F_EXCL
   4.4BSD CHANGE	NLM_F_REPLACE

   True CHANGE		NLM_F_CREATE|NLM_F_REPLACE
   Append		NLM_F_CREATE
   Check		NLM_F_EXCL
 */

#define NLMSG_ALIGNTO	4
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
	//这个宏是确定netlink消息数据的长度??这里的长度是经过对齐后的header加上没有对齐的data长度...
	//这样就可以计算出data的具体长度了..
#define NLMSG_LENGTH(len) ((len)+NLMSG_ALIGN(NLMSG_HDRLEN))
	//这个宏是确定netlink消息占用的空间大小...需要特别注意和NLMSG_LENGTH的差别..这个很重要!!!灵活运用这2个宏.
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
	//返回data的起始地址..
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
				  (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
	//查看了下这个宏的使用场景...netlink的消息封装有时候是netlink header + protocol header + payload..
	//eg: #define RTM_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct rtmsg))
	//就是得到去掉netlink header 和 rtmsg的长度...得到实际中的payload的长度了..!!!
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))

#define NLMSG_NOOP		0x1	/* Nothing.		*/
#define NLMSG_ERROR		0x2	/* Error		*/
#define NLMSG_DONE		0x3	/* End of a dump	*/
#define NLMSG_OVERRUN		0x4	/* Data lost		*/

#define NLMSG_MIN_TYPE		0x10	/* < 0x10: reserved control messages */

struct nlmsgerr
{
	int		error;
	struct nlmsghdr msg;
};

#define NETLINK_ADD_MEMBERSHIP	1
#define NETLINK_DROP_MEMBERSHIP	2
#define NETLINK_PKTINFO		3
#define NETLINK_BROADCAST_ERROR	4
#define NETLINK_NO_ENOBUFS	5

struct nl_pktinfo
{
	__u32	group;
};

#define NET_MAJOR 36		/* Major 36 is reserved for networking 						*/

enum {
	NETLINK_UNCONNECTED = 0,
	NETLINK_CONNECTED,
};

/*
 *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 * |        Header       | Pad |     Payload       | Pad |
 * |   (struct nlattr)  | ing  |                         | ing  |
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 *  <-------------- nlattr->nla_len -------------->
 */

struct nlattr
{
	__u16           nla_len;
	__u16           nla_type;
};

/*
 * nla_type (16 bits)
 * +---+---+-------------------------------+
 * | N | O | Attribute Type                |
 * +---+---+-------------------------------+
 * N := Carries nested attributes
 * O := Payload stored in network byte order
 *
 * Note: The N and O flag are mutually exclusive.
 */
#define NLA_F_NESTED		(1 << 15)
#define NLA_F_NET_BYTEORDER	(1 << 14)
#define NLA_TYPE_MASK		~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

#define NLA_ALIGNTO		4
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN		((int) NLA_ALIGN(sizeof(struct nlattr)))

#ifdef __KERNEL__

#include <linux/capability.h>
#include <linux/skbuff.h>

static inline struct nlmsghdr *nlmsg_hdr(const struct sk_buff *skb)
{
	return (struct nlmsghdr *)skb->data;
}
/*
	作为skb里面的CB.
*/
struct netlink_skb_parms
{
	struct ucred		creds;		/* Skb credentials	*/
		//发送者的pid号.
	__u32			pid;
		//接受该skb数据包的组.
	__u32			dst_group;
	kernel_cap_t		eff_cap;
	__u32			loginuid;	/* Login (audit) uid */
	__u32			sessionid;	/* Session id (audit) */
	__u32			sid;		/* SELinux security id */
};

#define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))
#define NETLINK_CREDS(skb)	(&NETLINK_CB((skb)).creds)


extern struct sock *netlink_kernel_create(struct net *net,
					  int unit,unsigned int groups,
					  void (*input)(struct sk_buff *skb),
					  struct mutex *cb_mutex,
					  struct module *module);
extern void netlink_kernel_release(struct sock *sk);
extern int netlink_change_ngroups(struct sock *sk, unsigned int groups);
extern void netlink_clear_multicast_users(struct sock *sk, unsigned int group);
extern void netlink_ack(struct sk_buff *in_skb, struct nlmsghdr *nlh, int err);
extern int netlink_has_listeners(struct sock *sk, unsigned int group);
extern int netlink_unicast(struct sock *ssk, struct sk_buff *skb, __u32 pid, int nonblock);
extern int netlink_broadcast(struct sock *ssk, struct sk_buff *skb, __u32 pid,
			     __u32 group, gfp_t allocation);
extern void netlink_set_err(struct sock *ssk, __u32 pid, __u32 group, int code);
extern int netlink_register_notifier(struct notifier_block *nb);
extern int netlink_unregister_notifier(struct notifier_block *nb);

/* finegrained unicast helpers: */
struct sock *netlink_getsockbyfilp(struct file *filp);
int netlink_attachskb(struct sock *sk, struct sk_buff *skb,
		      long *timeo, struct sock *ssk);
void netlink_detachskb(struct sock *sk, struct sk_buff *skb);
int netlink_sendskb(struct sock *sk, struct sk_buff *skb);

/*
 *	skb should fit one page. This choice is good for headerless malloc.
 *	But we should limit to 8K so that userspace does not have to
 *	use enormous buffer sizes on recvmsg() calls just to avoid
 *	MSG_TRUNC when PAGE_SIZE is very large.
 */
#if PAGE_SIZE < 8192UL
#define NLMSG_GOODSIZE	SKB_WITH_OVERHEAD(PAGE_SIZE)
#else
#define NLMSG_GOODSIZE	SKB_WITH_OVERHEAD(8192UL)
#endif

#define NLMSG_DEFAULT_SIZE (NLMSG_GOODSIZE - NLMSG_HDRLEN)


struct netlink_callback
{
	struct sk_buff	*skb;
	struct nlmsghdr	*nlh;
	int		(*dump)(struct sk_buff * skb, struct netlink_callback *cb);
	int		(*done)(struct netlink_callback *cb);
	int		family;
	long		args[6];
};

struct netlink_notify
{
	struct net *net;
	int pid;
	int protocol;
};

static __inline__ struct nlmsghdr *
__nlmsg_put(struct sk_buff *skb, u32 pid, u32 seq, int type, int len, int flags)
{
	struct nlmsghdr *nlh;
	int size = NLMSG_LENGTH(len);

	nlh = (struct nlmsghdr*)skb_put(skb, NLMSG_ALIGN(size));
	nlh->nlmsg_type = type;
	nlh->nlmsg_len = size;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_pid = pid;
	nlh->nlmsg_seq = seq;
	if (!__builtin_constant_p(size) || NLMSG_ALIGN(size) - size != 0)
		memset(NLMSG_DATA(nlh) + len, 0, NLMSG_ALIGN(size) - size);
	return nlh;
}
/*
创建一个netlink的消息....会先判断skb的空间(tailroom)是否可以容纳netlink消息..(判断)
*/
#define NLMSG_NEW(skb, pid, seq, type, len, flags) \
({	if (unlikely(skb_tailroom(skb) < (int)NLMSG_SPACE(len))) \
		goto nlmsg_failure; \
	__nlmsg_put(skb, pid, seq, type, len, flags); })

#define NLMSG_PUT(skb, pid, seq, type, len) \
	NLMSG_NEW(skb, pid, seq, type, len, 0)

extern int netlink_dump_start(struct sock *ssk, struct sk_buff *skb,
			      struct nlmsghdr *nlh,
			      int (*dump)(struct sk_buff *skb, struct netlink_callback*),
			      int (*done)(struct netlink_callback*));


#define NL_NONROOT_RECV 0x1
#define NL_NONROOT_SEND 0x2
extern void netlink_set_nonroot(int protocol, unsigned flag);

#endif /* __KERNEL__ */

#endif	/* __LINUX_NETLINK_H */
