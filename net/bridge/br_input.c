/*
 *	Handle incoming frames
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_bridge.h>
#include "br_private.h"

/* Bridge group multicast address 802.1d (pg 51). */
const u8 br_group_address[ETH_ALEN] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

static void br_pass_frame_up(struct net_bridge *br, struct sk_buff *skb)
{
	struct net_device *indev, *brdev = br->dev;

	brdev->stats.rx_packets++;
	brdev->stats.rx_bytes += skb->len;

	indev = skb->dev;	//indev = "eth1"
	skb->dev = brdev;	//skb->dev="br0"

	NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, indev, NULL, netif_receive_skb);
}

/* note: already called with rcu_read_lock (preempt_disabled) */
int br_handle_frame_finish(struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	struct net_bridge_port *p = rcu_dereference(skb->dev->br_port);
	struct net_bridge *br;
	struct net_bridge_fdb_entry *dst;
	struct sk_buff *skb2;

	if (!p || p->state == BR_STATE_DISABLED)
		goto drop;

	/* insert into forwarding database after filtering to avoid spoofing */
	//帧的源MAC地址都会加入到数据库....
	br = p->br;
	br_fdb_update(br, p, eth_hdr(skb)->h_source);
	//处于学习状态..在上面的函数学习好了...就把数据包给丢了..
	//它并不会去转发数据包咯.!!
	if (p->state == BR_STATE_LEARNING)
		goto drop;

	/* The packet skb2 goes to the local host (NULL to skip). */
	skb2 = NULL;

	if (br->dev->flags & IFF_PROMISC)
		skb2 = skb;

	dst = NULL;

	if (is_multicast_ether_addr(dest)) {
		br->dev->stats.multicast++;
		skb2 = skb;
	} else if ((dst = __br_fdb_get(br, dest)) && dst->is_local) {
	/*
	这里是一个重要的过程...尝试去在转发数据库里面寻找entry...
	*/
		skb2 = skb;									
		/* Do not forward the packet since it's local. */
		skb = NULL;
	}

	if (skb2 == skb)
		skb2 = skb_clone(skb, GFP_ATOMIC);				//执行到这里面..
	/*
	只要skb2不为空...则会调用函数br_pass_frame_up，该函数是把数据包再次调用netif_receive_skb..
	1.网卡处于混杂模式..(那就是接受任何数据包咯..因此也需要发送到本地.)
	2.数据包指示的MAC地址为多播..
	3.转发数据库找到的entry指明是本地的..
	*/
	if (skb2)
		br_pass_frame_up(br, skb2);	

	if (skb) {
		if (dst)
			br_forward(dst->dst, skb);	//知道数据包应该转发到哪个接口.!!!
		else
			br_flood_forward(br, skb);	//转发数据库里面找不到出口设备...因为就flood出去...!!!
	}

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}

/* note: already called with rcu_read_lock (preempt_disabled) */
static int br_handle_local_finish(struct sk_buff *skb)
{
	struct net_bridge_port *p = rcu_dereference(skb->dev->br_port);

	if (p)
		br_fdb_update(p->br, p, eth_hdr(skb)->h_source);
	return 0;	 /* process further */
}

/* Does address match the link local multicast address.
 * 01:80:c2:00:00:0X
 */
static inline int is_link_local(const unsigned char *dest)
{
	__be16 *a = (__be16 *)dest;
	static const __be16 *b = (const __be16 *)br_group_address;
	static const __be16 m = cpu_to_be16(0xfff0);

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | ((a[2] ^ b[2]) & m)) == 0;
}

/*
 * Called via br_handle_frame_hook.
 * Return NULL if skb is handled
 * note: already called with rcu_read_lock (preempt_disabled)
 */
struct sk_buff *br_handle_frame(struct net_bridge_port *p, struct sk_buff *skb)
{
	const unsigned char *dest = eth_hdr(skb)->h_dest;
	int (*rhook)(struct sk_buff *skb);

	if (!is_valid_ether_addr(eth_hdr(skb)->h_source))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return NULL;

	if (unlikely(is_link_local(dest))) {
		/* Pause frames shouldn't be passed up by driver anyway */
		if (skb->protocol == htons(ETH_P_PAUSE))
			goto drop;

		/* If STP is turned off, then forward */
		if (p->br->stp_enabled == BR_NO_STP && dest[5] == 0)
			goto forward;

		if (NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_IN, skb, skb->dev,
			    NULL, br_handle_local_finish))
			return NULL;	/* frame consumed by filter */
		else
			return skb;	/* continue processing */
	}

forward:
	switch (p->state) {
	case BR_STATE_FORWARDING:
		rhook = rcu_dereference(br_should_route_hook);
		if (rhook != NULL) {
			if (rhook(skb))
				return skb;
			dest = eth_hdr(skb)->h_dest;
		}
		/* fall through */
	case BR_STATE_LEARNING:
		//判断是不是发送给自己的...比较网桥设备的链路层地址..
		if (!compare_ether_addr(p->br->dev->dev_addr, dest))
			skb->pkt_type = PACKET_HOST;

		NF_HOOK(PF_BRIDGE, NF_BR_PRE_ROUTING, skb, skb->dev, NULL, br_handle_frame_finish);
		break;
	default:
	/*
	网桥端口处于BR_STATE_FORWARDING才可以转发数据的.不处于该状态直接丢弃掉数据.
	*/
drop:
		kfree_skb(skb);
	}
	return NULL;
}
