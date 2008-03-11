#ifndef COMPAT_SKBUFF_H
#define COMPAT_SKBUFF_H 1

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19)
#	define skb_nfmark(skb) (((struct sk_buff *)(skb))->nfmark)
#else
#	define skb_nfmark(skb) (((struct sk_buff *)(skb))->mark)
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 21)
#	define ip_hdr(skb) ((skb)->nh.iph)
#	define ip_hdrlen(skb) (ip_hdr(skb)->ihl * 4)
#	define skb_network_header(skb) ((skb)->nh.raw)
static inline void skb_reset_network_header(struct sk_buff *skb)
{
	skb->nh.raw = skb->data;
}
#endif

#endif /* COMPAT_SKBUFF_H */
