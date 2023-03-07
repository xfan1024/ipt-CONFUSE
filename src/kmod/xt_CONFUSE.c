// SPDX-License-Identifier: GPL-2.0-only
/*
 * modify udp packet data to avoid deep packet inspection
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter/x_tables.h>
#include <net/udp.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/ipv6.h>
#include <net/ip6_checksum.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xiaofan <xfan1024@live.com>");
MODULE_DESCRIPTION("Xtables: modify udp packet data to avoid DPI");

struct nf_confuse_param
{
	__u64  srand;
};

static inline u64 xorshift_next(u64 x64)
{
	x64 ^= x64 << 13;
	x64 ^= x64 >> 7;
	x64 ^= x64 << 17;
	return x64;
}

static void confuse_data(u8 *data, unsigned int len, u64 srand) {
	unsigned int i;
	union {
		u8 bytes[8];
		u64 val;
	} u;

	while (likely(len >= 8)) {
		srand = xorshift_next(srand);
		u.val = cpu_to_le64(srand);
		for (i = 0; i < 8; i++) {
			*data++ ^= u.bytes[i];
		}
		len -= 8;
	}
	if (likely(len)) {
		srand = xorshift_next(srand);
		u.val = cpu_to_le64(srand);
		for (i = 0; i < len; i++) {
			*data++ ^= u.bytes[i];
		}
	}
}

static unsigned int
confuse_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct nf_confuse_param *param = par->targinfo;
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *uh = udp_hdr(skb);
	unsigned int l3_hdr_len;
	unsigned int l4_total;
	unsigned int data_len;
	u8 *data;
	u8 prot;

	if (iph->version == 4) {
		prot = iph->protocol;
		l3_hdr_len = (unsigned int)sizeof(struct iphdr);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (iph->version == 6) {
		prot = ((struct ipv6hdr*)iph)->nexthdr;
		l3_hdr_len = (unsigned int)sizeof(struct ipv6hdr);
	}
#endif
	else {
		pr_warn("unknown ip version: %u\n", iph->version);
		return NF_DROP;
	}

	if (prot != IPPROTO_UDP) {
		pr_warn("only used for udp\n");
		return XT_CONTINUE;
	}

	l4_total = be16_to_cpu(uh->len);
	if (skb_linearize(skb)) {
		pr_warn("skb_linearize skb fail");
		return NF_DROP;
	}

	if (!pskb_may_pull(skb, l3_hdr_len + l4_total)) {
		pr_warn("pskb_may_pull fail\n");
		return NF_DROP;
	}
	data = (u8*)(udp_hdr(skb) + 1);
	data_len = l4_total - sizeof(struct udphdr);
	confuse_data(data, data_len, param->srand);
	if (!skb->skb_iif) {
		if (skb->ip_summed == CHECKSUM_NONE) {
			// fix csum only send-skb not offload
			if (iph->version == 4) {
				udp_set_csum(false, skb, iph->saddr, iph->daddr, l4_total);
			}
#if IS_ENABLED(CONFIG_IPV6)
			else if (iph->version == 6) {
				struct ipv6hdr *ip6h = ipv6_hdr(skb);
				udp6_set_csum(false, skb, &ip6h->saddr, &ip6h->daddr, l4_total);
			}
#endif
		}
	}
	else {
		if (skb->ip_summed == CHECKSUM_NONE) {
			// simply set no need to check csum only recv-skb not offload
			// maybe we could check csum before confuse_data called
			// but it consumes cpu performance and not necessary
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			uh->check = 0;
		}
	}
	return XT_CONTINUE;
}

static struct xt_target confuse_tg_reg[] __read_mostly = {
	{
#if IS_ENABLED(CONFIG_IPV6)
		.name		= "CONFUSE",
		.family		= NFPROTO_IPV6,
		.target		= confuse_tg,
		.targetsize	= sizeof(struct nf_confuse_param),
		.table		= "mangle",
		.hooks		= (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_LOCAL_OUT),
		.me		= THIS_MODULE,
	},
#endif
	{
		.name		= "CONFUSE",
		.family		= NFPROTO_IPV4,
		.target		= confuse_tg,
		.targetsize	= sizeof(struct nf_confuse_param),
		.table		= "mangle",
		.hooks		= (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_LOCAL_OUT),
		.me		= THIS_MODULE,
	},
};

static int __init confuse_tg_init(void)
{
	return xt_register_targets(confuse_tg_reg,
				  ARRAY_SIZE(confuse_tg_reg));
}

static void __exit confuse_tg_exit(void)
{
	xt_unregister_targets(confuse_tg_reg, ARRAY_SIZE(confuse_tg_reg));
}

module_init(confuse_tg_init);
module_exit(confuse_tg_exit);
#if IS_ENABLED(CONFIG_IPV6)
MODULE_ALIAS("ip6t_CONFUSE");
#endif
MODULE_ALIAS("ipt_CONFUSE");
