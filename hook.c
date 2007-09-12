#include <linux/ip.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/connector.h>
#include <linux/netfilter.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/version.h>

#include <net/ip.h>
#include <net/sock.h>

#include "hook.h"

#define HOOK_MAGIC_HEADER_SIZE 	16
#define HOOK_MAGIC 		0xcafe1234
#define IN_DEV 			"eth0"
#define OUT_DEV 		"eth0"

static struct net_device *in_dev;
static struct net_device *out_dev;
static struct cb_id cn_hook_in_id 	= { .idx = HOOK_IN_ID, .val = HOOK_ID_VAL };
static struct cb_id cn_hook_out_id 	= { .idx = HOOK_OUT_ID, .val = HOOK_ID_VAL };

static void hk_uspace_to_in(void *arg)
{
	struct cn_msg *m = arg;
	struct sk_buff *skb;
	int ret;
	int size;

	size = m->len + HOOK_MAGIC_HEADER_SIZE + 2;
	skb = dev_alloc_skb(size);
	if (!skb) {
		printk("%s: cannot allocate: %d bytes\n", __FUNCTION__, size);
		return;
	}

	skb_reserve(skb, HOOK_MAGIC_HEADER_SIZE);
	*(unsigned int *)skb->head = HOOK_MAGIC;

	skb_reserve(skb, 2);

         /* copy the data into the sk_buff */
	memcpy(skb->data, m->data, m->len);
	skb_put(skb, m->len);

        skb->protocol = eth_type_trans(skb, in_dev);
	ret = netif_rx(skb);

	return;
}

static void hk_uspace_to_out(void *arg)
{
	struct cn_msg *m = arg;
	struct sk_buff *skb;
	int ret;
	int size;

	size = m->len + 2;
	skb = dev_alloc_skb(size);
	if (!skb) {
		printk("%s: cannot allocate: %d bytes\n", __FUNCTION__, size);
		return;
	}

	skb_reserve(skb, 2);

         /* copy the data into the sk_buff */
	memcpy(skb->data, m->data, m->len);
	skb_put(skb, m->len);
        skb->protocol = htons(((struct ethhdr *)skb->data)->h_proto);
	skb_pull(skb, sizeof(struct ethhdr));
	skb_reset_network_header(skb);

	skb->dev = out_dev;
	if (out_dev->hard_header) {
		/*
		 * We can pass NULL as dest mac header, because this was set
		 * when sent to user space (see pep_out)
		 */
		out_dev->hard_header(skb, out_dev, ntohs(skb->protocol), NULL, out_dev->dev_addr, skb->len);
	}
	ret = dev_queue_xmit(skb);

	return;
}

static int hk_send_to_usr_space(struct sk_buff *skb, struct cb_id *id)
{
	struct cn_msg *m;
	int ret = 0;

	/* get back to the eth header */
	skb_push(skb, sizeof(struct ethhdr));

	m = kzalloc(sizeof(*m) + skb->len, gfp_any());
	if (!m) {
		printk("cannot allocate %d bytes\n", skb->len + sizeof(*m));
		ret = -ENOMEM;
		goto out;
	}

	memcpy(&m->id, id, sizeof(m->id));
	m->seq = 0;
	m->len = skb->len;

	memcpy(m->data, skb->data, skb->len);

	ret = cn_netlink_send(m, 0, gfp_any());

	kfree(m);
out:
	return ret;
}

#ifdef TEST_IP
/* static unsigned int test_ip = htonl(0xd41b300a); */ /* 212.27.48.10 */
static unsigned int test_ip = htonl(0xc0a80101); /* 192.168.1.1 */
#endif

static unsigned int
pep_in(unsigned int hooknum, struct sk_buff **pskb,
	 const struct net_device *in, const struct net_device *out,
	 int (*okfn)(struct sk_buff *))
{
	int ret;
#ifdef TEST_IP
	struct iphdr *iph = (struct iphdr *)skb_network_header(*pskb);
#endif

	if ((*(unsigned int *)(*pskb)->head) != HOOK_MAGIC
#ifdef TEST_IP
		&& (iph->daddr == test_ip || iph->saddr == test_ip)
#endif
	) {
		ret = hk_send_to_usr_space(*pskb, &cn_hook_in_id);
		kfree_skb(*pskb);
		return NF_STOLEN;
	}
	return NF_ACCEPT;
}

static unsigned int
pep_out(unsigned int hooknum, struct sk_buff **pskb,
	 const struct net_device *in, const struct net_device *out,
	 int (*okfn)(struct sk_buff *))
{
	int ret;
	struct ethhdr *eth;
#ifdef TEST_IP
	struct iphdr *iph = (struct iphdr *)skb_network_header(*pskb);
#endif

	if ((*(unsigned int *)(*pskb)->head) != HOOK_MAGIC
#ifdef TEST_IP
		&& (iph->daddr == test_ip || iph->saddr == test_ip)
#endif
	) {
		/* Save the dest mac now, it will be lost otherwise */
		if ((*pskb)->dst && (*pskb)->dst->neighbour) {
			skb_push((*pskb), sizeof(struct ethhdr));
			eth = (struct ethhdr *)(*pskb)->data;
			skb_pull((*pskb), sizeof(struct ethhdr));
			memcpy(eth->h_dest, (*pskb)->dst->neighbour->ha, ETH_ALEN);
			eth->h_proto = htons((*pskb)->protocol);
		}

		ret = hk_send_to_usr_space(*pskb, &cn_hook_out_id);
		kfree_skb(*pskb);
		return NF_STOLEN;
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops pep_in_hook = {
	.hook		= pep_in,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum        = NF_IP_PRE_ROUTING,
	.priority       = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops pep_out_hook = {
	.hook		= pep_out,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum        = NF_IP_POST_ROUTING,
	/*
	 * We are last, because we want all the routing process to be
	 * made as normal before (maybe) stealing the packet
	 */
	.priority       = NF_IP_PRI_LAST,
};

/*
 * Up to linux 2.6.24, the CONNECTOR_MAX_MSG_SIZE was limited to 1024, this
 * function patches the sole location of the check in the kernel text code
 * The following ifdef'ed code is a hack to work around this limitation
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static int hk_patch_force;
module_param(hk_patch_force, int, 0);
MODULE_PARM_DESC(hk_patch_force, "Force patching even if the found default is not 1024");

static unsigned long connector_max_msg_size_offset = 0x50;
module_param(connector_max_msg_size_offset, ulong, 0);
MODULE_PARM_DESC(connector_max_msg_size_offset, "The offset of the cmp $400, %ax (3d 00 04 00 00) instruction in cn_input");

static unsigned long cn_input_addr;
module_param(cn_input_addr, ulong, 0);
MODULE_PARM_DESC(cn_input_addr, "The address of cn_input in the running kernel");

static void __init hk_patch_hack(void)
{
	unsigned long *addr = (unsigned long *)(cn_input_addr + connector_max_msg_size_offset);
	unsigned long new_max = 16 * 1024;

	if (!cn_input_addr)
		return;

	if (*addr != 1024 && !hk_patch_force) {
		printk("hk: addr value is not 1024 (it's %lu), use hk_patch_force=1 to patch anyway\n", *addr);
		return;
	}

	memcpy(addr, &new_max, sizeof(new_max));

	/* kprobes does that to sync the cpus */
	sync_core();
	if (cpu_has_clflush)
		asm("clflush (%0) " :: "r" (addr) : "memory");
}
#else
static void __init hk_patch_hack(void)
{
	return;
}
#endif

static int __init init(void)
{
	int ret;

	hk_patch_hack();

	in_dev = dev_get_by_name(IN_DEV);
	out_dev = dev_get_by_name(OUT_DEV);

	ret = nf_register_hook(&pep_in_hook);
	if (ret < 0) {
		printk("can't register pep_in hook.\n");
		goto err1;
	}

	ret = nf_register_hook(&pep_out_hook);
	if (ret < 0) {
		printk("can't register pep_out hook.\n");
		goto err2;
	}

	ret = cn_add_callback(&cn_hook_in_id, "uspace_to_in", hk_uspace_to_in);
	if (ret) {
		printk("can't register in cn callback.\n");
		goto err_cn;
	}

	ret = cn_add_callback(&cn_hook_out_id, "uspace_to_out", hk_uspace_to_out);
	if (ret) {
		printk("can't register out cn callback.\n");
		goto err_cn2;
	}

	return 0;

err_cn2:
	cn_del_callback(&cn_hook_in_id);
err_cn:
	nf_unregister_hook(&pep_out_hook);
err2:
	nf_unregister_hook(&pep_in_hook);
err1:
	return ret;
}

static void __exit exit(void)
{
	cn_del_callback(&cn_hook_out_id);
	cn_del_callback(&cn_hook_in_id);
	nf_unregister_hook(&pep_in_hook);
	nf_unregister_hook(&pep_out_hook);
}

module_init(init)
module_exit(exit)
MODULE_LICENSE("GPL");
