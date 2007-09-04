#include <linux/ip.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/connector.h>
#include <linux/netfilter.h>
#include <linux/etherdevice.h>
#include <linux/netfilter_ipv4.h>

#include <net/ip.h>
#include <net/sock.h>

#include "hook.h"

static struct cb_id cn_test_id = { .idx = HOOK_ID, .val = HOOK_ID_VAL };
static int cn_test_timer_counter = 0;

static struct net_device *pdev;
static struct ethhdr pheader = {
	.h_source	= { 0x00, 0xff, 0x1e, 0xc2, 0xd8, 0x37 },
	.h_dest 	= { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.h_proto 	= ntohs(ETH_P_IP),
};

static struct sk_buff *ours = NULL;
static void hk_packet_cn_callback(void *data)
{
	struct cn_msg *m = data;
	struct sk_buff *skb;
	int ret;

	m->len -= 56;
	printk("called back, sending %d\n", m->len + ETH_HLEN + 5);
	skb = dev_alloc_skb(ETH_HLEN + m->len + 5);
	ours = skb;
	if (!skb) {
		printk("Cannot allocate NET_SKB_PAD + m->len: %d bytes\n", ETH_HLEN + m->len + 5);
		return;
	}

	//skb->dev = dev_get_by_name("eth0");
	skb_reserve(skb, 2);
#if 0
	if (!skb->dev) {
		printk("Cannot find dev eth0\n");
		dev_kfree_skb(skb);
		return;
	}
#endif

	skb_put(skb, ETH_HLEN + m->len);
	memcpy(skb->data, &pheader, ETH_HLEN);

         /* copy the data into the sk_buff */
	memcpy(skb->data + ETH_HLEN, m->data, m->len);

        skb->protocol = eth_type_trans(skb, dev_get_by_name("eth0"));
	ret = netif_rx(skb);
	printk("xmited packet, packet_type is %d %d\n", skb->pkt_type, ret);

	return;
}

static int hk_packet_dispatch(struct sk_buff *skb)
{
	struct cn_msg *m;
	void *data;
	int len;
	int ret = 0;

	pdev = skb->dev;

	/* get back to the ip header */
	skb_push(skb, sizeof(struct iphdr));

	data = skb->data;
	len = skb->len;

	m = kzalloc(sizeof(*m) + len, GFP_ATOMIC);
	if (!m) {
		printk("cannot allocate %d bytes\n", len + sizeof(*m));
		ret = -ENOMEM;
		goto out;
	}

	memcpy(&m->id, &cn_test_id, sizeof(m->id));
	m->seq = cn_test_timer_counter;
	m->len = len;

	cn_test_timer_counter++;

	memcpy(m->data, data, m->len);

	ret = cn_netlink_send(m, 0, gfp_any());
	//if (ret < 0)
	printk("Sent to user space, ret is %d\n", ret);

	kfree(m);

out:
	return ret;
}

//static unsigned int test_ip = htonl(0xd41b300a); /* 212.27.48.10 */
static unsigned int test_ip = htonl(0xc0a80101); /* 192.168.1.1 */

static unsigned int
pep_in(unsigned int hooknum, struct sk_buff **pskb,
	 const struct net_device *in, const struct net_device *out,
	 int (*okfn)(struct sk_buff *))
{
	int ret;
	struct iphdr *iph = (struct iphdr *)skb_network_header(*pskb);

	if ((iph->daddr == test_ip || iph->saddr == test_ip) && *pskb != ours) {
		ret = hk_packet_dispatch(*pskb);
		return NF_STOLEN;
	}
	return NF_ACCEPT;
}

static unsigned int
pep_out(unsigned int hooknum, struct sk_buff **pskb,
	 const struct net_device *in, const struct net_device *out,
	 int (*okfn)(struct sk_buff *))
{
	int ret = NF_ACCEPT;

	//ret = hk_packet_dispatch(*pskb);
	//printk("%s(): %d\n", __FUNCTION__, ret);
	return ret;
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
	.priority       = NF_IP_PRI_FIRST,
};

static int init(void)
{
	int ret;

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

	ret = cn_add_callback(&cn_test_id, "cn_test", hk_packet_cn_callback);
	if (ret) {
		printk("can't register cn callback.\n");
		goto err_cn;
	}

	return 0;

err_cn:
	nf_unregister_hook(&pep_out_hook);
err2:
	nf_unregister_hook(&pep_in_hook);
err1:
	return ret;
}

static void exit(void)
{
	cn_del_callback(&cn_test_id);
	nf_unregister_hook(&pep_in_hook);
	nf_unregister_hook(&pep_out_hook);
}

module_init(init)
module_exit(exit)
MODULE_LICENSE("GPL");
