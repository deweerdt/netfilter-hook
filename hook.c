#include <linux/wait.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <net/sock.h>

#define NETLINK_TEST 17

void nl_data_ready (struct sock *sk, int len)
{
  wake_up_interruptible(sk->sk_sleep);
}

static struct sock *nl_sk = NULL;

#define STRING "This is a test1"
int netlink_test(void)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int size;
	void *data;

	nl_sk = netlink_kernel_create(NETLINK_TEST, 0, nl_data_ready, NULL, THIS_MODULE);
	/* wait for message coming down from user-space */
#if 0
	skb = skb_recv_datagram(nl_sk, 0, 0, &err);
	nlh = (struct nlmsghdr *)skb->data;
	printk("%s: received netlink message payload:%s\n",
			__FUNCTION__, (char *)NLMSG_DATA(nlh));
	//pid = nlh->nlmsg_pid; /*pid of sending process */
#endif
	size = NLMSG_SPACE(1024);

	skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	nlh = NLMSG_PUT(skb, 0, 1, NLMSG_DONE, size - sizeof(*nlh));

	data = NLMSG_DATA(nlh);

	memcpy(data, STRING, strlen(STRING)+1);


	NETLINK_CB(skb).dst_group = 0; /* not in mcast group */
	NETLINK_CB(skb).pid = 0;      /* from kernel */
	netlink_broadcast(nl_sk, skb, 0, 1, GFP_ATOMIC);
	sock_release(nl_sk->sk_socket);

nlmsg_failure:
	return 0;
}
static unsigned int
pep_in(unsigned int hooknum, struct sk_buff **pskb,
	 const struct net_device *in, const struct net_device *out,
	 int (*okfn)(struct sk_buff *))
{
	printk("%s()\n", __FUNCTION__);
	return NF_ACCEPT;
}

static unsigned int
pep_out(unsigned int hooknum, struct sk_buff **pskb,
	 const struct net_device *in, const struct net_device *out,
	 int (*okfn)(struct sk_buff *))
{
	printk("%s()\n", __FUNCTION__);
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
	.hooknum        = NF_IP_PRE_ROUTING,
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

	netlink_test();
	return 0;
err2:
	nf_unregister_hook(&pep_in_hook);
err1:
	return ret;
}

static void exit(void)
{
	nf_unregister_hook(&pep_in_hook);
	nf_unregister_hook(&pep_out_hook);
}

module_init(init)
module_exit(exit)
