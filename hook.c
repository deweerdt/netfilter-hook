#include <linux/wait.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/connector.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <net/sock.h>

#include "hook.h"

static struct cb_id cn_test_id = { .idx = HOOK_ID, .val = HOOK_ID_VAL };
static int cn_test_timer_counter = 0;

static void hk_packet_cn_callback(void *data)
{
	return;
}
static int hk_packet_dispatch(void *unused)
{
    struct cn_msg *m;
    char data[64];
    int ret;

    ret = cn_add_callback(&cn_test_id, "cn_test", hk_packet_cn_callback);
    if (ret)
	    return ret;

    while (!kthread_should_stop()) {
	    m = kzalloc(sizeof(*m) + sizeof(data), GFP_ATOMIC);
	    if (!m)
		    goto out;

	    memcpy(&m->id, &cn_test_id, sizeof(m->id));
	    m->seq = cn_test_timer_counter;
	    m->len = sizeof(data);
	    m->len = scnprintf(data, sizeof(data), "counter = %u", cn_test_timer_counter) + 1;

	    cn_test_timer_counter++;

	    memcpy(m + 1, data, m->len);

	    ret = cn_netlink_send(m, 0, gfp_any());
	    if (ret < 0)
		    printk("ret is %d\n", ret);

	    kfree(m);
	    mdelay(1000);
    }

out:
    cn_del_callback(&cn_test_id);

    return 0;
}

static unsigned int
pep_in(unsigned int hooknum, struct sk_buff **pskb,
	 const struct net_device *in, const struct net_device *out,
	 int (*okfn)(struct sk_buff *))
{
	//printk("%s()\n", __FUNCTION__);
	return NF_ACCEPT;
}

static unsigned int
pep_out(unsigned int hooknum, struct sk_buff **pskb,
	 const struct net_device *in, const struct net_device *out,
	 int (*okfn)(struct sk_buff *))
{
	//printk("%s()\n", __FUNCTION__);
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

static struct task_struct *hk_task;

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

	hk_task = kthread_run(hk_packet_dispatch, NULL, "khk_task");
	if (IS_ERR(hk_task)) {
		ret = PTR_ERR(hk_task);
		printk("Could not lauch hkh_task\n");
		goto err_thread;
	}
	return 0;
err_thread:
	nf_unregister_hook(&pep_out_hook);
err2:
	nf_unregister_hook(&pep_in_hook);
err1:
	return ret;
}

static void exit(void)
{
	if (hk_task)
		kthread_stop(hk_task);
	nf_unregister_hook(&pep_in_hook);
	nf_unregister_hook(&pep_out_hook);
}

module_init(init)
module_exit(exit)
MODULE_LICENSE("GPL");
