#include <linux/fs.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/completion.h>
#include <linux/netfilter_ipv4.h>
#include <linux/miscdevice.h>

#include <asm/uaccess.h>

#define NH_MINOR 214


enum {
	NH_SET_FILTER = 1,
	NH_RM_FILTER = 2,
};

enum {
	NH_READ = 1 << 0,
	NH_WRITE = 1 << 1,
	NH_INIT_DONE = 1 << 2,
};

struct nh_filter {
	u8 proto;
	u32 saddr;
	u32 daddr;
	u16 dport;
	u16 sport;
	char in_dev[255];
	char out_dev[255];
	struct net_device *in;
	struct net_device *out;
	int priority;
	int hooknum;
	int flags;
};

static LIST_HEAD(nh_privs);
static DEFINE_SPINLOCK(nh_privs_lock);

struct nh_private {
	struct list_head list;
	struct nh_filter *filter;
	struct completion completion;
	struct sk_buff_head skb_queue ;

};

#define NF_IP_NUMHOOKS 5
static struct nf_hook_ops *cb_in_use[NF_IP_NUMHOOKS];

enum {
	CHECK_PROTO,
	CHECK_OUT,
	CHECK_IN,
	CHECK_SADDR,
	CHECK_DADDR,
	CHECK_SPORT,
	CHECK_DPORT,
};

static struct nh_private *pass(struct sk_buff *skb,
				 const struct net_device *in,
				 const struct net_device *out,
				 int hooknum)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22)
	struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *tph = (struct tcphdr *)skb_transport_header(skb);
#else
	struct iphdr *iph = (struct iphdr *)skb->nh.raw;
	struct tcphdr *tph = (struct tcphdr *)skb->th.raw;
#endif
	struct nh_private *e;

	spin_lock(&nh_privs_lock);

	list_for_each_entry(e, &nh_privs, list) {
		if (e->filter->hooknum != hooknum)
			goto found;
		if (e->filter->flags & CHECK_OUT && e->filter->out != out)
			goto found;
		if (e->filter->flags & CHECK_IN && e->filter->in != in)
			goto found;
		if (e->filter->flags & CHECK_PROTO && e->filter->proto != iph->protocol)
			goto found;
		if (e->filter->flags & CHECK_SADDR && e->filter->saddr != iph->saddr)
			goto found;
		if (e->filter->flags & CHECK_DADDR && e->filter->daddr != iph->daddr)
			goto found;
		if (e->filter->flags & CHECK_SPORT && e->filter->sport != tph->source)
			goto found;
		if (e->filter->flags & CHECK_DPORT && e->filter->dport != tph->dest)
			goto found;
	}

	spin_unlock(&nh_privs_lock);
	return NULL;

found:
	spin_unlock(&nh_privs_lock);
	return e;
}

static unsigned int nf_cb(
		unsigned int hooknum,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
		struct sk_buff *skb,
#else
		struct sk_buff **pskb,
#endif
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct ethhdr *eth;
	struct nh_private *p;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
	struct sk_buff **pskb = &skb;
#endif
	if (pass(*pskb, in, out, hooknum)) {
		/* Save the dest mac now, it will be lost otherwise */
		if ((*pskb)->dst && (*pskb)->dst->neighbour) {
			skb_push((*pskb), sizeof(struct ethhdr));
			eth = (struct ethhdr *)(*pskb)->data;
			skb_pull((*pskb), sizeof(struct ethhdr));
			memcpy(eth->h_dest, (*pskb)->dst->neighbour->ha, ETH_ALEN);
		}

		skb_queue_tail(&p->skb_queue, *pskb);
		complete(&p->completion);
		return NF_STOLEN;
	}
	return NF_ACCEPT;
}


int setup_filter(struct nh_private *p)
{
	struct nh_filter *f = p->filter;
	struct nf_hook_ops *nf_hook;
	int ret;

	nf_hook = kzalloc(sizeof(*nf_hook), GFP_KERNEL);
	if (!nf_hook)
		return -ENOMEM;

	f->in = dev_get_by_name(&init_net, f->in_dev);
	if (!f->in)
		f->flags |= CHECK_IN;
	f->out = dev_get_by_name(&init_net, f->out_dev);
	if (f->out)
	       f->flags |= CHECK_OUT;
	if (f->saddr)
	       f->flags |= CHECK_SADDR;
	if (f->daddr)
	       f->flags |= CHECK_DADDR;
	if (f->dport)
	       f->flags |= CHECK_DPORT;
	if (f->sport)
	       f->flags |= CHECK_SPORT;
	if (f->proto)
		f->flags |= CHECK_PROTO;

	if (!cb_in_use[f->priority]) {
		nf_hook->hook = nf_cb;
		nf_hook->owner = THIS_MODULE;
		nf_hook->pf = PF_INET;
		nf_hook->hooknum = f->hooknum;
		nf_hook->priority = f->priority;
		ret = nf_register_hook(nf_hook);
		if (ret < 0) {
			printk("nf_hook: can't register netfilter hook.\n");
			goto err;
		}
		cb_in_use[f->priority] = nf_hook;
	}

err:
	kfree(nf_hook);
	return ret;
}

static int nh_open(struct inode *inode, struct file *file)
{
	struct nh_private *p;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	skb_queue_head_init(&p->skb_queue) ;
	init_completion(&p->completion);
	file->private_data = p;

	return 0;
}
static int nh_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static ssize_t nh_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct nh_private *p;

	p = file->private_data;

	if (!p->filter) {
		return -EBADF;
	}
	return 0;
}

static ssize_t nh_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct nh_private *p;
	struct sk_buff *skb;
	int ret;

	p = file->private_data;

	if (!p->filter) {
		return -EBADF;
	}

	if(skb_queue_empty(&p->skb_queue))
		if (wait_for_completion_interruptible(&p->completion))
			return -ERESTARTSYS;

	skb = skb_dequeue(&p->skb_queue);
	if (!skb)
		return -EIO;

	if (skb->len > count) {
		return -EINVAL;
	}

	ret = copy_to_user(buf, skb->data, skb->len);

	return ret;
}

static int nh_ioctl(struct inode *inode, struct file *file,
		    unsigned int req, unsigned long pointer)
{
	struct nh_private *p;
	struct nh_filter *filter;
	int ret;

	p = file->private_data;

	switch (req) {
	case NH_SET_FILTER:
		filter = kzalloc(sizeof(*filter), GFP_KERNEL);
		if (!filter)
			return -ENOMEM;

		if (copy_from_user(filter, (void *)pointer, sizeof(*filter)))
			return -EFAULT;


		p->filter = filter;
		ret = setup_filter(p);
		if (ret) {
			spin_lock(&nh_privs_lock);
			list_add(&p->list, &nh_privs);
			spin_unlock(&nh_privs_lock);
		}


		return ret;
	case NH_RM_FILTER:
		kfree(p->filter);
		return 0;
	}

	return -EINVAL;
}

static const struct file_operations net_hook_fops = {
	.owner		= THIS_MODULE,
	.open		= nh_open,
	.release	= nh_release,
	.ioctl		= nh_ioctl,
	.read		= nh_read,
	.write		= nh_write,
};


static struct miscdevice net_hook_dev = {
	NH_MINOR,
	"net_hook",
	&net_hook_fops
};

static int __init nh_init(void)
{
	int ret;

	ret = misc_register(&net_hook_dev);
	if (ret)
		printk(KERN_ERR "net_hook: can't misc_register on minor %d\n", NH_MINOR);
	return ret;
}
module_init(nh_init);

static void __exit nh_exit(void)
{
	misc_deregister(&net_hook_dev);
}
module_exit(nh_exit);

