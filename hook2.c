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

#include "hook.h"

#define NH_MINOR 214


static LIST_HEAD(current_skbs);
static DEFINE_SPINLOCK(skb_list_lock);
struct skb_entry {
	struct list_head list;
	struct sk_buff *skb;
};

static struct skb_entry *is_hooked(struct sk_buff *skb)
{
	struct skb_entry *e;
	int found = 0;
	spin_lock(&skb_list_lock);
	list_for_each_entry(e, &current_skbs, list) {
		if(e->skb == skb) {
			found = 1;
			break;
		}
	}
	spin_unlock(&skb_list_lock);

	return found ? e : NULL;
}
enum {
	NH_READ = 1 << 0,
	NH_WRITE = 1 << 1,
	NH_INIT_DONE = 1 << 2,
};

static LIST_HEAD(nh_privs);
static DEFINE_SPINLOCK(nh_privs_lock);

struct nh_private {
	struct list_head list;
	struct nh_filter *filter;
	struct nh_writer *writer;
	struct completion completion;
	struct sk_buff_head skb_queue ;

};


#define NF_IP_NUMHOOKS 5
static struct nf_hook_ops *cb_in_use[NF_IP_NUMHOOKS];

enum {
	CHECK_PROTO 	= (1 << 0),
	CHECK_OUT 	= (1 << 1),
	CHECK_IN 	= (1 << 2),
	CHECK_SADDR 	= (1 << 3),
	CHECK_DADDR 	= (1 << 4),
	CHECK_SPORT 	= (1 << 5),
	CHECK_DPORT 	= (1 << 6),
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
	struct iphdr *iph = skb->nh.iph;
	struct tcphdr *tph = skb->h.th;
#endif
	struct nh_private *e;

	spin_lock(&nh_privs_lock);

	list_for_each_entry(e, &nh_privs, list) {
		if (e->filter->hooknum != hooknum) {
			//printk("AZE 1\n");
			continue;
		}
		if (e->filter->flags & CHECK_OUT && e->filter->out != out) {
			//printk("AZE 2\n");
			continue;
		}
		if (e->filter->flags & CHECK_IN && e->filter->in != in) {
			//printk("AZE 3\n");
			continue;
		}
		if (e->filter->flags & CHECK_PROTO && e->filter->proto != iph->protocol) {
			//printk("AZE 4\n");
			continue;
		}
		if (e->filter->flags & CHECK_SADDR && e->filter->saddr != iph->saddr) {
			//printk("AZE 5\n");
			continue;
		}
		if (e->filter->flags & CHECK_DADDR && e->filter->daddr != iph->daddr) {
			//printk("AZE 6\n");
			continue;
		}
		if (e->filter->flags & CHECK_SPORT && e->filter->sport != tph->source) {
			//printk("AZE 7\n");
			continue;
		}
		if (e->filter->flags & CHECK_DPORT && e->filter->dport != tph->dest) {
			//printk("e->filter->dport %d != tph->dest %d \n", e->filter->dport, tph->dest);
			continue;
		}

		spin_unlock(&nh_privs_lock);
		return e;
	}

	spin_unlock(&nh_privs_lock);
	return NULL;
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
	struct nh_private *p;
	struct skb_entry *e;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
	struct sk_buff **pskb = &skb;
#endif

	e = is_hooked(*pskb);

	if (e) {
		spin_lock(&skb_list_lock);
		list_del(&e->list);
		spin_unlock(&skb_list_lock);
		kfree(e);
		return NF_ACCEPT;
	}

	p = pass(*pskb, in, out, hooknum);
	if (p) {
		/* Save the dest mac now, it will be lost otherwise */
#if 0
		if ((*pskb)->dst && (*pskb)->dst->neighbour) {
			skb_push((*pskb), sizeof(struct ethhdr));
			eth = (struct ethhdr *)(*pskb)->data;
			skb_pull((*pskb), sizeof(struct ethhdr));
			memcpy(eth->h_dest, (*pskb)->dst->neighbour->ha, ETH_ALEN);
		}
#endif

		skb_queue_tail(&p->skb_queue, *pskb);
		complete(&p->completion);
		return NF_STOLEN;
	}
	return NF_ACCEPT;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define NET_NAMESPACE
#else
#define NET_NAMESPACE &init_net,
#endif

int setup_filter(struct nh_private *p)
{
	struct nh_filter *f = p->filter;
	struct nf_hook_ops *nf_hook;
	int ret = 0;

	nf_hook = kzalloc(sizeof(*nf_hook), GFP_KERNEL);
	if (!nf_hook)
		return -ENOMEM;

	f->in = dev_get_by_name(NET_NAMESPACE f->in_dev);
	if (f->in)
		f->flags |= CHECK_IN;
	f->out = dev_get_by_name(NET_NAMESPACE f->out_dev);
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

	return 0;
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
	struct nh_private *p = file->private_data;

	if (p->filter) {
		spin_lock(&nh_privs_lock);
		list_del(&p->list);
		spin_unlock(&nh_privs_lock);
		kfree(p->filter);
	}
	kfree(p->writer);
	kfree(p);
	return 0;
}

static ssize_t nh_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct nh_private *p;
	struct sk_buff *skb;
	int ret;

	p = file->private_data;

	if (!p->writer) {
		printk("p->writer %p %p\n", p->filter, p->writer);
		return -EBADF;
	}

	skb = dev_alloc_skb(count);
	if (!skb)
		return -ENOMEM;

	if (copy_from_user(skb->data, buf, count)) {
		kfree_skb(skb);
		return -EFAULT;
	}
	skb_put(skb, count);

	if (p->writer->mode == TO_ROUTING_STACK) {
		struct skb_entry *e;
	        e = kmalloc(sizeof(*e), GFP_ATOMIC);
		if (!e)
			return NF_DROP;
		e->skb = skb;

		spin_lock(&skb_list_lock);
		list_add(&e->list, &current_skbs);
		spin_unlock(&skb_list_lock);
		ret = netif_rx(skb);
	} else {
		/* TO_INTERFACE */
		skb->dev = p->writer->dest_dev;
		if (skb->dev->hard_header)
			skb->dev->hard_header(skb, skb->dev, be16_to_cpu(skb->protocol), NULL, skb->dev->dev_addr, skb->len);
		ret = dev_queue_xmit(skb);
		printk("ret is %d\n", ret);
	}


	return count;
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

	ret = skb->len;
	if (copy_to_user(buf, skb->data, skb->len)) {
		kfree_skb(skb);
		return -EFAULT;
	}
	kfree_skb(skb);

	return skb->len;
}

static int nh_ioctl(struct inode *inode, struct file *file,
		    unsigned int req, unsigned long pointer)
{
	struct nh_private *p;
	struct nh_filter *filter;
	struct nh_writer *writer;
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

#if 0
		printk("Got filter:\n\
				u8 proto = %d\n\
				u32 saddr = %d\n\
				u32 daddr = %d\n\
				u16 dport = %d\n\
				u16 sport = %d\n\
				char in_dev[255] = %s\n\
				char out_dev[255] = %s\n\
				int priority = %d\n\
				int hooknum = %d\n\
				int flags = %d\n", filter->proto, filter->saddr, filter->daddr, filter->dport, filter->sport,
						   filter->in_dev, filter->out_dev, filter->priority, filter->hooknum, filter->flags);
#endif

		if (!ret) {
			spin_lock(&nh_privs_lock);
			list_add(&p->list, &nh_privs);
			spin_unlock(&nh_privs_lock);
		}


		return ret;
	case NH_RM_FILTER:
		if (p->filter) {
			spin_lock(&nh_privs_lock);
			list_del(&p->list);
			spin_unlock(&nh_privs_lock);
			kfree(p->filter);
		}
		return 0;
	case NH_SET_WRITE_MODE:
		writer = kzalloc(sizeof(*writer), GFP_KERNEL);
		if (!writer)
			return -ENOMEM;

		if (copy_from_user(writer, (void *)pointer, sizeof(*writer)))
			return -EFAULT;

		p->writer = writer;
		p->writer->dest_dev = dev_get_by_name(writer->dest_dev_str);
		printk("OK\n");
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
	int i;
	for (i = 0; i < ARRAY_SIZE(cb_in_use); i++) {
		if (cb_in_use[i]) {
			nf_unregister_hook(cb_in_use[i]);
			kfree(cb_in_use[i]);
		}
	}
	misc_deregister(&net_hook_dev);
}
module_exit(nh_exit);

