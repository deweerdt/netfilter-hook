#include <linux/fs.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>

#include <asm/uaccess.h>

#define NH_MINOR 214

static struct nf_hook_ops nf_out_hook = {
	.hook		= nf_out,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum        = NF_IP_POST_ROUTING,
	.priority       = NF_IP_PRI_LAST,
};

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
	u32 saddr;
	u32 daddr;
	u16 dport;
	u16 sport;
	char in_dev[255];
	char out_dev[255];
	struct net_device *in;
	struct net_device *out;
	int flags;
};
struct nh_private {
	struct nh_filter *filter;
};

static LIST_HEAD(filters);
static DEFINE_SPINLOCK(filter_list_lock);
struct filter_entry {
	struct list_head list;
	struct nh_filter *filter;
};

enum {
	CHECK_OUT,
	CHECK_IN,
	CHECK_SADDR,
	CHECK_DADDR,
	CHECK_SPORT,
	CHECK_DPORT,
};
static int pass(struct sk_buff *skb,
		struct net_device *in, struct net_device *out)
{
	struct filter_entry *e;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22)
	struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *tph = (struct tcphdr *)skb_transport_header(skb);
#else
	struct iphdr *iph = (struct iphdr *)skb->nh.raw;
	struct tcphdr *tph = (struct tcphdr *)skb->th.raw;
#endif

	spin_lock(&filter_list_lock);

	list_for_each_entry(e, &filters, list) {
		if (e->filter->flags & CHECK_OUT && e->filter->out != out)
			goto found;
		if (e->filter->flags & CHECK_IN && e->filter->in != in)
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

	spin_unlock(&filter_list_lock);
	return 0;

found:
	spin_unlock(&filter_list_lock);
	return 1;
}

int setup_filter(struct nh_private *p)
{
	struct nh_filter *f = p->filter;
	f->in = dev_get_by_name(&init_net, f->in_dev);
	f->out = dev_get_by_name(&init_net, f->out_dev);
	
	return 0;
}

static int nh_open(struct inode *inode, struct file *file)
{
	struct nh_private *p;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

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

	p = file->private_data;

	if (!p->filter) {
		return -EBADF;
	}

	return 0;
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

