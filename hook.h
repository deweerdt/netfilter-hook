#ifndef __HOOK_H__
#define __HOOK_H__

enum {
	NH_SET_FILTER = 1,
	NH_RM_FILTER = 2,
	NH_SET_WRITE_MODE = 3,
};

enum {
	TO_INTERFACE 		= (1 << 0),
	TO_INTERFACE_QUEUE 	= (1 << 1),
	TO_ROUTING_STACK 	= (1 << 2),
};

struct nh_writer {
	char dest_dev_str[255];
	void *dest_dev;
	int mode;
};

struct nh_filter {
	unsigned char proto;
	unsigned long saddr;
	unsigned long daddr;
	unsigned short dport;
	unsigned short sport;
	char in_dev[255];
	char out_dev[255];
	void *in;
	void *out;
	int priority;
	int hooknum;
	int flags;
};


#ifndef __KERNEL__

#include <stdio.h>
#include <linux/netfilter.h>

#define printk printf
#define KERN_ERR

#endif

static void dump_line(char *data, int offset, int limit)
{
	int i;

	printk(KERN_ERR "%03x:", offset);
	for (i = 0; i < limit; i++) {
		printk(" %02x", (unsigned char)data[offset + i]);
	}
	printk("\n");
}
static void __attribute__((unused)) dump_zone(void *buf, int len)
{
	int i;
	char *data = buf;

	printk(KERN_ERR "================================================================================\n");
	for (i=0; i < len; i+=16) {
		int limit;
		limit = 16;
		if (i + limit > len)
			limit = len - i;
		dump_line(data, i, limit);
	}
	printk(KERN_ERR "================================================================================\n");
}

#endif /* __HOOK_H__ */
