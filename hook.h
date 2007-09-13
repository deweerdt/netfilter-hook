#ifndef __HOOK_H__
#define __HOOK_H__

#define HOOK_IN_ID 	(CN_NETLINK_USERS + 1)
#define HOOK_OUT_ID 	(CN_NETLINK_USERS + 2)
#define HOOK_ID_VAL 	0x1

#ifdef __KERNEL__
#  if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,16)
#     define cpu_has_clflush boot_cpu_has(X86_FEATURE_CLFLSH)
#  endif
#  if defined(__i386__)
#     define htons(x) (x << 8 | x >> 8)
#     define ntohs(x) (x << 8 | x >> 8)
#  endif
#endif

#ifndef __KERNEL__
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
