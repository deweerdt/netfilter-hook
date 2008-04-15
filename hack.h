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
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22)
	if (cpu_has_clflush)
		asm("clflush (%0) " :: "r" (addr) : "memory");
#endif
}
#else
static void __init hk_patch_hack(void)
{
	return;
}
#endif


