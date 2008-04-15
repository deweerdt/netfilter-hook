struct lh_filter {
	u32 saddr; 
	u32 daddr; 
	u16 sport; 
	u16 dport; 
	char *in_device;
	char *out_device;
	int priority;
	int hooknum;
};

int lh_open(struct lh_filter *filter)
{

}

int lh_close(int fd)
{

}
