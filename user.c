#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "hook.h"

/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING	0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN		1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD		2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT		3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING	4

int main(int argc, char **argv)
{
	int fd, ret;
	char buf[4096];
	struct nh_filter f;
	struct nh_writer w;

	fd = open("/dev/nf_hook", O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(0);
	}

	f.hooknum = NF_IP_POST_ROUTING;
	f.saddr = 0xaaaaaaaa;
	ret = ioctl(fd, NH_SET_FILTER, &f);
	if (ret < 0) {
		perror("ioctl 1");
		exit(0);
	}

	w.mode = TO_INTERFACE;
	strcpy(w.dest_dev_str, "eth0");
	ret = ioctl(fd, NH_SET_WRITE_MODE, &w);
	if (ret < 0) {
		perror("ioctl 2");
		exit(0);
	}
	perror("ioctl ?");

	do {
		ret = read(fd, buf, sizeof(buf));
		if (ret < 0) {
			perror("read");
			exit(0);
		}
		dump_zone(buf, ret);
		ret = write(fd, buf, ret);
		if (ret < 0) {
			perror("write");
			exit(0);
		}
	} while (ret > 0);
	close(fd);
	return 0;
}
