#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>

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

struct arg {
	int fd;
	int count;
};
static struct arg a1;
static struct arg a2;
void *net_pipe(void *arg)
{
	struct arg *a = arg;
	int fd = a->fd;
	char buf[4096];
	int ret;
	do {
		ret = read(fd, buf, sizeof(buf));
		if (ret < 0) {
			perror("read");
			exit(0);
		}
		ret = write(fd, buf, ret);
		if (ret < 0) {
			perror("write");
			exit(0);
		}
		a->count++;
	} while (ret > 0);
	close(fd);
	return NULL;
}
void sigint_handler(int arg)
{
	printf("t1 saw %d packets\n", a1.count);
	printf("t2 saw %d packets\n", a2.count);
	exit(0);
}
int main(int argc, char **argv)
{
	int fd, ret;
	struct nh_filter f;
	struct nh_writer w;
	pthread_t t1, t2;

	signal(SIGINT, sigint_handler);

	/*
	 * 1
	 */
	memset(&f, 0, sizeof(f));
	memset(&w, 0, sizeof(w));
	fd = open("/dev/nf_hook", O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(0);
	}

	f.hooknum = NF_IP_POST_ROUTING;

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

	a1.fd = fd;
	pthread_create(&t1, NULL, net_pipe, &a1);

	/*
	 * 2
	 */
	memset(&f, 0, sizeof(f));
	memset(&w, 0, sizeof(w));
	fd = open("/dev/nf_hook", O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(0);
	}

	f.hooknum = NF_IP_LOCAL_IN;
	ret = ioctl(fd, NH_SET_FILTER, &f);
	if (ret < 0) {
		perror("ioctl 1");
		exit(0);
	}

	w.mode = TO_ROUTING_STACK;
	strcpy(w.dest_dev_str, "eth0");
	ret = ioctl(fd, NH_SET_WRITE_MODE, &w);
	if (ret < 0) {
		perror("ioctl 2");
		exit(0);
	}
	a2.fd = fd;
	pthread_create(&t2, NULL, net_pipe, &a2);

	pthread_join(t2, NULL);
	pthread_join(t1, NULL);
	return 0;
}
