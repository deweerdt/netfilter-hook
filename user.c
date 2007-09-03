#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include <linux/netlink.h>
#include <linux/connector.h>

#include "hook.h"

static int seq = 0;
static int netlink_send(int s, struct cn_msg *msg)
{
	struct nlmsghdr *nlh;
	unsigned int size;
	int err;
	char buf[CONNECTOR_MAX_MSG_SIZE];
	struct cn_msg *m;

	size = NLMSG_SPACE(sizeof(struct cn_msg) + msg->len);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_seq = seq++;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_len = NLMSG_LENGTH(size - sizeof(*nlh));
	nlh->nlmsg_flags = 0;

	m = NLMSG_DATA(nlh);

	memcpy(m, msg, sizeof(*m) + msg->len);

	err = send(s, nlh, size, 0);
	if (err == -1) {
		fprintf(stderr, "Failed to send: %s [%d].\n", strerror(errno), errno);
	}

	return err;
}

static int send_packet(int s, void *buf, int len)
{
	struct cn_msg *data;

	data = (struct cn_msg *)buf;

	data->id.idx = HOOK_ID;
	data->id.val = HOOK_ID_VAL;
	data->seq = seq++;
	data->ack = 0;
	data->len = len;

	len = netlink_send(s, data);
	if (len > 0)
		fprintf(stderr, "message has been sent to %08x.%08x.\n", data->id.idx, data->id.val);

	return len;
}

int main(int argc, char **argv)
{
	int s;
	char buf[1024];
	int len;
	struct nlmsghdr *reply;
	struct sockaddr_nl l_local;
	struct cn_msg *data;
	FILE *out;
	time_t tm;

	if (argc < 2)
		out = stdout;
	else {
		out = fopen(argv[1], "a+");
		if (!out) {
			fprintf(stderr, "Unable to open %s for writing: %s\n",
					argv[1], strerror(errno));
			out = stdout;
		}
	}

	memset(buf, 0, sizeof(buf));

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (s == -1) {
		perror("socket");
		return -1;
	}

	l_local.nl_family = AF_NETLINK;
	l_local.nl_groups = 1 << (HOOK_ID -1); /* bitmask of requested groups */
	l_local.nl_pid = 0;

	if (bind(s, (struct sockaddr *)&l_local, sizeof(struct sockaddr_nl)) == -1) {
		perror("bind");
		close(s);
		return -1;
	}


	while (1) {
		memset(buf, 0, sizeof(buf));
		len = recv(s, buf, sizeof(buf), 0);
		if (len == -1) {
			perror("recv buf");
			close(s);
			return -1;
		}
		reply = (struct nlmsghdr *)buf;

		switch (reply->nlmsg_type) {
			case NLMSG_ERROR:
				fprintf(out, "Error message received.\n");
				fflush(out);
				break;
			case NLMSG_DONE:
				data = (struct cn_msg *)NLMSG_DATA(reply);

				time(&tm);
				fprintf(out, "%.24s : cksum: %x\n",
						ctime(&tm), ntohs(((uint16_t *)data->data)[5]));
				fflush(out);
				send_packet(s, data->data, len);
				break;
			default:
				break;
		}
	}

	close(s);
	return 0;
}
