#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <linux/netlink.h>
#include <linux/connector.h>

#include "hook.h"

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
			fprintf(out, "%.24s : [%x.%x] [%08u.%08u].\n",
					ctime(&tm), data->id.idx, data->id.val, data->seq, data->ack);
			fflush(out);
			break;
		default:
			break;
	}

	close(s);
	return 0;
}
