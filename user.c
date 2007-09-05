#include <sys/socket.h>
#include <sys/select.h>
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

#if 1
#define pr_debug(x, a...) do { \
			 	char __buf[4096]; \
				sprintf(__buf, x, ##a); \
				fprintf(stderr, "%s", __buf); \
			  } while(0);
#else
#define pr_debug(...) do {} while(0)
#endif

static void __attribute__((unused)) dump_mem(void *mem, size_t len, size_t size)
{
	uint8_t *u8;
#if 0
	uint16_t *u16;
#endif
	uint32_t *u32;
	int i;
	char buf[4096] = "";
	char buf2[4096] = "";

	switch (size) {
		case 1:
			u8 = mem;
			for (i=0; i <= len / size; i++) {
				if (!(i%8))
					pr_debug("%02x ", u8[i]);
			}
			break;
		case 4:
			u32 = mem;
			for (i=0; i <= len / size; i++) {
				buf2[0] = '\0';
				sprintf(buf2, "%08x ", htonl(u32[i]));
				strcat(buf, buf2);
				if (!(i%8)) {
					pr_debug("%s\n", buf);
					buf[0] = '\0';
				}
			}
			break;
		default:
			pr_debug("Unhandled size %d\n", size);
	}
	pr_debug("\n");
	return;
}


static int netlink_send_packet(int s, struct cn_msg *msg)
{
	struct nlmsghdr *nlh;
	unsigned int size;
	int err;
	char buf[CONNECTOR_MAX_MSG_SIZE];
	struct cn_msg *m;

	size = NLMSG_SPACE(sizeof(struct cn_msg) + msg->len);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_seq = 0;
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

static int cn_send_packet(int s, void *buf, int len, int id)
{
	struct cn_msg *data;

	data = (struct cn_msg *)buf;

	data->id.idx = id;
	data->id.val = HOOK_ID_VAL;
	data->seq = 0;
	data->ack = 0;
	data->len = len;

	len = netlink_send_packet(s, data);
	return len;
}

static int open_hook_socket(int id)
{
	int s;
	struct sockaddr_nl l_local;

	s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (s == -1) {
		return -1;
	}

	l_local.nl_family = AF_NETLINK;
	l_local.nl_groups = 1 << (id - 1);
	l_local.nl_pid = 0;

	if (bind(s, (struct sockaddr *)&l_local, sizeof(struct sockaddr_nl)) == -1) {
		close(s);
		return -1;
	}

	return s;
}

static int recv_and_send(int s, int id)
{
	int len;
	char buf[4096];
	struct nlmsghdr *reply;
	struct cn_msg *data;

	memset(buf, 0, sizeof(buf));
	len = recv(s, buf, sizeof(buf), 0);
	if (len < 0) {
		return -1;
	}
	reply = (struct nlmsghdr *)buf;

	switch (reply->nlmsg_type) {
		case NLMSG_ERROR:
			fprintf(stderr, "Error message received.\n");
			break;
		case NLMSG_DONE:
			data = (struct cn_msg *)NLMSG_DATA(reply);
			cn_send_packet(s, data->data, len, id);
			break;
		default:
			break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int s_in;
	fd_set read_sock;
	int line; /* used for debugging only */

	s_in = open_hook_socket(HOOK_IN_ID);
	if (s_in < 0) {
		perror("cannot open inbound netlink connection");
		exit(-1);
	}

	while (1) {
		int ret;
		int s_max = s_in + 1;

		FD_ZERO(&read_sock);
		FD_SET(s_in, &read_sock);

		ret = select(s_max, &read_sock, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == -EINTR) {
				continue;
			} else {
				line = __LINE__;
				goto err;
			}
		}

		if (FD_ISSET(s_in, &read_sock)) {
			ret = recv_and_send(s_in, HOOK_IN_ID);
			if (ret < 0) {
				line = __LINE__;
				goto err;
			}
		}
	}

	goto clean_out;
err:
	fprintf(stderr, "Got an error line %d: %s. Exiting\n", line, strerror(errno));
clean_out:
	close(s_in);
	return 0;
}
