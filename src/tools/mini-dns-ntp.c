#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <getopt.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
int main(int argc, char **argv) {
	int opt = 0;
	int mode = 0;
	int fd = 3;
	int set_pktinfo = 0;
	while ((opt = getopt(argc, argv, "dnf:w")) > 0) {
		switch (opt) {
			case 'd':
				mode = 1;
				break;
			case 'n':
				mode = 0;
				break;
			case 'f':
				fd = atoi(optarg);
				break;
			case 'w':
				set_pktinfo = 1;
				break;
			default:
				fprintf(stderr, "Usage: %s -d (DNS) -n (NTP) -f (file descriptor number)\n", argv[0]);
				return 1;
				break;
		}
	}
	if (set_pktinfo) {
		int one = 1;
		setsockopt(fd, SOL_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
		one = 1;
		setsockopt(fd, SOL_IP, IP_PKTINFO, &one, sizeof(one));
	}
	while (1) {
		unsigned char data_buf[64] = {0};
		unsigned char anc_buf[128] = {0};
		unsigned char rinfo_buf[64] = {0};
		struct iovec iov_data = {.iov_base=data_buf, .iov_len=sizeof(data_buf)};
		struct msghdr mh = {.msg_name=rinfo_buf, .msg_namelen=sizeof(rinfo_buf), .msg_iov=&iov_data, .msg_iovlen=1, .msg_control=&anc_buf, .msg_controllen=sizeof(anc_buf), .msg_flags=0};
		errno = 0;
		ssize_t s = recvmsg(fd, &mh, 0);
		if (s <= 0) {
			switch (errno) {
				case 0:
				case EINTR:
				case EAGAIN:
					continue;
				default: goto fail;
			}
		}
		if (mode) {
			if (s < 12) continue;
			uint16_t flags = ntohs(*(uint16_t *)(&data_buf[2]));
			if (flags & 0x8000) continue;
			flags = (flags & 0x7900) | 0x8680;
			(*(uint16_t *)&data_buf[2]) = htons(flags);
			memset(&data_buf[4], 0, 8);
			s = 12;
		} else {
			if (s < 48) continue;
			uint8_t flags = data_buf[0];
			if ((flags & 0x7) != 3) continue;
			data_buf[0] = 0x24; // no leap second, version 4, server
			data_buf[1] = 1; // stratum 1
			data_buf[2] = 10; // 1024 seconds
			data_buf[3] = 0xec; // 2^-20
			uint32_t *data_buf32 = (uint32_t *) data_buf;
			data_buf32[1] = 0;
			data_buf32[2] = htonl(1);
			data_buf32[3] = htonl(0x58555f52); // XU_R
			data_buf32[6] = data_buf32[10];
			data_buf32[7] = data_buf32[11];
			struct timespec current_time = {0};
			if (clock_gettime(CLOCK_REALTIME, &current_time)) continue;
			uint32_t seconds = current_time.tv_sec + 2208988800U;
			uint64_t fraction = (((uint64_t)current_time.tv_nsec) << 23) / 1953125;
			if (fraction >= 0x100000000ULL) continue;
			data_buf32[4] = htonl(seconds & 0xffffff00U);
			data_buf32[5] = 0;
			data_buf32[8] = htonl(seconds);
			data_buf32[9] = htonl(fraction);
			data_buf32[10] = data_buf32[8];
			data_buf32[11] = data_buf32[9];
			s = 48;
		}
		int has_cmsg = 0;
		unsigned char new_cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo) + sizeof(struct in_pktinfo))] = {0};
		struct msghdr mh2 = {.msg_name=rinfo_buf, .msg_namelen=sizeof(rinfo_buf), .msg_iov=&iov_data, .msg_iovlen=1, .msg_control=new_cmsgbuf, .msg_controllen=sizeof(new_cmsgbuf), .msg_flags=0};
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
			if ((cmsg->cmsg_level == SOL_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO)) {
				if (cmsg->cmsg_len < sizeof(struct in6_pktinfo)) continue;
				struct in6_pktinfo info = {0};
				struct in6_pktinfo *orig_info = CMSG_DATA(cmsg);
				memcpy(&info.ipi6_addr, &orig_info->ipi6_addr, sizeof(struct in6_addr));
				info.ipi6_ifindex = orig_info->ipi6_ifindex;
				struct cmsghdr *new_cmsg = CMSG_FIRSTHDR(&mh2);
				new_cmsg->cmsg_level = SOL_IPV6;
				new_cmsg->cmsg_type = IPV6_PKTINFO;
				new_cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
				memcpy(CMSG_DATA(new_cmsg), &info, sizeof(struct in6_pktinfo));
				mh2.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
				has_cmsg=1;
				break;
			} else if ((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == IP_PKTINFO)) {
				if (cmsg->cmsg_len < sizeof(struct in_pktinfo)) continue;
				struct in_pktinfo info = {0};
				struct in_pktinfo *orig_info = CMSG_DATA(cmsg);
				memcpy(&info.ipi_addr, &orig_info->ipi_addr, sizeof(struct in_addr));
				info.ipi_ifindex = orig_info->ipi_ifindex;
				struct cmsghdr *new_cmsg = CMSG_FIRSTHDR(&mh2);
				new_cmsg->cmsg_level = SOL_IP;
				new_cmsg->cmsg_type = IP_PKTINFO;
				new_cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
				memcpy(CMSG_DATA(new_cmsg), &info, sizeof(struct in_pktinfo));
				mh2.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
				has_cmsg=1;
				break;
			}
		}
		if (!has_cmsg) {
			mh2.msg_control = NULL;
			mh2.msg_controllen = 0;
		}
		iov_data.iov_len = s;
		sendmsg(fd, &mh2, 0);
	}
fail:
	fprintf(stderr, "recvmsg failed: %s\n", strerror(errno));
	return -1;
}
