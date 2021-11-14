
# include <traceroute.h>
# include <ftlibc.h>

# include <netinet/ip_icmp.h>
# include <netinet/udp.h>
# include <netinet/tcp.h>
# include <net/if.h>
# include <sys/ioctl.h>
# include <unistd.h>

# include <string.h>
# include <errno.h>
# include <stdlib.h>

__attribute__ ((always_inline))
static inline void init_ip(struct iphdr* const ip, uint8_t protocol)
{
	*ip = (struct iphdr){
		.version = 4,
		.ihl = sizeof(struct iphdr) / 4,
		.tos = OPT_HAS(OPT_TOS) ? gctx.parse.opts_args.tos : 0,
		.tot_len = gctx.packetlen,
		.id = 0,
		.frag_off = OPT_HAS(OPT_DONTFRAG) ? 2 : 0,
		.ttl = gctx.hop,
		.protocol = protocol,
		.check = 0,
		.saddr = INADDR_ANY,
		.daddr = (*((struct sockaddr_in*)&gctx.dest_sockaddr)).sin_addr.s_addr
	};

	if (gettimeofday(&gctx.sendtime, NULL) != 0)
	{
		PRINT_ERROR(MSG_ERROR_SYSCALL, "gettimeofday", errno);
		exit(ERR_SYSCALL);
	}
}

__attribute__ ((always_inline))
static inline void send_packet(const uint8_t* packet, const struct iphdr* const ip)
{
	if (OPT_HAS(OPT_PROBES_UDP))
		(*(struct sockaddr_in*)&gctx.dest_sockaddr).sin_port = htons(gctx.destport);

	const ssize_t sent_bytes = sendto(
		OPT_HAS(OPT_PROBES_UDP) ? gctx.sendsockfd : gctx.sockfd,
		(const void*)packet,
		gctx.packetlen,
		0,
		(const struct sockaddr*)&gctx.dest_sockaddr,
		sizeof(const struct sockaddr)
	);

	if (sent_bytes < 0)
	{
		PRINT_ERROR(MSG_ERROR_SYSCALL, "sendto", errno);
		exit(ERR_SYSCALL);
	}
	else if (ip && sent_bytes != ip->tot_len)
	{
		printf(__progname ": wrote %s %hu chars, ret=%ld\n",
			   gctx.dest_ip, ip->tot_len, sent_bytes);
	}
}

void send_probes_udp4()
{
	uint8_t packet[MAX_PACKET_LEN] = {0};

	struct udphdr* const	udp = (struct udphdr*)packet;

	if (gctx.packetlen < sizeof(*udp))
		gctx.packetlen = sizeof(*udp);

	///NOTE: Seem like those values are ovewritten by the kernel,
	/// not a problem yet
	*udp = (struct udphdr){
		.source = htons(gctx.srcport),
		.dest = htons(gctx.destport),
		.len = htons(gctx.packetlen),
		.check = 0,
	};

	if (gctx.destport++ == gctx.parse.opts_args.port + 100)
		gctx.destport -= 100;

	ft_memset(packet + sizeof(*udp),
	PAYLOADBYTE, gctx.packetlen - sizeof(*udp));

	if (gettimeofday(&gctx.sendtime, NULL) != 0)
	{
		PRINT_ERROR(MSG_ERROR_SYSCALL, "gettimeofday", errno);
		exit(ERR_SYSCALL);
	}

	send_packet(packet, NULL);
}

void cut_connectiontcp_rst()
{
	uint8_t packet[MAX_PACKET_LEN] = {0};

    struct iphdr* const		ip = (struct iphdr*)packet;
	struct tcphdr* const	tcp = (struct tcphdr*)(packet + sizeof(*ip));

	if (gctx.packetlen < sizeof(*ip) + sizeof(*tcp))
		gctx.packetlen = sizeof(*ip) + sizeof(*tcp);

	*tcp = (struct tcphdr){
		.source = htons(gctx.srcport),
		.dest = gctx.destport, /// port allocated previously, already has network's endianess
		.seq = 0,
		.ack_seq = 0,
		.res1 = 0,
		.doff = sizeof(struct tcphdr) / 4,
		.fin = 0,
		.syn = 0,
		.rst = 1,
		.psh = 0,
		.ack = 1,
		.urg = 0,
		.res2 = 0,
		.window = 0,
		.check = 0,
		.urg_ptr = 0
	};

	init_ip(ip, IPPROTO_TCP);
	ft_memset(packet + sizeof(*ip) + sizeof(*tcp),
	PAYLOADBYTE, gctx.packetlen - (sizeof(*ip) + sizeof(*tcp)));
	tcp->check = in_cksum((uint16_t*)packet, gctx.packetlen);
	send_packet(packet, ip);
}

in_addr_t get_ip_by_if(const char* ifname)
{
	int sfd = socket(AF_INET, SOCK_DGRAM, 0);

	struct ifreq ifr;

	ifr.ifr_addr.sa_family = AF_INET;

	ft_memcpy(ifr.ifr_name, ifname, ft_strlen(ifname));

	if (ioctl(sfd, SIOCGIFADDR, &ifr) < 0)
	{
		/// JUST A TEMP SOLUTION
		printf("%s\n", strerror(errno));
		printf("ERROR EXIT");
		exit(1);
	}

	close(sfd);

	return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

uint16_t tcp_checksum(const struct iphdr* const ip)
{
	uint8_t buff[0X10000] = {0};
	uint8_t* ptr = buff;

	static in_addr_t myip = INADDR_ANY;

	if (myip == INADDR_ANY)
		myip = get_ip_by_if("wlp2s0");

	/* Prepend pseudo ip header */

	*(in_addr_t*)ptr = myip;
	ptr += sizeof(uint32_t);

	*(in_addr_t*)ptr = (*((struct sockaddr_in*)&gctx.dest_sockaddr)).sin_addr.s_addr;
	ptr += sizeof(uint32_t);

	*(ptr++) = 0;

	*(ptr++) = IPPROTO_TCP;

	*(uint16_t*)ptr = htons(gctx.packetlen - (ip->ihl * 4));
	ptr += sizeof(uint16_t);

	/* Add tcp header + payload */

	ft_memcpy(ptr, (uint8_t*)ip + (ip->ihl * 4), gctx.packetlen - (ip->ihl * 4));

	/* Calculate the checksum */

	const uint16_t check = in_cksum((uint16_t*)buff, (ptr - buff) + (gctx.packetlen - (ip->ihl * 4)));

	return check;
}

void set_tcp_options(uint8_t* tcp_opt)
{
	/* Set MSS (Max Segment Size (max payload size)) */
	*(tcp_opt++) = 2;
	*(tcp_opt++) = 4;
	*(uint16_t*)tcp_opt = htons(1460);
	tcp_opt += sizeof(uint16_t);

	/* Permit SACK (Selective ACKnowledgement) */
	*(tcp_opt++) = 4;
	*(tcp_opt++) = 2;

	/* Set timestamp */
	*(tcp_opt++) = 8;
	*(tcp_opt++) = 10;
	*(uint32_t*)tcp_opt = htonl(488234631);
	tcp_opt += sizeof(uint32_t);
	*(uint32_t*)tcp_opt = htonl(0);
	tcp_opt += sizeof(uint32_t);

	/* Padding 1 byte */
	*(tcp_opt++) = 1;

	/* Window scale */
	*(tcp_opt++) = 3;
	*(tcp_opt++) = 3;
	*(tcp_opt++) = 2;
}

void send_probes_tcp()
{
	uint8_t packet[MAX_PACKET_LEN] = {0};

    struct iphdr* const		ip = (struct iphdr*)packet;
	struct tcphdr* const	tcp = (struct tcphdr*)(packet + sizeof(*ip));
	uint8_t*				tcp_opt = (uint8_t*)(packet + sizeof(*ip) + sizeof(*tcp));

	if (gctx.packetlen < sizeof(*ip) + sizeof(*tcp) + TCP_OPTIONSLEN)
		gctx.packetlen = sizeof(*ip) + sizeof(*tcp) + TCP_OPTIONSLEN;

	in_port_t src_port = (rand() + 0XFFFF / 2) % (0XFFFF + 0X1);
	uint32_t seq = (rand() + (0X07FFFFFF / 2)) % 0X07FFFFFF;

	*tcp = (struct tcphdr){
		.source = htons(34061),//htons(src_port),
		.dest = htons(gctx.destport),
		.seq = htonl(2952925273),//htonl(seq),
		.ack_seq = 0,
		.res1 = 0,
		.doff = (sizeof(struct tcphdr) + TCP_OPTIONSLEN) / 4,
		.fin = 0,
		.syn = 1,
		.rst = 0,
		.psh = 0,
		.ack = 0,
		.urg = 0,
		.res2 = 0,
		.window = htons(5840), // random test
		.check = 0,
		.urg_ptr = 0
	};

	set_tcp_options(tcp_opt);
	init_ip(ip, IPPROTO_TCP);
	ft_memset(packet + (ip->ihl * 4) + sizeof(*tcp) + TCP_OPTIONSLEN,
	PAYLOADBYTE, gctx.packetlen - ((ip->ihl * 4) + sizeof(*tcp) + TCP_OPTIONSLEN));
	tcp->check = tcp_checksum(ip);
	send_packet(packet, ip);
}

void send_probes_icmp4()
{
    uint8_t packet[MAX_PACKET_LEN] = {0};

    struct iphdr* const		ip = (struct iphdr*)packet;
    struct icmphdr* const	icp = (struct icmphdr*)(packet + 20); ///TODO: sizeof ip is 20

	if (gctx.packetlen < sizeof(*ip) + sizeof(*icp))
		gctx.packetlen = sizeof(*ip) + sizeof(*icp);

	*icp = (struct icmphdr){
		.type = ICMP_ECHO,
		.code = 0,
		.checksum = 0,
		.un.echo.id = gctx.progid,
		.un.echo.sequence = gctx.parse.opts_args.port++
	};

	init_ip(ip, IPPROTO_ICMP);
	ft_memset(packet + sizeof(*ip) + sizeof(*icp),
	PAYLOADBYTE, gctx.packetlen - (sizeof(*ip) + sizeof(*icp)));
	icp->checksum = in_cksum((uint16_t*)(packet + sizeof(*ip)), gctx.packetlen - sizeof(*ip));
	send_packet(packet, ip);
}

void send_probes4()
{
    send_probes_icmp4();
}

void send_probes6()
{

}