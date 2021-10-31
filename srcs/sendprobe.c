
# include <traceroute.h>
# include <ftlibc.h>

# include <netinet/ip_icmp.h>
# include <netinet/udp.h>
# include <netinet/tcp.h>

# include <errno.h>
# include <stdlib.h>

__attribute__ ((always_inline))
static inline void init_ip(struct iphdr* const ip, uint8_t protocol)
{
	*ip = (struct iphdr){
		.version = 4,
		.ihl = 5,
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
		(*(struct sockaddr_in*)&gctx.dest_sockaddr).sin_port = gctx.destport;

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
		.source = gctx.srcport,
		.dest = gctx.destport,
		.seq = 0,
		.ack_seq = 0,
		.res1 = 0,
		.doff = sizeof(struct tcphdr) / 4,
		.fin = 0,
		.syn = 0,
		.rst = 1,
		.psh = 0,
		.ack = 0,
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

void send_probes_tcp()
{
	uint8_t packet[MAX_PACKET_LEN] = {0};

    struct iphdr* const		ip = (struct iphdr*)packet;
	struct tcphdr* const	tcp = (struct tcphdr*)(packet + sizeof(*ip));

	if (gctx.packetlen < sizeof(*ip) + sizeof(*tcp))
		gctx.packetlen = sizeof(*ip) + sizeof(*tcp);

	*tcp = (struct tcphdr){
		.source = gctx.srcport,
		.dest = gctx.destport, // 80 ?!?? (sourc ???)
		.seq = 0,
		.ack_seq = 0,
		.res1 = 0,
		.doff = sizeof(struct tcphdr) / 4,
		.fin = 0,
		.syn = 1,
		.rst = 0,
		.psh = 0,
		.ack = 0,
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

void send_probes_icmp4()
{
    uint8_t packet[MAX_PACKET_LEN] = {0};

    struct iphdr* const		ip = (struct iphdr*)packet;
    struct icmphdr* const	icp = (struct icmphdr*)(packet + sizeof(*ip));

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