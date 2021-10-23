
# include <traceroure.h>
# include <ftlibc.h>

# include <netinet/ip_icmp.h>
# include <errno.h>
 
void send_probes_icmp4()
{
    uint8_t packet[MAX_PACKET_LEN] = {0};

    struct iphdr* const		ip = (struct iphdr*)packet;
    struct icmphdr* const	icp = (struct icmphdr*)(packet + sizeof(*ip));
    struct timeval* const	tp = (struct timeval*)(packet + sizeof(*ip) + sizeof(*icp));

	*ip = (struct iphdr){
		.version = 4,
		.ihl = 5,
		.tos = OPT_HAS(OPT_TOS) ? gctx.parse.opts_args.tos : 0,
		.tot_len = MAX(sizeof(*ip) + sizeof(*icp), gctx.packetlen - (sizeof(*ip) + sizeof(*icp))),
		.id = 0,
		.frag_off = 0,
		.ttl = gctx.hop,
		.protocol = IPPROTO_ICMP,
		.check = 0,
		.saddr = INADDR_ANY,
		.daddr = (*((struct sockaddr_in*)&gctx.dest_sockaddr)).sin_addr.s_addr
	};

	*icp = (struct icmphdr){
		.type = ICMP_ECHO,
		.code = 0,
		.checksum = 0,
		.un.echo.id = gctx.progid,
		.un.echo.sequence = gctx.hop
	};

	///TODO: Handle < 16bytes payloads
	if (gettimeofday(tp, NULL) != 0)
	{
		PRINT_ERROR(MSG_ERROR_SYSCALL, "gettimeofday", errno);
		exit(ERR_SYSCALL);
	}

	ft_memset(packet + sizeof(*ip) + sizeof(*icp) + sizeof(*tp),
	PAYLOADBYTE, MAX(0, gctx.packetlen - (sizeof(*ip) + sizeof(*icp) + sizeof(*tp))));

	icp->checksum = in_cksum((uint16_t*)(packet + sizeof(*ip)), MAX(sizeof(*icp), gctx.packetlen - sizeof(*ip)));

	const ssize_t sent_bytes = sendto(
		gctx.sockfd,
		(const void*)packet,
		ip->tot_len,
		0,
		(const struct sockaddr*)&gctx.dest_sockaddr,
		sizeof(const struct sockaddr)
	);

	if (sent_bytes < 0)
	{
		PRINT_ERROR(MSG_ERROR_SYSCALL, "sendto", errno);
		exit(ERR_SYSCALL);
	}
	else if (sent_bytes != ip->tot_len)
	{
		printf(__progname ": wrote %s %ld chars, ret=%ld\n",
			   gctx.dest_ip, ip->tot_len, sent_bytes);
	}

	gctx.packet_transm_nb++;
}

void send_probes4()
{
    send_probes_icmp4();
}

void send_probes6()
{

}