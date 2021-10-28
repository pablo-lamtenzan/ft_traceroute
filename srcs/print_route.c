
# include <traceroute.h>
# include <hopstats.h>
# include <ftlibc.h>
# include <errno.h>

# include <netinet/ip_icmp.h>

# define PRINT_HOST_INFO(dns, ip) (						\
		printf("  %s (%s)", dns, ip)					\
	)

# define PRINT_TIMESTAMP(timediff) (					\
		printf("  %.3fms", timediff)					\
	)

__attribute__ ((always_inline))
static inline double get_timediff()
{
	tvsub(&gctx.recvtime, &gctx.sendtime);
	return (TV_TO_MS(gctx.recvtime));
}

__attribute__ ((always_inline))
static inline error_type print_iteration(const struct iphdr* const ip)
{
	error_type			st = SUCCESS;
	static in_addr_t	prevhostaddr = 0;

	if (ip->saddr != prevhostaddr)
	{
		prevhostaddr = ip->saddr;

		if (getnameinfo(&gctx.recv_sockaddr, sizeof(gctx.recv_sockaddr), (char*)&gctx.dest_dns, ARRAYSIZE(gctx.dest_dns), 0, 0, 0) != 0)
		{
			PRINT_ERROR(MSG_ERROR_SYSCALL, "getnameinfo", errno);
			st = ERR_SYSCALL;
			goto error ;
		}

		PRINT_HOST_INFO(gctx.dest_dns, inet_ntoa((struct in_addr){.s_addr=ip->saddr}));
	}
	PRINT_TIMESTAMP(get_timediff());
error:
	return st;
}

error_type print_route4(const void* const recvbuff, ssize_t bufflen)
{
	error_type			st = CONTINUE;

	const struct iphdr* const ip = (struct iphdr*)recvbuff;
	const struct icmphdr* icp = (struct icmphdr*)(recvbuff + sizeof(*ip));

	if (bufflen < (ip->ihl * 4) + (uint32_t)sizeof(*icp))
		goto error;

	switch (icp->type)
	{
		case ICMP_TIME_EXCEEDED:
			if (icp->code == ICMP_EXC_TTL)
				print_iteration(ip);
			else { ; /* some fragmentation errors */ }
			break ;

		case ICMP_ECHOREPLY:
			static int itearation = 0;
			if (++itearation <= 3)
				print_iteration(ip);
			if (itearation == 3)
			{
				st = SUCCESS;
				printf("%s", "\n");
			}
			else
				st = CONTINUE;
			break ;

		default:
			break ;
	}

error:
	return st;
}

error_type print_route6(const void* const recvbuff, ssize_t bufflen)
{
	(void)recvbuff;
	(void)bufflen;
	return SUCCESS;
}