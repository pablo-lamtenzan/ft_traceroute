
# include <traceroute.h>
# include <ftlibc.h>
# include <errno.h>
# include <host.h>

# include <netinet/ip_icmp.h>
# include <netinet/udp.h>
# include <netinet/tcp.h>
# include <stdbool.h>

# define PRINT_HOP(hop) (		\
	printf("\n%2lu", hop)		\
	)

__attribute__ ((always_inline))
static inline double get_timediff()
{
	tvsub(&gctx.recvtime, &gctx.sendtime);
	return (TV_TO_MS(gctx.recvtime));
}

__attribute__ ((always_inline))
static inline error_type print_iteration(int8_t code)
{
	static host_t hostarr[MAX_HOSTS];
	static host_t prev[MAX_HOSTS];

	if (gctx.is_timeout == true)
	{
		gctx.is_timeout = false;

		hostarr[arrhostlen(hostarr)].istimeout = true;
		hostarr[arrhostlen(hostarr)].saddr = 42;

		if (gctx.probescount % gctx.parse.opts_args.probes_nb_per_hop == 0)
		{
			ft_memset(prev, 0, arrhostlen(prev) * sizeof(host_t));
			ft_memcpy(prev, hostarr, arrhostlen(hostarr) * sizeof(host_t));
			if (print_hostarr(hostarr) == false)
				return ERR_SYSCALL;
			ft_memset(hostarr, 0, arrhostlen(hostarr) * sizeof(host_t));
			gctx.hop++;
		}
		return SUCCESS;
	}

	in_addr_t saddr = (*(struct sockaddr_in*)&gctx.recv_sockaddr).sin_addr.s_addr;

	if (findhost(prev, arrhostlen(prev), saddr) == NULL)
	{
		const size_t	len = arrhostlen(hostarr);
		host_t*			found;

		if ((found = findhost(hostarr, len, saddr)))
		{
			timestamp_t* t = &found->times[timesplen(found->times)];
			t->code = code;
			t->t = get_timediff();
		}
		else
		{
			found = &hostarr[len];
			*found = (host_t){
				.saddr = saddr,
				.skaddr = gctx.recv_sockaddr,
			};

			timestamp_t* t = &found->times[timesplen(found->times)];
			t->code = code;
			t->t = get_timediff();
		}

		uint64_t prevprobescount = gctx.probescount;
		if (code == NOCODE)
			gctx.probescount++;

		if (prevprobescount != gctx.probescount
		&& gctx.probescount % gctx.parse.opts_args.probes_nb_per_hop == 0)
		{
			ft_memset(prev, 0, arrhostlen(prev) * sizeof(host_t));
			ft_memcpy(prev, hostarr, arrhostlen(hostarr) * sizeof(host_t));
			if (print_hostarr(hostarr) == false)
				return ERR_SYSCALL;
			ft_memset(hostarr, 0, arrhostlen(hostarr) * sizeof(host_t));
			gctx.hop++;
		}
	}
	return SUCCESS;
}

error_type print_route4(const void* const recvbuff, ssize_t bufflen)
{
	error_type			st = CONTINUE;
	static uint32_t		itearation = 0;

	const struct iphdr* const ip = (struct iphdr*)recvbuff;

	if (ip->version != 4)
		goto error;
	
	///TODO: Ignore packet non - adressed to us (icmp use pid, tcp use my ip != dest ip)
	
	if (OPT_HAS(OPT_PROBES_TCP) && ip->protocol == IPPROTO_TCP)
	{
		const struct tcphdr* const tcp = (struct tcphdr*)(recvbuff + sizeof(*ip));

		if (bufflen < (ip->ihl * 4) + (uint32_t)sizeof(*tcp))
			goto error;

		if (ip->saddr == (*(struct sockaddr_in*)&gctx.dest_sockaddr).sin_addr.s_addr
			&& ((tcp->ack && tcp->syn) || tcp->rst))
		{
			if (++itearation <= gctx.parse.opts_args.probes_nb_per_hop
			&& print_iteration(NOCODE) != SUCCESS)
			{
				st = ERR_SYSCALL;
				goto error;
			}
			if (itearation == gctx.parse.opts_args.probes_nb_per_hop)
			{
				st = SUCCESS;
				printf("%s", "\n");
			}
			else
				st = CONTINUE;
			goto error;
		}

		///TODO: Answer using tcp reset to end the conection silencously (half-open technique)
	}
	else if (ip->protocol == IPPROTO_ICMP)
	{
		const struct icmphdr* icp = (struct icmphdr*)(recvbuff + sizeof(*ip));

		if (bufflen < (ip->ihl * 4) + (uint32_t)sizeof(*icp))
			goto error;

		switch (icp->type)
		{
			case ICMP_DEST_UNREACH:
				if (print_iteration(icp->code) != SUCCESS)
				{
					st = ERR_SYSCALL;
					goto error;
				}
				break ;
			case ICMP_TIME_EXCEEDED:
				if (((struct icmphdr*)(recvbuff + 48))->un.echo.id == gctx.progid)
				{
					if (icp->code == ICMP_EXC_TTL)
					{
						if (print_iteration(NOCODE) != SUCCESS)
						{
							st = ERR_SYSCALL;
							goto error;
						}
					}
				}
				else
					{
						printf("[DEBUG] Ignore packet that is not mine\n");
					}

				break ;

			case ICMP_ECHOREPLY:
				st = CONTINUE;
				if (icp->un.echo.id == gctx.progid
				&& ip->saddr == (*(struct sockaddr_in*)&gctx.dest_sockaddr).sin_addr.s_addr)
				{
					if (++itearation <= gctx.parse.opts_args.probes_nb_per_hop)
					{
						if (print_iteration(NOCODE) != SUCCESS)
						{
							st = ERR_SYSCALL;
							goto error;
						}
					}
					if (itearation == gctx.parse.opts_args.probes_nb_per_hop)
					{
						st = SUCCESS;
					}
				}
				else
				{
					printf("[DEBUG] ICMP DEST ADDR != FOUND\n");
				}
				break ;

			default:	
				printf("other icmp type is %d\n", icp->type);
				break ;
		}
	}

	//printf("[DEBUG] protocol %d\n", ip->protocol);

	///NOTE: Recv protocol is UDP for UDP and seems to not pass the first node
	///NOTE: Recv protocol is TCP for TCP and don't pass the first node

	// printf("icmp type: %hu\n", icp->type);
	//printf("ip = %s\n", inet_ntoa((struct in_addr){ip->daddr}));

	

error:
	return st;
}

// error_type print_route_udp(const void* const recvbuff, ssize_t bufflen)
// {
// 	error_type		st = CONTINUE;

// 	const struct iphdr* const ip = (struct iphdr*)recvbuff;
// 	const struct udphdr* const udp = (struct udphdr*)(recvbuff + sizeof(*ip));

// 	if (bufflen < (ip->ihl * 4) + sizeof(*udp))
// 		goto error;

// error:
// 	return st;
// }

error_type print_route6(const void* const recvbuff, ssize_t bufflen)
{
	(void)recvbuff;
	(void)bufflen;
	return SUCCESS;
}
