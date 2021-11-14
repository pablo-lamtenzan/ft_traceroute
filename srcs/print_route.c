
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
static inline bool	ismsg_zeroed(const uint8_t* const msg, ssize_t msglen)
{
	size_t sum = 0;

	for (ssize_t i = 0 ; i < msglen ; i++)
		sum += msg[i];
	return sum == 0;
}

__attribute__ ((always_inline))
static inline double get_timediff()
{
	tvsub(&gctx.recvtime, &gctx.sendtime);
	return (TV_TO_MS(gctx.recvtime));
}

static error_type print_iteration(int8_t code)
{
	error_type st = SUCCESS;

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
				goto end;
			ft_memset(hostarr, 0, arrhostlen(hostarr) * sizeof(host_t));
			gctx.hop++;

			if (OPT_HAS(OPT_PROBES_UDP))
			{
				if (setsockopt(gctx.sendsockfd, IPPROTO_IP, IP_TTL,
				(int[]){gctx.hop}, sizeof(int)) < 0)
				{
					st = ERR_SYSCALL;
        			PRINT_ERROR(MSG_ERROR_SYSCALL, "setsockopt", errno);
					goto end;
				}
			}
		}
		goto end;
	}

	in_addr_t saddr = (*(struct sockaddr_in*)&gctx.recv_sockaddr).sin_addr.s_addr;

	///TODO: TODO
	if (1||findhost(prev, arrhostlen(prev), saddr) == NULL)
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
		if (code == NOCODE || (OPT_HAS(OPT_PROBES_UDP) && code == ICMP_PORT_UNREACH))
			gctx.probescount++;

		if (prevprobescount != gctx.probescount
		&& gctx.probescount % gctx.parse.opts_args.probes_nb_per_hop == 0)
		{
			ft_memset(prev, 0, arrhostlen(prev) * sizeof(host_t));
			ft_memcpy(prev, hostarr, arrhostlen(hostarr) * sizeof(host_t));
			if (print_hostarr(hostarr) == false)
				goto end;
			ft_memset(hostarr, 0, arrhostlen(hostarr) * sizeof(host_t));
			gctx.hop++;

			if (OPT_HAS(OPT_PROBES_UDP))
			{
				if (setsockopt(gctx.sendsockfd, IPPROTO_IP, IP_TTL,
				(int[]){gctx.hop}, sizeof(int)) < 0)
				{
					st = ERR_SYSCALL;
        			PRINT_ERROR(MSG_ERROR_SYSCALL, "setsockopt", errno);
					goto end;
				}
			}
		}
	}
	else
	{
		printf("[DEBUG] Filter has blocked a duplicated from a previous hop\n");
	}
end:
	return st;
}

error_type print_route4(const void* const recvbuff, ssize_t bufflen)
{
	error_type			st = CONTINUE;
	static uint32_t		itearation = 0;

	const struct iphdr* const ip = (struct iphdr*)recvbuff;

	if (gctx.is_timeout == true)
	{
		if (print_iteration(NOCODE) != SUCCESS)
			st = ERR_SYSCALL;
		goto error;
	}

	if (ip->version != 4)
		goto error;
	
	if (OPT_HAS(OPT_PROBES_TCP) && ip->protocol == IPPROTO_TCP)
	{
		if (bufflen < (ip->ihl * 4) + (uint32_t)sizeof(struct tcphdr))
			goto error;

		const struct tcphdr* const tcp = (struct tcphdr*)(recvbuff + ip->ihl * 4);

		///TODO: If syn/ack port is open, else if rst port is closed
		///TODO: Alse i can receive just a syn, port is open (simultaneous open or split handshake connection)
		if (ip->saddr == (*(struct sockaddr_in*)&gctx.dest_sockaddr).sin_addr.s_addr
			&& ((tcp->ack && tcp->syn)))
		{
			if (++itearation <= gctx.parse.opts_args.probes_nb_per_hop
			&& print_iteration(NOCODE) != SUCCESS)
			{
				st = ERR_SYSCALL;
				goto error;
			}
			if (itearation == gctx.parse.opts_args.probes_nb_per_hop)
				st = SUCCESS;
			else
				st = CONTINUE;
			goto error;

			cut_connectiontcp_rst(ip->saddr);
		}
	}
	else if (ip->protocol == IPPROTO_ICMP)
	{
		if (bufflen < (ip->ihl * 4) + (uint32_t)sizeof(struct icmphdr))
			goto error;

		const struct icmphdr* icp = (struct icmphdr*)(recvbuff + ip->ihl * 4);

		switch (icp->type)
		{
			case ICMP_DEST_UNREACH:
				if (OPT_HAS(OPT_PROBES_UDP) == false
				|| ip->saddr != (*(struct sockaddr_in*)&gctx.dest_sockaddr).sin_addr.s_addr)
				{
					if (print_iteration(icp->code) != SUCCESS)
					{
						st = ERR_SYSCALL;
						goto error;
					}
				}
				else
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
						st = SUCCESS;
				}
				break ;

			case ICMP_TIME_EXCEEDED:
				size_t iphlen = ip->ihl * 4;
				size_t iphlen_old = ((struct iphdr*)(recvbuff + iphlen + sizeof(*icp)))->ihl * 4;
				if (((struct icmphdr*)(recvbuff + iphlen + sizeof(*icp) + iphlen_old))->un.echo.id == gctx.progid
				|| (OPT_HAS(OPT_PROBES_UDP) && ((struct udphdr*)(recvbuff + iphlen + sizeof(*icp) + iphlen_old))->dest == ntohs(gctx.destport))
				|| (OPT_HAS(OPT_PROBES_TCP) && ((struct tcphdr*)(recvbuff + iphlen + sizeof(*icp) + iphlen_old))->dest == ntohs(gctx.destport)))
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
						printf("[DEBUG] Ignore packet that is not mine (%d - %d)\n", ((struct udphdr*)(recvbuff + iphlen + sizeof(*icp) + iphlen_old))->dest, ntohs(gctx.destport));
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
						st = SUCCESS;
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
		///NOTE: TCP still been blocked maybe check NAT(?)

error:
	return st;
}

error_type print_route6(const void* const recvbuff, ssize_t bufflen)
{
	(void)recvbuff;
	(void)bufflen;
	return SUCCESS;
}
