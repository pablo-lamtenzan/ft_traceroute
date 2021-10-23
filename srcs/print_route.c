
# include <traceroure.h>
# include <hopstats.h>
# include <ftlibc.h>

# include <netinet/ip_icmp.h>

# define PRINT_HOP_INDEX(hop) (printf("%2lu", hop))

# define PRINT_INFO_STATS(dns, ip, min, mean, max) (	\
	printf("  %s (%s)  %.3fms  %.3fms  %.3fms",			\
	dns, ip, min, mean, max)							\
	)

static double get_timediff(struct timeval* tp)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	tvsub(&tv, tp);

	return (TV_TO_MS(tv));
}

/**
 * 	@return false if all the elements of array @p hsbuff
 * 	haven't finished to record
*/
static bool	is_hophost_arr_fully_recording(hoststats4_t* const hsbuff)
{
	for (size_t i = 0 ; !ISZEROED(hsbuff[i]) ; i++)
	{
		if (hsbuff[i].recording == false)
			return (false);
	}
	return (true);
}

# define MAX_HOST_PER_HOP 0X100

/**
 * 	@param hsbuff A pointer hoststats4_t array first elem (must be zeroed)
 * 	@param address An address to match in the @p hsbuff
 * 	@return A pointer to the found hsbuff_t whether found or add
 * 	an element at the end of @p hsbuff and init it with @p address
*/
static hoststats4_t* get_hophost(hoststats4_t* const hsbuff, in_addr_t address)
{
	size_t it = 0;
	for ( ; !ISZEROED(hsbuff[it]) ; it++)
	{
		if (hsbuff[it].saddr == address)
			return (&hsbuff[it]);
	}
	if (it == MAX_HOST_PER_HOP)
		return NULL;
	hsbuff[it] = (hoststats4_t){
		.recording = true,
		.saddr = address,
		.st_tmin = PSEUDOINFINITY
	};
	return &hsbuff[it];
}

///NOTE: hop is incremented due to a timeout

error_t print_route4(const void* const recvbuff, ssize_t bufflen)
{
    error_t st = SUCCESS;

    static uint64_t		last_hop;
    static hoststats4_t	hop_hosts[MAX_HOST_PER_HOP];

	if (last_hop != gctx.hop)
	{
		if (is_hophost_arr_fully_recording(hop_hosts))
			printf("%2lu  * * *", last_hop);
		printf("%c", '\n');

    	ft_memset(hop_hosts, 0, ARRAYSIZE(hop_hosts));
		last_hop = gctx.hop;
	}

	const struct iphdr* const ip = (struct iphdr*)recvbuff;
	const struct icmphdr* const icp = (struct icmphdr*)(recvbuff + sizeof(*ip));

	if (bufflen < (ip->ihl << 2) + (uint32_t)sizeof(*icp))
		goto error;

	if (icp->type == ICMP_ECHOREPLY)
	{
		if (icp->un.echo.id != gctx.progid
		|| icp->un.echo.sequence != gctx.hop)
			goto error;

		hoststats4_t* host = get_hophost(hop_hosts, ip->saddr);
		if (host == NULL)
			goto error;

		if (!ISPRINTED(*host))
		{
			double timediff = get_timediff(recvbuff + sizeof(*ip) + sizeof(*icp));
				if (timediff < host->st_tmin)
					host->st_tmin = timediff;
				if (timediff > host->st_tmax)
					host->st_tmax = timediff;
				host->st_tsum += timediff;

			if (++host->st_total > VALIDE_HOST_REPLIES)
			{
				host->recording = false;

				gctx.gethostinfo_i32((struct in_addr[]){{.s_addr=host->saddr}},
				gctx.dest_dns, gctx.dest_ip);

				if (is_hophost_arr_fully_recording(hop_hosts))
					PRINT_HOP_INDEX(gctx.hop);
				PRINT_INFO_STATS(gctx.dest_dns, gctx.dest_ip, host->st_tmin, host->st_tsum / host->st_total, host->st_tmax);

				ft_memset(gctx.dest_dns, 0, ARRAYSIZE(gctx.dest_dns));
				ft_memset(gctx.dest_ip, 0, ARRAYSIZE(gctx.dest_ip));
			}
		}
	}
	else
		; // maybe have to print error but i don't think so

error:
	return st;
}

error_t print_route6(const void* const recvbuff, ssize_t bufflen)
{
	(void)recvbuff;
	(void)bufflen;
}