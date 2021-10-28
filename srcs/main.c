
# include <traceroute.h>
# include <ftlibc.h>

# include <unistd.h>
# include <errno.h>
# include <sys/select.h>
# include <stdbool.h>

///FIX: Last mesage output and addr
///TODO: inet_ntop si forbiden

// Perfect output example:
/*
➜  ft_traceroute traceroute 42.fr
traceroute to 42.fr (163.172.250.16), 30 hops max, 60 byte packets
 1  172.16.4.3 (172.16.4.3)  2.222 ms  2.228 ms  2.123 ms
 2  192.168.1.254 (192.168.1.254)  2.712 ms  6.427 ms  6.588 ms
 3  194.149.169.61 (194.149.169.61)  14.435 ms  14.223 ms  14.387 ms
 4  194.149.166.62 (194.149.166.62)  13.897 ms  13.874 ms  14.125 ms
 5  * * *
 6  62.210.0.168 (62.210.0.168)  15.127 ms 62.210.0.174 (62.210.0.174)  10.779 ms 62.210.0.170 (62.210.0.170)  10.873 ms
 7  51.158.1.43 (51.158.1.43)  10.328 ms 51.158.1.35 (51.158.1.35)  64.152 ms  63.917 ms
 8  45x-s44-2-a9k2.dc3.poneytelecom.eu (195.154.1.107)  64.838 ms 45x-s44-2-a9k1.dc3.poneytelecom.eu (195.154.1.105)  65.087 ms 45x-s44-2-a9k2.dc3.poneytelecom.eu (195.154.1.107)  64.222 ms
 9  195.154.1.175 (195.154.1.175)  65.401 ms  65.663 ms  65.843 ms
10  163.172.250.16 (163.172.250.16)  64.612 ms  64.592 ms  64.572 ms

*/

# define PRINT_HEADER(dns, ip, maxhops, packsz) (							\
		printf(__progname " to %s (%s), %lu hops max, %lu byte packets\n",	\
		dns, ip, maxhops, packsz)											\
		)

# define PRINT_HOP(hop) (		\
	printf("\n%2lu", hop)		\
	)

# define PRINT_FIRST_HOP(hop) (	\
	printf("%2lu", hop)	\
	)

__attribute__((always_inline))
static inline error_type  check_initial_validity(int ac)
{
    error_type st = SUCCESS;

    if (getuid() != 0)
    {
        PRINT_ERROR(__progname ": %s\n", "user must be root");
        st = ERR_USERPRIV;
        goto error;
    }

    if (ac == 1)
    {
		///TODO: Print usage
        //PRINT_ERROR("%s", MSG_REQUIRED_DESTINATION);
        st = ERR_DESTADDR;
    }

error:
    return st;
}

gcontext_t gctx = {

};

__attribute__ ((always_inline))
static inline void spetialize_by_version()
{
#ifdef IS_IPV6_SUPORTED
	if (OPT_HAS(OPT_IPV6))
	{
		gctx.gethostinfo_str = &gethostinfo_str6;
		gctx.init_socket = &init_socket6;
		gctx.send_probes = &send_probes6;
		gctx.print_route = &print_route6;
	}
	else
	{
#endif
		gctx.gethostinfo_str = &gethostinfo_str4;
		gctx.init_socket = &init_socket4;
		gctx.send_probes = &send_probes4;
		gctx.print_route = &print_route4;
#ifdef IS_IPV6_SUPORTED
	}
#endif
}

int		main(int ac, const char* av[])
{
	error_type st = SUCCESS;

	++av;

	if ((st = check_initial_validity(ac))
	|| (st = parse_opts(&av)) != SUCCESS)
		goto error;

	spetialize_by_version();

	if ((st = gctx.gethostinfo_str(*av, gctx.dest_dns, (int8_t*)gctx.dest_ip)) != SUCCESS)
		goto error;

	if (*(av + 1))
	{
		///TODO: If is string digit and all this parsing stuff ...
		gctx.packetlen = ft_atol(*(av + 1));
		if (gctx.packetlen > MAX_PACKET_LEN)
		{
			PRINT_ERROR(MSG_ERROR_PACKETLEN_SZ, gctx.packetlen);
			st = ERR_OPT;
			goto error;
		}
	}
	else
		gctx.packetlen = OPT_HAS(OPT_IPV6) ? DEFAULT_PACKETLEN6 : DEFAULT_PACKETLEN4;

	if ((st = gctx.init_socket()) != SUCCESS)
		goto error;

	gctx.progid = getpid() & 0XFFFF;
	gctx.hop_max = OPT_HAS(OPT_END_HOP) ? gctx.parse.opts_args.max_hops : DEFAULT_HOPMAX;
	gctx.hop = OPT_HAS(OPT_START_HOP) ? gctx.parse.opts_args.initial_hops : 1;

	PRINT_HEADER(gctx.dest_dns, gctx.dest_ip, gctx.hop_max, gctx.packetlen);

	static uint8_t	recvbuff[MAX_PACKET_LEN];
	ssize_t			receiv_bytes;
	size_t			probescount = 0;

	PRINT_FIRST_HOP(gctx.hop);

	for ( ; gctx.hop < gctx.hop_max ; )
	{
		gctx.send_probes();

		if ((st = receive_probe(recvbuff, ARRAYSIZE(recvbuff), &receiv_bytes)) != SUCCESS
		&& st != CONTINUE)
			goto error;

		if (st != CONTINUE &&
		(st = gctx.print_route(recvbuff, receiv_bytes)) != CONTINUE)
			goto error;

		ft_memset(recvbuff, 0, receiv_bytes);

		if (++probescount % 3 == 0)
		{
			gctx.hop++;
			PRINT_HOP(gctx.hop);
		}
	}

error:
	close(gctx.sockfd);
	return st;
}
