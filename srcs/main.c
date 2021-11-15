
# include <traceroute.h>
# include <ftlibc.h>

# include <unistd.h>
# include <errno.h>
# include <sys/select.h>
# include <stdbool.h>
# include <time.h>
# include <stdlib.h>

///TODO: TEST FLAGS AND FUCNTIONALITY

///TODO: Check for TODO's accross the code

///TODO: I got a filter for duplicates ips ... I guess i must test at 42

///TODO: When i get my ip for tcp checksum the interface can change ...
/// Use the interface that the docker will provide


# define PRINT_HEADER(dns, ip, maxhops, packsz) (							\
		printf(__progname " to %s (%s), %lu hops max, %lu byte packets\n",	\
		dns, ip, maxhops, packsz)											\
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
        PRINT_ERROR("%s", MSG_USAGE);
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
		gctx.init_socket = OPT_HAS(OPT_PROBES_UDP) ? &init_socket4_udp : OPT_HAS(OPT_PROBES_TCP) ? &init_socket4_tcp : &init_socket4_icmp;
		gctx.send_probes = OPT_HAS(OPT_PROBES_UDP) ? &send_probes_udp4 : OPT_HAS(OPT_PROBES_TCP) ? &send_probes_tcp : &send_probes_icmp4;
		gctx.print_route = &print_route4;
#ifdef IS_IPV6_SUPORTED
	}
#endif
}

int		main(int ac, const char* av[])
{
	error_type st = SUCCESS;

	srand(time(0));

	++av;

	if ((st = check_initial_validity(ac))
	|| (st = parse_opts(&av)) != SUCCESS)
		goto error;

	if (OPT_HAS(OPT_HELP))
	{
		PRINT_ERROR("%s", MSG_USAGE);
        st = ERR_DESTADDR;
		goto error;
	}

	if ((bool)OPT_HAS(OPT_PROBES_TCP) + (bool)OPT_HAS(OPT_PROBES_UDP) + (bool)OPT_HAS(OPT_PROBES_ICMP) > 1)
	{
		PRINT_ERROR(__progname": %s\n", "Incompatible probes types, must select only 1 (ICMP is set by default)");
		st = ERR_OPT;
		goto error;
	}

	spetialize_by_version();

	if ((st = gctx.gethostinfo_str(*av, gctx.dest_dns, (int8_t*)gctx.dest_ip)) != SUCCESS)
		goto error;

	if (*(av + 1))
	{
		if (is_string_digit(*(av + 1)) == false)
		{
			PRINT_ERROR(__progname ": %s\n", "packetlen bad format");
			goto error;
		}
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
	gctx.hop = OPT_HAS(OPT_START_HOP) ? gctx.parse.opts_args.initial_hops : DEFAULT_HOPSTART;
	gctx.destport = OPT_HAS(OPT_PORT) ? gctx.parse.opts_args.port : OPT_HAS(OPT_PROBES_TCP) ? DEFAULT_TCPPORT : DEFAULT_PORT;
	gctx.parse.opts_args.probes_nb_per_hop = OPT_HAS(OPT_NBPKSEND) ? gctx.parse.opts_args.probes_nb_per_hop : DEFAULT_NBPROBESPERHOP;

	PRINT_HEADER(gctx.dest_dns, gctx.dest_ip, gctx.hop_max, gctx.packetlen);

	static uint8_t	recvbuff[MAX_PACKET_LEN];
	ssize_t			receiv_bytes = 0;

	for ( ; gctx.hop < gctx.hop_max ; )
	{

		if (st != KEEP_RCV)
			gctx.send_probes();

		if ((st = receive_probe(recvbuff, ARRAYSIZE(recvbuff), &receiv_bytes)) != SUCCESS
		|| (st = gctx.print_route(recvbuff, receiv_bytes)) != CONTINUE && st != KEEP_RCV)
			goto error;

		ft_memset(recvbuff, 0, receiv_bytes);
	}

error:
	if (OPT_HAS(OPT_PROBES_UDP))
		close(gctx.sendsockfd);
	close(gctx.sockfd);
	return st;
}
