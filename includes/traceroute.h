
# pragma once

# include <ft_error.h>
# include <parse_types.h>

# include <sys/time.h>
# include <arpa/inet.h>
# include <bits/local_lim.h>
# include <netdb.h>

#ifdef AF_INET6
# define IS_IPV6_SUPORTED
#endif

# define DEFAULT_PACKETLEN4 60
# define MAX_PACKET_LEN 65000
# define DEFAULT_HOPMAX 30

#ifdef IS_IPV6_SUPORTED
# define DEFAULT_PACKETLEN6 80
#endif

typedef error_type (*gethostinfo_str_t)(const char*, uint8_t* const, int8_t* const);
typedef error_type (*gethostinfo_i32_t)(void*, uint8_t* const, int8_t* const);
typedef error_type (*init_socket_t)();
typedef void	(*send_probe_t)();
typedef error_type (*print_route_t)(const void* const, ssize_t);

typedef struct			gcontext
{
	struct sockaddr		dest_sockaddr;
	struct sockaddr		recv_sockaddr;
	uint8_t				dest_dns[NI_MAXHOST];
	uint8_t				dest_ip[HOST_NAME_MAX];
	size_t				packetlen;
	int					sockfd;
	int					sendsockfd;
	uint16_t			progid;
	parse_t				parse;
	uint64_t			hop;
	uint64_t			probescount;
	uint64_t			hop_max;
	struct timeval		sendtime;
	struct timeval		recvtime;
	uint8_t				is_timeout;
	in_port_t			srcport;
	in_port_t			destport;

	struct
	{
		gethostinfo_str_t	_gethostinfo_str;
		init_socket_t		_init_socket;
		send_probe_t		_send_probes;
		print_route_t		_print_route;
	} gfamilydependent;
	# define gethostinfo_str gfamilydependent._gethostinfo_str
	# define init_socket gfamilydependent._init_socket
	# define send_probes gfamilydependent._send_probes
	# define print_route gfamilydependent._print_route
}						gcontext_t;

extern gcontext_t gctx;

# define DEFAULT_PORT 33434
# define DEFAULT_TCPPORT 80
# define PAYLOADBYTE ((uint8_t)((uint8_t)4 | ((uint8_t)2 << 4)))
# define PSEUDOINFINITY (~(uint64_t)0UL)
# define DEFAULT_HOPSTART 1
# define DEFAULT_NBPROBESPERHOP 3

# define OPT_HAS(opt) (gctx.parse.opts & (opt))
# define OPT_ADD(opt) (gctx.parse.opts |= (opt))
# define OPT_DEL(opt) (gctx.parse.opts &= ~(opt))

# define ARRAYSIZE(arr) (sizeof(arr) / sizeof(*arr))
# define MAX(l, r) ((l) > (r) ? (l) : (r))

# define GETSOCKTYPE (OPT_HAS(OPT_PROBES_UDP | OPT_PROBES_TCP) ? SOCK_DGRAM : SOCK_RAW)
# define GETSOCKPROTOCOL (OPT_HAS(OPT_PROBES_TCP) ? IPPROTO_TCP : OPT_HAS(OPT_PROBES_UDP) ? IPPROTO_UDP : IPPROTO_ICMP)

# define TV_TO_MS(tv) (double)((double)(tv.tv_sec) * 1000.0 + (double)(tv.tv_usec) / 1000.0)

error_type		parse_opts(const char** av[]);

error_type		gethostinfo_str4(const char* hostname, uint8_t* const destdns, int8_t* const destip);
error_type		gethostinfo_i32_4(void* ipaddr, uint8_t* const destdns, int8_t* const destip);
error_type		init_socket4_icmp();
error_type		init_socket4_udp();
error_type		init_socket4_tcp();

void			send_probes4();
error_type		receive_probe(uint8_t* const dest, size_t destlen, ssize_t* const recvbytes);
error_type		print_route4(const void* const recvbuff, ssize_t bufflen);
void			send_probes_icmp4();
void			send_probes_udp4();
void			send_probes_tcp();
void			cut_connectiontcp_rst();

#ifdef IS_IPV6_SUPORTED

error_type		gethostinfo_str6(const char* hostname, uint8_t* const destdns, int8_t* const destip);
error_type		gethostinfo_i32_6(void* ipaddr, uint8_t* const destdns, int8_t* const destip);
error_type		init_socket6();
void			send_probes6();
error_type		print_route6(const void* const recvbuff, ssize_t bufflen);

#endif

u_short	in_cksum(u_short *addr, int len);
void	tvsub(struct timeval* out, struct timeval* in);
