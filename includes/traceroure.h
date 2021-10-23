
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

typedef error_t (*gethostinfo_str_t)(const char*, uint8_t* const, uint8_t* const);
typedef error_t (*gethostinfo_i32_t)(void*, uint8_t* const, uint8_t* const);
typedef error_t (*init_socket_t)();
typedef void	(*send_probe_t)();
typedef error_t (*print_route_t)(const void* const, ssize_t);

typedef struct			gcontext
{
	struct sockaddr		dest_sockaddr;
	const uint8_t		dest_dns[NI_MAXHOST];
	const uint8_t		dest_ip[HOST_NAME_MAX];
	size_t				packetlen;
	int					sockfd;
	uint16_t			progid;
	parse_t				parse;
	uint64_t			hop;
	uint64_t			hop_max;

	struct
	{
		uint64_t _packet_per_hop_nb;
		uint64_t _packet_transm_nb;
		uint64_t _packet_receiv_nb;
		uint64_t _packet_error_nb;
	} gpacket_count;
	# define packet_per_hop_nb gpacket_count._packet_per_hop_nb
	# define packet_transm_nb gpacket_count._packet_transm_nb
	# define packet_receiv_nb gpacket_count._packet_receiv_nb
	# define packet_error_nb gpacket_count._packet_error_nb

	struct
	{
		double _tmin;
		double _tmax;
		double _tsum;
	} gtiming;
	# define tmin gtiming._tmin
	# define tmax gtiming._tmax
	# define tsum gtiming._tsum

	struct
	{
		gethostinfo_str_t	_gethostinfo_str;
		gethostinfo_i32_t	_gethostinfo_i32;
		init_socket_t		_init_socket;
		send_probe_t		_send_probes;
		print_route_t		_print_route;
	} gfamilydependent;
	# define gethostinfo_str gfamilydependent._gethostinfo_str
	# define gethostinfo_i32 gfamilydependent._gethostinfo_i32
	# define init_socket gfamilydependent._init_socket
	# define send_probes gfamilydependent._send_probes
	# define print_route gfamilydependent._print_route
}						gcontext_t;

extern gcontext_t gctx;

# define PAYLOADBYTE ((uint8_t)((uint8_t)4 | ((uint8_t)2 << 4)))
# define PSEUDOINFINITY (~(uint64_t)0UL)
# define VALIDE_HOST_REPLIES 3
# define DFT_TIMEOUT_SEC 5

# define OPT_HAS(opt) (gctx.parse.opts & (opt))
# define OPT_ADD(opt) (gctx.parse.opts |= (opt))
# define OPT_DEL(opt) (gctx.parse.opts &= ~(opt))

# define ARRAYSIZE(arr) (sizeof(arr) / sizeof(*arr))
# define MAX(l, r) ((l) > (r) ? (l) : (r))

# define TV_TO_MS(tv) (double)((double)(tv.tv_sec) * 1000.0 + (double)(tv.tv_usec) / 1000.0)

error_t		gethostinfo_str4(const char* hostname, uint8_t* const destdns, uint8_t* const destip);
error_t		gethostinfo_i32_4(void* ipaddr, uint8_t* const destdns, uint8_t* const destip);
error_t		init_socket4();
void		send_probes4();
error_t		receive_probe(uint8_t* const dest, size_t destlen, ssize_t* const recvbytes);
error_t		print_route4(const void* const recvbuff, ssize_t bufflen);


#ifdef IS_IPV6_SUPORTED

error_t		gethostinfo_str6(const char* hostname, uint8_t* const destdns, uint8_t* const destip);
error_t		gethostinfo_i32_6(void* ipaddr, uint8_t* const destdns, uint8_t* const destip);
error_t		init_socket6();
void		send_probes6();
error_t		print_route6(const void* const recvbuff, ssize_t bufflen);

#endif

u_short	in_cksum(u_short *addr, int len);
void	tvsub(struct timeval* out, struct timeval* in);
