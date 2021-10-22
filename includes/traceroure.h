
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

typedef error_t (*gethostinfo_str_t)(const char*);
typedef error_t (*gethostinfo_i32_t)(void*);
typedef error_t (*init_socket_t)();
typedef void	(*send_probe_t)();

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
	} gfamilydependent;
	# define gethostinfo_str gfamilydependent._gethostinfo_str
	# define gethostinfo_i32 gfamilydependent._gethostinfo_i32
	# define init_socket gfamilydependent._init_socket
	# define send_probes gfamilydependent._send_probes
}						gcontext_t;

extern gcontext_t gctx;

# define OPT_HAS(opt) (gctx.parse.opts & (opt))
# define OPT_ADD(opt) (gctx.parse.opts |= (opt))
# define OPT_DEL(opt) (gctx.parse.opts &= ~(opt))

error_t		gethostinfo_str4(const char* hostname);
error_t		gethostinfo_i32_4(void* ipaddr);
error_t		init_socket4();
void		send_probes4();
void		trace_route();

#ifdef IS_IPV6_SUPORTED

error_t		gethostinfo_str6(const char* hostname);
error_t		gethostinfo_i32_6(void* ipaddr);
error_t		init_socket6();
void		send_probes6();

#endif
