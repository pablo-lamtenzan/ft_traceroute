
# pragma once

# include <inttypes.h>
# include <stdbool.h>

typedef enum	opt
{
	OPT_START_HOP =	(1 << 0),				// -f
	OPT_END_HOP =	(OPT_START_HOP << 1),	// -m
	OPT_PORT =		(OPT_END_HOP << 1),		// -p
	OPT_SIMPKSEND =	(OPT_PORT << 1),		// -N
	OPT_NBPKSEND =	(OPT_SIMPKSEND << 1),	// -q
	OPT_TOS =		(OPT_NBPKSEND << 1),	// -t
	OPT_WAITSEND =	(OPT_TOS << 1),			// -z
	OPT_WAITRECV =	(OPT_WAITSEND << 1),	// -w

	OPT_IPV4 =		(OPT_WAITRECV << 1),	// -4
	OPT_IPV6 =		(OPT_IPV4 << 1),		// -6
	OPT_PROBES_TCP =(OPT_IPV6 << 1),		// -T
	OPT_PROBES_UDP =(OPT_PROBES_TCP << 1),	// -U
	OPT_PROBES_ICMP=(OPT_PROBES_UDP << 1),	// -I
	OPT_DONTFRAG =	(OPT_PROBES_ICMP << 1),	// -F
	OPT_HELP =		(OPT_DONTFRAG << 1)		// -h
}				opt_t;

typedef struct	opts_arg
{
	uint64_t	initial_hops;				// -f
	uint64_t	max_hops;					// -m
	uint8_t		port;						// -p
	uint64_t	simultanious_probes;		// -N
	uint32_t	probes_nb_per_hop;			// -q
	uint8_t		tos;						// -t
	uint64_t	waitsend;					// -z
	uint64_t	waitrecv;					// -w
}				opts_arg_t;

typedef struct	parse
{
	uint16_t		opts;
	opts_arg_t	opts_args;	
}				parse_t;

bool            is_string_digit(const char* s);
