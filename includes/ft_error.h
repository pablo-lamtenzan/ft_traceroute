
# pragma once

# include <gcc_dependent.h>
# include <stdio.h>

typedef enum	fterror
{
	SUCCESS,
	ERR_OPT,
	ERR_SYSCALL,
	ERR_DESTADDR,
	ERR_SOCKFAM,
	ERR_USERPRIV,
	CONTINUE,
	KEEP_RCV,
	DEST_UNREACH
}				error_type;

# define PRINT_ERROR(format, args...) dprintf(2, format, args)

# define MSG_ERROR_SYSCALL __progname ": syscall %s failed for some reason (code: %d)" "\n"
# define MSG_ERROR_PACKETLEN_SZ __progname ": too big packetlen %lu specified" "\n"
# define MSG_ERROR_UNKNOWN_HOSTNAME __progname ": %s: Name or service not known (code: %d)" "\n"
# define MSG_ERROR_INVALID_OPTION __progname ": Bad option `%s\'" "\n"

# define MSG_USAGE "Usage:\n \
\t" __progname " [ -46IUTFh ] [ -f first_ttl] [-m max_ttl ] [-N squeries ] [ -p port ] [ -t tos ] [-w wait_recv ] [ -q nqueries ] [ -z wait_send ] \
host [ packelen ]\n \
Options:\n \
\t-4\t\tUse IPv4\n \
\t-6\t\tUse IPv6\n \
\t-F\t\tDo not fragment packets\n \
\t-I\t\tUse ICMP ECHO for traceruting\n \
\t-U\t\tUse ICMP PORT UNREACHABLE for tracerouting\n \
\t-T\t\tUse TCP SYN for tracerouting with TCP half-open (default port is 80)\n \
\t-f\t\t<first_ttl> Start the route at first_ttl\n \
\t-m\t\t<max_ttl> End the route at max_ttl if no destination host has been found\n \
\t-N\t\t<squeries> Number of preves sent simultaneously (not supported)\n \
\t-p\t\t<port> Set the destination port to use. For ICMP and UDP default value is 33434, for ICMP port \
is used as sequence value and for UDP as destination port. Each iteration is incremented by 1. For TCP \
is a constant value (defualt is 80) and is used as destination port.\n \
\t-t\t\t<tos> Set the TOS (Type of Service) for outgoing packets\n \
\t-w\t\t<wait_recv> (not implemented yet)\n \
\t-q\t\t<nqueries> Set the number of probes for each hop. Default is 3.\n \
\t-z\t\t<wait_send> (not implemented yet)\n"
