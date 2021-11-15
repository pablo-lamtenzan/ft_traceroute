
# include <host.h>
# include <traceroute.h>
# include <errno.h>

# include <stdio.h>
# include <netinet/ip_icmp.h>
# include <netdb.h>

host_t* findhost(host_t *const hostarr, size_t hostarrlen, in_addr_t saddr)
{
    for (size_t i = 0 ; i < hostarrlen ; i++)
        if (hostarr[i].saddr == saddr)
            return &hostarr[i];
    return (void*)0;
}

size_t arrhostlen(const host_t* const arrhost)
{
    size_t i = 0;

    while (arrhost[i].saddr != 0)
        i++;
    return i > MAX_HOSTS ? MAX_HOSTS : i;
}

void arrhostcpynontimeout(host_t* dest, const host_t* src)
{
	size_t y = 0;

	for (size_t i = 0 ; src[i].saddr != 0 ; i++)
	{
		if (src[i].istimeout == false)
			dest[y++] = src[i];
	}
}

size_t timesplen(timestamp_t* const timestaparr)
{
    size_t i = 0;

    while (timestaparr[i].t != 0)
        i++;
    return i > MAX_HOSTS ? MAX_HOSTS : i;
}

__attribute__ ((always_inline))
static inline void print_unreach(uint8_t code)
{
	uint8_t c;

	switch (code)
	{
		case ICMP_NET_UNREACH:
			c = 'N';
			break ;
		case ICMP_HOST_UNREACH:
			c = 'H';
			break ;
		case ICMP_PROT_UNREACH:
			c = 'P';
			break ;
		case ICMP_PORT_UNREACH:
			c = 'p';
			break ;
		case ICMP_FRAG_NEEDED:
			c = 'F';
			break ;
		case ICMP_SR_FAILED:
			c = 'S';
			break ;
		case ICMP_NET_UNKNOWN:
		case ICMP_HOST_UNKNOWN:
			c = 'U';
			break ;
		case ICMP_HOST_ISOLATED:
			c = 'I';
			break ;
		case ICMP_NET_ANO:
		case ICMP_HOST_ANO:
			c = 'A';
			break ;
		case ICMP_NET_UNR_TOS:
		case ICMP_HOST_UNR_TOS:
			c = 'T';
			break ;

		case ICMP_PKT_FILTERED:
		case ICMP_PREC_VIOLATION:
		case ICMP_PREC_CUTOFF:
		default:
			c = 0; // <%d>
	}
	if (c == 0)
		printf(" !<%hhu>", code);
	else
		printf(" !%c", c);
}

# define PRINT_HOST_INFO(dns, ip) (						\
		printf("  %s (%s)", dns, ip)					\
	)

# define PRINT_TIMESTAMP(timediff) (					\
		printf("  %.3fms", timediff)					\
	)

# define PRINT_HOP(hop) (                               \
        printf("%2lu", hop)                             \
    )

# define PRINT_TIMEOUT(symbol) (                        \
        printf("  %c", symbol)                          \
    )


bool print_hostarr(const host_t* const hostarr)
{
    PRINT_HOP(gctx.hop);
    for (size_t i = 0 ; hostarr[i].saddr != 0 ; i++)
    {
        if (hostarr[i].istimeout == true)
        {
            PRINT_TIMEOUT('*');
            continue ;
        }

        if (getnameinfo(&hostarr[i].skaddr, sizeof(hostarr[i].skaddr), (char*)&gctx.dest_dns, ARRAYSIZE(gctx.dest_dns), 0, 0, 0) != 0)
		{
			PRINT_ERROR(MSG_ERROR_SYSCALL, "getnameinfo", errno);
			return false;
		}

        PRINT_HOST_INFO(gctx.dest_dns, inet_ntoa((*(struct sockaddr_in*)&hostarr[i].skaddr).sin_addr));

        for (size_t y = 0 ; hostarr[i].times[y].t != 0 ; y++)
        {
            PRINT_TIMESTAMP(hostarr[i].times[y].t);
            if (hostarr[i].times[y].code != NOCODE)
                print_unreach(hostarr[i].times[y].code);
        }
    }
    printf("%c", '\n');
    return (true);
}
