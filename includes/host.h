
# pragma once

# include <netdb.h>
# include <stdbool.h>

# define MAX_HOSTS 10
# define NOCODE -1

typedef struct	ft_timestamp
{
	double		t;
	char		code;
}				timestamp_t;

typedef struct	ft_host
{
	bool			istimeout;
	in_addr_t		saddr;
	struct sockaddr	skaddr;
	timestamp_t		times[MAX_HOSTS];
}				host_t;

host_t* findhost(host_t *const hostarr, size_t hostarrlen, in_addr_t saddr);
size_t	arrhostlen(const host_t* const arrhost);
size_t	timesplen(timestamp_t* const timestaparr);
bool	print_hostarr(const host_t* const hostarr);