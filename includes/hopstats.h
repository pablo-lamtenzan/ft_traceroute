
# pragma once

# include <stdbool.h>
# include <netdb.h>

# define ISPRINTED(x) ((x).recording == false)
# define ISZEROED(x) ((x).saddr == 0 && (x).st_total == 0)

typedef struct	hopstats4
{
	in_addr_t	saddr;
	bool		recording;
	struct
	{
		double		_tmin;
		double		_tmax;
		double		_tsum;
		uint32_t	_total;
	} stats;
	# define st_tmin stats._tmin
	# define st_tmax stats._tmax
	# define st_tsum stats._tsum
	# define st_total stats._total
}				hoststats4_t;
