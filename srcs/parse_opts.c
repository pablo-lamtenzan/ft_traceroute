
# include <traceroute.h>
# include <parse.h>
# include <ftlibc.h>

__attribute__ ((pure))
bool            is_string_digit(const char* s)
{
    if (*s == '-')
        s++;
    while (*s)
    {
        if (*s < '0' || *s > '9')
            return (false);
        s++;
    }
    return (true);
}

bool	parse_opt_waitrecv(const char* arg)
{
	bool st = true;

    if (is_string_digit(arg) == false)
    {
        PRINT_ERROR(__progname ": %s\n", "option -w: invalid argument");
        st = false;
        goto error;
    }
	long value = ft_atol(arg);
	if (value < 0 || value > 86400)
	{
		PRINT_ERROR(__progname ": %s\n", "wait time must be in range 0 <-> 86400");
		st = false;
		goto error;
	}
	gctx.parse.opts_args.waitrecv = value;
error:
	return st;
}

bool	parse_opt_waitsend(const char* arg)
{
	bool st = true;

    if (is_string_digit(arg) == false)
    {
        PRINT_ERROR(__progname ": %s\n", "option -z: invalid argument");
        st = false;
        goto error;
    }
	long value = ft_atol(arg);
	if (value < 0 || value > 3600000)
	{
		PRINT_ERROR(__progname ": %s\n", "pause msecs must be in range 0 <-> 3600000");
		st = false;
		goto error;
	}
		gctx.parse.opts_args.waitsend = value;
error:
	return st;
}

bool	parse_opt_tos(const char* arg)
{
	bool st = true;

    if (is_string_digit(arg) == false)
    {
        PRINT_ERROR(__progname ": %s\n", "option -t: invalid argument");
        st = false;
        goto error;
    }
	long value = ft_atol(arg);
	if (value < 0 || value > 255)
	{
		PRINT_ERROR(__progname ": %s\n", "tos must be in range 0 <-> 255");
		st = false;
		goto error;
	}
	gctx.parse.opts_args.tos = value;
error:
	return st;

}

bool	parse_opt_nb_probes_per_hop(const char* arg)
{
	bool st = true;

    if (is_string_digit(arg) == false)
    {
        PRINT_ERROR(__progname ": %s\n", "option -q: invalid argument");
        st = false;
        goto error;
    }
	long value = ft_atol(arg);
	if (value < 1 || value > 10)
	{
		PRINT_ERROR(__progname ": %s\n", "probes per hop must be in range 1 <-> 10");
		st = false;
		goto error;
	}
	gctx.parse.opts_args.probes_nb_per_hop = value;
error:
	return st;
}

bool    parse_opt_simultaneous_packet_send(const char* arg)
{
    bool st = true;

    if (is_string_digit(arg) == false)
    {
        PRINT_ERROR(__progname ": %s\n", "option -N: invalid argument");
        st = false;
        goto error;
    }
    long value = ft_atol(arg);
	if (value < 1 || value > 64)
	{
		PRINT_ERROR(__progname ": %s\n", "simultaneous packets must be in range 1 <-> 64");
		st = false;
		goto error;
	}
	gctx.parse.opts_args.simultanious_probes = value;
error:
	return st;
}

bool    parse_opt_port(const char* arg)
{
    bool st = true;

    if (is_string_digit(arg) == false)
    {
        PRINT_ERROR(__progname ": %s\n", "option -m: invilid argument");
        st = false;
        goto error;
    }
    long value = ft_atol(arg);
    if (value > 65535 || value < 1)
    {
        PRINT_ERROR(__progname ": %s\n",  "port must be in range 1 <-> 65535");
        st = false;
        goto error;
    }
    gctx.parse.opts_args.port = value;
error:
    return st;
}

bool    parse_opt_endhop(const char* arg)
{
    bool st = true;

    if (is_string_digit(arg) == false)
    {
        PRINT_ERROR(__progname ": %s\n", "option -m: invalid argument");
        st = false;
        goto error;
    }
    long value = ft_atol(arg);
    if (value < 1 || value > 255)
    {
        PRINT_ERROR(__progname ": %s\n", "max hops must be in range 1 <-> 255");
        st = false;
        goto error;
    }
    gctx.parse.opts_args.max_hops = value;
error:
    return st;
}

bool    parse_opt_starthop(const char* arg)
{
    bool st = true;

    if (is_string_digit(arg) == false)
    {
        PRINT_ERROR(__progname ": %s\n", "option -f: invalid argument");
        st = false;
        goto error;
    }
    long value = ft_atol(arg);
    if (value > 30 || value < 0)
    {
        PRINT_ERROR(__progname ": %s\n", "first hop out of range");
        st = false;
        goto error;
    }
    gctx.parse.opts_args.initial_hops = value;
error:
    return st;
}

static bool    opt_arg_is_present(register size_t* const av_idx, const char** av[])
{
    if ((*av)[++(*av_idx)] == NULL)
    {
        ///TODO: 
        printf("[TODO] Usage no args [TODO]\n");
        //PRINT_ERROR(USAGE_NO_ARG, ++(*av)[*av_idx - 1]);
        return (false);
    }
    return (true);
}

error_type	parse_opts(const char** av[])
{
    static const char* const opts[] = {
        "-f", "-m", "-p", "-N",
        "-q", "-t", "-z", "-w",
        "-4", "-6", "-T", "-U",
        "-I"
    };

    static const fill_opt_args_t fillers[] = {
        &parse_opt_starthop,
		&parse_opt_endhop,
		&parse_opt_port,
		&parse_opt_simultaneous_packet_send,
		&parse_opt_nb_probes_per_hop,
		&parse_opt_tos,
		&parse_opt_waitsend,
		&parse_opt_waitrecv
    };

    size_t av_idx = 0;
    for ( ; (*av)[av_idx] && *(*av)[av_idx] == '-' ; av_idx++)
    {
        bool found = false;
        for (register size_t opts_idx = 0 ; opts_idx < ARRAYSIZE(opts) ; opts_idx++)
        {
            if (ft_strncmp((*av)[av_idx], opts[opts_idx], OPT_SIZE) == 0)
            {
                if (opts_idx < ARRAYSIZE(fillers)
                && (opt_arg_is_present(&av_idx, av) == false
                || fillers[opts_idx]((*av)[av_idx]) == false))
                    goto invalid_opt;
                OPT_ADD(1 << opts_idx);
                found = true;
                break ;
            }
        }
        if (found == false)
        {
            PRINT_ERROR(MSG_ERROR_INVALID_OPTION, ++(*av)[av_idx]);
            goto invalid_opt;
        }
    }
    *av += av_idx;
    return (SUCCESS);

invalid_opt:
    return (ERR_OPT);
}