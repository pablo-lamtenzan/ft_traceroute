INCDIR	=	includes
SRCDIR	=	srcs

HDRS	=\
$(addprefix includes/,\
	ft_error.h\
	ftlibc.h\
	gcc_dependent.h\
	host.h\
	parse.h\
	parse_types.h\
	traceroute.h\
)
SRCS	=\
$(addprefix srcs/,\
	$(addprefix ftlibc/,\
		atol.c\
		memcpy.c\
		memset.c\
		strlen.c\
		strncmp.c\
	)\
	gethostinfo.c\
	host.c\
	init_socket.c\
	$(addprefix legacy/,\
		cksum.c\
		tvsub.c\
	)\
	main.c\
	parse_opts.c\
	print_route.c\
	receivprobe.c\
	sendprobe.c\
)
