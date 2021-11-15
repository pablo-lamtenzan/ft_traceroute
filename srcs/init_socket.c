
# include <traceroute.h>
# include <errno.h>

# include <unistd.h>

error_type requestportfromkernel4(in_port_t requested, in_port_t* dest, uint8_t protocol)
{
    error_type st = SUCCESS;

    struct sockaddr_in in = {
		.sin_family = AF_INET,
		.sin_port = htons(requested)
	};
    int sfd;
    socklen_t inlen = sizeof(in);

	*dest = 0;

    if ((sfd = socket(AF_INET, SOCK_STREAM, protocol)) < 0)
    {
        st = ERR_SYSCALL;
        PRINT_ERROR(MSG_ERROR_SYSCALL, "socket", errno);
        goto error;
    }

	if (bind(sfd, (struct sockaddr*)&in, inlen) < 0)
	{
		st = ERR_SYSCALL;
		PRINT_ERROR(MSG_ERROR_SYSCALL, "bind", errno);
		PRINT_ERROR(__progname": %s\n", "Failed request port from kernel");
		goto error;
	}

	if (getsockname(sfd, (struct sockaddr*)&in, &inlen) < 0)
	{
		st = ERR_SYSCALL;
		PRINT_ERROR(MSG_ERROR_SYSCALL, "getsockname", errno);
	}
	*dest = in.sin_port;

error:
	close(sfd);
	return st;
}

error_type init_socket4_tcp()
{
    error_type st = SUCCESS;

    if ((gctx.sendsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0
    || (gctx.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        st = ERR_SYSCALL;
        PRINT_ERROR(MSG_ERROR_SYSCALL, "socket", errno);
        goto error;
    }

    if (setsockopt(gctx.sendsockfd, IPPROTO_IP, IP_HDRINCL,
    (int[]){1}, sizeof(int)) < 0)
    {
        st = ERR_SYSCALL;
        PRINT_ERROR(MSG_ERROR_SYSCALL, "setsockopt", errno);
    }

error:
    return st;
}

error_type init_socket4_udp()
{
    error_type st = SUCCESS;

    if ((gctx.sendsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0
    || (gctx.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        st = ERR_SYSCALL;
        PRINT_ERROR(MSG_ERROR_SYSCALL, "socket", errno);
        goto error;
    }

    if (setsockopt(gctx.sendsockfd, IPPROTO_IP, IP_HDRINCL,
    (int[]){1}, sizeof(int)) < 0)
    {
        st = ERR_SYSCALL;
        PRINT_ERROR(MSG_ERROR_SYSCALL, "setsockopt", errno);
    }

error:
    return st;
}

error_type init_socket4_icmp()
{
    error_type st = SUCCESS;

    if ((gctx.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        st = ERR_SYSCALL;
        PRINT_ERROR(MSG_ERROR_SYSCALL, "socket", errno);
        goto error;
    }

    if (setsockopt(gctx.sockfd, IPPROTO_IP, IP_HDRINCL,
    (int[]){1}, sizeof(int)) < 0
    || setsockopt(gctx.sockfd, SOL_SOCKET, SO_SNDBUF,
    (int[]){(int)gctx.packetlen}, sizeof(int)) < 0)
    {
        st = ERR_SYSCALL;
        PRINT_ERROR(MSG_ERROR_SYSCALL, "setsockopt", errno);
    }

error:
    return st;
}

error_type init_socket6()
{
    return SUCCESS;
}