
# include <traceroute.h>
# include <errno.h>

error_type init_socket4()
{
    error_type st = SUCCESS;

    if ((gctx.sockfd = socket(AF_INET, GETSOCKTYPE, GETSOCKPROTOCOL)) < 0)
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