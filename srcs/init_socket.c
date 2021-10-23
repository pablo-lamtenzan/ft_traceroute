
# include <traceroure.h>
# include <errno.h>

error_t init_socket4()
{
    error_t st = SUCCESS;

    ///TODO: I handle only icmp for the moment
    if ((gctx.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        st = ERR_SYSCALL;
        PRINT_ERROR(MSG_ERROR_SYSCALL, "socket");
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

error_t init_socket6()
{
    
}