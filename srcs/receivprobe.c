
# include <traceroute.h>
# include <errno.h>

# define PRINT_TIMEOUT(symbol) (printf(" %c ", symbol))

error_type receive_probe(uint8_t* const dest, size_t destlen, ssize_t* const recvbytes)
{
    error_type st = SUCCESS;

    fd_set fdr;
    FD_ZERO(&fdr);
    FD_SET(gctx.sockfd, &fdr);

    struct timeval waittime = (struct timeval){
        .tv_sec = 1,
        .tv_usec = 666667
    };

    for ( ; ; )
    {
        if (select(gctx.sockfd + 1, &fdr, 0, 0, &waittime) > 0)
        {
            if (FD_ISSET(gctx.sockfd, &fdr)
            && (*recvbytes = recvfrom(gctx.sockfd, dest, destlen, 0, 0, 0)) < 0)
            {
                if (errno == EINTR)
                    continue ;
                else
                {
                    st = ERR_SYSCALL;
                    PRINT_ERROR(MSG_ERROR_SYSCALL, "recvmsg", errno);
                    goto end;
                }
            }
        }
        else if (FD_ISSET(gctx.sockfd, &fdr) == 0)
        {
            PRINT_TIMEOUT('*');
            goto end;
        }
        else
        {
            PRINT_ERROR(MSG_ERROR_SYSCALL, "select", errno);
            st = ERR_SYSCALL;
            goto end;
        }
    }

end:
    FD_CLR(gctx.sockfd, &fdr);
	return st;
}
